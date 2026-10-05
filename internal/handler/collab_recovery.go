// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

var errCollabSessionExpired = errors.New("collaboration session expired before commit")

func (s *Server) collabSessionFresh(r *http.Request) bool {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return false
	}
	_, err = s.Cookies.Verify(cookie.Value)
	return err == nil
}

// Recovery/archive access locks the document before the user, matching canonical
// saves and per-frame authorization. Middleware identity alone is insufficient
// after a lock wait; live owner role and session generation are checked here.
func (s *Server) collabOwnerTransaction(w http.ResponseWriter, r *http.Request, id, org, user uuid.UUID) (pgx.Tx, *generated.Queries, *generated.Document, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		writeError(w, 401, "session required")
		return nil, nil, nil, false
	}
	payload, err := s.Cookies.Verify(cookie.Value)
	var session auth.SessionPayload
	if err != nil || json.Unmarshal(payload, &session) != nil || session.UserID != user {
		writeError(w, 401, "session invalid")
		return nil, nil, nil, false
	}
	// The organization fence must be followed by a fresh committed request
	// snapshot even if an operator changes the database's default isolation.
	tx, err := s.Pool.BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		writeInternalError(w, err)
		return nil, nil, nil, false
	}
	q := s.Queries.WithTx(tx)
	doc, err := q.GetDocumentForPrivacyUpdate(r.Context(), generated.GetDocumentForPrivacyUpdateParams{DocumentID: id, OrgID: org})
	if err != nil {
		_ = tx.Rollback(r.Context())
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "document not found")
		} else {
			writeInternalError(w, err)
		}
		return nil, nil, nil, false
	}
	var role string
	var generation int64
	err = tx.QueryRow(r.Context(), `SELECT role,session_generation FROM users WHERE id=$1 AND org_id=$2 FOR SHARE`, user, org).Scan(&role, &generation)
	if err != nil || role != string(auth.RoleOwner) || session.Generation != generation {
		_ = tx.Rollback(r.Context())
		writeError(w, 403, "owner permission or session revoked")
		return nil, nil, nil, false
	}
	if _, err := s.Cookies.Verify(cookie.Value); err != nil {
		_ = tx.Rollback(r.Context())
		writeError(w, 401, "session expired while awaiting authorization")
		return nil, nil, nil, false
	}
	return tx, q, doc, true
}

func (s *Server) handleCollabRecoveryState(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	tx, q, doc, ok := s.collabOwnerTransaction(w, r, id, u.OrgID, u.UserID)
	if !ok {
		return
	}
	defer tx.Rollback(ctx)
	generation, err := q.GetDocumentCollabGeneration(ctx, generated.GetDocumentCollabGenerationParams{ID: id, OrgID: u.OrgID})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	rows, err := q.ListCollabRecoveryArchives(ctx, generated.ListCollabRecoveryArchivesParams{DocumentID: id, OrgID: u.OrgID})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	archives := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		var history any
		if a.HistoryGeneration.Valid {
			history = strconv.FormatInt(a.HistoryGeneration.Int64, 10)
		}
		archives = append(archives, map[string]any{"id": a.ID, "origin": a.Origin, "history_generation": history, "observed_canonical_generation": strconv.FormatInt(a.ObservedCanonicalGeneration, 10), "created_at": a.CreatedAt.Time.UTC().Format(time.RFC3339Nano), "expires_at": a.ExpiresAt.Time.UTC().Format(time.RFC3339Nano), "size_bytes": a.SizeBytes})
	}
	if !s.collabSessionFresh(r) {
		writeError(w, 401, "session expired during recovery review")
		return
	}
	writeJSON(w, 200, map[string]any{"document": toDocumentResponse(doc), "document_deleted": doc.DeletedAt.Valid, "generation": strconv.FormatInt(generation, 10), "archives": archives})
}

type collabRecoveryInput struct {
	Generation        string `json:"generation"`
	ExpectedUpdatedAt string `json:"expected_updated_at"`
	Acknowledged      bool   `json:"acknowledged"`
}

func (s *Server) handleCollabRecovery(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in collabRecoveryInput
	if decodeJSON(r, &in) != nil {
		writeError(w, 400, "invalid recovery request")
		return
	}
	generation, err := strconv.ParseInt(in.Generation, 10, 64)
	expected, timeErr := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil || generation <= 0 || strconv.FormatInt(generation, 10) != in.Generation || timeErr != nil || !in.Acknowledged {
		writeError(w, 400, "acknowledgement, generation and expected_updated_at are required")
		return
	}
	if s.Collab == nil {
		writeError(w, 503, "collaboration unavailable")
		return
	}
	lease, err := s.Collab.BeginRecovery(id, u.OrgID)
	if err != nil {
		writeError(w, 409, "collaboration recovery is busy; retry after preserving your draft")
		return
	}
	defer lease.Release()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	tx, q, doc, ok := s.collabOwnerTransaction(w, r, id, u.OrgID, u.UserID)
	if !ok {
		return
	}
	defer tx.Rollback(ctx)
	if doc.DeletedAt.Valid || doc.Status != "draft" || doc.SourceKind != "blocks" {
		writeError(w, 409, "recovery requires an editable block draft")
		return
	}
	privacyFence, err := q.TryCollabArchivePrivacyFence(ctx, u.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if !privacyFence {
		writeError(w, 409, "privacy review is changing; retry after it completes")
		return
	}
	var saved *generated.Document
	var advanced int64
	var event audit.PendingEvent
	commit := func(snapshot collab.RecoverySnapshot) error {
		cookie, _ := r.Cookie(SessionCookieName)
		if _, err := s.Cookies.Verify(cookie.Value); err != nil {
			return collab.ErrGeneration
		}
		var roomGeneration pgtype.Int8
		if snapshot.Generation > 0 {
			roomGeneration = pgtype.Int8{Int64: snapshot.Generation, Valid: true}
		}
		var err error
		advanced, err = q.RecoverCanonicalCollab(ctx, generated.RecoverCanonicalCollabParams{DocumentID: id, OrgID: u.OrgID, Generation: generation, ExpectedUpdatedAt: pgtype.Timestamptz{Time: expected, Valid: true}, UserID: u.UserID, Acknowledged: true, RoomState: snapshot.State, RoomGeneration: roomGeneration})
		if err != nil {
			return err
		}
		if advanced == 0 {
			return errCanonicalSaveObservation
		}
		saved, err = q.GetDocument(ctx, generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
		if err != nil {
			return err
		}
		event, err = s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id, Kind: audit.KindCollabRecovered, Payload: map[string]any{"generation": strconv.FormatInt(advanced, 10)}})
		if err != nil {
			return err
		}
		if !s.collabSessionFresh(r) {
			return errCollabSessionExpired
		}
		return tx.Commit(ctx)
	}
	if lease.Room != nil {
		err = lease.Room.CommitRecovery(commit)
	} else {
		err = commit(collab.RecoverySnapshot{})
	}
	if errors.Is(err, errCanonicalSaveObservation) || errors.Is(err, collab.ErrGeneration) {
		writeError(w, 412, "document changed; review the current document before recovery")
		return
	}
	if errors.Is(err, errCollabSessionExpired) {
		writeError(w, 401, "session expired before recovery committed")
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "54000" {
		writeError(w, 507, "recovery archive capacity reached; export and review existing archives first")
		return
	}
	if errors.As(err, &pgErr) && pgErr.Code == "55000" {
		writeError(w, 409, "recovery requires privacy review after completed erasure")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := lease.Finish(); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(event)
	writeJSON(w, 200, map[string]any{"document": toDocumentResponse(saved), "generation": strconv.FormatInt(advanced, 10)})
}

func (s *Server) handleCollabArchiveDownload(w http.ResponseWriter, r *http.Request) {
	s.collabArchiveAccess(w, r, false)
}
func (s *Server) handleCollabArchiveDelete(w http.ResponseWriter, r *http.Request) {
	s.collabArchiveAccess(w, r, true)
}

func (s *Server) collabArchiveAccess(w http.ResponseWriter, r *http.Request, remove bool) {
	if remove {
		var in struct {
			Acknowledged bool `json:"acknowledged"`
		}
		if decodeJSON(r, &in) != nil || !in.Acknowledged {
			writeError(w, 400, "archive deletion acknowledgement required")
			return
		}
	}
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	archiveID, ok := parseUUIDParam(w, r, "archiveID")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	tx, q, _, ok := s.collabOwnerTransaction(w, r, id, u.OrgID, u.UserID)
	if !ok {
		return
	}
	defer tx.Rollback(ctx)
	a, err := q.GetCollabRecoveryArchive(ctx, generated.GetCollabRecoveryArchiveParams{ArchiveID: archiveID, DocumentID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "archive not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	kind := audit.KindCollabArchiveDownloaded
	if remove {
		privacyFence, err := q.TryCollabArchivePrivacyFence(ctx, u.OrgID)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		if !privacyFence {
			writeError(w, 409, "privacy review is changing; retry after it completes")
			return
		}
		deferred, err := q.CollabArchiveDeletionDeferred(ctx, generated.CollabArchiveDeletionDeferredParams{DocumentID: id, OrgID: u.OrgID})
		if err != nil {
			writeInternalError(w, err)
			return
		}
		if deferred {
			writeError(w, 409, "archive deletion awaits the open privacy request review")
			return
		}
		rows, err := q.DeleteCollabRecoveryArchive(ctx, generated.DeleteCollabRecoveryArchiveParams{ArchiveID: archiveID, DocumentID: id, OrgID: u.OrgID})
		if err != nil {
			writeInternalError(w, err)
			return
		}
		if rows != 1 {
			writeError(w, 409, "archive changed; review before deleting")
			return
		}
		kind = audit.KindCollabArchiveDeleted
	}
	event, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id, Kind: kind, Payload: map[string]any{"archive_id": archiveID}})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if !s.collabSessionFresh(r) {
		writeError(w, 401, "session expired before archive access committed")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(event)
	if remove {
		w.WriteHeader(204)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="hash-collaboration-`+archiveID.String()+`.bin"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	_, _ = w.Write(a.YdocState)
}
