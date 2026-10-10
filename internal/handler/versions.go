// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/versions"
)

// versionDTO is the wire shape exposed by REST + MCP. Block tree and
// variables are returned as raw JSON so callers can pass them straight back
// into the editor without a re-encode roundtrip.
type versionDTO struct {
	ID            string          `json:"id"`
	DocumentID    string          `json:"document_id"`
	VersionNo     int32           `json:"version_no"`
	Name          string          `json:"name"`
	SourceKind    string          `json:"source_kind"`
	BlocksJSON    json.RawMessage `json:"blocks_json,omitempty"`
	VariablesJSON json.RawMessage `json:"variables_json"`
	CreatedBy     string          `json:"created_by,omitempty"`
	CreatedVia    string          `json:"created_via"`
	CreatedAt     string          `json:"created_at"`
	ParentID      string          `json:"parent_id,omitempty"`
	SchemaVersion int32           `json:"schema_version"`
	Summary       string          `json:"summary,omitempty"`
}

func toVersionDTO(v *generated.DocumentVersion) versionDTO {
	out := versionDTO{
		ID:            v.ID.String(),
		DocumentID:    v.DocumentID.String(),
		VersionNo:     v.VersionNo,
		Name:          v.Name,
		SourceKind:    v.SourceKind,
		BlocksJSON:    v.BlockTreeJson,
		VariablesJSON: v.VariablesJson,
		CreatedVia:    v.CreatedVia,
		CreatedAt:     v.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		SchemaVersion: v.SchemaVersion,
		Summary:       v.Summary,
	}
	if v.CreatedBy.Valid {
		out.CreatedBy = uuid.UUID(v.CreatedBy.Bytes).String()
	}
	if v.ParentID.Valid {
		out.ParentID = uuid.UUID(v.ParentID.Bytes).String()
	}
	return out
}

// GET /api/v1/documents/{id}/versions
func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	// Org guard: confirm doc belongs to caller's org before exposing history.
	if _, err := s.Queries.GetActiveDocumentIdentity(r.Context(), generated.GetActiveDocumentIdentityParams{ID: docID, OrgID: sess.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	limit := int32(parseLimit(r.URL.Query().Get("limit"), 50, 200))
	rows, err := s.Versions.History(r.Context(), docID, limit)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]versionDTO, 0, len(rows))
	for _, v := range rows {
		out = append(out, toVersionDTO(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out, "count": len(out)})
}

// GET /api/v1/documents/{id}/versions/{n}
func (s *Server) handleGetVersion(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	n64, err := strconv.ParseInt(chi.URLParam(r, "n"), 10, 32)
	if err != nil || n64 <= 0 {
		writeError(w, http.StatusBadRequest, "invalid version number")
		return
	}
	if _, err := s.Queries.GetActiveDocumentIdentity(r.Context(), generated.GetActiveDocumentIdentityParams{ID: docID, OrgID: sess.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	row, err := s.Queries.GetDocumentVersionByNoForRead(r.Context(), generated.GetDocumentVersionByNoForReadParams{DocumentID: docID, VersionNo: int32(n64)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "version not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	if row.OrgID != sess.OrgID {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}
	v := generated.DocumentVersion(*row)
	writeJSON(w, http.StatusOK, toVersionDTO(&v))
}

// GET /api/v1/documents/{id}/diff?from=<n>&to=<n>
//
// 'to' defaults to the latest version, 'from' to to-1 (so a no-args call
// returns the most recent change, the common timeline use case).
func (s *Server) handleDiffVersions(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	if len(doc.HtmlSourceJson) != 0 {
		writeError(w, http.StatusConflict, "HTML revisions use declared-source and exact-PDF history; block-tree diff is unavailable")
		return
	}
	maxNo, err := s.Queries.GetLatestDocumentVersionNo(r.Context(), docID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if maxNo <= 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"from": nil, "to": nil, "changes": []any{}, "counts": versions.DiffCounts{},
		})
		return
	}
	to := int32(parseLimit(r.URL.Query().Get("to"), int(maxNo), int(maxNo)))
	from := int32(parseLimit(r.URL.Query().Get("from"), int(to-1), int(maxNo)))
	if from < 1 {
		from = 1
	}
	if from > to {
		writeError(w, http.StatusBadRequest, "from must be <= to")
		return
	}
	if from == to {
		// diffing a version against itself: zero changes by definition.
		v, err := s.Versions.GetByNo(r.Context(), docID, to)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"from":    diffSideFromRow(v),
			"to":      diffSideFromRow(v),
			"changes": []any{},
			"counts":  versions.DiffCounts{},
		})
		return
	}
	fromV, err := s.Versions.GetByNo(r.Context(), docID, from)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	toV, err := s.Versions.GetByNo(r.Context(), docID, to)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if fromV.OrgID != sess.OrgID || toV.OrgID != sess.OrgID {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}
	changes, err := versions.Diff(fromV.BlockTreeJson, toV.BlockTreeJson)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from":    diffSideFromRow(fromV),
		"to":      diffSideFromRow(toV),
		"changes": changes,
		"counts":  versions.SummarizeCounts(changes),
	})
}

func diffSideFromRow(v *generated.DocumentVersion) versions.DiffSide {
	tree, _ := blocksFromRaw(v.BlockTreeJson)
	return versions.DiffSide{
		VersionID:  v.ID.String(),
		VersionNo:  v.VersionNo,
		DocumentID: v.DocumentID.String(),
		BlockCount: tree,
		NameAtRev:  v.Name,
	}
}

// blocksFromRaw counts top-level blocks in a tree's JSONB. Best-effort: a
// malformed tree returns 0, which is safe in the diff metadata response.
func blocksFromRaw(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var t struct {
		Blocks []json.RawMessage `json:"blocks"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return 0, err
	}
	return len(t.Blocks), nil
}

// POST /api/v1/documents/{id}/versions/{n}/restore
//
// Materializes a historical version onto the live document row + snapshots a
// new version (Via='restore') so the timeline shows the action. Only legal
// while the document is still draft (sent docs are immutable).
func (s *Server) handleRestoreVersion(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	n64, err := strconv.ParseInt(chi.URLParam(r, "n"), 10, 32)
	if err != nil || n64 <= 0 {
		writeError(w, http.StatusBadRequest, "invalid version number")
		return
	}
	var in struct {
		ExpectedUpdatedAt string `json:"expected_updated_at"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid restore request")
		return
	}
	if in.ExpectedUpdatedAt == "" {
		writeError(w, http.StatusPreconditionRequired, "expected_updated_at is required")
		return
	}
	expected, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "expected_updated_at must be RFC3339")
		return
	}

	authorize, ok := s.sessionMutationAuthorization(w, r, sess)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockDraft(ctx, tx, authoring.Actor{OrgID: sess.OrgID, UserID: sess.UserID, Authorize: authorize}, docID)
	if err != nil {
		s.writeDraftAuthoringError(w, "restore document version failed", err)
		return
	}
	q := s.Queries.WithTx(tx)
	locked := guard.Document
	if locked.SourceKind != "blocks" {
		writeError(w, http.StatusConflict, "restore only supported on block-source documents")
		return
	}
	actorID := guard.UserID()
	if !locked.UpdatedAt.Valid || !locked.UpdatedAt.Time.Equal(expected) {
		writeError(w, http.StatusPreconditionFailed, "Document changed since observation. Fetch and review before restoring.")
		return
	}

	// Only this scoped target lookup translates absence into a readable error.
	// No-row mutation, version and audit writes below are internal failures.
	target, err := q.GetDocumentVersionByNo(ctx, generated.GetDocumentVersionByNoParams{DocumentID: docID, VersionNo: int32(n64)})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if target.OrgID != sess.OrgID {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}
	if target.SourceKind != "blocks" {
		writeError(w, http.StatusConflict, "target version is not block-source")
		return
	}
	if _, _, err := versions.New(q).Restore(ctx, versions.RestoreInput{
		DocumentID: docID, TargetVersion: int32(n64), OrgID: sess.OrgID, CreatedBy: &actorID,
	}); err != nil {
		writeInternalError(w, err)
		return
	}
	updated, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{
		ID:            docID,
		OrgID:         sess.OrgID,
		BlocksJson:    target.BlockTreeJson,
		VariablesJson: target.VariablesJson,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID:       sess.OrgID,
		ActorUserID: &actorID,
		DocumentID:  &docID,
		Kind:        audit.KindDocumentUpdated,
		IP:          firstIPFromHeader(r),
		UserAgent:   r.UserAgent(),
		Payload: map[string]any{
			"via":             "rest",
			"tool":            "restore_document_version",
			"restored_from_v": target.VersionNo,
			"restored_blocks": blockCountOrZero(target.BlockTreeJson),
		},
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := guard.Recheck(ctx); err != nil {
		s.writeDraftAuthoringError(w, "restore document version failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(pending)
	writeJSON(w, http.StatusOK, map[string]any{
		"document":        toDocumentResponse(updated),
		"restored_from_v": target.VersionNo,
	})
}

func blockCountOrZero(raw json.RawMessage) int {
	n, _ := blocksFromRaw(raw)
	return n
}

// parseLimit reads a numeric query param with sane defaults + clamping.
func parseLimit(s string, def, max int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	if max > 0 && n > max {
		return max
	}
	return n
}
