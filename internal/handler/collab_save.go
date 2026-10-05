// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	blockschema "github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type collabSaveInput struct {
	PeerID            string          `json:"peer_id"`
	Checkpoint        string          `json:"checkpoint"`
	Generation        string          `json:"generation"`
	ExpectedUpdatedAt string          `json:"expected_updated_at"`
	BlocksJSON        json.RawMessage `json:"blocks_json"`
}

var errCanonicalSaveObservation = errors.New("canonical document observation changed")

func (s *Server) handleCollabSave(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in collabSaveInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid save request")
		return
	}
	generation, err := strconv.ParseInt(in.Generation, 10, 64)
	token, tokenErr := hex.DecodeString(in.Checkpoint)
	expected, timeErr := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil || generation <= 0 || strconv.FormatInt(generation, 10) != in.Generation || tokenErr != nil || len(token) != 32 || hex.EncodeToString(token) != in.Checkpoint || timeErr != nil || len(in.PeerID) == 0 || len(in.PeerID) > 128 {
		writeError(w, 400, "valid checkpoint, generation and expected_updated_at are required")
		return
	}
	blocks, err := blockschema.NormalizeTreeJSON(in.BlocksJSON)
	if err != nil {
		writeError(w, 400, "invalid blocks_json: "+err.Error())
		return
	}
	if s.Collab == nil {
		writeError(w, 503, "collaboration unavailable")
		return
	}
	room, err := s.Collab.RoomForSave(id, u.OrgID, u.UserID, in.PeerID)
	if err != nil {
		writeError(w, 412, "Collaboration changed; preserve your draft and synchronize before retrying.")
		return
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		writeError(w, 401, "session required")
		return
	}
	payload, err := s.Cookies.Verify(cookie.Value)
	var session auth.SessionPayload
	if err != nil || json.Unmarshal(payload, &session) != nil || session.UserID != u.UserID {
		writeError(w, 401, "session invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	q := s.Queries.WithTx(tx)
	existing, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "document not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if existing.Status != "draft" || existing.SourceKind != "blocks" {
		writeError(w, 409, "document is not an editable block draft")
		return
	}
	var role string
	var sessionGeneration int64
	err = tx.QueryRow(ctx, `SELECT role,session_generation FROM users WHERE id=$1 AND org_id=$2 FOR SHARE`, u.UserID, u.OrgID).Scan(&role, &sessionGeneration)
	if err != nil || (role != string(auth.RoleSender) && role != string(auth.RoleOwner)) || session.Generation != sessionGeneration {
		writeError(w, 403, "collaboration write permission or session revoked")
		return
	}
	if _, err = s.Cookies.Verify(cookie.Value); err != nil {
		writeError(w, 401, "session expired while awaiting authorization")
		return
	}
	var response documentResponse
	var pending audit.PendingEvent
	var checkpoint [32]byte
	copy(checkpoint[:], token)
	err = room.CommitSaveCheckpoint(in.PeerID, checkpoint, func(cp collab.SaveCheckpoint) error {
		if _, err := s.Cookies.Verify(cookie.Value); err != nil {
			return collab.ErrSaveCheckpoint
		}
		if cp.Generation != generation {
			return collab.ErrSaveCheckpoint
		}
		accepted, err := q.SaveCanonicalCollab(ctx, generated.SaveCanonicalCollabParams{DocumentID: id, OrgID: u.OrgID, Generation: cp.Generation, ExpectedUpdatedAt: pgtype.Timestamptz{Time: expected, Valid: true}, BlocksJson: blocks, YdocState: cp.State, UpdateCount: int32(cp.PendingUpdates), UserID: u.UserID})
		if err != nil {
			return err
		}
		if !accepted {
			return errCanonicalSaveObservation
		}
		saved, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
		if err != nil {
			return err
		}
		pending, err = s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id, Kind: audit.KindDocumentUpdated})
		if err != nil {
			return err
		}
		response = toDocumentResponse(saved)
		return tx.Commit(ctx)
	})
	if errors.Is(err, collab.ErrSaveCheckpoint) {
		writeError(w, http.StatusConflict, "Collaboration advanced during save; synchronize and retry with a fresh checkpoint.")
		return
	}
	if errors.Is(err, errCanonicalSaveObservation) || errors.Is(err, collab.ErrGeneration) {
		writeError(w, 412, "Document or collaboration changed; preserve your draft and synchronize before retrying.")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(pending)
	_ = room.PublishSaveReceipt(ctx, generation+1, response.UpdatedAt)
	writeJSON(w, 200, map[string]any{"document": response, "generation": strconv.FormatInt(generation+1, 10)})
}
