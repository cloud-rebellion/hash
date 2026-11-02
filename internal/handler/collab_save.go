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

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

type collabSaveInput struct {
	PeerID            string          `json:"peer_id"`
	Checkpoint        string          `json:"checkpoint"`
	Generation        string          `json:"generation"`
	ExpectedUpdatedAt string          `json:"expected_updated_at"`
	BlocksJSON        json.RawMessage `json:"blocks_json"`
}

var errCanonicalSaveObservation = pdfadmission.ErrCanonicalCollabObservationV1

func (s *Server) handleCollabSave(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	input, ok := s.newBlocksHTTPInputV1(w, r, u.OrgID)
	if !ok {
		return
	}
	defer input.CloseConsumerV1()
	var in collabSaveInput
	if err := decodePlainDraftInputV1(input, r, &in); err != nil {
		writeError(w, 400, "invalid save request")
		return
	}
	generation, err := strconv.ParseInt(in.Generation, 10, 64)
	token, tokenErr := hex.DecodeString(in.Checkpoint)
	_, timeErr := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil || generation <= 0 || strconv.FormatInt(generation, 10) != in.Generation || tokenErr != nil || len(token) != 32 || hex.EncodeToString(token) != in.Checkpoint || timeErr != nil || len(in.PeerID) == 0 || len(in.PeerID) > 128 {
		writeError(w, 400, "valid checkpoint, generation and expected_updated_at are required")
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
	var checkpoint [32]byte
	copy(checkpoint[:], token)
	result, err := blockauthoring.SaveCanonicalCollabV1(ctx,
		blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit},
		blockauthoring.ActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: auth.SessionTransactionAuthorization(s.Cookies, cookie.Value, session, u.OrgID), Via: "rest", Tool: "collab_save"},
		s.Collab, id, in.ExpectedUpdatedAt, checkRESTBlockObservationV1,
		blockauthoring.CanonicalCollabInputV1{PeerID: in.PeerID, Checkpoint: checkpoint, Generation: generation, BlocksJSON: in.BlocksJSON})
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if errors.Is(err, collab.ErrSaveCheckpoint) {
		writeError(w, http.StatusConflict, "Collaboration advanced during save; synchronize and retry with a fresh checkpoint.")
		return
	}
	if errors.Is(err, errCanonicalSaveObservation) || errors.Is(err, collab.ErrGeneration) || errors.Is(err, errBlockObservationStale) {
		writeError(w, 412, "Document or collaboration changed; preserve your draft and synchronize before retrying.")
		return
	}
	if err != nil {
		s.writeOwnedPlainDraftErrorV1(w, err)
		return
	}
	response := toDocumentResponse(result.Document)
	_ = room.PublishSaveReceipt(ctx, generation+1, response.UpdatedAt)
	writeJSON(w, 200, map[string]any{"document": response, "generation": strconv.FormatInt(generation+1, 10)})
}
