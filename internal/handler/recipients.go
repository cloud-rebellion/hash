// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
)

type recipientResponse struct {
	ID            uuid.UUID `json:"id"`
	DocumentID    uuid.UUID `json:"document_id"`
	Role          string    `json:"role"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	OrderIndex    int32     `json:"order_index"`
	Locale        string    `json:"locale"`
	Status        string    `json:"status"`
	SentAt        string    `json:"sent_at,omitempty"`
	FirstViewedAt string    `json:"first_viewed_at,omitempty"`
	SignedAt      string    `json:"signed_at,omitempty"`
	CreatedAt     string    `json:"created_at"`
}

func toRecipientResponse(r *generated.Recipient) recipientResponse {
	out := recipientResponse{
		ID:         r.ID,
		DocumentID: r.DocumentID,
		Role:       r.Role,
		Email:      r.Email,
		Name:       r.Name,
		OrderIndex: r.OrderIndex,
		Locale:     r.Locale,
		Status:     r.Status,
		CreatedAt:  r.CreatedAt.Time.Format(time.RFC3339),
	}
	if r.SentAt.Valid {
		out.SentAt = r.SentAt.Time.Format(time.RFC3339)
	}
	if r.FirstViewedAt.Valid {
		out.FirstViewedAt = r.FirstViewedAt.Time.Format(time.RFC3339)
	}
	if r.SignedAt.Valid {
		out.SignedAt = r.SignedAt.Time.Format(time.RFC3339)
	}
	return out
}

type createRecipientInput struct {
	Role       string `json:"role"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	OrderIndex int32  `json:"order_index"`
	Locale     string `json:"locale"`
}

func (s *Server) handleListRecipients(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if !s.assertDocumentInOrg(w, r, docID, u) {
		return
	}
	rows, err := s.Queries.ListRecipientsByDocument(r.Context(), docID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list recipients failed")
		return
	}
	out := make([]recipientResponse, 0, len(rows))
	for _, rec := range rows {
		out = append(out, toRecipientResponse(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"recipients": out})
}

func (s *Server) handleCreateRecipient(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in createRecipientInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	actor, ok := s.recipientMutationActor(w, r, u)
	if !ok {
		return
	}
	engine := recipients.MutationEngine{Pool: s.Pool, Audit: s.Audit, Billing: s.Billing}
	rec, err := engine.Create(r.Context(), actor, docID, recipients.Values{
		Email: in.Email, Name: in.Name, Role: in.Role, OrderIndex: in.OrderIndex, Locale: in.Locale,
	})
	if err != nil {
		s.writeRecipientMutationError(w, "create recipient", err)
		return
	}
	writeJSON(w, http.StatusCreated, toRecipientResponse(rec))
}

type updateRecipientInput struct {
	Email      *string `json:"email,omitempty"`
	Name       *string `json:"name,omitempty"`
	Role       *string `json:"role,omitempty"`
	OrderIndex *int32  `json:"order_index,omitempty"`
	Locale     *string `json:"locale,omitempty"`
}

func (s *Server) handleUpdateRecipient(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	rid, ok := parseUUIDParam(w, r, "rid")
	if !ok {
		return
	}
	var in updateRecipientInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	actor, ok := s.recipientMutationActor(w, r, u)
	if !ok {
		return
	}
	engine := recipients.MutationEngine{Pool: s.Pool, Audit: s.Audit, Billing: s.Billing}
	rec, err := engine.Update(r.Context(), actor, docID, rid, recipients.Patch{
		Email: in.Email, Name: in.Name, Role: in.Role, OrderIndex: in.OrderIndex, Locale: in.Locale,
	})
	if err != nil {
		s.writeRecipientMutationError(w, "update recipient", err)
		return
	}
	writeJSON(w, http.StatusOK, toRecipientResponse(rec))
}

func (s *Server) handleDeleteRecipient(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	rid, ok := parseUUIDParam(w, r, "rid")
	if !ok {
		return
	}
	actor, ok := s.recipientMutationActor(w, r, u)
	if !ok {
		return
	}
	engine := recipients.MutationEngine{Pool: s.Pool, Audit: s.Audit, Billing: s.Billing}
	if _, err := engine.Delete(r.Context(), actor, docID, rid); err != nil {
		s.writeRecipientMutationError(w, "delete recipient", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) recipientMutationActor(w http.ResponseWriter, r *http.Request, u auth.SessionUser) (recipients.MutationActor, bool) {
	authorize, ok := s.sessionMutationAuthorization(w, r, u)
	if !ok {
		return recipients.MutationActor{}, false
	}
	return recipients.MutationActor{
		OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize,
		Via: "rest", IP: clientIP(r), UserAgent: r.UserAgent(),
	}, true
}

func (s *Server) writeRecipientMutationError(w http.ResponseWriter, operation string, err error) {
	var validationErr *recipients.ValidationError
	switch {
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		writeError(w, http.StatusUnauthorized, "credential expired before transaction committed")
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		writeError(w, http.StatusForbidden, "permission or credential revoked")
	case errors.Is(err, recipients.ErrDocumentNotFound):
		writeError(w, http.StatusNotFound, "document not found")
	case errors.Is(err, recipients.ErrRecipientNotFound):
		writeError(w, http.StatusNotFound, "recipient not found")
	case errors.Is(err, recipients.ErrDocumentNotDraft):
		writeError(w, http.StatusConflict, "document not editable (must be draft)")
	case errors.Is(err, recipients.ErrDocumentHasEvidence):
		writeError(w, http.StatusConflict, "document contains retained signing evidence or sealing state; review before editing recipients")
	case errors.Is(err, recipients.ErrPrivacyReviewChanging):
		writeError(w, http.StatusConflict, "privacy review is changing; retry after it completes")
	case errors.Is(err, recipients.ErrPendingPrivacyReview):
		writeError(w, http.StatusConflict, "recipient changes await the open privacy request review")
	case errors.As(err, &validationErr):
		writeError(w, http.StatusBadRequest, validationErr.Error())
	default:
		if !s.writeAuthoringQuotaError(w, err) {
			writeInternalErrorMsg(w, operation, err)
		}
	}
}

func normalizeRecipientUpdate(existing *generated.Recipient, in updateRecipientInput) (recipients.Values, error) {
	return recipients.NormalizePatch(existing, recipients.Patch{
		Email: in.Email, Name: in.Name, Role: in.Role, OrderIndex: in.OrderIndex, Locale: in.Locale,
	})
}

// requireDraftDocument provides a friendly HTTP error before authoring work,
// while every write query repeats the status predicate atomically to close a
// concurrent send race.
func (s *Server) requireDraftDocument(w http.ResponseWriter, r *http.Request, docID uuid.UUID, u auth.SessionUser) (*generated.Document, bool) {
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return nil, false
	}
	if doc.Status != "draft" {
		writeError(w, http.StatusConflict, "document not editable (must be draft)")
		return nil, false
	}
	return doc, true
}

// assertDocumentInOrg verifies the document is in the user's org so we can't
// read or mutate cross-tenant rows. Writes 404 on miss, 500 on lookup error.
func (s *Server) assertDocumentInOrg(w http.ResponseWriter, r *http.Request, docID uuid.UUID, u auth.SessionUser) bool {
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return false
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return false
	}
	return true
}
