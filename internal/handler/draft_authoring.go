// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/google/uuid"
)

// sessionDraftAuthorization retains the original signed credential when a
// shared mutation helper cannot write a response itself. Context identity is
// admission information; the draft guard checks the live member in its tx.
func (s *Server) sessionDraftAuthorization(r *http.Request, orgID, userID uuid.UUID) (auth.TransactionAuthorization, error) {
	u, ok := auth.FromContext(r.Context())
	if !ok || u.OrgID != orgID || u.UserID != userID || orgID == uuid.Nil || userID == uuid.Nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || s.Cookies == nil {
		return nil, auth.ErrMutationCredentialExpired
	}
	payload, err := s.Cookies.Verify(cookie.Value)
	if err != nil {
		return nil, auth.ErrMutationCredentialExpired
	}
	var session auth.SessionPayload
	if json.Unmarshal(payload, &session) != nil || session.UserID != userID {
		return nil, auth.ErrMutationPermissionRevoked
	}
	return auth.SessionTransactionAuthorization(s.Cookies, cookie.Value, session, orgID), nil
}

func draftAuthoringErrorStatus(err error) (int, bool) {
	switch {
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		return http.StatusUnauthorized, true
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		return http.StatusForbidden, true
	case errors.Is(err, authoring.ErrDocumentNotFound):
		return http.StatusNotFound, true
	case errors.Is(err, authoring.ErrDocumentNotDraft), errors.Is(err, authoring.ErrDocumentHasEvidence),
		errors.Is(err, authoring.ErrPrivacyReviewChanging), errors.Is(err, authoring.ErrPendingPrivacyReview):
		return http.StatusConflict, true
	default:
		return http.StatusInternalServerError, false
	}
}

func (s *Server) writeDraftAuthoringError(w http.ResponseWriter, operation string, err error) {
	if status, known := draftAuthoringErrorStatus(err); known {
		writeError(w, status, err.Error())
		return
	}
	writeInternalErrorMsg(w, operation, err)
}
