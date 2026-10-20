// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/commentwindow"
	"github.com/bright-interaction/hash/internal/sign"
)

func (s *Server) writeCommentPageErrorV1(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, commentwindow.ErrSelection):
		writeError(w, http.StatusBadRequest, "invalid comment page selection")
	case errors.Is(err, errCommentSessionExpired):
		writeError(w, http.StatusUnauthorized, "session expired")
	case errors.Is(err, errCommentSessionRevoked), errors.Is(err, sign.ErrSenderCommentNotAuthorized):
		writeError(w, http.StatusForbidden, "permission or session revoked")
	case errors.Is(err, sign.ErrCommentDocumentNotFound):
		writeError(w, http.StatusNotFound, "document not found")
	case errors.Is(err, sign.ErrSigningAdmissionUnavailableV1):
		w.Header().Set("Retry-After", "1")
		writeSignerReadError(w, err)
	case errors.Is(err, sign.ErrMagicLinkExpired), errors.Is(err, sign.ErrDocumentNotSignable), errors.Is(err, errSignerReadChanged):
		writeSignerReadError(w, err)
	default:
		writeInternalErrorMsg(w, "list comments", err)
	}
}
