// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"errors"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"net/http"
)

func (s *Server) archiveOwnedTemplateV1(w http.ResponseWriter, r *http.Request, user, org, id uuid.UUID) {
	authorize, err := s.sessionDraftAuthorization(r, org, user)
	if err != nil {
		s.writeTemplateMutationError(w, "archive template failed", err)
		return
	}
	result, err := blockauthoring.ArchiveTemplateV1(r.Context(), blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit}, blockauthoring.ActorV1{OrgID: org, UserID: user, Authorize: authorize}, id)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if errors.Is(err, blockauthoring.ErrTemplateNotFoundV1) {
		writeError(w, http.StatusNotFound, "template not found")
		return
	}
	if errors.Is(err, pdfadmission.ErrTemplateArchiveV1) {
		writeError(w, http.StatusServiceUnavailable, "template archive capacity unavailable")
		return
	}
	if err != nil {
		s.writeTemplateMutationError(w, "archive template failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
