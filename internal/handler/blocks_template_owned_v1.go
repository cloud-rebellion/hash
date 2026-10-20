// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"errors"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"io"
	"net/http"
)

func decodeBlocksStrictTemplateInputV1(input *pdfadmission.ApplicationBlocksInputV1, r *http.Request, dst any) error {
	return input.WithHTTPBodyV1(r.Context(), r.Body, func(raw []byte) error {
		copy := r.Clone(r.Context())
		copy.Body = io.NopCloser(bytes.NewReader(raw))
		return decodeSignerJSON(copy, dst)
	})
}
func (s *Server) finishOwnedBlocksTemplateV1(w http.ResponseWriter, r *http.Request, user, org uuid.UUID, in blockauthoring.TemplateInputV1, status int) {
	authorize, err := s.sessionDraftAuthorization(r, org, user)
	if err != nil {
		s.writeTemplateMutationError(w, "template mutation failed", err)
		return
	}
	result, err := blockauthoring.WriteTemplateV1(r.Context(), blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit}, blockauthoring.ActorV1{OrgID: org, UserID: user, Authorize: authorize}, in)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		s.writeOwnedBlocksTemplateErrorV1(w, "template mutation failed", err)
		return
	}
	response := toTemplateResponseBaseV1(result.Template)
	response.ContentSHA256 = result.Content.SHA256Hex()
	writeJSON(w, status, response)
}
func (s *Server) readOwnedBlocksTemplateV1(w http.ResponseWriter, r *http.Request, user, org, id uuid.UUID) {
	authorize, err := s.sessionDraftAuthorization(r, org, user)
	if err != nil {
		s.writeTemplateMutationError(w, "get template failed", err)
		return
	}
	result, err := blockauthoring.ReadTemplateV1(r.Context(), blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions}, blockauthoring.ActorV1{OrgID: org, UserID: user, Authorize: authorize}, id)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		s.writeOwnedBlocksTemplateErrorV1(w, "get template failed", err)
		return
	}
	response := toTemplateResponseBaseV1(result.Template)
	response.ContentSHA256 = result.Content.SHA256Hex()
	writeJSON(w, http.StatusOK, response)
}
func (s *Server) writeOwnedBlocksTemplateErrorV1(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, blockauthoring.ErrTemplateNotFoundV1) {
		writeError(w, http.StatusNotFound, "template not found")
		return
	}
	if errors.Is(err, pdfadmission.ErrBlocksTemplateSourceV1) || errors.Is(err, pdfadmission.ErrBlocksWriterV1) {
		writeError(w, http.StatusServiceUnavailable, "block template source capacity unavailable")
		return
	}
	s.writeTemplateMutationError(w, operation, err)
}
