// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package handler

import (
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/go-chi/chi/v5"
)

func (s *Server) emailTemplateActor(w http.ResponseWriter, r *http.Request) (authoring.Actor, bool) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return authoring.Actor{}, false
	}
	a, err := s.sessionOwnerActor(r, u)
	if err != nil {
		s.writeEmailTemplateError(w, err)
		return authoring.Actor{}, false
	}
	return a, true
}
func (s *Server) emailTemplateService() emailtemplates.Service {
	return emailtemplates.Service{Pool: s.Pool, Audit: s.Audit}
}
func (s *Server) writeEmailTemplateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, emailtemplates.ErrStale):
		writeError(w, http.StatusConflict, "Email template revision changed. Reload and review before saving or previewing.")
	case errors.Is(err, emailtemplates.ErrInput):
		writeError(w, http.StatusBadRequest, "Check the email template kind, byte limits, variables and safe formatting. Links, images, attributes and scripts are unavailable.")
	default:
		s.writeDraftAuthoringError(w, "email template operation", err)
	}
}
func (s *Server) handleListEmailTemplates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.emailTemplateActor(w, r)
	if !ok {
		return
	}
	rows, err := s.emailTemplateService().List(r.Context(), a)
	if err != nil {
		s.writeEmailTemplateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": 1, "templates": rows, "limits": map[string]int{"subject_bytes": dispatch.ServiceEmailSubjectSourceBytesV1, "html_bytes": dispatch.ServiceEmailHTMLSourceBytesV1, "text_bytes": dispatch.ServiceEmailTextSourceBytesV1}, "preview_synthetic": true})
}
func (s *Server) decodeEmailTemplate(w http.ResponseWriter, r *http.Request) (string, emailtemplates.Input, bool) {
	kind := chi.URLParam(r, "kind")
	if !dispatch.ServiceEmailKindV1(kind) {
		s.writeEmailTemplateError(w, emailtemplates.ErrInput)
		return "", emailtemplates.Input{}, false
	}
	// Bound the complete JSON representation, including escaped source. The
	// decoder also rejects unknown/duplicate fields and trailing JSON values.
	r.Body = http.MaxBytesReader(w, r.Body, 160*1024)
	var wire struct {
		ExpectedRevision *int64  `json:"expected_revision"`
		SubjectTemplate  *string `json:"subject_template"`
		HTMLTemplate     *string `json:"html_template"`
		TextTemplate     *string `json:"text_template"`
	}
	if err := decodeSignerJSON(r, &wire); err != nil || wire.ExpectedRevision == nil || wire.SubjectTemplate == nil || wire.HTMLTemplate == nil || wire.TextTemplate == nil {
		s.writeEmailTemplateError(w, emailtemplates.ErrInput)
		return "", emailtemplates.Input{}, false
	}
	in := emailtemplates.Input{ExpectedRevision: *wire.ExpectedRevision, SubjectTemplate: *wire.SubjectTemplate, HTMLTemplate: *wire.HTMLTemplate, TextTemplate: *wire.TextTemplate}
	return kind, in, true
}
func (s *Server) handleSaveEmailTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.emailTemplateActor(w, r)
	if !ok {
		return
	}
	kind, in, ok := s.decodeEmailTemplate(w, r)
	if !ok {
		return
	}
	row, err := s.emailTemplateService().Save(r.Context(), a, kind, in)
	if err != nil {
		s.writeEmailTemplateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, row)
}
func (s *Server) handlePreviewEmailTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.emailTemplateActor(w, r)
	if !ok {
		return
	}
	kind, in, ok := s.decodeEmailTemplate(w, r)
	if !ok {
		return
	}
	out, err := s.emailTemplateService().Preview(r.Context(), a, kind, in)
	if err != nil {
		s.writeEmailTemplateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
