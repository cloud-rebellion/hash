// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/bright-interaction/hash/internal/pdfadmission"
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
	var work *pdfadmission.WorkAdmissionV1
	if s.Send != nil && s.Send.WorkRuntime != nil && s.Send.WorkRuntime.MatchesPoolV1(s.Pool) && s.Send.WorkRuntime.SessionsV1() == s.HTMLCreationSessions {
		work = s.Send.WorkRuntime.WorkV1()
	}
	return emailtemplates.Service{Pool: s.Pool, Audit: s.Audit, Work: work, Runtime: s.AIRuntime}
}
func (s *Server) writeEmailTemplateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, emailtemplates.ErrWorkspaceAIUnavailable):
		writeError(w, http.StatusPreconditionFailed, "Configure an enabled workspace AI provider in Settings before requesting a design proposal.")
	case errors.Is(err, emailtemplates.ErrStale):
		writeError(w, http.StatusConflict, "Email template revision changed. Reload and review before saving or previewing.")
	case errors.Is(err, emailtemplates.ErrInput):
		writeError(w, http.StatusBadRequest, "Check the email content, design, logo commitment, byte limits and variables. The native content slot is required; scripts, remote images and concealed actions are unavailable.")
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
	defer func() {
		for _, row := range rows {
			row.CloseConsumerV1()
		}
	}()
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": 1, "templates": rows, "limits": map[string]int{"subject_bytes": dispatch.ServiceEmailSubjectSourceBytesV1, "html_bytes": dispatch.ServiceEmailHTMLSourceBytesV1, "text_bytes": dispatch.ServiceEmailTextSourceBytesV1, "design_bytes": dispatch.ServiceEmailDesignSourceBytesV1}, "preview_synthetic": true})
}
func (s *Server) decodeEmailTemplate(w http.ResponseWriter, r *http.Request) (string, emailtemplates.Input, bool) {
	kind := chi.URLParam(r, "kind")
	if !dispatch.ServiceEmailKindV1(kind) {
		s.writeEmailTemplateError(w, emailtemplates.ErrInput)
		return "", emailtemplates.Input{}, false
	}
	// Bound the complete JSON representation, including escaped source. The
	// decoder also rejects unknown/duplicate fields and trailing JSON values.
	r.Body = http.MaxBytesReader(w, r.Body, 160*1024+6*dispatch.ServiceEmailDesignSourceBytesV1)
	var wire struct {
		ExpectedRevision *int64          `json:"expected_revision"`
		SubjectTemplate  *string         `json:"subject_template"`
		HTMLTemplate     *string         `json:"html_template"`
		TextTemplate     *string         `json:"text_template"`
		DesignJSON       json.RawMessage `json:"design_json"`
	}
	if err := decodeSignerJSON(r, &wire); err != nil || wire.ExpectedRevision == nil || wire.SubjectTemplate == nil || wire.HTMLTemplate == nil || wire.TextTemplate == nil {
		s.writeEmailTemplateError(w, emailtemplates.ErrInput)
		return "", emailtemplates.Input{}, false
	}
	in := emailtemplates.Input{ExpectedRevision: *wire.ExpectedRevision, SubjectTemplate: *wire.SubjectTemplate, HTMLTemplate: *wire.HTMLTemplate, TextTemplate: *wire.TextTemplate}
	if wire.DesignJSON != nil {
		var design string
		if string(wire.DesignJSON) == "null" || json.Unmarshal(wire.DesignJSON, &design) != nil {
			s.writeEmailTemplateError(w, emailtemplates.ErrInput)
			return "", emailtemplates.Input{}, false
		}
		in.DesignJSON = &design
	}
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
	defer row.CloseConsumerV1()
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
	defer out.CloseConsumerV1()
	writeJSON(w, http.StatusOK, out)
}
