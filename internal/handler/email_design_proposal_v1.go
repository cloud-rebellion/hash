// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package handler

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/go-chi/chi/v5"
	"net/http"
)

// Owner-only proposal uses the same original session/owner/CAS service as Save.
// It returns a synthetic candidate and never saves, sends or configures AI.
func (s *Server) handleProposeEmailDesignV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := s.emailTemplateActor(w, r)
	if !ok {
		return
	}
	kind := chi.URLParam(r, "kind")
	if !dispatch.ServiceEmailTemplateEditableKindV1(kind) {
		s.writeEmailTemplateError(w, emailtemplates.ErrInput)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 160*1024+6*dispatch.ServiceEmailDesignSourceBytesV1)
	var wire struct {
		ExpectedRevision *int64          `json:"expected_revision"`
		SubjectTemplate  *string         `json:"subject_template"`
		HTMLTemplate     *string         `json:"html_template"`
		TextTemplate     *string         `json:"text_template"`
		DesignJSON       json.RawMessage `json:"design_json"`
		Prompt           *string         `json:"prompt"`
	}
	if decodeSignerJSON(r, &wire) != nil || wire.ExpectedRevision == nil || wire.SubjectTemplate == nil || wire.HTMLTemplate == nil || wire.TextTemplate == nil || wire.Prompt == nil {
		s.writeEmailTemplateError(w, emailtemplates.ErrInput)
		return
	}
	in := emailtemplates.ProposalInput{Input: emailtemplates.Input{ExpectedRevision: *wire.ExpectedRevision, SubjectTemplate: *wire.SubjectTemplate, HTMLTemplate: *wire.HTMLTemplate, TextTemplate: *wire.TextTemplate}, Prompt: *wire.Prompt}
	if wire.DesignJSON != nil {
		var value string
		if string(wire.DesignJSON) == "null" || json.Unmarshal(wire.DesignJSON, &value) != nil {
			s.writeEmailTemplateError(w, emailtemplates.ErrInput)
			return
		}
		in.DesignJSON = &value
	}
	out, err := s.emailTemplateService().Propose(r.Context(), actor, kind, in)
	if err != nil {
		s.writeEmailTemplateError(w, err)
		return
	}
	defer out.CloseConsumerV1()
	writeJSON(w, http.StatusOK, out)
}
