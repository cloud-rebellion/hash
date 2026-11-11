// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package handler

import (
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/emailtemplates"
)

func (s *Server) writeEmailPreferencesErrorV1(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, emailtemplates.ErrInput):
		writeError(w, http.StatusBadRequest, "Choose English or Swedish and supply the observed workspace email preference revision.")
	case errors.Is(err, emailtemplates.ErrStale):
		writeError(w, http.StatusConflict, "Workspace email language changed. Reload and review before saving.")
	default:
		s.writeEmailTemplateError(w, err)
	}
}

func (s *Server) handleGetEmailPreferencesV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := s.emailTemplateActor(w, r)
	if !ok {
		return
	}
	out, err := s.emailTemplateService().PreferencesV1(r.Context(), actor)
	if err != nil {
		s.writeEmailPreferencesErrorV1(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSaveEmailPreferencesV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := s.emailTemplateActor(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var in struct {
		ExpectedRevision *int64  `json:"expected_revision"`
		Locale           *string `json:"locale"`
	}
	if decodeSignerJSON(r, &in) != nil || in.ExpectedRevision == nil || in.Locale == nil {
		s.writeEmailPreferencesErrorV1(w, emailtemplates.ErrInput)
		return
	}
	out, err := s.emailTemplateService().SavePreferencesV1(r.Context(), actor, emailtemplates.PreferencesInputV1{ExpectedRevision: *in.ExpectedRevision, Locale: *in.Locale})
	if err != nil {
		s.writeEmailPreferencesErrorV1(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
