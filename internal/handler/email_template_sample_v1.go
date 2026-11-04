// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package handler

import (
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/bright-interaction/hash/internal/workspacesmtp"
	"github.com/go-chi/chi/v5"
)

func (s *Server) handleTestSavedEmailTemplateV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.workspaceSMTPActor(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var in struct {
		ExpectedSMTPRevision     *int64 `json:"expected_smtp_revision"`
		ExpectedTemplateRevision *int64 `json:"expected_template_revision"`
	}
	if decodeSignerJSON(r, &in) != nil || in.ExpectedSMTPRevision == nil || in.ExpectedTemplateRevision == nil {
		s.writeWorkspaceSMTPError(w, workspacesmtp.ErrInput)
		return
	}
	ctx, source, err := s.emailTemplateService().BeginSourceReadV1(r.Context(), a)
	if err != nil {
		s.writeEmailTemplateError(w, err)
		return
	}
	defer source.CloseConsumerV1()
	v, err := s.workspaceSMTPService().TestSavedTemplateV1(ctx, a, chi.URLParam(r, "kind"), *in.ExpectedSMTPRevision, *in.ExpectedTemplateRevision)
	if err != nil {
		if errors.Is(err, emailtemplates.ErrStale) || errors.Is(err, emailtemplates.ErrInput) {
			s.writeEmailTemplateError(w, err)
		} else {
			s.writeWorkspaceSMTPError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, v)
}
