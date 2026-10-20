// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

type htmlAuthoringInputContextKeyV1 struct{}

// Only the fixed authenticated route installs this owner, using the live user
// org returned by RequireSession. No body witness selects its grant tenant.
func (s *Server) beginHTMLAuthoringInputV1(w http.ResponseWriter, r *http.Request, org uuid.UUID, profile pdfadmission.HTMLAuthoringInputProfileV1) (*http.Request, func(), bool) {
	if s.HTMLCreationSessions == nil {
		writeHTMLAuthoringInputUnavailableV1(w)
		return r, nil, false
	}
	owner, err := s.HTMLCreationSessions.NewHTMLAuthoringInputV1(r.Context(), org, profile)
	if err != nil {
		writeHTMLAuthoringInputUnavailableV1(w)
		return r, nil, false
	}
	return r.WithContext(context.WithValue(r.Context(), htmlAuthoringInputContextKeyV1{}, owner)), owner.CloseConsumerV1, true
}
func readHTMLAuthoringInputJSONV1(r *http.Request, limit int64) ([]byte, error) {
	if owner, ok := r.Context().Value(htmlAuthoringInputContextKeyV1{}).(*pdfadmission.ApplicationHTMLAuthoringInputV1); ok {
		return owner.ReadBodyV1(r.Context(), r.Body)
	}
	// Other legal endpoints and pure parser callers retain their original limit.
	// Each of the eight selected production handlers installs the native owner.
	return io.ReadAll(http.MaxBytesReader(nil, r.Body, limit))
}
func canonicalHTMLAuthoringInputV1(r *http.Request, master, defaults []byte) (htmlmaster.TemplateCommitment, error) {
	if owner, ok := r.Context().Value(htmlAuthoringInputContextKeyV1{}).(*pdfadmission.ApplicationHTMLAuthoringInputV1); ok {
		return owner.CanonicalTemplateV1(r.Context())
	}
	return htmlmaster.CanonicalTemplate(master, defaults)
}
func writeHTMLAuthoringInputUnavailableV1(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusServiceUnavailable, "HTML authoring input capacity is temporarily unavailable")
}
func writeHTMLAuthoringInputFailureV1(w http.ResponseWriter, err error) bool {
	if errors.Is(err, pdfadmission.ErrHTMLAuthoringInputV1) {
		writeHTMLAuthoringInputUnavailableV1(w)
		return true
	}
	return false
}
