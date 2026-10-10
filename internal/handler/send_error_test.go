// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/send"
)

func TestWriteSendErrorReportsUnresolvedVariablesAsAuthoringError(t *testing.T) {
	recorder := httptest.NewRecorder()
	server := &Server{}
	server.writeSendError(recorder, fmt.Errorf("%w: client, effective_date", send.ErrUnresolvedVariables))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	for _, name := range []string{"client", "effective_date"} {
		if !strings.Contains(recorder.Body.String(), name) {
			t.Fatalf("response %q does not identify %q", recorder.Body.String(), name)
		}
	}
}

func TestWriteSendErrorReportsWithdrawnLegalStarterAsAuthoringError(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&Server{}).writeSendError(recorder, send.ErrUnsafeBuiltInLegalDraft)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestWriteSendErrorReportsUnsupportedBlockEvidenceAsAuthoringError(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&Server{}).writeSendError(recorder, fmt.Errorf("%w: image", send.ErrUnsupportedBlockEvidence))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestWriteSendErrorReportsUnsupportedBrandingLogoAsConflict(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&Server{}).writeSendError(recorder, send.ErrUnsupportedBrandingLogo)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
}

func TestWriteSendErrorReportsUnverifiedSourceWithoutUpstreamDetails(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&Server{}).writeSendError(recorder, fmt.Errorf("%w: upstream credential=synthetic-private-marker", resolver.ErrSourceFreshness))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "retry sending") || strings.Contains(body, "synthetic-private-marker") {
		t.Fatalf("response must offer a safe retry without upstream details: %s", body)
	}
}
