// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/sanitize"
)

func TestHTMLHistoricalPDFProcessingRefusalsExposeCapacityWithoutPrivateProof(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		status     int
		retryAfter string
	}{
		{"capacity", sanitize.ErrPDFWorkerCapacity, http.StatusTooManyRequests, "1"},
		{"unavailable", sanitize.ErrPDFWorkerUnavailable, http.StatusServiceUnavailable, ""},
		{"deadline", context.DeadlineExceeded, http.StatusServiceUnavailable, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&Server{}).writeHTMLDocumentReadError(w, fmt.Errorf("private fixture diagnostics: %w", tc.err))
			if w.Code != tc.status || w.Header().Get("Retry-After") != tc.retryAfter {
				t.Fatalf("processing refusal status=%d retry=%q", w.Code, w.Header().Get("Retry-After"))
			}
			if w.Header().Get("Content-Type") == "application/pdf" || strings.Contains(w.Body.String(), "private fixture diagnostics") ||
				w.Header().Get("X-Hash-PDF-SHA256") != "" || w.Header().Get("X-Hash-HTML-Source-Commitment") != "" {
				t.Fatal("processing refusal exposed private bytes, diagnostics or PDF proof")
			}
		})
	}
}
