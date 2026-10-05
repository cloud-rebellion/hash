// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDocumentPreviewFramingPreservesSecurityBoundaries(t *testing.T) {
	for _, kind := range []string{"html", "pdf", "ordinary"} {
		t.Run(kind, func(t *testing.T) {
			s := &Server{CSPScriptSrc: " 'sha256-bootstrap'"}
			response := httptest.NewRecorder()
			s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if kind == "html" || kind == "pdf" {
					setDocumentPreviewHeaders(w, kind == "html")
				}
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/documents/id/preview", nil))
			policy := response.Header().Get("Content-Security-Policy")
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("preview lost private-response protections")
			}
			if kind == "ordinary" {
				if response.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(policy, "frame-ancestors 'none'") {
					t.Fatal("non-preview response became frameable")
				}
				return
			}
			if response.Header().Get("X-Frame-Options") != "SAMEORIGIN" || !strings.Contains(policy, "frame-ancestors 'self'") || strings.Contains(policy, "frame-ancestors 'none'") {
				t.Fatal("preview must permit only its own origin as ancestor")
			}
			if kind == "html" {
				for _, required := range []string{"script-src 'none'", "connect-src 'none'", "object-src 'none'", "form-action 'none'", "base-uri 'none'", "sandbox allow-same-origin"} {
					if !strings.Contains(policy, required) {
						t.Fatalf("static preview permits active content: missing %s", required)
					}
				}
				if strings.Contains(policy, "allow-scripts") || strings.Contains(policy, "sha256-bootstrap") {
					t.Fatal("application script capability leaked into static preview")
				}
			} else if !strings.Contains(policy, "script-src 'self' 'sha256-bootstrap'") || !strings.Contains(policy, "default-src 'self'") {
				t.Fatal("PDF framing changed baseline resource policy")
			}
		})
	}
}
