// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrivateResponseCachingDisabledAcrossStatuses(t *testing.T) {
	for _, path := range []string{"/api/v1/me", "/api/v1/documents/123/pdf", "/api/automation/v1/signature-requests", "/auth/login", "/auth/callback?code=secret", "/auth/logout", "/mcp", "/mcp/tools"} {
		for _, status := range []int{200, 302, 401, 403, 500} {
			h := (&Server{}).securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
			response := httptest.NewRecorder()
			h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
				t.Fatalf("path=%s status=%d cache headers missing", path, status)
			}
		}
	}
}

func TestPublicAssetsRetainCachingPolicy(t *testing.T) {
	for _, path := range []string{"/branding/logo/public.png", "/_app/immutable/app.js"} {
		h := (&Server{}).securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.WriteHeader(200)
		}))
		response := httptest.NewRecorder()
		h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Header().Get("Cache-Control") != "public, max-age=3600" || response.Header().Get("Pragma") != "" {
			t.Fatalf("public path=%s caching changed", path)
		}
	}
}
