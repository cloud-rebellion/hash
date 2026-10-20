// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/sign"
)

// These tests exercise the real outer route limiters with no configured signing
// runtime. Requests admitted by the limiter reach the actual controlled503 gate;
// they do not authenticate a token or claim successful signer access. The SPA
// bootstrap remains204 and an exhausted real limiter remains429.
func newSignerRateLimitRouter(withClarifier bool) http.Handler {
	srv := &Server{
		Sign: &sign.Engine{},
		Frontend: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	if withClarifier {
		srv.Clarifier = &aiapps.Clarifier{}
	}
	router := chi.NewRouter()
	srv.mountSignerRoutes(router)
	return router
}

func signerRateLimitRequest(h http.Handler, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	// All requests intentionally share an address, modelling a customer office
	// behind one NAT. The route token is the ceremony-level limiter identity.
	req.RemoteAddr = "198.51.100.40:43123"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Dest", "document")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	return res
}

func assertSignerRateLimitRuntimeUnavailable(t *testing.T, res *httptest.ResponseRecorder) {
	t.Helper()
	if res.Code != http.StatusServiceUnavailable || res.Body.String() != "{\"error\":\"signer access is temporarily unavailable\"}\n" {
		t.Fatalf("admitted route did not reach controlled missing-runtime gate: status=%d body=%s", res.Code, res.Body.String())
	}
}

func TestSignerRouteRiskClassesUseIndependentTokenBudgets(t *testing.T) {
	h := newSignerRateLimitRouter(true)
	tests := []struct {
		name   string
		method string
		path   string
		limit  int
		status int
	}{
		{name: "bootstrap read", method: http.MethodGet, path: "/sign/read-token/", limit: signerReadRequestsPerMinute, status: http.StatusNoContent},
		{name: "legal mutation", method: http.MethodPost, path: "/sign/mutation-token/view", limit: signerMutationRequestsPerMinute, status: http.StatusServiceUnavailable},
		{name: "artifact download", method: http.MethodGet, path: "/sign/download-token/pdf", limit: signerDownloadRequestsPerMinute, status: http.StatusServiceUnavailable},
		{name: "paid clarification", method: http.MethodPost, path: "/sign/clarify-token/clarify", limit: signerClarifyRequestsPerMinute, status: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := signerRateLimitRequest(h, test.method, test.path)
			if res.Code != test.status {
				t.Fatalf("%s %s status = %d, want %d; body=%s", test.method, test.path, res.Code, test.status, res.Body.String())
			}
			if test.status == http.StatusServiceUnavailable {
				assertSignerRateLimitRuntimeUnavailable(t, res)
			}
			if got := res.Header().Get("X-RateLimit-Limit"); got != fmt.Sprint(test.limit) {
				t.Fatalf("%s %s rate limit = %q, want %d", test.method, test.path, got, test.limit)
			}
		})
	}
}

func TestSignerReadTrafficDoesNotExhaustMutationBudget(t *testing.T) {
	h := newSignerRateLimitRouter(false)
	// The former shared 60/min IP bucket failed here before the first signer in
	// a multi-party/test flow could submit. Legitimate bootstrap polling above
	// that old ceiling must neither fail nor consume the mutation bucket.
	for i := 0; i < 61; i++ {
		res := signerRateLimitRequest(h, http.MethodGet, "/sign/same-token/")
		if res.Code != http.StatusNoContent {
			t.Fatalf("bootstrap read %d status = %d, want 204", i+1, res.Code)
		}
	}
	res := signerRateLimitRequest(h, http.MethodPost, "/sign/same-token/view")
	assertSignerRateLimitRuntimeUnavailable(t, res)
}

func TestSignerMutationLimitIsolatedByTokenBehindSharedNAT(t *testing.T) {
	h := newSignerRateLimitRouter(false)
	for i := 0; i < signerMutationRequestsPerMinute; i++ {
		res := signerRateLimitRequest(h, http.MethodPost, "/sign/token-a/view")
		assertSignerRateLimitRuntimeUnavailable(t, res)
	}
	if res := signerRateLimitRequest(h, http.MethodPost, "/sign/token-a/view"); res.Code != http.StatusTooManyRequests {
		t.Fatalf("token A over-limit mutation status = %d, want 429", res.Code)
	}
	// Same office IP, different ceremony credential: token A's abuse cannot
	// starve a second legitimate signer.
	assertSignerRateLimitRuntimeUnavailable(t, signerRateLimitRequest(h, http.MethodPost, "/sign/token-b/view"))
	// Nor does mutation exhaustion block token A from reading its ceremony.
	if res := signerRateLimitRequest(h, http.MethodGet, "/sign/token-a/"); res.Code != http.StatusNoContent {
		t.Fatalf("token A read after mutation exhaustion status = %d, want 204", res.Code)
	}
}

func TestSignerGlobalIPCeilingStillBoundsTokenRotation(t *testing.T) {
	h := newSignerRateLimitRouter(false)
	for i := 0; i < signerGlobalIPRequestsPerMinute; i++ {
		path := fmt.Sprintf("/sign/forged-token-%d/", i)
		if res := signerRateLimitRequest(h, http.MethodGet, path); res.Code != http.StatusNoContent {
			t.Fatalf("global request %d status = %d, want 204", i+1, res.Code)
		}
	}
	res := signerRateLimitRequest(h, http.MethodGet, "/sign/one-token-too-many/")
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("request above global IP ceiling status = %d, want 429", res.Code)
	}
}
