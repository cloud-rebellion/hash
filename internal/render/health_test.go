// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestGotenbergPingRequiresExactHealthyEndpoint(t *testing.T) {
	for _, status := range []int{204, 301, 302, 400, 401, 403, 404, 429, 500, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var redirected atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					redirected.Store(true)
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Location", "/login")
				w.WriteHeader(status)
			}))
			defer srv.Close()
			if err := NewGotenberg(srv.URL).Ping(context.Background()); err == nil {
				t.Fatalf("renderer status %d must fail readiness", status)
			}
			if redirected.Load() {
				t.Fatal("health probe followed a redirect to another endpoint")
			}
		})
	}
}
