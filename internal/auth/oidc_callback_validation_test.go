// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"errors"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOIDCCallbackRejectsAmbiguousHandshakeBeforeDiscovery(t *testing.T) {
	for _, tc := range []struct{ name, query, cookies string }{
		{"empty state", "state=&code=x", "hash_oauth_state=; hash_oauth_nonce=n; hash_oauth_verifier=v"},
		{"duplicate state cookie", "state=s&code=x", "hash_oauth_state=s; hash_oauth_state=s; hash_oauth_nonce=n; hash_oauth_verifier=v"},
		{"duplicate state query", "state=s&state=s&code=x", "hash_oauth_state=s; hash_oauth_nonce=n; hash_oauth_verifier=v"},
		{"duplicate code", "state=s&code=x&code=y", "hash_oauth_state=s; hash_oauth_nonce=n; hash_oauth_verifier=v"},
		{"empty verifier", "state=s&code=x", "hash_oauth_state=s; hash_oauth_nonce=n; hash_oauth_verifier="},
		{"duplicate nonce", "state=s&code=x", "hash_oauth_state=s; hash_oauth_nonce=n; hash_oauth_nonce=m; hash_oauth_verifier=v"},
		{"malformed query", "state=s&code=%zz", "hash_oauth_state=s; hash_oauth_nonce=n; hash_oauth_verifier=v"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &OIDC{cfg: OIDCConfig{IssuerURL: "invalid-issuer"}}
			r := httptest.NewRequest(http.MethodGet, "https://hash.example/auth/callback?"+tc.query, nil)
			r.Header.Set("Cookie", tc.cookies)
			_, _, _, _, err := o.Callback(context.Background(), r)
			if err == nil {
				t.Fatal("invalid handshake accepted")
			}
			if strings.Contains(err.Error(), "oidc unavailable") {
				t.Fatalf("discovery preceded validation: %v", err)
			}
		})
	}
}

type callbackTransport func(*http.Request) (*http.Response, error)

func (f callbackTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOIDCCallbackTokenExchangeHasDeadline(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: callbackTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 30*time.Second {
			t.Fatal("exchange missing callback deadline")
		}
		return nil, errors.New("synthetic token exchange failure")
	})}
	o := &OIDC{oauth2: &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: "https://idp.example/token"}}}
	r := httptest.NewRequest(http.MethodGet, "https://hash.example/auth/callback?state=s&code=x", nil)
	r.Header.Set("Cookie", "hash_oauth_state=s; hash_oauth_nonce=n; hash_oauth_verifier=v")
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	_, _, _, _, err := o.Callback(ctx, r)
	if err == nil || calls == 0 {
		t.Fatalf("exchange error=%v calls=%d", err, calls)
	}
}
