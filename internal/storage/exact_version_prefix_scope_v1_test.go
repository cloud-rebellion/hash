// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Adopt after the production patch: this matrix names its private fence.
func TestExactKeyVersionPrefixDispatchScopeV1(t *testing.T) {
	const key = "org/test/documents/source.pdf"
	for _, tc := range []struct {
		name, method, prefix, marker string
		exact, versions, allowed     bool
	}{
		{"initial-exact-list", http.MethodGet, key, "", true, true, true},
		{"continue-same-exact-key", http.MethodGet, key, key, true, true, true},
		{"longer-key-before-dispatch", http.MethodGet, key, key + "~collision", true, true, false},
		{"unexpected-earlier-marker", http.MethodGet, key, "a", true, true, false},
		{"normal-unscoped-list", http.MethodGet, key, key + "~collision", false, true, true},
		{"unrelated-prefix", http.MethodGet, "other-prefix", "other-marker", true, true, true},
		{"object-get-keeps-working", http.MethodGet, key, key + "~collision", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			transport := &boundedStorageTransportV1{base: boundedStorageRoundTripTestV1(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), ContentLength: 0, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})}
			ctx := context.Background()
			if tc.exact {
				ctx = withExactVersionPrefixLimitV1(ctx, key)
			}
			query := url.Values{"prefix": {tc.prefix}, "key-marker": {tc.marker}}
			if tc.versions {
				query.Set("versions", "")
			}
			r, err := http.NewRequestWithContext(ctx, tc.method, "http://exact-prefix.invalid/hash-prefix-test/?"+query.Encode(), nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := transport.RoundTrip(r)
			if response != nil {
				if closeErr := response.Body.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			if tc.allowed {
				if err != nil || calls != 1 {
					t.Fatal("legitimate request was refused", err, calls)
				}
			} else if err != errExactVersionPrefixPageV1 || calls != 0 || response != nil {
				t.Fatal("out-of-prefix continuation crossed the actual transport fence", err, calls)
			}
		})
	}
}
