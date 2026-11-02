// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCredentialMintsUseHashFormatAndRetainSecretEntropy(t *testing.T) {
	for _, mint := range []func() (*MintedKey, error){MintAPIKey, MintDocumentAgentKey} {
		key, err := mint()
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.SplitN(key.Plaintext, "_", 3)
		if len(parts) != 3 || parts[0] != "hash" || parts[1] != key.Prefix {
			t.Fatal("minted credential does not use the Hash format and original routing prefix")
		}
		secret, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || len(secret) != 24 || len(parts[2]) != 32 {
			t.Fatal("minted credential lost its 24-byte base64url secret")
		}
		expected := sha256.Sum256([]byte(key.Plaintext))
		if string(key.Hash) != string(expected[:]) {
			t.Fatal("minted credential hash does not bind all original bytes")
		}
	}
}

func TestParseAPIKeyPreservesBothFormatsAndRoutingNamespaces(t *testing.T) {
	for _, outer := range []string{"hash_", "mth_"} {
		for _, route := range []string{"a" + strings.Repeat("0b", 16), "d" + strings.Repeat("0b", 16), "deadbeef"} {
			t.Run(outer+route[:1], func(t *testing.T) {
				input := outer + route + "_synthetic-secret_with-underscore"
				prefix, full, err := ParseAPIKey(input)
				if err != nil || prefix != route || string(full) != input {
					t.Fatal("parse did not retain the original format, routing prefix and full credential bytes")
				}
				wantNamespace := ""
				if len(route) != 8 {
					wantNamespace = route[:1]
				}
				if credentialNamespace(prefix) != wantNamespace {
					t.Fatal("outer product format changed the existing routing namespace")
				}
			})
		}
	}
	for _, outer := range []string{"hash_", "mth_"} {
		for _, rest := range []string{"", "deadbeef", "deadbeef_", "deadbeeG_secret", "a1234_secret", "x" + strings.Repeat("ab", 16) + "_secret", "a" + strings.Repeat("a", 31) + "_secret", "d" + strings.Repeat("a", 33) + "_secret"} {
			if _, _, err := ParseAPIKey(outer + rest); err == nil {
				t.Fatal("malformed credential routing or empty secret accepted")
			}
		}
	}
	for _, input := range []string{"", "HASH_deadbeef_secret", "Hash_deadbeef_secret", "mthx_deadbeef_secret", "hashdeadbeef_secret", " hash_deadbeef_secret", "prefix_hash_deadbeef_secret"} {
		if _, _, err := ParseAPIKey(input); err == nil {
			t.Fatal("unsupported outer credential format accepted")
		}
	}
}

func TestRequireAPIKeyAcceptsOriginalHashesForCurrentAndLegacyFormats(t *testing.T) {
	for _, outer := range []string{"hash_", "mth_"} {
		for _, route := range []string{"a" + strings.Repeat("12", 16), "d" + strings.Repeat("12", 16), "deadbeef"} {
			for _, header := range []string{"Authorization", "X-API-Key"} {
				t.Run(outer+route[:1]+header, func(t *testing.T) {
					input := outer + route + "_synthetic-secret"
					stored := sha256.Sum256([]byte(input))
					var claims, handled int
					docID := uuid.Nil
					if strings.HasPrefix(route, "d") && len(route) > 8 {
						docID = uuid.New()
					}
					verifier := apiKeyVerifierStub{id: uuid.New(), userID: uuid.New(), orgID: uuid.New(), hash: stored[:], docScope: docID, scopes: []string{"read"}, claim: func(_ context.Context, _, doc uuid.UUID) error {
						claims++
						if doc != docID {
							t.Fatal("credential lost its original document scope")
						}
						return nil
					}}
					h := RequireAPIKey(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						handled++
						scopes, present := TokenScopesFromContext(r.Context())
						if !present || len(scopes) != 1 || scopes[0] != "read" || HasWriteScope(r.Context()) {
							t.Fatal("credential scopes changed during format compatibility")
						}
						w.WriteHeader(http.StatusNoContent)
					}))
					r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
					value := input
					if header == "Authorization" {
						value = "Bearer " + input
					}
					r.Header.Set(header, value)
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != http.StatusNoContent || handled != 1 || claims != 1 {
						t.Fatalf("original credential rejected: status=%d handled=%d claims=%d", w.Code, handled, claims)
					}
				})
			}
		}
	}
}

func TestRequireAPIKeyCannotRelabelOuterFormatOrRoutingType(t *testing.T) {
	for _, outer := range []string{"hash_", "mth_"} {
		for _, route := range []string{"a" + strings.Repeat("cd", 16), "d" + strings.Repeat("cd", 16), "deadbeef"} {
			original := outer + route + "_synthetic-secret"
			stored := sha256.Sum256([]byte(original))
			otherOuter := "hash_"
			if outer == otherOuter {
				otherOuter = "mth_"
			}
			invalid := []string{otherOuter + route + "_synthetic-secret", outer + route + "_wrong-secret"}
			if len(route) > 8 {
				otherType := "a"
				if route[:1] == otherType {
					otherType = "d"
				}
				invalid = append(invalid, outer+otherType+route[1:]+"_synthetic-secret")
			}
			for _, input := range invalid {
				claims := 0
				// Even if the lookup returns the stored row, a relabelled token must
				// fail the full-byte hash before any use claim or handler dispatch.
				verifier := apiKeyVerifierStub{hash: stored[:], claim: func(context.Context, uuid.UUID, uuid.UUID) error { claims++; return nil }}
				h := RequireAPIKey(verifier)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("changed credential reached handler") }))
				r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
				r.Header.Set("Authorization", "Bearer "+input)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusUnauthorized || claims != 0 {
					t.Fatalf("changed credential accepted/claimed: status=%d claims=%d", w.Code, claims)
				}
			}
		}
	}
}
