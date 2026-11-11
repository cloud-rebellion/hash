// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/auth"
)

// ownerKeyVerifier admits exactly one real minted key as an owner with no scopes.
type ownerKeyVerifier struct {
	prefix string
	hash   []byte
}

func (v ownerKeyVerifier) LookupByPrefix(_ context.Context, prefix string) (uuid.UUID, uuid.UUID, uuid.UUID, string, string, []byte, uuid.UUID, []string, error) {
	if prefix != v.prefix {
		return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, auth.ErrMutationPermissionRevoked
	}
	return uuid.New(), uuid.New(), uuid.New(), "owner", "owner@example.test", v.hash, uuid.Nil, []string{}, nil
}

func (ownerKeyVerifier) Claim(context.Context, uuid.UUID, uuid.UUID) error { return nil }

// Template approval is human-only. RequireAPIKey writes the same identity keys
// as RequireSession, so the route mount is the only thing keeping an owner's
// API key away from approve and preview.
func TestOwnerAPIKeyIsRefusedOnHumanOnlyTemplateRoutes(t *testing.T) {
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(key.Plaintext))
	srv := &Server{APIKeys: ownerKeyVerifier{prefix: key.Prefix, hash: sum[:]}}
	r := srv.Routes()
	id := "00000000-0000-0000-0000-000000000001"
	headers := map[string]func(*http.Request){
		"bearer":    func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+key.Plaintext) },
		"x-api-key": func(req *http.Request) { req.Header.Set("X-API-Key", key.Plaintext) },
	}
	for _, path := range []string{"/api/v1/templates/" + id + "/html/approve", "/api/v1/templates/" + id + "/html/preview"} {
		for name, set := range headers {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			set(req)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("%s via %s: got %d (%s), want 401", path, name, rr.Code, rr.Body.String())
			}
		}
	}

	// Positive control: the same key is admitted on the automation API. With no
	// scopes it reaches the scope check and gets 403, which is not the 401 of
	// the middleware refusing it.
	for name, set := range headers {
		req := httptest.NewRequest(http.MethodGet, "/api/automation/v1/documents", nil)
		set(req)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("control via %s: got %d (%s), want 403 from the scope check", name, rr.Code, rr.Body.String())
		}
	}
}
