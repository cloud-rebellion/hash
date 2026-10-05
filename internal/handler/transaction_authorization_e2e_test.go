//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Direct processor fixtures must carry the same verified credential receipt as
// real API calls; a manually populated SessionUser is not authentication.
func automationCredentialContextE2E(t *testing.T, ctx context.Context, q *generated.Queries, user *generated.User) context.Context {
	t.Helper()
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateAPIKey(ctx, generated.CreateAPIKeyParams{
		OrgID: user.OrgID, UserID: user.ID, KeyPrefix: key.Prefix, KeyHash: key.Hash,
		Name: "Automation fixture", Scopes: []string{"write:authoring", "write:workflow"},
	}); err != nil {
		t.Fatal(err)
	}
	var admitted context.Context
	request := httptest.NewRequest(http.MethodPost, "https://hash.example.test/api/automation/v1/signature-requests", nil).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+key.Plaintext)
	response := httptest.NewRecorder()
	auth.RequireAPIKey(&auth.PgVerifier{Queries: q})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admitted = r.Context()
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || admitted == nil {
		t.Fatalf("fixture API admission failed: status=%d", response.Code)
	}
	return admitted
}
