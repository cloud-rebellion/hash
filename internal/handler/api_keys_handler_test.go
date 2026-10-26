// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/auth"
)

func TestAPIKeyEndpoints_RejectUnauthenticated(t *testing.T) {
	srv := &Server{}
	r := srv.Routes()

	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/api-keys"},
		{http.MethodPost, "/api/v1/api-keys"},
		{http.MethodDelete, "/api/v1/api-keys/00000000-0000-0000-0000-000000000000"},
		{http.MethodGet, "/api/v1/webhooks"},
		{http.MethodPost, "/api/v1/webhooks"},
		{http.MethodDelete, "/api/v1/webhooks/00000000-0000-0000-0000-000000000000"},
		{http.MethodGet, "/api/v1/dashboard"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: got %d, want 401", tc.method, tc.path, rr.Code)
		}
	}
}

func TestSecurityHeadersOnNewRoutes(t *testing.T) {
	srv := &Server{}
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("CSP missing on new endpoint: %q", rr.Header().Get("Content-Security-Policy"))
	}
}

func TestCreateAPIKeyValidationDoesNotDependOnMCPBilling(t *testing.T) {
	// Billing is deliberately nil. When API-key issuance was incorrectly gated
	// on MCP this request returned 503 before ordinary request validation. The
	// standalone automation API is core, so its credential can be prepared even
	// when no MCP entitlement engine is configured.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(`{"name":"","scopes":["write:authoring","write:workflow"]}`))
	ctx := context.WithValue(req.Context(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	ctx = context.WithValue(ctx, auth.EmailKey, "owner@example.test")
	res := httptest.NewRecorder()
	(&Server{}).handleCreateAPIKey(res, req.WithContext(ctx))
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "name required") {
		t.Fatalf("issuance validation status/body = %d/%s, want plan-independent 400", res.Code, res.Body.String())
	}
}

func TestAPIKeyCreationScopesDefaultToAuthoringAndPreserveExplicitGrants(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  json.RawMessage
		want []string
	}{
		{"omitted", nil, []string{"read", "write:authoring"}},
		{"read only", json.RawMessage(`["read"]`), []string{"read"}},
		{"authoring only", json.RawMessage(`["write:authoring"]`), []string{"write:authoring"}},
		{"workflow opt-in", json.RawMessage(`["write:workflow"]`), []string{"write:workflow"}},
		{"integration", json.RawMessage(`["read","write:authoring","write:workflow"]`), []string{"read", "write:authoring", "write:workflow"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := apiKeyCreationScopes(tc.raw)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatal("new credential defaults or explicit grants changed unexpectedly")
			}
		})
	}
}

func TestAPIKeyCreationRejectsEmptyAndAmbiguousScopeBodiesBeforeEffects(t *testing.T) {
	// No database/mint dependency is configured: these must refuse before key
	// creation. Duplicate/case aliases must not override the selected grants.
	for _, body := range []string{
		`{"name":"test","scopes":[]}`,
		`{"name":"test","scopes":null}`,
		`{"name":"test","scopes":"read"}`,
		`{"name":"test","scopes":{}}`,
		`{"name":"test","scopes":[null]}`,
		`{"name":"test","scopes":["unknown"]}`,
		`{"name":"test","scopes":["read","write:admin"]}`,
		`{"name":"test","scopes":["read"],"scopes":["write:workflow"]}`,
		`{"name":"test","Scopes":["write:workflow"]}`,
		`{"name":"test","scopes":["read"]} {"scopes":["write:workflow"]}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(body))
		ctx := context.WithValue(req.Context(), auth.UserIDKey, uuid.New())
		ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
		ctx = context.WithValue(ctx, auth.RoleKey, "owner")
		ctx = context.WithValue(ctx, auth.EmailKey, "owner@example.test")
		res := httptest.NewRecorder()
		(&Server{}).handleCreateAPIKey(res, req.WithContext(ctx))
		if res.Code != http.StatusBadRequest {
			t.Fatalf("invalid/ambiguous credential body status=%d", res.Code)
		}
	}
}
