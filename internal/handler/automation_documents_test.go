// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/google/uuid"
)

func TestAutomationDocumentScopeRequiresOriginalOrgAPIReceipt(t *testing.T) {
	for _, tc := range []struct {
		name, required string
		scopes         []string
		document       bool
		want           int
	}{
		{"read only", "read", []string{"read"}, false, http.StatusNoContent},
		{"workflow only", "write:workflow", []string{"write:workflow"}, false, http.StatusNoContent},
		{"read cannot send", "write:workflow", []string{"read"}, false, http.StatusForbidden},
		{"authoring cannot send", "write:workflow", []string{"write:authoring"}, false, http.StatusForbidden},
		{"workflow cannot read", "read", []string{"write:workflow"}, false, http.StatusForbidden},
		{"empty scopes", "read", nil, false, http.StatusForbidden},
		{"legacy admin is not explicit read", "read", []string{"admin"}, false, http.StatusForbidden},
		{"document token", "read", []string{"read", "write:workflow"}, true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := auth.MintAPIKey()
			if err != nil {
				t.Fatal(err)
			}
			verifier := automationAPIKeyVerifier{id: uuid.New(), userID: uuid.New(), orgID: uuid.New(), role: "owner", email: "owner@example.test", hash: key.Hash, scopes: tc.scopes}
			if tc.document {
				verifier.docScope = uuid.New()
			}
			called := false
			handler := auth.RequireAPIKey(verifier)(requireAutomationDocumentScope(tc.required, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})))
			r := httptest.NewRequest(http.MethodGet, "/api/automation/v1/documents", nil)
			r.Header.Set("Authorization", "Bearer "+key.Plaintext)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.want || called != (tc.want == http.StatusNoContent) {
				t.Fatalf("admission=%d called=%t", w.Code, called)
			}
		})
	}
	for _, forged := range []bool{false, true} {
		ctx := context.Background()
		if forged {
			ctx = context.WithValue(ctx, auth.UserIDKey, uuid.New())
			ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
			ctx = context.WithValue(ctx, auth.RoleKey, "owner")
			ctx = context.WithValue(ctx, auth.TokenScopesKey, []string{"read"})
		}
		w := httptest.NewRecorder()
		requireAutomationDocumentRead(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("forged identity reached machine reader") })).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))
		if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Fatalf("forged admission=%d", w.Code)
		}
	}
}

func TestAutomationDocumentSendRequiresExactBoundedJSON(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"ordinary", `{"lawful_basis":"contract"}`, true},
		{"package", `{"lawful_basis":"contract","package_send":{"expected_updated_at":"2026-10-26T11:00:00Z","package_id":"59297362-75d2-40fc-a2a6-fb6a43d080fb","generation":"1"}}`, true},
		{"duplicate", `{"lawful_basis":"contract","lawful_basis":"consent"}`, false},
		{"case alias", `{"lawful_basis":"contract","LAWFUL_BASIS":"contract"}`, false},
		{"unknown", `{"lawful_basis":"contract","signer_url":"private"}`, false},
		{"trailing", `{"lawful_basis":"contract"}{}`, false},
		{"array", `[]`, false},
		{"null package", `{"lawful_basis":"contract","package_send":null}`, false},
		{"null basis", `{"lawful_basis":null}`, false},
		{"nested duplicate", `{"lawful_basis":"contract","package_send":{"generation":"1","generation":"2"}}`, false},
		{"nested alias", `{"lawful_basis":"contract","package_send":{"GENERATION":"1"}}`, false},
		{"invalid utf8", "{\"lawful_basis\":\"con\xfftract\"}", false},
		{"unpaired surrogate", `{"lawful_basis":"\ud800"}`, false},
		{"body limit", `{"lawful_basis":"` + strings.Repeat("x", automationDocumentBodyLimit) + `"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeAutomationDocumentSend(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t error=%v", tc.valid, err)
			}
		})
	}
}
