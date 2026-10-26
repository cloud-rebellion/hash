//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// This is the actual authenticated key-issuance/storage/audit path against a
// disposable PostgreSQL fixture; it performs no provider, SMTP or signing work.
func TestAPIKeyCreationScopeDefaultsAndExplicitWorkflowE2E(t *testing.T) {
	ctx, pool, q, server, orgID, userID := setupDSRE2E(t)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanup, `DELETE FROM orgs WHERE id=$1`, orgID); err != nil { //nolint:rawsql -- fixture-owned rows only
			t.Error("remove synthetic API-key fixture organization")
		}
	})
	legacyMint, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal("mint synthetic legacy credential")
	}
	legacy, err := q.CreateAPIKey(ctx, generated.CreateAPIKeyParams{
		OrgID: orgID, UserID: userID, Name: "Existing integration key", KeyPrefix: legacyMint.Prefix,
		KeyHash: legacyMint.Hash, Scopes: []string{"read", "write:authoring", "write:workflow"},
	})
	if err != nil {
		t.Fatal("store synthetic legacy credential")
	}
	cookie := dsrSessionCookieE2E(t, server, userID, 0, time.Hour)
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"omitted", `{"name":"AI authoring default"}`, []string{"read", "write:authoring"}},
		{"read only", `{"name":"Read integration","scopes":["read"]}`, []string{"read"}},
		{"workflow opt-in", `{"name":"Explicit workflow","scopes":["write:workflow"]}`, []string{"write:workflow"}},
		{"integration opt-in", `{"name":"Signature requests","scopes":["read","write:authoring","write:workflow"]}`, []string{"read", "write:authoring", "write:workflow"}},
		{"empty", `{"name":"Empty","scopes":[]}`, nil},
		{"null", `{"name":"Null","scopes":null}`, nil},
		{"invalid", `{"name":"Unknown","scopes":["write:admin"]}`, nil},
		{"duplicate field", `{"name":"Ambiguous","scopes":["read"],"scopes":["write:workflow"]}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			beforeKeys, err := q.ListAPIKeysByUser(ctx, userID)
			if err != nil {
				t.Fatal("read fixture key inventory")
			}
			beforeEvents, err := q.ListChainedEventsPageForOrg(ctx, generated.ListChainedEventsPageForOrgParams{OrgID: orgID, PageLimit: 50})
			if err != nil {
				t.Fatal("read fixture audit inventory")
			}
			response := submitSessionOperationE2E(server, http.MethodPost, "/api/v1/api-keys", tc.body, cookie)
			if tc.want == nil {
				if response.Code != http.StatusBadRequest {
					t.Fatalf("invalid scope issuance status=%d", response.Code)
				}
				afterKeys, keyErr := q.ListAPIKeysByUser(ctx, userID)
				afterEvents, eventErr := q.ListChainedEventsPageForOrg(ctx, generated.ListChainedEventsPageForOrgParams{OrgID: orgID, PageLimit: 50})
				if keyErr != nil || eventErr != nil || !reflect.DeepEqual(beforeKeys, afterKeys) || !reflect.DeepEqual(beforeEvents, afterEvents) {
					t.Fatal("refused scope request changed credentials or audit history")
				}
				return
			}
			if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("key issuance status=%d", response.Code)
			}
			var result apiKeyResponse
			if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.ID == uuid.Nil || result.Plaintext == "" || !reflect.DeepEqual(result.Scopes, tc.want) {
				t.Fatal("one-time issuance did not return the exact selected permissions")
			}
			stored, err := q.GetAPIKeyByPrefix(ctx, result.Prefix)
			if err != nil || stored.ID != result.ID || stored.OrgID != orgID || stored.UserID != userID || !reflect.DeepEqual(stored.Scopes, tc.want) {
				t.Fatal("stored key grants differ from the response/default policy")
			}
			verifier := auth.PgVerifier{Queries: q}
			_, _, _, _, _, _, _, effectiveScopes, err := verifier.LookupByPrefix(ctx, result.Prefix)
			if err != nil || !reflect.DeepEqual(effectiveScopes, tc.want) {
				t.Fatal("credential lookup changed the exact stored grants")
			}
			events, err := q.ListChainedEventsPageForOrg(ctx, generated.ListChainedEventsPageForOrgParams{OrgID: orgID, PageLimit: 50})
			if err != nil || len(events) != len(beforeEvents)+1 {
				t.Fatal("key issuance did not commit exactly one audit event")
			}
			last := events[len(events)-1]
			var payload struct {
				KeyID  uuid.UUID `json:"key_id"`
				Scopes []string  `json:"scopes"`
			}
			if last.Kind != "api_key.created" || !last.ActorUserID.Valid || uuid.UUID(last.ActorUserID.Bytes) != userID ||
				json.Unmarshal(last.PayloadJson, &payload) != nil || payload.KeyID != result.ID || !reflect.DeepEqual(payload.Scopes, tc.want) || bytes.Contains(last.PayloadJson, []byte(result.Plaintext)) {
				t.Fatal("credential audit lost its actor/exact scopes or exposed plaintext")
			}
		})
	}
	retained, err := q.GetAPIKeyByPrefix(ctx, legacy.KeyPrefix)
	if err != nil || !reflect.DeepEqual(legacy, retained) {
		t.Fatal("new defaults changed an existing explicit integration credential")
	}
}
