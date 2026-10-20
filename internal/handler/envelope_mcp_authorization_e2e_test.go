//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func setupEnvelopeMCPE2E(t *testing.T) (lifecycleAuthorizationFixture, uuid.UUID) {
	t.Helper()
	f := setupLifecycleAuthorizationE2E(t, "sender", false, true)
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Envelopes: envelopes.New(f.q), PublicURL: f.s.PublicURL})
	child, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Standalone child", BlocksJson: []byte(`{"version":1,"blocks":[]}`), VariablesJson: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	return f, child.ID
}

func mintAuthoringMCPE2E(t *testing.T, f lifecycleAuthorizationFixture) (*auth.MintedKey, uuid.UUID) {
	t.Helper()
	mint, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, Name: "Fresh authoring fixture", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"read", "write:authoring"}})
	if err != nil {
		t.Fatal(err)
	}
	return mint, key.ID
}

func submitAuthoringMCPE2E(f lifecycleAuthorizationFixture, ctx context.Context, tool, key string, args map[string]any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func authoringMCPStateE2E(t *testing.T, f lifecycleAuthorizationFixture) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
 'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
 'proposals',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY id),'[]'::jsonb) FROM document_proposals p WHERE org_id=$1),
 'ai_usage',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]'::jsonb) FROM ai_completion_audit a WHERE org_id=$1),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1)
 )::text`, f.org).Scan(&state); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- fixture-owned complete authoring state; admitted key-use claim deliberately excluded
	return state
}

func envelopeMCPArgsE2E(t *testing.T, f lifecycleAuthorizationFixture, standalone uuid.UUID, tool string) map[string]any {
	t.Helper()
	kids, err := envelopes.New(f.q).Children(f.ctx, f.doc.ID, f.org)
	if err != nil || len(kids) != 2 {
		t.Fatal("fixture children", err)
	}
	switch tool {
	case "create_envelope":
		return map[string]any{"name": "Reviewed bundle", "child_ids": []uuid.UUID{standalone}}
	case "promote_to_envelope":
		return map[string]any{"document_id": standalone}
	case "attach_to_envelope":
		return map[string]any{"envelope_id": f.doc.ID, "child_id": standalone, "position": 0}
	case "detach_from_envelope":
		return map[string]any{"child_id": kids[0].ID}
	default:
		return map[string]any{"envelope_id": f.doc.ID, "child_id_order": []uuid.UUID{kids[1].ID, kids[0].ID}}
	}
}

func envelopeMCPWaitDocE2E(f lifecycleAuthorizationFixture, standalone uuid.UUID, tool string) uuid.UUID {
	if tool == "create_envelope" || tool == "promote_to_envelope" {
		return standalone
	}
	return f.doc.ID
}

func holdAuthoringDocumentMCPE2E(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) pgx.Tx {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := f.q.WithTx(tx).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: id, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestEnvelopeMCPRetainsOriginalAuthorAndKeyAfterParentWaitE2E(t *testing.T) {
	for _, tool := range []string{"create_envelope", "promote_to_envelope", "attach_to_envelope", "detach_from_envelope", "reorder_envelope_children"} {
		for _, change := range []string{"demotion", "key-delete"} {
			t.Run(tool+"/"+change, func(t *testing.T) {
				f, standalone := setupEnvelopeMCPE2E(t)
				mint, keyID := mintAuthoringMCPE2E(t, f)
				args := envelopeMCPArgsE2E(t, f, standalone, tool)
				blocked := holdAuthoringDocumentMCPE2E(t, f, envelopeMCPWaitDocE2E(f, standalone, tool))
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitAuthoringMCPE2E(f, f.ctx, tool, mint.Plaintext, args) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
				var err error
				if change == "demotion" {
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
				} else {
					_, err = f.q.DeleteAPIKey(f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: f.user.ID})
				}
				if err != nil {
					t.Fatal(err)
				}
				before := authoringMCPStateE2E(t, f)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != auth.ErrMutationPermissionRevoked.Error() {
					t.Fatalf("late original author/key=%q", got)
				}
				if got := authoringMCPStateE2E(t, f); got != before {
					t.Fatal("refused topology mutation changed documents/audit")
				}
			})
		}
	}
}

func TestEnvelopeMCPAuditRollbackAndReviewedTopologyE2E(t *testing.T) {
	for _, tool := range []string{"create_envelope", "promote_to_envelope", "attach_to_envelope", "detach_from_envelope", "reorder_envelope_children"} {
		t.Run(tool, func(t *testing.T) {
			f, standalone := setupEnvelopeMCPE2E(t)
			mint, _ := mintAuthoringMCPE2E(t, f)
			args := envelopeMCPArgsE2E(t, f, standalone, tool)
			before := authoringMCPStateE2E(t, f)
			drop := ownerOrgAuditFaultE2E(t, ownerOrgMutationFixture{lifecycleAuthorizationFixture: f}, true)
			if got := fieldMCPTextE2E(t, submitAuthoringMCPE2E(f, f.ctx, tool, mint.Plaintext, args), true); got != "envelope mutation failed" {
				t.Fatalf("audit no-row misclassified=%q", got)
			}
			drop()
			if authoringMCPStateE2E(t, f) != before {
				t.Fatal("audit failure committed topology")
			}
			text := fieldMCPTextE2E(t, submitAuthoringMCPE2E(f, f.ctx, tool, mint.Plaintext, args), false)
			if text == "" {
				t.Fatal("reviewed topology response empty")
			}
			var count int
			var actor uuid.UUID
			var payload string
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1`, f.org).Scan(&count); err != nil || count != 1 {
				t.Fatal("topology audit count", count, err)
			} //nolint:rawsql
			if err := f.pool.QueryRow(f.ctx, `SELECT actor_user_id,payload_json::text FROM events WHERE org_id=$1`, f.org).Scan(&actor, &payload); err != nil || actor != f.user.ID || !strings.Contains(payload, tool) {
				t.Fatal("wrong topology actor/tool", err)
			} //nolint:rawsql
			root, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
			if err != nil || root.Status != "draft" {
				t.Fatal("root state", err)
			}
			child, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: standalone, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			switch tool {
			case "create_envelope":
				if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) == f.doc.ID {
					t.Fatal("new shell did not attach child")
				}
			case "promote_to_envelope":
				if !child.IsEnvelope {
					t.Fatal("promotion missing")
				}
			case "attach_to_envelope":
				if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != f.doc.ID || child.EnvelopePosition.Int32 != 3 {
					t.Fatal("fresh append position wrong")
				}
			case "detach_from_envelope":
				id := args["child_id"].(uuid.UUID)
				child, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
				if err != nil || child.ParentEnvelopeID.Valid {
					t.Fatal("detach missing", err)
				}
			case "reorder_envelope_children":
				kids, err := envelopes.New(f.q).Children(f.ctx, f.doc.ID, f.org)
				ids := args["child_id_order"].([]uuid.UUID)
				if err != nil || kids[0].ID != ids[0] || kids[1].ID != ids[1] {
					t.Fatal("reorder did not persist intended order", err)
				}
			}
		})
	}
}

func TestEnvelopeMCPAuditWaitExpiryAndScopeIsolationE2E(t *testing.T) {
	f, standalone := setupEnvelopeMCPE2E(t)
	mint, keyID := mintAuthoringMCPE2E(t, f)
	if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql
	args := envelopeMCPArgsE2E(t, f, standalone, "attach_to_envelope")
	before := authoringMCPStateE2E(t, f)
	blocked := ownerOrgLockE2E(t, ownerOrgMutationFixture{lifecycleAuthorizationFixture: f}, true)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- submitAuthoringMCPE2E(f, f.ctx, "attach_to_envelope", mint.Plaintext, args) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	deadline := time.Now().Add(3 * time.Second)
	for {
		var expired bool
		if err := f.pool.QueryRow(f.ctx, `SELECT expires_at<=clock_timestamp() FROM api_keys WHERE id=$1`, keyID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key not naturally expired")
		}
		time.Sleep(10 * time.Millisecond)
	} //nolint:rawsql
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != auth.ErrMutationCredentialExpired.Error() {
		t.Fatal("expiry after audit wait", got)
	}
	if authoringMCPStateE2E(t, f) != before {
		t.Fatal("expired key committed topology/audit")
	}
	fresh, _ := mintAuthoringMCPE2E(t, f)
	other, foreign := setupEnvelopeMCPE2E(t)
	foreignBefore := authoringMCPStateE2E(t, other)
	if got := fieldMCPTextE2E(t, submitAuthoringMCPE2E(f, f.ctx, "attach_to_envelope", fresh.Plaintext, map[string]any{"envelope_id": f.doc.ID, "child_id": foreign}), true); got != "document not found" {
		t.Fatal("cross tenant attach", got)
	}
	if authoringMCPStateE2E(t, f) != before || authoringMCPStateE2E(t, other) != foreignBefore {
		t.Fatal("cross tenant topology changed")
	}
	kids, err := envelopes.New(f.q).Children(f.ctx, f.doc.ID, f.org)
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.MintDocumentAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{DocumentID: kids[0].ID, OrgID: f.org, Name: "Child-only topology token", Prefix: token.Prefix, KeyHash: token.Hash, Scopes: []string{"write:authoring"}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: 1, CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	_ = fieldMCPTextE2E(t, submitAuthoringMCPE2E(f, f.ctx, "detach_from_envelope", token.Plaintext, map[string]any{"child_id": kids[0].ID}), true)
	if authoringMCPStateE2E(t, f) != before {
		t.Fatal("child token detached sibling envelope membership")
	}
}
