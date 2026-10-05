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
	"github.com/bright-interaction/hash/internal/mcp"
)

func setupVariableBindingMCPE2E(t *testing.T) variableBindingAuthorizationFixture {
	t.Helper()
	f := setupVariableBindingAuthorizationE2E(t, "owner")
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Resolver: f.s.Resolver, PublicURL: f.s.PublicURL})
	return f
}

func variableBindingMCPArgumentsE2E(f variableBindingAuthorizationFixture, tool string) map[string]any {
	args := map[string]any{"document_id": f.doc.ID, "variable": "customer"}
	switch tool {
	case "bind_variable_to_crm_deal":
		args["deal_id"], args["path"], args["fallback"] = "deal_updated", "deal.name", "New fallback"
	case "bind_variable_to_crm_contact":
		args["contact_id"], args["path"] = "contact_fixture", "name"
	case "bind_variable_to_scanner_finding":
		args["scan_id"], args["path"] = "scan_fixture", "summary.critical_count"
	case "bind_variable_to_org_setting":
		args["path"] = "org.name"
	}
	return args
}

func submitVariableBindingMCPE2E(f variableBindingAuthorizationFixture, ctx context.Context, tool, key string, args map[string]any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("User-Agent", "variable-binding-mcp-acceptance")
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, request)
	return response
}

func bindingMCPOperation(tool string) string {
	if tool == "unbind_variable" {
		return "delete"
	}
	return "upsert"
}

func TestVariableBindingMCPCredentialRecheckedAfterDocumentWaitE2E(t *testing.T) {
	for _, tool := range []string{"bind_variable_to_crm_deal", "unbind_variable"} {
		for _, change := range []string{"key-delete", "scope-reduction", "key-expiry", "token-revocation", "member-demotion"} {
			// Binding a live organization source requires an organization key.
			// The existing central document-token policy permits only unbinding.
			if tool != "unbind_variable" && change == "token-revocation" {
				continue
			}
			t.Run(tool+"/"+change, func(t *testing.T) {
				f := setupVariableBindingMCPE2E(t)
				owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
				mint, keyID := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, change == "token-revocation", 1)
				blocked := holdBindingParentE2E(t, f)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					result <- submitVariableBindingMCPE2E(f, context.Background(), tool, mint.Plaintext, variableBindingMCPArgumentsE2E(f, tool))
				}()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
				var err error
				switch change {
				case "key-delete":
					response := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/api-keys/"+keyID.String(), "", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
					if response.Code != http.StatusNoContent {
						t.Fatalf("actual binding key deletion=%d %s", response.Code, response.Body.String())
					}
				case "scope-reduction":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID) //nolint:rawsql
				case "key-expiry":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID) //nolint:rawsql
				case "token-revocation":
					_, err = f.q.RevokeDocAgentToken(f.ctx, generated.RevokeDocAgentTokenParams{ID: keyID, OrgID: f.org})
				case "member-demotion":
					response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
					if response.Code != http.StatusOK {
						t.Fatalf("actual binding member demotion=%d %s", response.Code, response.Body.String())
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				before := f.snapshot(t)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				response := receiveSessionOperationE2E(t, result)
				want := auth.ErrMutationPermissionRevoked.Error()
				if change == "key-expiry" {
					want = auth.ErrMutationCredentialExpired.Error()
				}
				if got := fieldMCPTextE2E(t, response, true); got != want {
					t.Fatalf("stale binding key=%q want%q", got, want)
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestVariableBindingMCPAuditWaitExpiryRollsBackE2E(t *testing.T) {
	for _, tool := range []string{"bind_variable_to_crm_deal", "unbind_variable"} {
		t.Run(tool, func(t *testing.T) {
			f := setupVariableBindingMCPE2E(t)
			before := f.snapshot(t)
			mint, keyID := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil {
				t.Fatal(err)
			} //nolint:rawsql
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- submitVariableBindingMCPE2E(f, context.Background(), tool, mint.Plaintext, variableBindingMCPArgumentsE2E(f, tool))
			}()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			var expired bool
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if err := f.pool.QueryRow(f.ctx, `SELECT expires_at<=clock_timestamp() FROM api_keys WHERE id=$1`, keyID).Scan(&expired); err != nil {
					t.Fatal(err)
				} //nolint:rawsql
				if expired {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !expired {
				t.Fatal("binding fixture key did not expire")
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != auth.ErrMutationCredentialExpired.Error() {
				t.Fatalf("late binding key expiry=%q", got)
			}
			f.assertUnchanged(t, before)
			fresh, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			fieldMCPTextE2E(t, submitVariableBindingMCPE2E(f, context.Background(), tool, fresh.Plaintext, variableBindingMCPArgumentsE2E(f, tool)), false)
		})
	}
}

func TestVariableBindingMCPCancellationDuringAuditWaitRollsBackE2E(t *testing.T) {
	for _, tool := range []string{"bind_variable_to_crm_deal", "unbind_variable"} {
		t.Run(tool, func(t *testing.T) {
			f := setupVariableBindingMCPE2E(t)
			before := f.snapshot(t)
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- submitVariableBindingMCPE2E(f, ctx, tool, mint.Plaintext, variableBindingMCPArgumentsE2E(f, tool))
			}()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			cancel()
			fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			f.assertUnchanged(t, before)
			fieldMCPTextE2E(t, submitVariableBindingMCPE2E(f, context.Background(), tool, mint.Plaintext, variableBindingMCPArgumentsE2E(f, tool)), false)
		})
	}
}

func TestVariableBindingMCPInternalFailuresRollBackAndRetryE2E(t *testing.T) {
	for _, tool := range []string{"bind_variable_to_crm_deal", "unbind_variable"} {
		faults := []string{"audit", "audit-no-row", "mutation"}
		if tool != "unbind_variable" {
			faults = append(faults, "mutation-no-row")
		}
		for _, fault := range faults {
			t.Run(tool+"/"+fault, func(t *testing.T) {
				f := setupVariableBindingMCPE2E(t)
				before := f.snapshot(t)
				drop := installBindingMutationFaultE2E(t, f, bindingMCPOperation(tool), fault)
				mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
				if got := fieldMCPTextE2E(t, submitVariableBindingMCPE2E(f, context.Background(), tool, mint.Plaintext, variableBindingMCPArgumentsE2E(f, tool)), true); got != "internal error" {
					t.Fatalf("binding internal fault exposed %q", got)
				}
				f.assertUnchanged(t, before)
				drop()
				fieldMCPTextE2E(t, submitVariableBindingMCPE2E(f, context.Background(), tool, mint.Plaintext, variableBindingMCPArgumentsE2E(f, tool)), false)
			})
		}
	}
}

func TestVariableBindingMCPPreservesEvidencePrivacyAndDraftStateE2E(t *testing.T) {
	for _, tool := range []string{"bind_variable_to_crm_deal", "unbind_variable"} {
		for _, state := range []string{"evidence", "linked-privacy", "global-privacy", "privacy-changing", "sent", "soft-deleted"} {
			t.Run(tool+"/"+state, func(t *testing.T) {
				f := setupVariableBindingMCPE2E(t)
				seedBindingAuthoringRefusalE2E(t, f, state)
				before := f.snapshot(t)
				mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
				fieldMCPTextE2E(t, submitVariableBindingMCPE2E(f, context.Background(), tool, mint.Plaintext, variableBindingMCPArgumentsE2E(f, tool)), true)
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestVariableBindingMCPOneUseAndCanonicalToolsE2E(t *testing.T) {
	for _, tool := range []string{"bind_variable_to_crm_deal", "bind_variable_to_crm_contact", "bind_variable_to_scanner_finding", "bind_variable_to_org_setting", "unbind_variable"} {
		t.Run(tool, func(t *testing.T) {
			f := setupVariableBindingMCPE2E(t)
			if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
				t.Fatal(err)
			}
			oneUse := tool == "unbind_variable"
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, oneUse, 1)
			args := variableBindingMCPArgumentsE2E(f, tool)
			text := fieldMCPTextE2E(t, submitVariableBindingMCPE2E(f, context.Background(), tool, mint.Plaintext, args), false)
			if f.source.calls.Load() != 0 {
				t.Fatal("binding authoring fetched an external source")
			}
			var dto map[string]any
			if json.Unmarshal([]byte(text), &dto) != nil {
				t.Fatal("binding tool did not return its JSON DTO")
			}
			rows, err := f.q.ListVariableBindings(f.ctx, f.doc.ID)
			if tool == "unbind_variable" {
				if err != nil || len(rows) != 0 || dto["unbound"] != "customer" {
					t.Fatal("unbind success did not remove its exact binding")
				}
			} else {
				if err != nil || len(rows) != 1 || rows[0].VariableName != "customer" || dto["variable"] != "customer" {
					t.Fatal("bind success did not persist its exact variable")
				}
				if tool == "bind_variable_to_crm_deal" && (rows[0].SourceRef != "deal_updated" || rows[0].SourcePath != "deal.name" || rows[0].Fallback != "New fallback") {
					t.Fatal("CRM source ref/path/fallback changed")
				}
			}
			assertBindingCanonicalAuditE2E(t, f, "mcp", tool, 1)
			if oneUse {
				key, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
				if err != nil || key.UsedCount != 1 || !key.LastUsedAt.Valid {
					t.Fatal("binding guard claimed a one-use token twice")
				}
				before := f.snapshot(t)
				if response := submitVariableBindingMCPE2E(f, context.Background(), tool, mint.Plaintext, args); response.Code != http.StatusUnauthorized {
					t.Fatalf("binding one-use replay=%d", response.Code)
				}
				f.assertUnchanged(t, before)
			}
		})
	}
}

func TestVariableBindingMCPDocumentTokensCannotBindOrganizationSourcesE2E(t *testing.T) {
	for _, tool := range []string{"bind_variable_to_crm_deal", "bind_variable_to_crm_contact", "bind_variable_to_scanner_finding", "bind_variable_to_org_setting"} {
		t.Run(tool, func(t *testing.T) {
			f := setupVariableBindingMCPE2E(t)
			before := f.snapshot(t)
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, true, 1)
			text := fieldMCPTextE2E(t, submitVariableBindingMCPE2E(f, context.Background(), tool, mint.Plaintext, variableBindingMCPArgumentsE2E(f, tool)), true)
			if !strings.Contains(text, "scoped to a single document") {
				t.Fatalf("organization source binding bypassed document-token policy: %q", text)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestVariableBindingMCPSoftDeleteAfterParentWaitE2E(t *testing.T) {
	for _, tool := range []string{"bind_variable_to_crm_deal", "unbind_variable"} {
		t.Run(tool, func(t *testing.T) {
			f := setupVariableBindingMCPE2E(t)
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			blocked := holdBindingParentE2E(t, f)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- submitVariableBindingMCPE2E(f, context.Background(), tool, mint.Plaintext, variableBindingMCPArgumentsE2E(f, tool))
			}()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
			if _, err := blocked.Exec(f.ctx, `UPDATE documents SET deleted_at=now() WHERE id=$1`, f.doc.ID); err != nil {
				t.Fatal(err)
			} //nolint:rawsql
			expected := f.snapshotDB(t, blocked)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != "document not found" {
				t.Fatalf("deleted binding parent exposed %q", got)
			}
			f.assertUnchanged(t, expected)
		})
	}
}

func TestVariableBindingMCPRejectsForgedReceiptAndTenantScopeE2E(t *testing.T) {
	f, foreign := setupVariableBindingMCPE2E(t), setupVariableBindingMCPE2E(t)
	sibling, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Binding sibling", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	before, foreignBefore := f.snapshot(t), foreign.snapshot(t)
	docKey, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, true, 0)
	orgKey, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
	ctx := context.WithValue(f.ctx, auth.UserIDKey, f.user.ID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, f.org)
	ctx = context.WithValue(ctx, auth.RoleKey, f.user.Role)
	ctx = context.WithValue(ctx, auth.EmailKey, f.user.Email)
	ctx = context.WithValue(ctx, auth.TokenScopesKey, []string{"write:authoring"})
	for _, tool := range []string{"bind_variable_to_crm_deal", "unbind_variable"} {
		args := variableBindingMCPArgumentsE2E(f, tool)
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
		request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
		response := httptest.NewRecorder()
		f.s.MCP.Handler().ServeHTTP(response, request)
		if got := fieldMCPTextE2E(t, response, true); got != auth.ErrMutationPermissionRevoked.Error() {
			t.Fatalf("forged binding receipt=%q", got)
		}
		args["document_id"] = sibling.ID
		fieldMCPTextE2E(t, submitVariableBindingMCPE2E(f, context.Background(), tool, docKey.Plaintext, args), true)
		args["document_id"] = foreign.doc.ID
		fieldMCPTextE2E(t, submitVariableBindingMCPE2E(f, context.Background(), tool, orgKey.Plaintext, args), true)
		f.assertUnchanged(t, before)
		foreign.assertUnchanged(t, foreignBefore)
	}
}

func TestVariableBindingMCPValidatesInputsBeforeMutationE2E(t *testing.T) {
	f := setupVariableBindingMCPE2E(t)
	before := f.snapshot(t)
	mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
	for _, invalid := range []map[string]any{{"variable": "1customer"}, {"variable": strings.Repeat("a", 129)}, {"deal_id": "../admin"}, {"path": "bad\x00path"}, {"path": strings.Repeat("p", 1025)}, {"fallback": "private\x00fallback"}, {"fallback": strings.Repeat("x", 16*1024+1)}} {
		args := variableBindingMCPArgumentsE2E(f, "bind_variable_to_crm_deal")
		for key, value := range invalid {
			args[key] = value
		}
		fieldMCPTextE2E(t, submitVariableBindingMCPE2E(f, context.Background(), "bind_variable_to_crm_deal", mint.Plaintext, args), true)
		f.assertUnchanged(t, before)
	}
}
