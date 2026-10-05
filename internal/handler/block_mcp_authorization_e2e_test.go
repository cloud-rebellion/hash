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
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/versions"
)

var blockMCPToolsE2E = []string{"set_document_blocks", "append_block", "update_block", "delete_block", "reorder_blocks", "add_signature_field", "import_html", "import_markdown", "set_variables"}

func blockMCPArgumentsE2E(f blockAuthorizationFixture, tool string) map[string]any {
	args := map[string]any{"document_id": f.doc.ID, "expected_updated_at": f.doc.UpdatedAt.Time.Format(time.RFC3339Nano)}
	switch tool {
	case "set_document_blocks":
		args["blocks_json"] = json.RawMessage(`{"version":1,"blocks":[{"id":"mcp-replacement","type":"paragraph","text":"Reviewed MCP replacement"}]}`)
	case "append_block":
		args["block"] = map[string]any{"id": "mcp-added", "type": "paragraph", "text": "Reviewed MCP appended terms"}
	case "update_block":
		args["block_id"], args["block"] = "agreement", map[string]any{"id": "ignored-body-identity", "type": "paragraph", "text": "Reviewed MCP replacement"}
	case "delete_block":
		args["block_id"] = "agreement"
	case "reorder_blocks":
		args["block_ids"] = []string{"signature", "agreement"}
	case "add_signature_field":
		args["recipient_role"], args["label"] = "signer", "Reviewed signature"
	case "import_html":
		args["html"] = "<p>Reviewed MCP import</p>"
	case "import_markdown":
		args["markdown"] = "Reviewed MCP import"
	case "set_variables":
		args["variables"] = map[string]string{"customer": "Reviewed MCP variables"}
	default:
		panic("unknown MCP block fixture tool")
	}
	return args
}

func submitBlockMCPE2E(f blockAuthorizationFixture, tool, key string, args map[string]any) *httptest.ResponseRecorder {
	return submitRecipientMCPE2E(f.lifecycleAuthorizationFixture, tool, key, args)
}

func blockMCPViaE2E(tool string) string {
	if strings.HasPrefix(tool, "import_") {
		return string(versions.ViaImport)
	}
	return string(versions.ViaMCP)
}

func TestBlockMCPCredentialsRecheckedAfterDocumentWaitE2E(t *testing.T) {
	for _, tool := range blockMCPToolsE2E {
		for _, change := range []string{"key-delete", "scope-reduction", "key-expiry", "document-token-revocation", "member-demotion"} {
			t.Run(tool+"/"+change, func(t *testing.T) {
				f := setupBlockAuthorizationE2E(t, "owner")
				f.enableMCP()
				before := f.snapshot(t)
				mint, keyID := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, change == "document-token-revocation", 1)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitBlockMCPE2E(f, tool, mint.Plaintext, blockMCPArgumentsE2E(f, tool)) }()
				blockAwaitLockE2E(t, f, blocked, result, "-- name: GetDocumentForUpdate", "transactionid")
				switch change {
				case "key-delete":
					if response := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/api-keys/"+keyID.String(), "", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)); response.Code != http.StatusNoContent {
						t.Fatalf("actual block key deletion=%d", response.Code)
					}
				case "scope-reduction":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID)
				case "key-expiry":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID)
				case "document-token-revocation":
					_, err = f.q.RevokeDocAgentToken(f.ctx, generated.RevokeDocAgentTokenParams{ID: keyID, OrgID: f.org})
				case "member-demotion":
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				want := auth.ErrMutationPermissionRevoked.Error()
				if change == "key-expiry" {
					want = auth.ErrMutationCredentialExpired.Error()
				}
				if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != want {
					t.Fatalf("stale MCP block credential=%q want%q", got, want)
				}
				f.assertUnchanged(t, before)
				if change == "document-token-revocation" {
					key, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
					if err != nil || key.UsedCount != 1 || !key.LastUsedAt.Valid {
						t.Fatal("block guard must retain exactly the original middleware use claim")
					}
				}
			})
		}
	}
}

func TestBlockMCPOneUseCommitAndReplayE2E(t *testing.T) {
	for _, tool := range blockMCPToolsE2E {
		t.Run(tool, func(t *testing.T) {
			f := setupBlockAuthorizationE2E(t, "sender")
			f.enableMCP()
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, true, 1)
			args := blockMCPArgumentsE2E(f, tool)
			fieldMCPTextE2E(t, submitBlockMCPE2E(f, tool, mint.Plaintext, args), false)
			doc := f.assertCommit(t, tool, blockMCPViaE2E(tool))
			if tool == "set_variables" && (!strings.Contains(string(doc.VariablesJson), "Reviewed MCP variables") || string(doc.BlocksJson) != string(f.doc.BlocksJson)) {
				t.Fatal("variable write replaced the block tree or lost requested values")
			}
			if tool == "update_block" {
				tree, err := blocks.ParseTree(doc.BlocksJson)
				if err != nil || tree.Blocks[0].ID != "agreement" || tree.Blocks[0].Text != "Reviewed MCP replacement" {
					t.Fatal("MCP replacement lost path-owned block identity or requested text")
				}
			}
			key, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
			if err != nil || key.UsedCount != 1 || !key.LastUsedAt.Valid {
				t.Fatal("successful block write claimed its one-use token twice")
			}
			before := f.snapshot(t)
			if response := submitBlockMCPE2E(f, tool, mint.Plaintext, args); response.Code != http.StatusUnauthorized {
				t.Fatalf("block one-use replay=%d", response.Code)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestBlockMCPRefusesForgedPublicAuthorizationE2E(t *testing.T) {
	f := setupBlockAuthorizationE2E(t, "owner")
	f.enableMCP()
	before := f.snapshot(t)
	ctx := context.WithValue(f.ctx, auth.UserIDKey, f.user.ID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, f.org)
	ctx = context.WithValue(ctx, auth.RoleKey, f.user.Role)
	ctx = context.WithValue(ctx, auth.EmailKey, f.user.Email)
	ctx = context.WithValue(ctx, auth.TokenScopesKey, []string{"write:authoring"})
	for _, tool := range blockMCPToolsE2E {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": blockMCPArgumentsE2E(f, tool)}})
		request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
		response := httptest.NewRecorder()
		f.s.MCP.Handler().ServeHTTP(response, request)
		if got := fieldMCPTextE2E(t, response, true); got != auth.ErrMutationPermissionRevoked.Error() {
			t.Fatalf("forged block receipt refusal=%q", got)
		}
		f.assertUnchanged(t, before)
	}
}

func TestBlockMCPScopeAndTenantBoundariesE2E(t *testing.T) {
	f, foreign := setupBlockAuthorizationE2E(t, "owner"), setupBlockAuthorizationE2E(t, "owner")
	f.enableMCP()
	sibling, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "MCP block sibling", BlocksJson: f.doc.BlocksJson, VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	before, foreignBefore := f.snapshot(t), foreign.snapshot(t)
	docKey, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, true, 0)
	orgKey, keyID := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
	for _, tool := range blockMCPToolsE2E {
		args := blockMCPArgumentsE2E(f, tool)
		args["document_id"], args["expected_updated_at"] = sibling.ID, sibling.UpdatedAt.Time.Format(time.RFC3339Nano)
		if got := fieldMCPTextE2E(t, submitBlockMCPE2E(f, tool, docKey.Plaintext, args), true); got != auth.ErrDocScopeMismatch.Error() {
			t.Fatalf("block document scope escape=%q", got)
		}
		args["document_id"], args["expected_updated_at"] = foreign.doc.ID, foreign.doc.UpdatedAt.Time.Format(time.RFC3339Nano)
		if got := fieldMCPTextE2E(t, submitBlockMCPE2E(f, tool, orgKey.Plaintext, args), true); got != authoring.ErrDocumentNotFound.Error() {
			t.Fatalf("block tenant escape=%q", got)
		}
		f.assertUnchanged(t, before)
		foreign.assertUnchanged(t, foreignBefore)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID); err != nil {
		t.Fatal(err)
	}
	for _, tool := range blockMCPToolsE2E {
		if got := fieldMCPTextE2E(t, submitBlockMCPE2E(f, tool, orgKey.Plaintext, blockMCPArgumentsE2E(f, tool)), true); got != "the '"+tool+"' tool requires the 'write:authoring' scope" {
			t.Fatalf("block missing scope=%q", got)
		}
		f.assertUnchanged(t, before)
	}
}

func TestBlockMCPObservationsLeaveVersionsUntouchedE2E(t *testing.T) {
	for _, tool := range blockMCPToolsE2E {
		t.Run(tool, func(t *testing.T) {
			f := setupBlockAuthorizationE2E(t, "owner")
			f.enableMCP()
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			before := f.snapshot(t)
			for _, stamp := range []string{"", "invalid", f.doc.UpdatedAt.Time.Add(-time.Second).Format(time.RFC3339Nano)} {
				args := blockMCPArgumentsE2E(f, tool)
				args["expected_updated_at"] = stamp
				fieldMCPTextE2E(t, submitBlockMCPE2E(f, tool, mint.Plaintext, args), true)
				f.assertUnchanged(t, before)
			}
			fieldMCPTextE2E(t, submitBlockMCPE2E(f, tool, mint.Plaintext, blockMCPArgumentsE2E(f, tool)), false)
			f.assertCommit(t, tool, blockMCPViaE2E(tool))
		})
	}
}

func TestBlockMCPAuditWaitExpiryRollsBackVersionsE2E(t *testing.T) {
	for _, tool := range []string{"set_document_blocks", "set_variables"} {
		t.Run(tool, func(t *testing.T) {
			f := setupBlockAuthorizationE2E(t, "owner")
			f.enableMCP()
			mint, keyID := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			args := blockMCPArgumentsE2E(f, tool)
			go func() { result <- submitBlockMCPE2E(f, tool, mint.Plaintext, args) }()
			blockAwaitLockE2E(t, f, blocked, result, "-- name: AcquireOrgChainLock", "advisory")
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
					t.Fatal("MCP block key did not naturally expire")
				}
				time.Sleep(10 * time.Millisecond)
			}
			f.assertUnchanged(t, before)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != auth.ErrMutationCredentialExpired.Error() {
				t.Fatalf("audit-expired MCP block=%q", got)
			}
			f.assertUnchanged(t, before)
			fresh, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			fieldMCPTextE2E(t, submitBlockMCPE2E(f, tool, fresh.Plaintext, args), false)
			f.assertCommit(t, tool, blockMCPViaE2E(tool))
		})
	}
}

func TestBlockMCPInternalFailuresRollBackAndRetryE2E(t *testing.T) {
	for _, tool := range []string{"set_document_blocks", "set_variables"} {
		for _, fault := range []string{"audit-exception", "audit-no-row", "version-exception", "version-no-row", "mutation-no-row"} {
			t.Run(tool+"/"+fault, func(t *testing.T) {
				f := setupBlockAuthorizationE2E(t, "owner")
				f.enableMCP()
				mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
				before := f.snapshot(t)
				drop := blockAuthoringFaultE2E(t, f, fault)
				args := blockMCPArgumentsE2E(f, tool)
				if got := fieldMCPTextE2E(t, submitBlockMCPE2E(f, tool, mint.Plaintext, args), true); got != "internal error" {
					t.Fatalf("block internal failure exposed details: %q", got)
				}
				f.assertUnchanged(t, before)
				drop()
				fieldMCPTextE2E(t, submitBlockMCPE2E(f, tool, mint.Plaintext, args), false)
				f.assertCommit(t, tool, blockMCPViaE2E(tool))
			})
		}
	}
}

func TestBlockMCPFreshStateAndPrivacyPreserveVersionsE2E(t *testing.T) {
	for _, tool := range []string{"set_document_blocks", "set_variables"} {
		for _, state := range []string{"deleted", "active", "pdf", "evidence", "linked-privacy"} {
			t.Run(tool+"/"+state, func(t *testing.T) {
				f := setupBlockAuthorizationE2E(t, "owner")
				f.enableMCP()
				mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitBlockMCPE2E(f, tool, mint.Plaintext, blockMCPArgumentsE2E(f, tool)) }()
				blockAwaitLockE2E(t, f, blocked, result, "-- name: GetDocumentForUpdate", "transactionid")
				_, want := f.seedRefusal(t, state, blocked)
				before := f.snapshotDB(t, blocked)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != want {
					t.Fatalf("fresh MCP block state=%q want%q", got, want)
				}
				f.assertUnchanged(t, before)
			})
		}
		for _, state := range []string{"global-privacy", "changing"} {
			t.Run(tool+"/"+state, func(t *testing.T) {
				f := setupBlockAuthorizationE2E(t, "owner")
				f.enableMCP()
				mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
				want := authoring.ErrPendingPrivacyReview.Error()
				if state == "changing" {
					pending, err := f.pool.Begin(f.ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer pending.Rollback(context.Background())
					f.seedRefusal(t, "global-privacy", pending)
					want = authoring.ErrPrivacyReviewChanging.Error()
				} else {
					f.seedRefusal(t, state, f.pool)
				}
				before := f.snapshot(t)
				if got := fieldMCPTextE2E(t, submitBlockMCPE2E(f, tool, mint.Plaintext, blockMCPArgumentsE2E(f, tool)), true); got != want {
					t.Fatalf("MCP block privacy=%q want%q", got, want)
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}
