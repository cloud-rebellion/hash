//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
)

type restoreAuthorizationFixture struct {
	blockAuthorizationFixture
	target *generated.DocumentVersion
}

func setupRestoreAuthorizationE2E(t *testing.T, role string) restoreAuthorizationFixture {
	t.Helper()
	f := setupBlockAuthorizationE2E(t, role)
	target, err := versions.New(f.q).Snapshot(f.ctx, versions.SnapshotInput{
		DocumentID: f.doc.ID, OrgID: f.org, Name: f.doc.Name, SourceKind: "blocks", BlocksJSON: f.doc.BlocksJson,
		VariablesJS: f.doc.VariablesJson, CreatedBy: &f.user.ID, Via: versions.ViaHuman, Summary: "Historical restore target",
	})
	if err != nil {
		t.Fatal(err)
	}
	f.doc, err = f.q.UpdateDocumentBlocks(f.ctx, generated.UpdateDocumentBlocksParams{
		ID: f.doc.ID, OrgID: f.org,
		BlocksJson:    json.RawMessage(`{"version":1,"blocks":[{"id":"agreement","type":"paragraph","text":"Current reviewed terms"},{"id":"signature","type":"signature_field","attrs":{"recipient_role":"signer"}}]}`),
		VariablesJson: json.RawMessage(`{"customer":"Current reviewed customer"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.enableMCP()
	return restoreAuthorizationFixture{f, target}
}

func (f restoreAuthorizationFixture) call(transport, credential, stamp string, docID uuid.UUID, version int32) *httptest.ResponseRecorder {
	if transport == "mcp" {
		return submitBlockMCPE2E(f.blockAuthorizationFixture, "restore_document_version", credential, map[string]any{
			"document_id": docID, "target_version": version, "expected_updated_at": stamp,
		})
	}
	body, _ := json.Marshal(map[string]any{"expected_updated_at": stamp})
	return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+docID.String()+"/versions/"+strconv.Itoa(int(version))+"/restore", string(body), credential)
}

func (f restoreAuthorizationFixture) submit(transport, credential string) *httptest.ResponseRecorder {
	return f.call(transport, credential, f.doc.UpdatedAt.Time.Format(time.RFC3339Nano), f.doc.ID, f.target.VersionNo)
}

func assertRestoreErrorE2E(t *testing.T, transport string, response *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if transport == "mcp" {
		if got := fieldMCPTextE2E(t, response, true); got != message {
			t.Fatalf("restore tool refusal=%q want%q", got, message)
		}
		return
	}
	if response.Code != status || !strings.Contains(response.Body.String(), message) {
		t.Fatalf("restore refusal=%d want%d %s", response.Code, status, response.Body.String())
	}
}

func (f restoreAuthorizationFixture) assertCommit(t *testing.T) {
	t.Helper()
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if string(doc.BlocksJson) != string(f.target.BlockTreeJson) || string(doc.VariablesJson) != string(f.target.VariablesJson) || doc.UpdatedAt.Time.Equal(f.doc.UpdatedAt.Time) {
		t.Fatal("restore did not materialize exactly the historical block/variable content with a fresh receipt")
	}
	var versionCount, exactVersions, eventCount, exactEvents, outboxCount int
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM document_versions WHERE document_id=$1),
		(SELECT count(*) FROM document_versions v JOIN documents d ON d.id=v.document_id
		 WHERE v.document_id=$1 AND v.version_no=2 AND v.created_by=$2 AND v.created_via='restore'
		 AND v.block_tree_json=d.blocks_json AND v.variables_json=d.variables_json),
		(SELECT count(*) FROM events WHERE document_id=$1),
		(SELECT count(*) FROM events WHERE document_id=$1 AND actor_user_id=$2 AND kind='document.updated'
		 AND payload_json->>'tool'='restore_document_version' AND payload_json->>'restored_from_v'='1'),
		(SELECT count(*) FROM email_deliveries WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1))`,
		f.doc.ID, f.user.ID).Scan(&versionCount, &exactVersions, &eventCount, &exactEvents, &outboxCount); err != nil { //nolint:rawsql -- exact fixture restore/version/audit/outbox proof
		t.Fatal(err)
	}
	if versionCount != 2 || exactVersions != 1 || eventCount != 1 || exactEvents != 1 || outboxCount != 0 {
		t.Fatalf("restore versions/exact/events/exact/outbox=%d/%d/%d/%d/%d want2/1/1/1/0", versionCount, exactVersions, eventCount, exactEvents, outboxCount)
	}
	rows, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(rows)
	if result := verifier.Result(); !result.OK || !result.Complete || result.TotalChecked != 1 {
		t.Fatalf("restore chain invalid: %+v", result)
	}
}

func TestRestoreSessionRechecksOriginalAuthorityAfterDocumentWaitE2E(t *testing.T) {
	for _, change := range []string{"demotion", "logout", "expiry"} {
		t.Run(change, func(t *testing.T) {
			f := setupRestoreAuthorizationE2E(t, "sender")
			owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			ttl := time.Hour
			if change == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit("rest", cookie) }()
			blockAwaitLockE2E(t, f.blockAuthorizationFixture, blocked, result, "-- name: GetDocumentForUpdate", "transactionid")
			want, message := http.StatusForbidden, auth.ErrMutationPermissionRevoked.Error()
			switch change {
			case "demotion":
				if response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour)); response.Code != http.StatusOK {
					t.Fatalf("actual restore member demotion=%d", response.Code)
				}
			case "logout":
				if response := submitSessionOperationE2E(f.s, http.MethodPost, "/auth/logout", "", cookie); response.Code != http.StatusOK {
					t.Fatalf("actual restore logout=%d", response.Code)
				}
			case "expiry":
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				want, message = http.StatusUnauthorized, auth.ErrMutationCredentialExpired.Error()
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			assertRestoreErrorE2E(t, "rest", receiveSessionOperationE2E(t, result), want, message)
			f.assertUnchanged(t, before)
		})
	}
}

func TestRestoreMCPCredentialsRecheckedAfterDocumentWaitE2E(t *testing.T) {
	for _, change := range []string{"key-delete", "scope-reduction", "key-expiry", "document-token-revocation", "member-demotion"} {
		t.Run(change, func(t *testing.T) {
			f := setupRestoreAuthorizationE2E(t, "owner")
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
			go func() { result <- f.submit("mcp", mint.Plaintext) }()
			blockAwaitLockE2E(t, f.blockAuthorizationFixture, blocked, result, "-- name: GetDocumentForUpdate", "transactionid")
			switch change {
			case "key-delete":
				if response := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/api-keys/"+keyID.String(), "", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)); response.Code != http.StatusNoContent {
					t.Fatalf("actual restore key deletion=%d", response.Code)
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
			message := auth.ErrMutationPermissionRevoked.Error()
			if change == "key-expiry" {
				message = auth.ErrMutationCredentialExpired.Error()
			}
			assertRestoreErrorE2E(t, "mcp", receiveSessionOperationE2E(t, result), 0, message)
			f.assertUnchanged(t, before)
			if change == "document-token-revocation" {
				row, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
				if err != nil || row.UsedCount != 1 || !row.LastUsedAt.Valid {
					t.Fatal("restore callback reclaimed the original middleware token use")
				}
			}
		})
	}
}

func TestRestoreAuditWaitExpiryRollsBackContentVersionAndAuditE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			f := setupRestoreAuthorizationE2E(t, "sender")
			credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
			keyID := uuid.Nil
			if transport == "mcp" {
				mint, id := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
				credential, keyID = mint.Plaintext, id
				if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil {
					t.Fatal(err)
				}
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
			go func() { result <- f.submit(transport, credential) }()
			blockAwaitLockE2E(t, f.blockAuthorizationFixture, blocked, result, "-- name: AcquireOrgChainLock", "advisory")
			if transport == "rest" {
				awaitSessionCookieExpiryE2E(t, f.s, credential)
			} else {
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
						t.Fatal("restore key did not naturally expire")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			f.assertUnchanged(t, before)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			assertRestoreErrorE2E(t, transport, receiveSessionOperationE2E(t, result), http.StatusUnauthorized, auth.ErrMutationCredentialExpired.Error())
			f.assertUnchanged(t, before)
			credential = dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			if transport == "mcp" {
				mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
				credential = mint.Plaintext
			}
			response := f.submit(transport, credential)
			if transport == "mcp" {
				fieldMCPTextE2E(t, response, false)
			} else if response.Code != http.StatusOK {
				t.Fatalf("fresh restore retry=%d %s", response.Code, response.Body.String())
			}
			f.assertCommit(t)
		})
	}
}

func TestRestoreInternalFailuresRollBackAndRetryE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, fault := range []string{"audit-exception", "audit-no-row", "version-exception", "version-no-row", "mutation-no-row"} {
			t.Run(transport+"/"+fault, func(t *testing.T) {
				f := setupRestoreAuthorizationE2E(t, "owner")
				credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				if transport == "mcp" {
					mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
					credential = mint.Plaintext
				}
				before := f.snapshot(t)
				drop := blockAuthoringFaultE2E(t, f.blockAuthorizationFixture, fault)
				response := f.submit(transport, credential)
				assertRestoreErrorE2E(t, transport, response, http.StatusInternalServerError, "internal error")
				f.assertUnchanged(t, before)
				drop()
				response = f.submit(transport, credential)
				if transport == "mcp" {
					fieldMCPTextE2E(t, response, false)
				} else if response.Code != http.StatusOK {
					t.Fatalf("restored retry=%d %s", response.Code, response.Body.String())
				}
				f.assertCommit(t)
			})
		}
	}
}

func TestRestoreFreshStatePrivacyAndEvidenceAfterDocumentWaitE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, state := range []string{"deleted", "active", "pdf", "evidence", "linked-privacy"} {
			t.Run(transport+"/"+state, func(t *testing.T) {
				f := setupRestoreAuthorizationE2E(t, "owner")
				credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				if transport == "mcp" {
					mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
					credential = mint.Plaintext
				}
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- f.submit(transport, credential) }()
				blockAwaitLockE2E(t, f.blockAuthorizationFixture, blocked, result, "-- name: GetDocumentForUpdate", "transactionid")
				status, message := f.seedRefusal(t, state, blocked)
				if state == "pdf" {
					message = "restore only supported on block-source documents"
				}
				before := f.snapshotDB(t, blocked)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				assertRestoreErrorE2E(t, transport, receiveSessionOperationE2E(t, result), status, message)
				f.assertUnchanged(t, before)
			})
		}
		for _, state := range []string{"global-privacy", "changing"} {
			t.Run(transport+"/"+state, func(t *testing.T) {
				f := setupRestoreAuthorizationE2E(t, "owner")
				credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				if transport == "mcp" {
					mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
					credential = mint.Plaintext
				}
				message := authoring.ErrPendingPrivacyReview.Error()
				if state == "changing" {
					pending, err := f.pool.Begin(f.ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer pending.Rollback(context.Background())
					f.seedRefusal(t, "global-privacy", pending)
					message = authoring.ErrPrivacyReviewChanging.Error()
				} else {
					f.seedRefusal(t, state, f.pool)
				}
				before := f.snapshot(t)
				assertRestoreErrorE2E(t, transport, f.submit(transport, credential), http.StatusConflict, message)
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestRestoreSenderOwnerCanonicalEvidenceAndOneUseReplayE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, role := range []string{"sender", "owner"} {
			t.Run(transport+"/"+role, func(t *testing.T) {
				f := setupRestoreAuthorizationE2E(t, role)
				credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				var mint *auth.MintedKey
				if transport == "mcp" {
					mint, _ = mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, true, 1)
					credential = mint.Plaintext
				}
				response := f.submit(transport, credential)
				if transport == "mcp" {
					fieldMCPTextE2E(t, response, false)
				} else if response.Code != http.StatusOK {
					t.Fatalf("authorized restore=%d %s", response.Code, response.Body.String())
				}
				f.assertCommit(t)
				if transport == "mcp" {
					row, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
					if err != nil || row.UsedCount != 1 || !row.LastUsedAt.Valid {
						t.Fatal("successful restore double-claimed document token")
					}
					before := f.snapshot(t)
					if response := f.submit(transport, credential); response.Code != http.StatusUnauthorized {
						t.Fatalf("restore one-use replay=%d", response.Code)
					}
					f.assertUnchanged(t, before)
				}
			})
		}
	}
}

func TestRestoreMissingTargetStaleObservationAndTenantScopesE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			f, foreign := setupRestoreAuthorizationE2E(t, "owner"), setupRestoreAuthorizationE2E(t, "owner")
			credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			if transport == "mcp" {
				mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
				credential = mint.Plaintext
			}
			before, foreignBefore := f.snapshot(t), foreign.snapshot(t)
			stamp := f.doc.UpdatedAt.Time.Format(time.RFC3339Nano)
			assertRestoreErrorE2E(t, transport, f.call(transport, credential, stamp, f.doc.ID, 999), http.StatusNotFound, "version not found")
			f.assertUnchanged(t, before)
			assertRestoreErrorE2E(t, transport, f.call(transport, credential, stamp, foreign.doc.ID, foreign.target.VersionNo), http.StatusNotFound, authoring.ErrDocumentNotFound.Error())
			f.assertUnchanged(t, before)
			foreign.assertUnchanged(t, foreignBefore)
			stale := f.doc.UpdatedAt.Time.Add(-time.Second).Format(time.RFC3339Nano)
			if transport == "mcp" {
				fieldMCPTextE2E(t, f.call(transport, credential, stale, f.doc.ID, f.target.VersionNo), true)
			} else if response := f.call(transport, credential, stale, f.doc.ID, f.target.VersionNo); response.Code != http.StatusPreconditionFailed {
				t.Fatalf("stale restore=%d %s", response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
			if transport == "mcp" {
				mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, true, 0)
				assertRestoreErrorE2E(t, transport, f.call(transport, mint.Plaintext, stamp, foreign.doc.ID, foreign.target.VersionNo), 0, auth.ErrDocScopeMismatch.Error())
				f.assertUnchanged(t, before)
				foreign.assertUnchanged(t, foreignBefore)
			}
		})
	}
}

func TestRestoreMCPRefusesForgedPublicContextE2E(t *testing.T) {
	f := setupRestoreAuthorizationE2E(t, "owner")
	before := f.snapshot(t)
	ctx := context.WithValue(f.ctx, auth.UserIDKey, f.user.ID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, f.org)
	ctx = context.WithValue(ctx, auth.RoleKey, f.user.Role)
	ctx = context.WithValue(ctx, auth.TokenScopesKey, []string{"write:authoring"})
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "restore_document_version", "arguments": map[string]any{"document_id": f.doc.ID, "target_version": f.target.VersionNo, "expected_updated_at": f.doc.UpdatedAt.Time.Format(time.RFC3339Nano)}}})
	request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
	response := httptest.NewRecorder()
	f.s.MCP.Handler().ServeHTTP(response, request)
	assertRestoreErrorE2E(t, "mcp", response, 0, auth.ErrMutationPermissionRevoked.Error())
	f.assertUnchanged(t, before)
}

func TestRestoreRejectsPDFHistoricalTargetWithoutMutationE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			f := setupRestoreAuthorizationE2E(t, "owner")
			var err error
			// Only historical metadata is seeded. No PDF storage or sealing is
			// performed or claimed by this forbidden restoration scenario.
			f.target, err = versions.New(f.q).Snapshot(f.ctx, versions.SnapshotInput{
				DocumentID: f.doc.ID, OrgID: f.org, Name: f.doc.Name, SourceKind: "pdf",
				VariablesJS: json.RawMessage(`{}`), CreatedBy: &f.user.ID, Via: versions.ViaHuman,
			})
			if err != nil {
				t.Fatal(err)
			}
			credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			if transport == "mcp" {
				mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
				credential = mint.Plaintext
			}
			before := f.snapshot(t)
			assertRestoreErrorE2E(t, transport, f.submit(transport, credential), http.StatusConflict, "target version is not block-source")
			f.assertUnchanged(t, before)
		})
	}
}
