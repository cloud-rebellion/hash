//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Actual /mcp middleware admits synthetic local keys; no SMTP/storage worker
// consumes these fixtures. Snapshots exclude the admitted credential use itself.
func recipientMCPArgumentsE2E(f lifecycleAuthorizationFixture, tool string) map[string]any {
	args := map[string]any{"document_id": f.doc.ID}
	if tool == "add_recipient" {
		args["email"], args["name"] = "new-recipient@example.test", "New recipient"
	} else {
		args["recipient_id"] = f.recipient.ID
		if tool == "update_recipient" {
			args["name"] = "Edited recipient"
		}
	}
	return args
}

func submitRecipientMCPE2E(f lifecycleAuthorizationFixture, tool, key string, args map[string]any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("User-Agent", "recipient-mcp-acceptance")
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, request)
	return response
}

func mintRecipientMCPKeyE2E(t *testing.T, f lifecycleAuthorizationFixture, documentToken bool, uses int32) (*auth.MintedKey, uuid.UUID) {
	t.Helper()
	mint, err := auth.MintAPIKey()
	if documentToken {
		mint, err = auth.MintDocumentAgentKey()
	}
	if err != nil {
		t.Fatal(err)
	}
	if documentToken {
		key, err := f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{
			DocumentID: f.doc.ID, OrgID: f.org, Name: "Recipient fixture document key", Prefix: mint.Prefix, KeyHash: mint.Hash,
			Scopes: []string{"write:authoring"}, CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true},
			ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: uses,
		})
		if err != nil {
			t.Fatal(err)
		}
		return mint, key.ID
	}
	key, err := f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{
		OrgID: f.org, UserID: f.user.ID, Name: "Recipient fixture org key", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"write:authoring"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return mint, key.ID
}

func recipientMCPSnapshotE2E(t *testing.T, f lifecycleAuthorizationFixture) string {
	t.Helper()
	var related string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'fields',(SELECT coalesce(jsonb_agg(to_jsonb(df) ORDER BY df.id),'[]'::jsonb)
			FROM document_fields df JOIN documents d ON d.id=df.document_id WHERE d.org_id=$1),
		'privacy_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb)
			FROM data_subject_requests r WHERE r.org_id=$1))::text`, f.org).Scan(&related); err != nil { //nolint:rawsql -- fixture-owned rows
		t.Fatal(err)
	}
	return f.snapshot(t) + "\n" + related
}

func assertRecipientMCPUnchangedE2E(t *testing.T, f lifecycleAuthorizationFixture, before string) {
	t.Helper()
	if recipientMCPSnapshotE2E(t, f) != before {
		t.Fatal("refused MCP recipient mutation changed draft, recipient/token, fields, binding, audit, intent or outbox")
	}
}

func seedRecipientMCPFieldE2E(t *testing.T, f lifecycleAuthorizationFixture) {
	t.Helper()
	var zero, one pgtype.Numeric
	_ = zero.Scan("0")
	_ = one.Scan("1")
	if _, err := f.q.CreateDraftField(f.ctx, generated.CreateDraftFieldParams{
		DocumentID: f.doc.ID, OrgID: f.org, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true}, Type: "text", Page: 1,
		XPct: zero, YPct: zero, WPct: one, HPct: one, OptionsJson: json.RawMessage(`[]`),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRecipientMCPCredentialsRecheckedAfterDocumentWaitE2E(t *testing.T) {
	for _, tool := range []string{"add_recipient", "update_recipient", "delete_recipient"} {
		for _, change := range []string{"key-delete", "scope-reduction", "key-expiry", "document-token-revocation", "member-demotion"} {
			t.Run(tool+"/"+change, func(t *testing.T) {
				f := setupNativeLifecycleAuthorization256(t, "owner", false, false)
				f.enableMCP()
				seedRecipientMCPFieldE2E(t, f)
				before := recipientMCPSnapshotE2E(t, f)
				mint, keyID := mintRecipientMCPKeyE2E(t, f, change == "document-token-revocation", 1)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				result := make(chan *httptest.ResponseRecorder, 1)
				startAuthoringParentRequest624E2E(t, blocked, result, func() *httptest.ResponseRecorder {
					return submitRecipientMCPE2E(f, tool, mint.Plaintext, recipientMCPArgumentsE2E(f, tool))
				})
				awaitAuthoringParentWait624E2E(t, f, blocked, "-- name: GetRecipientMutationSourceHeaderV1", true)
				switch change {
				case "key-delete":
					response := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/api-keys/"+keyID.String(), "", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
					if response.Code != http.StatusNoContent {
						t.Fatalf("actual key deletion status=%d", response.Code)
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
				response := receiveSessionOperationE2E(t, result)
				assertLifecycleMCPResultE2E(t, response, true)
				want := auth.ErrMutationPermissionRevoked.Error()
				if change == "key-expiry" {
					want = auth.ErrMutationCredentialExpired.Error()
				}
				if !strings.Contains(response.Body.String(), want) {
					t.Fatalf("credential refusal did not preserve the typed error: %s", response.Body.String())
				}
				assertRecipientMCPUnchangedE2E(t, f, before)
				if change == "document-token-revocation" {
					key, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
					if err != nil || key.UsedCount != 1 || !key.LastUsedAt.Valid {
						t.Fatal("refused transaction must retain exactly its one middleware use claim")
					}
				}
			})
		}
	}
}

func TestRecipientMCPOneUseTokenDoesNotDoubleClaimE2E(t *testing.T) {
	for _, tool := range []string{"add_recipient", "update_recipient", "delete_recipient"} {
		t.Run(tool, func(t *testing.T) {
			f := setupNativeLifecycleAuthorization256(t, "sender", false, false)
			f.enableMCP()
			mint, _ := mintRecipientMCPKeyE2E(t, f, true, 1)
			args := recipientMCPArgumentsE2E(f, tool)
			originalAudit := authoringAuditBaselineE2E(t, f)
			assertLifecycleMCPResultE2E(t, submitRecipientMCPE2E(f, tool, mint.Plaintext, args), false)
			rows, err := f.q.ListRecipientsByDocument(f.ctx, f.doc.ID)
			if err != nil {
				t.Fatal(err)
			}
			subject, kind := f.recipient.ID, audit.KindRecipientDeleted
			switch tool {
			case "add_recipient":
				if len(rows) != 2 {
					t.Fatal("one-use create did not commit exactly one new recipient")
				}
				for _, row := range rows {
					if row.Email == "new-recipient@example.test" && row.Name == "New recipient" {
						subject = row.ID
					}
				}
				if subject == f.recipient.ID {
					t.Fatal("one-use create returned success without its requested recipient")
				}
				kind = audit.KindRecipientCreated
			case "update_recipient":
				if len(rows) != 1 || rows[0].ID != f.recipient.ID || rows[0].Name != "Edited recipient" {
					t.Fatal("one-use update did not commit its exact recipient edit")
				}
				kind = audit.KindRecipientUpdated
			case "delete_recipient":
				if len(rows) != 0 {
					t.Fatal("one-use delete did not remove its recipient")
				}
			}
			var total, matching int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER (WHERE kind=$2 AND actor_user_id=$3 AND recipient_id=$4
				AND payload_json->>'tool'=$5 AND payload_json->>'via'='mcp') FROM events WHERE document_id=$1 AND NOT (id=ANY($6::uuid[]))`,
				f.doc.ID, kind, f.user.ID, subject, tool, originalAudit.ids()).Scan(&total, &matching); err != nil {
				t.Fatal(err)
			}
			if total != 1 || matching != 1 {
				t.Fatalf("one-use mutation audit total/matching=%d/%d", total, matching)
			}
			originalAudit.assertAdded(t, f, 1)
			key, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
			if err != nil || key.UsedCount != 1 || !key.LastUsedAt.Valid {
				t.Fatal("authorizing twice consumed more than the one admitted token use")
			}
			before := recipientMCPSnapshotE2E(t, f)
			if response := submitRecipientMCPE2E(f, tool, mint.Plaintext, args); response.Code != http.StatusUnauthorized {
				t.Fatalf("one-use replay status=%d", response.Code)
			}
			assertRecipientMCPUnchangedE2E(t, f, before)
		})
	}
}

func TestRecipientMCPRefusesForgedContextWithoutReceiptE2E(t *testing.T) {
	f := setupNativeLifecycleAuthorization256(t, "owner", false, false)
	f.enableMCP()
	before := recipientMCPSnapshotE2E(t, f)
	ctx := context.WithValue(f.ctx, auth.UserIDKey, f.user.ID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, f.org)
	ctx = context.WithValue(ctx, auth.RoleKey, f.user.Role)
	ctx = context.WithValue(ctx, auth.EmailKey, f.user.Email)
	ctx = context.WithValue(ctx, auth.TokenScopesKey, []string{"write:authoring"})
	for _, tool := range []string{"add_recipient", "update_recipient", "delete_recipient"} {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": recipientMCPArgumentsE2E(f, tool)}})
		request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
		response := httptest.NewRecorder()
		f.s.MCP.Handler().ServeHTTP(response, request)
		assertLifecycleMCPResultE2E(t, response, true)
		if !strings.Contains(response.Body.String(), auth.ErrMutationPermissionRevoked.Error()) {
			t.Fatalf("forged public identity was not refused: %s", response.Body.String())
		}
		assertRecipientMCPUnchangedE2E(t, f, before)
	}
}

func TestRecipientMCPRefusesConcurrentSoftDeleteE2E(t *testing.T) {
	for _, tool := range []string{"add_recipient", "update_recipient", "delete_recipient"} {
		t.Run(tool, func(t *testing.T) {
			f := setupNativeLifecycleAuthorization256(t, "owner", false, false)
			f.enableMCP()
			seedRecipientMCPFieldE2E(t, f)
			mint, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			startAuthoringParentRequest624E2E(t, blocked, result, func() *httptest.ResponseRecorder {
				return submitRecipientMCPE2E(f, tool, mint.Plaintext, recipientMCPArgumentsE2E(f, tool))
			})
			awaitAuthoringParentWait624E2E(t, f, blocked, "-- name: GetRecipientMutationSourceHeaderV1", true)
			if _, err := blocked.Exec(f.ctx, `UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1`, f.doc.ID); err != nil {
				t.Fatal(err)
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			before := recipientMCPSnapshotE2E(t, f)
			response := receiveSessionOperationE2E(t, result)
			assertLifecycleMCPResultE2E(t, response, true)
			if !strings.Contains(response.Body.String(), recipients.ErrDocumentNotFound.Error()) {
				t.Fatalf("deleted draft refusal=%s", response.Body.String())
			}
			assertRecipientMCPUnchangedE2E(t, f, before)
		})
	}
}

func TestRecipientMCPScopeAndTenantBoundariesE2E(t *testing.T) {
	f := setupNativeLifecycleAuthorization256(t, "owner", false, false)
	f.enableMCP()
	sibling := createAuthoringSiblingE2E(t, f, "Recipient scope sibling")
	foreign := setupLifecycleAuthorizationE2E(t, "owner", false, false)
	docKey, _ := mintRecipientMCPKeyE2E(t, f, true, 10)
	orgKey, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
	before, foreignBefore := recipientMCPSnapshotE2E(t, f), recipientMCPSnapshotE2E(t, foreign)
	for _, tool := range []string{"add_recipient", "update_recipient", "delete_recipient"} {
		args := recipientMCPArgumentsE2E(f, tool)
		args["document_id"] = sibling.ID
		assertLifecycleMCPResultE2E(t, submitRecipientMCPE2E(f, tool, docKey.Plaintext, args), true)
		args["document_id"] = foreign.doc.ID
		args["recipient_id"] = foreign.recipient.ID
		response := submitRecipientMCPE2E(f, tool, orgKey.Plaintext, args)
		assertLifecycleMCPResultE2E(t, response, true)
		if !strings.Contains(response.Body.String(), recipients.ErrDocumentNotFound.Error()) {
			t.Fatalf("foreign tenant document refusal=%s", response.Body.String())
		}
		if tool != "add_recipient" {
			args["document_id"] = f.doc.ID
			response = submitRecipientMCPE2E(f, tool, orgKey.Plaintext, args)
			assertLifecycleMCPResultE2E(t, response, true)
			if !strings.Contains(response.Body.String(), recipients.ErrRecipientNotFound.Error()) {
				t.Fatalf("foreign recipient association refusal=%s", response.Body.String())
			}
		}
	}
	assertRecipientMCPUnchangedE2E(t, f, before)
	assertRecipientMCPUnchangedE2E(t, foreign, foreignBefore)
}

func TestRecipientMCPLockedDefaultAndNormalizedCRUDActorE2E(t *testing.T) {
	f := setupNativeLifecycleAuthorization256(t, "sender", false, false)
	f.enableMCP()
	originalAudit := authoringAuditBaselineE2E(t, f)
	mint, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"document_id": f.doc.ID, "name": "  New signer  ", "email": "  normalized@example.test  "}
	result := make(chan *httptest.ResponseRecorder, 1)
	startAuthoringParentRequest624E2E(t, blocked, result, func() *httptest.ResponseRecorder {
		return submitRecipientMCPE2E(f, "add_recipient", mint.Plaintext, args)
	})
	awaitAuthoringParentWait624E2E(t, f, blocked, "-- name: GetRecipientMutationSourceHeaderV1", true)
	deadline := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Microsecond)
	if _, err := blocked.Exec(f.ctx, `UPDATE documents SET default_locale='sv',expires_at=$2 WHERE id=$1`, f.doc.ID, deadline); err != nil {
		t.Fatal(err)
	}
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	response := receiveSessionOperationE2E(t, result)
	assertLifecycleMCPResultE2E(t, response, false)
	var reply struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &reply); err != nil || len(reply.Result.Content) != 1 {
		t.Fatal("normalized recipient result missing")
	}
	var created generated.Recipient
	if err := json.Unmarshal([]byte(reply.Result.Content[0].Text), &created); err != nil {
		t.Fatal(err)
	}
	if created.Name != "New signer" || created.Email != "normalized@example.test" || created.Role != "signer" || created.Locale != "sv" ||
		!created.MagicTokenExpiresAt.Valid || !created.MagicTokenExpiresAt.Time.Equal(deadline) {
		t.Fatalf("create did not normalize input or inherit the freshly locked locale/deadline: name=%q role=%q locale=%q", created.Name, created.Role, created.Locale)
	}
	update := map[string]any{"document_id": f.doc.ID, "recipient_id": created.ID, "name": "  Updated signer  ", "locale": "en_US", "role": "finance_signer"}
	assertLifecycleMCPResultE2E(t, submitRecipientMCPE2E(f, "update_recipient", mint.Plaintext, update), false)
	current, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: created.ID, OrgID: f.org})
	if err != nil || current.Name != "Updated signer" || current.Email != created.Email || current.Role != "finance_signer" || current.Locale != "en" {
		t.Fatal("update did not preserve omitted fields and normalize the explicit patch")
	}
	assertLifecycleMCPResultE2E(t, submitRecipientMCPE2E(f, "delete_recipient", mint.Plaintext,
		map[string]any{"document_id": f.doc.ID, "recipient_id": created.ID}), false)
	var remaining, audits, wrongActors int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM recipients WHERE id=$1),
		(SELECT count(*) FROM events WHERE document_id=$2 AND NOT (id=ANY($4::uuid[])) AND kind IN ('recipient.created','recipient.updated','recipient.deleted')),
		(SELECT count(*) FROM events WHERE document_id=$2 AND NOT (id=ANY($4::uuid[])) AND (actor_user_id IS DISTINCT FROM $3 OR recipient_id IS DISTINCT FROM $1
		OR payload_json->>'via' IS DISTINCT FROM 'mcp' OR ua IS DISTINCT FROM 'recipient-mcp-acceptance'))`, created.ID, f.doc.ID, f.user.ID, originalAudit.ids()).Scan(&remaining, &audits, &wrongActors); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 || audits != 3 || wrongActors != 0 {
		t.Fatalf("normalized CRUD recipient/audits/wrong identities=%d/%d/%d", remaining, audits, wrongActors)
	}
	originalAudit.assertAdded(t, f, 3)
	rows, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(rows)
	if verified := verifier.Result(); !verified.OK || verified.TotalChecked != len(originalAudit.events)+3 {
		t.Fatalf("successful deleted-recipient audit chain failed: %+v", verified)
	}
}

func TestRecipientMCPExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	for _, tool := range []string{"add_recipient", "update_recipient", "delete_recipient"} {
		t.Run(tool, func(t *testing.T) {
			f := setupNativeLifecycleAuthorization256(t, "owner", false, false)
			f.enableMCP()
			seedRecipientMCPFieldE2E(t, f)
			mint, keyID := mintRecipientMCPKeyE2E(t, f, false, 0)
			if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil {
				t.Fatal(err)
			}
			before := recipientMCPSnapshotE2E(t, f)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitRecipientMCPE2E(f, tool, mint.Plaintext, recipientMCPArgumentsE2E(f, tool)) }()
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
					t.Fatal("fixture API key did not expire")
				}
				time.Sleep(10 * time.Millisecond)
			}
			assertRecipientMCPUnchangedE2E(t, f, before)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			assertLifecycleMCPResultE2E(t, response, true)
			if !strings.Contains(response.Body.String(), auth.ErrMutationCredentialExpired.Error()) {
				t.Fatalf("final credential expiry refusal=%s", response.Body.String())
			}
			assertRecipientMCPUnchangedE2E(t, f, before)
		})
	}
}

func TestRecipientMCPPendingPrivacyReviewPreservesRecipientLinkageE2E(t *testing.T) {
	for _, linked := range []bool{true, false} {
		name := "organization-wide"
		if linked {
			name = "linked-document"
		}
		t.Run(name, func(t *testing.T) {
			f := setupNativeLifecycleAuthorization256(t, "owner", false, false)
			f.enableMCP()
			seedRecipientMCPFieldE2E(t, f)
			document := pgtype.UUID{}
			if linked {
				document = pgtype.UUID{Bytes: f.doc.ID, Valid: true}
			}
			request, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{
				OrgID: f.org, DocumentID: document, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true},
				SubjectEmail: f.recipient.Email, SubjectName: f.recipient.Name, Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			mint, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
			before := recipientMCPSnapshotE2E(t, f)
			for _, tool := range []string{"add_recipient", "update_recipient", "delete_recipient"} {
				response := submitRecipientMCPE2E(f, tool, mint.Plaintext, recipientMCPArgumentsE2E(f, tool))
				assertLifecycleMCPResultE2E(t, response, true)
				if !strings.Contains(response.Body.String(), recipients.ErrPendingPrivacyReview.Error()) {
					t.Fatalf("pending review refusal=%s", response.Body.String())
				}
				assertRecipientMCPUnchangedE2E(t, f, before)
			}
			current, err := f.q.GetDataSubjectRequest(f.ctx, generated.GetDataSubjectRequestParams{ID: request.ID, OrgID: f.org})
			if err != nil || !current.RecipientID.Valid || uuid.UUID(current.RecipientID.Bytes) != f.recipient.ID || current.SubjectEmail != f.recipient.Email {
				t.Fatal("refused recipient edits changed the linked privacy subject identity")
			}
		})
	}
}

func TestRecipientMCPInternalFailuresRollBackAndRetryE2E(t *testing.T) {
	for _, tool := range []string{"add_recipient", "update_recipient", "delete_recipient"} {
		for _, fault := range []string{"audit-exception", "audit-no-row", "mutation-no-row"} {
			t.Run(tool+"/"+fault, func(t *testing.T) {
				f := setupNativeLifecycleAuthorization256(t, "owner", false, false)
				f.enableMCP()
				seedRecipientMCPFieldE2E(t, f)
				mint, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
				before := recipientMCPSnapshotE2E(t, f)
				originalAudit := authoringAuditBaselineE2E(t, f)
				kind := map[string]string{
					"add_recipient": audit.KindRecipientCreated, "update_recipient": audit.KindRecipientUpdated, "delete_recipient": audit.KindRecipientDeleted,
				}[tool]
				name := "hash_mcp_recipient_failure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
				table, event := "events", "INSERT"
				predicate := fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.kind='%s'", f.doc.ID, kind)
				failure := "RAISE EXCEPTION 'fixture MCP recipient failure';"
				if fault == "audit-no-row" {
					failure = "RETURN NULL;"
				}
				if fault == "mutation-no-row" {
					table, failure = "recipients", "RETURN NULL;"
					switch tool {
					case "add_recipient":
						predicate = fmt.Sprintf("NEW.document_id='%s'::uuid", f.doc.ID)
					case "update_recipient":
						event, predicate = "UPDATE", fmt.Sprintf("NEW.id='%s'::uuid", f.recipient.ID)
					case "delete_recipient":
						event, predicate = "DELETE", fmt.Sprintf("OLD.id='%s'::uuid", f.recipient.ID)
					}
				}
				returnRow := "NEW"
				if event == "DELETE" {
					returnRow = "OLD"
				}
				if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF %s THEN %s END IF; RETURN %s; END $$;
					CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, predicate, failure, returnRow, name, event, table, name)); err != nil {
					t.Fatal(err)
				} //nolint:rawsql,gosec -- fixed fixture constants and generated UUID identifiers
				dropFault := func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if _, err := f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s()`, name, table, name)); err != nil {
						t.Error(err)
					} //nolint:rawsql,gosec -- fixture-owned trigger and function
				}
				t.Cleanup(dropFault)
				args := recipientMCPArgumentsE2E(f, tool)
				response := submitRecipientMCPE2E(f, tool, mint.Plaintext, args)
				assertLifecycleMCPResultE2E(t, response, true)
				var reply struct {
					Result struct {
						Content []struct {
							Type string `json:"type"`
							Text string `json:"text"`
						} `json:"content"`
					} `json:"result"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &reply); err != nil || len(reply.Result.Content) != 1 || reply.Result.Content[0].Type != "text" || reply.Result.Content[0].Text != "internal error" {
					t.Fatalf("internal %s/%s response must contain only the generic tool error: %s", tool, fault, response.Body.String())
				}
				for _, leak := range []string{"fixture MCP recipient failure", name, "SQLSTATE", "PL/pgSQL", "no rows in result set", "create recipient:", "update recipient:", "delete recipient:", "audit recipient mutation:"} {
					if strings.Contains(response.Body.String(), leak) {
						t.Fatalf("MCP internal error exposed %q", leak)
					}
				}
				assertRecipientMCPUnchangedE2E(t, f, before)
				dropFault()
				assertLifecycleMCPResultE2E(t, submitRecipientMCPE2E(f, tool, mint.Plaintext, args), false)
				rows, err := f.q.ListRecipientsByDocument(f.ctx, f.doc.ID)
				if err != nil {
					t.Fatal(err)
				}
				switch tool {
				case "add_recipient":
					if len(rows) != 2 {
						t.Fatal("retry did not commit exactly one new recipient")
					}
					found := false
					for _, row := range rows {
						found = found || row.Email == "new-recipient@example.test" && row.Name == "New recipient"
					}
					if !found {
						t.Fatal("retry did not commit the requested recipient")
					}
				case "update_recipient":
					if len(rows) != 1 || rows[0].ID != f.recipient.ID || rows[0].Name != "Edited recipient" {
						t.Fatal("retry did not commit the requested recipient edit")
					}
				case "delete_recipient":
					if len(rows) != 0 {
						t.Fatal("retry did not delete the recipient")
					}
				}
				var total, matching int
				if err := f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER (WHERE kind=$2 AND actor_user_id=$3
					AND payload_json->>'tool'=$4 AND payload_json->>'via'='mcp') FROM events WHERE document_id=$1 AND NOT (id=ANY($5::uuid[]))`,
					f.doc.ID, kind, f.user.ID, tool, originalAudit.ids()).Scan(&total, &matching); err != nil {
					t.Fatal(err)
				}
				if total != 1 || matching != 1 {
					t.Fatalf("retry audit total/matching=%d/%d want1/1", total, matching)
				}
				originalAudit.assertAdded(t, f, 1)
			})
		}
	}
}
