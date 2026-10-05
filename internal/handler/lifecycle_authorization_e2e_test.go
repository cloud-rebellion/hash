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

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type lifecycleAuthorizationFixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	q         *generated.Queries
	s         *Server
	org       uuid.UUID
	user      *generated.User
	doc       *generated.Document
	recipient *generated.Recipient
}

type lifecycleVariableSource struct{}

func (lifecycleVariableSource) Kind() resolver.SourceKind { return resolver.SourceAgentComputed }
func (lifecycleVariableSource) Fetch(context.Context, resolver.Ref) (string, error) {
	return "Resolved fixture customer", nil
}

func setupLifecycleAuthorizationE2E(t *testing.T, role string, sent, family bool) lifecycleAuthorizationFixture {
	t.Helper()
	ctx, pool, q, s, org, userID := setupDSRE2E(t)
	user, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: userID, OrgID: org, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	blocks := json.RawMessage(`{"version":1,"blocks":[{"id":"agreement","type":"paragraph","text":"Agreement for {{customer}}"},{"id":"signature","type":"signature_field","attrs":{"recipient_role":"signer"}}]}`)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org, SenderID: userID, Name: "Lifecycle authorization " + uuid.NewString(), BlocksJson: blocks,
		VariablesJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Name: "Lifecycle signer", Email: uuid.NewString() + "@lifecycle.test",
		MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, `DELETE FROM email_deliveries WHERE to_email IN (SELECT r.email FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1)`, org); err != nil { //nolint:rawsql -- fixture-owned rows only
			t.Error(err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org); err != nil { //nolint:rawsql
			t.Error(err)
		}
	})
	if _, err := q.UpsertVariableBinding(ctx, generated.UpsertVariableBindingParams{
		DocumentID: doc.ID, VariableName: "customer", SourceKind: string(resolver.SourceAgentComputed), SourceRef: "synthetic fixture",
	}); err != nil {
		t.Fatal(err)
	}
	s.Send = &send.Engine{
		Pool: pool, Queries: q, Audit: s.Audit, Mailer: dispatch.QueueingMailer{Q: q},
		Resolver: resolver.New(q, lifecycleVariableSource{}), Envelopes: &envelopes.Engine{Q: q}, PublicURL: s.PublicURL, OrgName: "Lifecycle fixture",
	}
	f := lifecycleAuthorizationFixture{ctx, pool, q, s, org, user, doc, recipient}
	if family {
		if _, err := q.MarkAsEnvelope(ctx, generated.MarkAsEnvelopeParams{ID: doc.ID, OrgID: org}); err != nil {
			t.Fatal(err)
		}
		for position := int32(1); position <= 2; position++ {
			child, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
				OrgID: org, SenderID: userID, Name: "Lifecycle child " + uuid.NewString(), BlocksJson: blocks,
				VariablesJson: json.RawMessage(`{"customer":"Frozen child fixture customer"}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := q.AttachToEnvelope(ctx, generated.AttachToEnvelopeParams{
				ID: child.ID, ParentEnvelopeID: pgtype.UUID{Bytes: doc.ID, Valid: true}, EnvelopePosition: pgtype.Int4{Int32: position, Valid: true}, OrgID: org,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if sent {
		// Actual REST admission/sealing/outbox establishes a valid ceremony with
		// its Article 13 markers. Block sources require no S3 or PDF renderer;
		// nothing consumes this fixture's email outbox.
		cookie := dsrSessionCookieE2E(t, s, userID, user.SessionGeneration, time.Hour)
		if response := f.submit("send", cookie); response.Code != http.StatusOK {
			t.Fatalf("bootstrap actual lifecycle send=%d %s", response.Code, response.Body.String())
		}
		if family {
			// Legacy child credentials/reminders must be shut down atomically
			// too, even though normal envelopes invite the wrapper's recipients.
			children, err := q.ListEnvelopeChildren(ctx, generated.ListEnvelopeChildrenParams{ParentEnvelopeID: pgtype.UUID{Bytes: doc.ID, Valid: true}, OrgID: org})
			if err != nil || len(children) != 2 {
				t.Fatalf("sent lifecycle children=%d err=%v", len(children), err)
			}
			for _, child := range children {
				// The authoring query correctly forbids adding an active child's
				// recipient. Seed this historical shape directly to exercise the
				// engine's existing defensive cleanup for legacy child records.
				if _, err := pool.Exec(ctx, `INSERT INTO recipients(document_id,role,name,email,magic_token_hash,magic_token_expires_at,locale)
					VALUES($1,'signer','Legacy child signer',$2,$3,$4,'en')`, child.ID, uuid.NewString()+"@lifecycle.test", hash, time.Now().Add(time.Hour)); err != nil { //nolint:rawsql -- intentional synthetic legacy shape
					t.Fatal(err)
				}
				if err := q.UpsertReminderSchedule(ctx, generated.UpsertReminderScheduleParams{DocumentID: child.ID, Column2: json.RawMessage(`[{"days_after_send":3}]`), FiresRemaining: 1}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return f
}

func (f lifecycleAuthorizationFixture) submit(operation, cookie string) *httptest.ResponseRecorder {
	body := ""
	if operation == "send" {
		body = `{"lawful_basis":"contract"}`
	} else if operation == "void" {
		body = `{"reason":"Lifecycle fixture close"}`
	}
	return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/"+operation, body, cookie)
}

func (f lifecycleAuthorizationFixture) snapshot(t *testing.T) string {
	t.Helper()
	var state string
	err := f.pool.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
		SELECT jsonb_build_object(
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
		'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY document_id,variable_name),'[]'::jsonb) FROM document_variable_bindings b WHERE document_id IN (SELECT id FROM owned)),
		'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM document_versions v WHERE document_id IN (SELECT id FROM owned)),
		'confirmation',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY document_id),'[]'::jsonb) FROM document_lawful_basis_confirmations c WHERE document_id IN (SELECT id FROM owned)),
		'intent',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY document_id),'[]'::jsonb) FROM send_sealing_intents i WHERE document_id IN (SELECT id FROM owned)),
		'reminders',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY document_id),'[]'::jsonb) FROM reminders r WHERE document_id IN (SELECT id FROM owned)),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE document_id IN (SELECT id FROM owned)),
		'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY id),'[]'::jsonb) FROM email_deliveries ed WHERE to_email IN (SELECT email FROM recipients WHERE document_id IN (SELECT id FROM owned)))
		)::text`, f.org).Scan(&state) //nolint:rawsql -- one exact synthetic document-family snapshot
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func (f lifecycleAuthorizationFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before {
		t.Fatal("refused lifecycle mutation changed ceremony, variables, binding observations, intent, credentials, reminders, notice, audit, or outbox")
	}
}

func TestLifecycleSessionRechecksAuthorizationAfterDocumentWaitE2E(t *testing.T) {
	for _, operation := range []string{"send", "void", "remind"} {
		for _, change := range []string{"demotion", "revocation", "expiry"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupLifecycleAuthorizationE2E(t, "sender", operation != "send", false)
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
				go func() { result <- f.submit(operation, cookie) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
				want := http.StatusForbidden
				switch change {
				case "demotion":
					response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
					if response.Code != http.StatusOK {
						t.Fatalf("actual member demotion=%d %s", response.Code, response.Body.String())
					}
				case "revocation":
					if response := submitSessionOperationE2E(f.s, http.MethodPost, "/auth/logout", "", cookie); response.Code != http.StatusOK {
						t.Fatalf("actual session logout=%d %s", response.Code, response.Body.String())
					}
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
					want = http.StatusUnauthorized
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				response := receiveSessionOperationE2E(t, result)
				if response.Code != want {
					t.Fatalf("stale %s=%d want=%d %s", operation, response.Code, want, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestLifecycleVoidExpiryDuringAuditWaitRollsBackFamilyE2E(t *testing.T) {
	f := setupLifecycleAuthorizationE2E(t, "sender", true, true)
	before := f.snapshot(t)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- f.submit("void", cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	awaitSessionCookieExpiryE2E(t, f.s, cookie)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	response := receiveSessionOperationE2E(t, result)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired family void=%d %s", response.Code, response.Body.String())
	}
	f.assertUnchanged(t, before)
}

func TestLifecycleVoidSenderAndOwnerCommitFamilyAtomicallyE2E(t *testing.T) {
	for _, role := range []string{"sender", "owner"} {
		t.Run(role, func(t *testing.T) {
			f := setupLifecycleAuthorizationE2E(t, role, true, true)
			response := f.submit("void", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
			if response.Code != http.StatusOK {
				t.Fatalf("valid family void=%d %s", response.Code, response.Body.String())
			}
			var docs, liveDocs, reminders, liveTokens, events, wrongActors int
			if err := f.pool.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
				SELECT (SELECT count(*) FROM owned),
				(SELECT count(*) FROM documents WHERE org_id=$1 AND status<>'voided'),
				(SELECT count(*) FROM reminders WHERE document_id IN (SELECT id FROM owned)),
				(SELECT count(*) FROM recipients WHERE document_id IN (SELECT id FROM owned) AND magic_token_expires_at>clock_timestamp()),
				(SELECT count(*) FROM events WHERE document_id IN (SELECT id FROM owned) AND kind=$2),
				(SELECT count(*) FROM events WHERE document_id IN (SELECT id FROM owned) AND kind=$2 AND actor_user_id IS DISTINCT FROM $3)`, f.org, audit.KindDocumentVoided, f.user.ID).Scan(&docs, &liveDocs, &reminders, &liveTokens, &events, &wrongActors); err != nil { //nolint:rawsql
				t.Fatal(err)
			}
			if docs != 3 || liveDocs != 0 || reminders != 0 || liveTokens != 0 || events != 3 || wrongActors != 0 {
				t.Fatalf("void family effects docs/live/reminders/tokens/audits/wrong actors=%d/%d/%d/%d/%d/%d", docs, liveDocs, reminders, liveTokens, events, wrongActors)
			}
		})
	}
}

func (f lifecycleAuthorizationFixture) enableMCP() {
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Send: f.s.Send, PublicURL: f.s.PublicURL})
}

func (f lifecycleAuthorizationFixture) submitMCPVoid(key string) *httptest.ResponseRecorder {
	return f.submitMCPLifecycle("void_document", key)
}

func (f lifecycleAuthorizationFixture) submitMCPLifecycle(tool, key string) *httptest.ResponseRecorder {
	arguments := map[string]any{"document_id": f.doc.ID}
	if tool == "void_document" {
		arguments["reason"] = "MCP fixture close"
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": arguments},
	})
	request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+key)
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, request)
	return response
}

func assertLifecycleMCPResultE2E(t *testing.T, response *httptest.ResponseRecorder, wantError bool) {
	t.Helper()
	var reply struct {
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &reply) != nil || len(reply.Error) > 0 || reply.Result.IsError != wantError {
		t.Fatalf("MCP lifecycle status=%d want tool error=%v %s", response.Code, wantError, response.Body.String())
	}
}

func TestLifecycleMCPVoidRechecksCredentialAfterDocumentWaitE2E(t *testing.T) {
	lifecycleMCPCredentialWaitE2E(t, "void_document")
}

func TestLifecycleMCPRemindRechecksCredentialAfterDocumentWaitE2E(t *testing.T) {
	lifecycleMCPCredentialWaitE2E(t, "remind_recipient")
}

func lifecycleMCPCredentialWaitE2E(t *testing.T, tool string) {
	for _, change := range []string{"key-delete", "scope-reduction", "key-expiry", "document-token-revocation"} {
		t.Run(change, func(t *testing.T) {
			f := setupLifecycleAuthorizationE2E(t, "owner", true, false)
			f.enableMCP()
			before := f.snapshot(t)
			mint, err := auth.MintAPIKey()
			if change == "document-token-revocation" {
				mint, err = auth.MintDocumentAgentKey()
			}
			if err != nil {
				t.Fatal(err)
			}
			var keyID uuid.UUID
			if change == "document-token-revocation" {
				key, err := f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{
					DocumentID: f.doc.ID, OrgID: f.org, Name: "Lifecycle fixture token", Prefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"write:workflow"},
					CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: 1,
				})
				if err != nil {
					t.Fatal(err)
				}
				keyID = key.ID
			} else {
				key, err := f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, Name: "Lifecycle fixture key", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"write:workflow"}})
				if err != nil {
					t.Fatal(err)
				}
				keyID = key.ID
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
			go func() { result <- f.submitMCPLifecycle(tool, mint.Plaintext) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
			switch change {
			case "key-delete":
				response := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/api-keys/"+keyID.String(), "", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
				if response.Code != http.StatusNoContent {
					t.Fatalf("actual key delete=%d %s", response.Code, response.Body.String())
				}
			case "scope-reduction":
				if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- fixture credential mutation after middleware admission
			case "key-expiry":
				if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql
			case "document-token-revocation":
				if _, err := f.q.RevokeDocAgentToken(f.ctx, generated.RevokeDocAgentTokenParams{ID: keyID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
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
				t.Fatalf("MCP lost precise credential refusal: %s", response.Body.String())
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestLifecycleMCPVoidConsumesOneDocumentTokenUseE2E(t *testing.T) {
	f := setupLifecycleAuthorizationE2E(t, "owner", true, false)
	f.enableMCP()
	mint, err := auth.MintDocumentAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{
		DocumentID: f.doc.ID, OrgID: f.org, Name: "One use lifecycle fixture", Prefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"write:workflow"},
		CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertLifecycleMCPResultE2E(t, f.submitMCPVoid(mint.Plaintext), false)
	current, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
	if err != nil || current.ID != key.ID || current.UsedCount != 1 || !current.LastUsedAt.Valid {
		t.Fatalf("document-token guard consumed more than the admitted use: err=%v", err)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil || doc.Status != "voided" {
		t.Fatalf("one-use MCP void did not commit: err=%v", err)
	}
	before := f.snapshot(t)
	if response := f.submitMCPVoid(mint.Plaintext); response.Code != http.StatusUnauthorized {
		t.Fatalf("exhausted token replay=%d %s", response.Code, response.Body.String())
	}
	f.assertUnchanged(t, before)
}

func TestLifecycleRemindExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	f := setupLifecycleAuthorizationE2E(t, "sender", true, false)
	before := f.snapshot(t)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- f.submit("remind", cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	awaitSessionCookieExpiryE2E(t, f.s, cookie)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	response := receiveSessionOperationE2E(t, result)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("reminder expired during audit=%d %s", response.Code, response.Body.String())
	}
	f.assertUnchanged(t, before)
	// The refusal must leave a valid ceremony available to a fresh sender
	// session, with one atomic reminder rather than a consumed old credential.
	response = f.submit("remind", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
	var resultBody struct {
		Reminded int `json:"reminded"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &resultBody) != nil || resultBody.Reminded != 1 {
		t.Fatalf("fresh sender retry after expired reminder=%d", response.Code)
	}
}

func TestLifecycleMCPRemindConsumesOneDocumentTokenUseE2E(t *testing.T) {
	f := setupLifecycleAuthorizationE2E(t, "owner", true, false)
	f.enableMCP()
	mint, err := auth.MintDocumentAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{
		DocumentID: f.doc.ID, OrgID: f.org, Name: "One use reminder fixture", Prefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"write:workflow"},
		CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	recipientBefore, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: f.recipient.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	scheduleBefore, err := f.q.GetReminderForUpdate(f.ctx, f.doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertLifecycleMCPResultE2E(t, f.submitMCPLifecycle("remind_recipient", mint.Plaintext), false)
	current, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
	if err != nil || current.ID != key.ID || current.UsedCount != 1 || !current.LastUsedAt.Valid {
		t.Fatalf("manual reminder consumed more than the admitted token use: err=%v", err)
	}
	recipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: f.recipient.ID, OrgID: f.org})
	if err != nil || string(recipient.MagicTokenHash) == string(recipientBefore.MagicTokenHash) || !recipient.MagicTokenExpiresAt.Valid || !recipient.MagicTokenExpiresAt.Time.After(time.Now()) {
		t.Fatalf("one-use reminder failed to rotate the live ceremony credential: err=%v", err)
	}
	schedule, err := f.q.GetReminderForUpdate(f.ctx, f.doc.ID)
	if err != nil || !schedule.LastFiredAt.Valid || !schedule.NextFireAt.Valid || !schedule.NextFireAt.Time.After(scheduleBefore.NextFireAt.Time) || schedule.FiresRemaining != scheduleBefore.FiresRemaining {
		t.Fatalf("manual reminder did not atomically reset its schedule: err=%v", err)
	}
	var emails, reminders, wrongActors int
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM email_deliveries WHERE to_email=$1),
		(SELECT count(*) FROM events WHERE document_id=$2 AND kind=$3),
		(SELECT count(*) FROM events WHERE document_id=$2 AND kind=$3 AND actor_user_id IS DISTINCT FROM $4)`, f.recipient.Email, f.doc.ID, audit.KindReminderSent, f.user.ID).Scan(&emails, &reminders, &wrongActors); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if emails != 2 || reminders != 1 || wrongActors != 0 {
		t.Fatalf("one-use reminder effects outbox/audits/wrong actors=%d/%d/%d", emails, reminders, wrongActors)
	}
	before := f.snapshot(t)
	if response := f.submitMCPLifecycle("remind_recipient", mint.Plaintext); response.Code != http.StatusUnauthorized {
		t.Fatalf("exhausted reminder token replay=%d %s", response.Code, response.Body.String())
	}
	f.assertUnchanged(t, before)
}

func TestLifecycleMCPVoidRefusesForgedIdentityWithoutReceiptE2E(t *testing.T) {
	f := setupLifecycleAuthorizationE2E(t, "owner", true, false)
	f.enableMCP()
	before := f.snapshot(t)
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "void_document", "arguments": map[string]any{"document_id": f.doc.ID}}})
	// Public identity/scope context values cannot create the private receipt
	// that only secret verification plus middleware use admission installs.
	ctx := context.WithValue(f.ctx, auth.UserIDKey, f.user.ID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, f.org)
	ctx = context.WithValue(ctx, auth.RoleKey, f.user.Role)
	ctx = context.WithValue(ctx, auth.EmailKey, f.user.Email)
	ctx = context.WithValue(ctx, auth.TokenScopesKey, []string{"write:workflow"})
	request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
	response := httptest.NewRecorder()
	f.s.MCP.Handler().ServeHTTP(response, request)
	assertLifecycleMCPResultE2E(t, response, true)
	if !strings.Contains(response.Body.String(), auth.ErrMutationPermissionRevoked.Error()) {
		t.Fatalf("forged receipt refusal=%s", response.Body.String())
	}
	f.assertUnchanged(t, before)
}
