//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/webhooksecret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ownerOrgMutationFixture struct {
	lifecycleAuthorizationFixture
	keyID, webhookID uuid.UUID
}

type ownerOrgOperation struct {
	name, method, path, body string
	success                  int
}

func setupOwnerOrgMutationE2E(t *testing.T) ownerOrgMutationFixture {
	t.Helper()
	t.Setenv("HASH_ENVIRONMENT", "development")
	f := setupLifecycleAuthorizationE2E(t, "owner", false, false)
	f.s.PublicURL = "http://localhost:39487"
	f.s.Environment = "development"
	f.s.AISealKey = bytes.Repeat([]byte{0x71}, 32)
	var err error
	f.s.WebhookSecrets, err = webhooksecret.NewKeyringHex(strings.Repeat("6a", 31)+"6b", "")
	if err != nil {
		t.Fatal(err)
	}
	ownerSetBrandingE2E(t, f.ctx, f.q, f.org, "#112233", "#445566")
	ct, err := ai.AESEncrypt(f.s.AISealKey, []byte("fixture-ai-key-original"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.q.UpsertOrgAISettings(f.ctx, generated.UpsertOrgAISettingsParams{OrgID: f.org, Provider: "mistral", BaseUrl: "http://localhost:39488", Model: "fixture-original", ApiKeyCt: ct, KeyLast4: "inal", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	mint, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Name: "existing owner credential", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	endpointID := uuid.New()
	sealed, err := f.s.WebhookSecrets.SealNew(f.org, endpointID, strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	hook, err := f.q.CreateWebhookEndpoint(f.ctx, generated.CreateWebhookEndpointParams{ID: endpointID, OrgID: f.org, Url: "http://localhost:39489/old", SecretRef: "per-endpoint-aesgcm-v1", SecretCiphertext: sealed, EventsSubscribed: []string{"document.sent"}})
	if err != nil {
		t.Fatal(err)
	}
	f.enableMCP()
	return ownerOrgMutationFixture{f, key.ID, hook.ID}
}

func ownerSetBrandingE2E(t *testing.T, ctx context.Context, q *generated.Queries, org uuid.UUID, primary, accent string) {
	t.Helper()
	b := branding.DefaultBranding()
	if _, err := q.UpsertOrgBranding(ctx, generated.UpsertOrgBrandingParams{OrgID: org, PrimaryHex: primary, AccentHex: accent, SurfaceHex: b.SurfaceHex, TextHex: b.TextHex, MutedHex: b.MutedHex, FontHeading: b.FontHeading, FontBody: b.FontBody, SignatureColor: b.SignatureColor}); err != nil {
		t.Fatal(err)
	}
}

func ownerOrgOperationsE2E(f ownerOrgMutationFixture) []ownerOrgOperation {
	return []ownerOrgOperation{
		{"branding", http.MethodPut, "/api/v1/branding", `{"primary_hex":"#abcdef"}`, http.StatusOK},
		{"ai-set", http.MethodPut, "/api/v1/ai/provider", `{"provider":"mistral","api_key":"fixture-new-ai-key"}`, http.StatusOK},
		{"ai-delete", http.MethodDelete, "/api/v1/ai/provider", "", http.StatusNoContent},
		{"key-create", http.MethodPost, "/api/v1/api-keys", `{"name":"new credential","scopes":["read"]}`, http.StatusCreated},
		{"key-delete", http.MethodDelete, "/api/v1/api-keys/" + f.keyID.String(), "", http.StatusNoContent},
		{"webhook-create", http.MethodPost, "/api/v1/webhooks", `{"url":"http://localhost:39489/new?secret=fixture-private-url","events_subscribed":["document.sent"]}`, http.StatusCreated},
		{"webhook-delete", http.MethodDelete, "/api/v1/webhooks/" + f.webhookID.String(), "", http.StatusNoContent},
	}
}

func ownerOrgSnapshotE2E(t *testing.T, f ownerOrgMutationFixture) string {
	t.Helper()
	var snapshot string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
 'branding',(SELECT row_to_json(b) FROM org_branding b WHERE b.org_id=$1),
 'ai',(SELECT row_to_json(a) FROM org_ai_settings a WHERE a.org_id=$1),
 'keys',(SELECT coalesce(jsonb_agg(to_jsonb(k)-'last_used_at' ORDER BY k.id),'[]'::jsonb) FROM api_keys k WHERE k.org_id=$1),
 'hooks',(SELECT coalesce(jsonb_agg(to_jsonb(h) ORDER BY h.id),'[]'::jsonb) FROM webhook_endpoints h WHERE h.org_id=$1),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM events e WHERE e.org_id=$1))::text`, f.org).Scan(&snapshot); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- fixture-owned state snapshot
	return snapshot
}

func submitOwnerOrgE2E(f ownerOrgMutationFixture, ctx context.Context, op ownerOrgOperation, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(op.method, f.s.PublicURL+op.path, strings.NewReader(op.body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func ownerOrgLockE2E(t *testing.T, f ownerOrgMutationFixture, auditLock bool) pgx.Tx {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if auditLock {
		err = f.q.WithTx(tx).AcquireOrgChainLock(f.ctx, f.org.String())
	} else {
		_, err = f.q.WithTx(tx).GetOrgForOwnerMutation(f.ctx, f.org)
	}
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func assertOwnerOrgUnchangedE2E(t *testing.T, f ownerOrgMutationFixture, before string) {
	t.Helper()
	if after := ownerOrgSnapshotE2E(t, f); after != before {
		t.Fatalf("organization mutation escaped refusal\nbefore=%s\nafter=%s", before, after)
	}
}

func TestOwnerOrgMutationRESTRechecksAfterOrgWaitE2E(t *testing.T) {
	for _, name := range []string{"branding", "ai-set", "ai-delete", "key-create", "key-delete", "webhook-create", "webhook-delete"} {
		for _, change := range []string{"demotion", "revocation", "expiry"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				f := setupOwnerOrgMutationE2E(t)
				var op ownerOrgOperation
				for _, v := range ownerOrgOperationsE2E(f) {
					if v.name == name {
						op = v
					}
				}
				blocked := ownerOrgLockE2E(t, f, false)
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, ttl)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitOwnerOrgE2E(f, f.ctx, op, cookie) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetOrgForOwnerMutation", "transactionid")
				var err error
				want := http.StatusForbidden
				switch change {
				case "demotion":
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"})
				case "revocation":
					_, err = f.q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: 0})
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
					want = http.StatusUnauthorized
				}
				if err != nil {
					t.Fatal(err)
				}
				before := ownerOrgSnapshotE2E(t, f)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				w := receiveSessionOperationE2E(t, result)
				if w.Code != want {
					t.Fatalf("stale owner=%d want=%d %s", w.Code, want, w.Body.String())
				}
				assertOwnerOrgUnchangedE2E(t, f, before)
				if strings.Contains(w.Body.String(), `"plaintext"`) || strings.Contains(w.Body.String(), `"secret"`) {
					t.Fatal("rejected mutation disclosed one-time secret")
				}
			})
		}
	}
}

func TestOwnerOrgMutationRESTAuditWaitRollsBackE2E(t *testing.T) {
	for _, name := range []string{"branding", "ai-set", "ai-delete", "key-create", "key-delete", "webhook-create", "webhook-delete"} {
		for _, failure := range []string{"expiry", "cancellation"} {
			t.Run(name+"/"+failure, func(t *testing.T) {
				f := setupOwnerOrgMutationE2E(t)
				var op ownerOrgOperation
				for _, v := range ownerOrgOperationsE2E(f) {
					if v.name == name {
						op = v
					}
				}
				before := ownerOrgSnapshotE2E(t, f)
				blocked := ownerOrgLockE2E(t, f, true)
				ttl := time.Hour
				if failure == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, ttl)
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitOwnerOrgE2E(f, ctx, op, cookie) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
				var w *httptest.ResponseRecorder
				if failure == "expiry" {
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
				} else {
					cancel()
					w = receiveSessionOperationE2E(t, result)
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if w == nil {
					w = receiveSessionOperationE2E(t, result)
				}
				want := http.StatusInternalServerError
				if failure == "expiry" {
					want = http.StatusUnauthorized
				}
				if w.Code != want {
					t.Fatalf("audit wait=%d want=%d %s", w.Code, want, w.Body.String())
				}
				assertOwnerOrgUnchangedE2E(t, f, before)
			})
		}
	}
}

func ownerOrgAuditFaultE2E(t *testing.T, f ownerOrgMutationFixture, noRow bool) func() {
	t.Helper()
	name := "hash_owner_fault_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	failure := "RAISE EXCEPTION 'fixture private owner audit failure';"
	if noRow {
		failure = "RETURN NULL;"
	}
	if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='%s'::uuid THEN %s END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION %s()`, name, f.org, failure, name, name)); err != nil {
		t.Fatal(err)
	} //nolint:rawsql,gosec -- generated UUID identifiers and fixed fixture predicate only
	drop := func() {
		if _, err := f.pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON events; DROP FUNCTION IF EXISTS %s()`, name, name)); err != nil {
			t.Error(err)
		}
	} //nolint:rawsql,gosec
	t.Cleanup(drop)
	return drop
}

func TestOwnerOrgMutationRESTAuditFailuresAndSuccessE2E(t *testing.T) {
	for _, name := range []string{"branding", "ai-set", "ai-delete", "key-create", "key-delete", "webhook-create", "webhook-delete"} {
		for _, noRow := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/no-row-%t", name, noRow), func(t *testing.T) {
				f := setupOwnerOrgMutationE2E(t)
				var op ownerOrgOperation
				for _, v := range ownerOrgOperationsE2E(f) {
					if v.name == name {
						op = v
					}
				}
				before := ownerOrgSnapshotE2E(t, f)
				drop := ownerOrgAuditFaultE2E(t, f, noRow)
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Hour)
				w := submitOwnerOrgE2E(f, f.ctx, op, cookie)
				if w.Code != http.StatusInternalServerError {
					t.Fatalf("audit fault=%d %s", w.Code, w.Body.String())
				}
				if strings.Contains(w.Body.String(), "fixture private") || strings.Contains(w.Body.String(), `"plaintext"`) || strings.Contains(w.Body.String(), `"secret"`) {
					t.Fatalf("private failure/secret disclosed: %s", w.Body.String())
				}
				assertOwnerOrgUnchangedE2E(t, f, before)
				drop()
				w = submitOwnerOrgE2E(f, f.ctx, op, cookie)
				if w.Code != op.success {
					t.Fatalf("fresh owner success=%d want=%d %s", w.Code, op.success, w.Body.String())
				}
				var events int
				if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1`, f.org).Scan(&events); err != nil || events != 1 {
					t.Fatalf("durable audit count=%d err=%v", events, err)
				} //nolint:rawsql
				if name == "key-create" || name == "webhook-create" {
					if w.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("one-time credential response cacheable")
					}
				}
				if name == "webhook-create" {
					var leaked int
					if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND payload_json::text LIKE '%fixture-private-url%'`, f.org).Scan(&leaked); err != nil || leaked != 0 {
						t.Fatal("webhook URL secret entered audit")
					}
				} //nolint:rawsql
			})
		}
	}
}

func submitOwnerBrandingMCPE2E(f ownerOrgMutationFixture, ctx context.Context, key string) *httptest.ResponseRecorder {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set_org_branding","arguments":{"primary_hex":"#abcdef"}}}`
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func mintOwnerBrandingKeyE2E(t *testing.T, f ownerOrgMutationFixture) (*auth.MintedKey, uuid.UUID) {
	t.Helper()
	mint, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	row, err := f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Name: "owner branding original key", Scopes: []string{"write:authoring"}})
	if err != nil {
		t.Fatal(err)
	}
	return mint, row.ID
}

func TestOwnerOrgMutationMCPRechecksOriginalKeyAfterOrgWaitE2E(t *testing.T) {
	for _, change := range []string{"member-demotion", "key-deletion", "key-scope", "key-hash", "key-expiry"} {
		t.Run(change, func(t *testing.T) {
			f := setupOwnerOrgMutationE2E(t)
			mint, keyID := mintOwnerBrandingKeyE2E(t, f)
			blocked := ownerOrgLockE2E(t, f, false)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitOwnerBrandingMCPE2E(f, f.ctx, mint.Plaintext) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetOrgForOwnerMutation", "transactionid")
			var err error
			want := auth.ErrMutationPermissionRevoked.Error()
			switch change {
			case "member-demotion":
				_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"})
			case "key-deletion":
				_, err = f.q.DeleteAPIKey(f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: f.user.ID})
			case "key-scope":
				_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID)
			case "key-hash":
				_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET key_hash=$2 WHERE id=$1`, keyID, bytes.Repeat([]byte{0x41}, 32))
			case "key-expiry":
				_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID)
				want = auth.ErrMutationCredentialExpired.Error()
			} //nolint:rawsql -- synthetic post-admission revocation
			if err != nil {
				t.Fatal(err)
			}
			before := ownerOrgSnapshotE2E(t, f)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != want {
				t.Fatalf("stale owner MCP=%q want=%q", got, want)
			}
			assertOwnerOrgUnchangedE2E(t, f, before)
		})
	}
}

func TestOwnerOrgMutationMCPAuditRefusalAndFreshSuccessE2E(t *testing.T) {
	for _, failure := range []string{"expiry", "cancellation", "audit-error", "audit-no-row"} {
		t.Run(failure, func(t *testing.T) {
			f := setupOwnerOrgMutationE2E(t)
			mint, keyID := mintOwnerBrandingKeyE2E(t, f)
			var drop func()
			if strings.HasPrefix(failure, "audit-") {
				drop = ownerOrgAuditFaultE2E(t, f, failure == "audit-no-row")
			}
			if failure == "expiry" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil {
					t.Fatal(err)
				}
			} //nolint:rawsql
			before := ownerOrgSnapshotE2E(t, f)
			var w *httptest.ResponseRecorder
			if drop != nil {
				w = submitOwnerBrandingMCPE2E(f, f.ctx, mint.Plaintext)
				drop()
			} else {
				blocked := ownerOrgLockE2E(t, f, true)
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitOwnerBrandingMCPE2E(f, ctx, mint.Plaintext) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
				if failure == "expiry" {
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
							t.Fatal("key did not expire")
						}
						time.Sleep(10 * time.Millisecond)
					}
				} else {
					cancel()
					w = receiveSessionOperationE2E(t, result)
				} //nolint:rawsql
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if w == nil {
					w = receiveSessionOperationE2E(t, result)
				}
			}
			fieldMCPTextE2E(t, w, true)
			assertOwnerOrgUnchangedE2E(t, f, before)
			fresh, _ := mintOwnerBrandingKeyE2E(t, f)
			fieldMCPTextE2E(t, submitOwnerBrandingMCPE2E(f, f.ctx, fresh.Plaintext), false)
		})
	}
}

func TestOwnerOrgMutationOmittedValuesFollowFreshLockedStateE2E(t *testing.T) {
	for _, surface := range []string{"rest-branding", "mcp-branding", "ai"} {
		t.Run(surface, func(t *testing.T) {
			f := setupOwnerOrgMutationE2E(t)
			blocked := ownerOrgLockE2E(t, f, false)
			mint, _ := mintOwnerBrandingKeyE2E(t, f)
			result := make(chan *httptest.ResponseRecorder, 1)
			op := ownerOrgOperationsE2E(f)[0]
			if surface == "ai" {
				op = ownerOrgOperation{"ai", http.MethodPut, "/api/v1/ai/provider", `{"provider":"mistral","api_key":""}`, http.StatusOK}
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Hour)
			go func() {
				if surface == "mcp-branding" {
					result <- submitOwnerBrandingMCPE2E(f, f.ctx, mint.Plaintext)
				} else {
					result <- submitOwnerOrgE2E(f, f.ctx, op, cookie)
				}
			}()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetOrgForOwnerMutation", "transactionid")
			var freshCT []byte
			if surface == "ai" {
				var err error
				freshCT, err = ai.AESEncrypt(f.s.AISealKey, []byte("fixture-rotated-ai-key"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.q.WithTx(blocked).UpsertOrgAISettings(f.ctx, generated.UpsertOrgAISettingsParams{OrgID: f.org, Provider: "mistral", BaseUrl: "http://localhost:39500", Model: "fixture-fresh", ApiKeyCt: freshCT, KeyLast4: "-key", Enabled: false}); err != nil {
					t.Fatal(err)
				}
			} else {
				ownerSetBrandingE2E(t, f.ctx, f.q.WithTx(blocked), f.org, "#010203", "#708090")
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			w := receiveSessionOperationE2E(t, result)
			if surface == "mcp-branding" {
				fieldMCPTextE2E(t, w, false)
			} else if w.Code != http.StatusOK {
				t.Fatalf("fresh merge=%d %s", w.Code, w.Body.String())
			}
			if surface == "ai" {
				row, err := f.q.GetOrgAISettings(f.ctx, f.org)
				if err != nil || !bytes.Equal(row.ApiKeyCt, freshCT) || row.Enabled || row.Model != "fixture-fresh" || row.BaseUrl != "http://localhost:39500" {
					t.Fatalf("stale provider defaults/ciphertext row=%+v err=%v", row, err)
				}
			} else {
				row, err := f.q.GetOrgBranding(f.ctx, f.org)
				if err != nil || row.PrimaryHex != "#ABCDEF" || row.AccentHex != "#708090" {
					t.Fatalf("stale branding default row=%+v err=%v", row, err)
				}
			}
		})
	}
}

func TestOwnerOrgMutationPreservesCredentialOwnerAndTenantScopeE2E(t *testing.T) {
	f := setupOwnerOrgMutationE2E(t)
	other := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
	cookie := dsrSessionCookieE2E(t, f.s, other, 0, time.Hour)
	before := ownerOrgSnapshotE2E(t, f)
	w := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/api-keys/"+f.keyID.String(), "", cookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("other owner's API key deletion=%d %s", w.Code, w.Body.String())
	}
	assertOwnerOrgUnchangedE2E(t, f, before)
	foreign := setupOwnerOrgMutationE2E(t)
	cookie = dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Hour)
	for _, op := range []ownerOrgOperation{{"foreign-key", http.MethodDelete, "/api/v1/api-keys/" + foreign.keyID.String(), "", 404}, {"foreign-hook", http.MethodDelete, "/api/v1/webhooks/" + foreign.webhookID.String(), "", 404}} {
		w := submitOwnerOrgE2E(f, f.ctx, op, cookie)
		if w.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant deletion=%d %s", w.Code, w.Body.String())
		}
	}
	assertOwnerOrgUnchangedE2E(t, f, before)
}
