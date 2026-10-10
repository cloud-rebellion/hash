//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/webhooksecret"
	"github.com/google/uuid"
)

func setupOwnerWebhookMCPE2E(t *testing.T) ownerOrgMutationFixture {
	t.Helper()
	f := setupOwnerOrgMutationE2E(t)
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Send: f.s.Send, PublicURL: f.s.PublicURL, Environment: f.s.Environment, WebhookSecrets: f.s.WebhookSecrets})
	return f
}

func submitOwnerWebhookMCPE2E(f ownerOrgMutationFixture, ctx context.Context, tool, key string, id uuid.UUID) *httptest.ResponseRecorder {
	args := map[string]any{"endpoint_id": id}
	if tool == "create_webhook" {
		args = map[string]any{"url": "http://localhost:39489/new?secret=fixture-private-webhook-url", "events_subscribed": []string{"document.sent"}}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func assertNoWebhookSecretResponseE2E(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(w.Body.String(), `\"secret\"`) || strings.Contains(w.Body.String(), "fixture-private-webhook-url") || strings.Contains(w.Body.String(), "fixture private owner audit failure") {
		t.Fatal("refused webhook mutation disclosed endpoint secret or private diagnostic")
	}
}

func TestOwnerWebhookMCPOriginalOwnerAndKeyAfterOrgWaitE2E(t *testing.T) {
	for _, tool := range []string{"create_webhook", "delete_webhook"} {
		for _, change := range []string{"member-demotion", "key-deletion", "scope-reduction", "key-hash", "key-expiry"} {
			t.Run(tool+"/"+change, func(t *testing.T) {
				f := setupOwnerWebhookMCPE2E(t)
				mint, keyID := mintOwnerBrandingKeyE2E(t, f)
				blocked := ownerOrgLockE2E(t, f, false)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitOwnerWebhookMCPE2E(f, f.ctx, tool, mint.Plaintext, f.webhookID) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetOrgForOwnerMutation", "transactionid")
				var err error
				want := auth.ErrMutationPermissionRevoked.Error()
				switch change {
				case "member-demotion":
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"})
				case "key-deletion":
					_, err = f.q.DeleteAPIKey(f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: f.user.ID})
				case "scope-reduction":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID) //nolint:rawsql -- admitted credential changed while org row blocked
				case "key-hash":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET key_hash=$2 WHERE id=$1`, keyID, bytes.Repeat([]byte{0x31}, 32)) //nolint:rawsql
				case "key-expiry":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID)
					want = auth.ErrMutationCredentialExpired.Error() //nolint:rawsql
				}
				if err != nil {
					t.Fatal(err)
				}
				before := ownerOrgSnapshotE2E(t, f)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				w := receiveSessionOperationE2E(t, result)
				if text := fieldMCPTextE2E(t, w, true); text != want {
					t.Fatalf("original webhook credential=%q want%q", text, want)
				}
				assertNoWebhookSecretResponseE2E(t, w)
				assertOwnerOrgUnchangedE2E(t, f, before)
			})
		}
	}
}

func TestOwnerWebhookMCPAuditWaitRollsBackAndFreshOwnerSucceedsE2E(t *testing.T) {
	for _, tool := range []string{"create_webhook", "delete_webhook"} {
		for _, failure := range []string{"expiry", "cancellation", "audit-error", "audit-no-row"} {
			t.Run(tool+"/"+failure, func(t *testing.T) {
				f := setupOwnerWebhookMCPE2E(t)
				mint, keyID := mintOwnerBrandingKeyE2E(t, f)
				if failure == "expiry" {
					if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil {
						t.Fatal(err)
					}
				} //nolint:rawsql
				before := ownerOrgSnapshotE2E(t, f)
				var w *httptest.ResponseRecorder
				if strings.HasPrefix(failure, "audit-") {
					drop := ownerOrgAuditFaultE2E(t, f, failure == "audit-no-row")
					w = submitOwnerWebhookMCPE2E(f, f.ctx, tool, mint.Plaintext, f.webhookID)
					drop()
				} else {
					blocked := ownerOrgLockE2E(t, f, true)
					ctx, cancel := context.WithCancel(f.ctx)
					defer cancel()
					result := make(chan *httptest.ResponseRecorder, 1)
					go func() { result <- submitOwnerWebhookMCPE2E(f, ctx, tool, mint.Plaintext, f.webhookID) }()
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
								t.Fatal("original webhook key did not naturally expire")
							}
							time.Sleep(10 * time.Millisecond)
						} //nolint:rawsql
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
				}
				text := fieldMCPTextE2E(t, w, true)
				if failure == "expiry" {
					if text != auth.ErrMutationCredentialExpired.Error() {
						t.Fatalf("audit-wait expiry=%q", text)
					}
				} else if text != "webhook mutation failed" {
					t.Fatalf("unexpected/internal audit error disclosed or misclassified: %q", text)
				}
				assertNoWebhookSecretResponseE2E(t, w)
				assertOwnerOrgUnchangedE2E(t, f, before)
				fresh, freshID := mintOwnerBrandingKeyE2E(t, f)
				if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read','write:authoring']::text[] WHERE id=$1`, freshID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- synthetic complete owner key for positive create/readback

				success := submitOwnerWebhookMCPE2E(f, f.ctx, tool, fresh.Plaintext, f.webhookID)
				resultText := fieldMCPTextE2E(t, success, false)
				if success.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("webhook one-time secret response cacheable")
				}
				var response struct {
					ID      uuid.UUID `json:"id"`
					Secret  string    `json:"secret"`
					Deleted string    `json:"deleted"`
				}
				if err := json.Unmarshal([]byte(resultText), &response); err != nil {
					t.Fatal(err)
				}
				kind, endpointID := "webhook.deleted", f.webhookID
				if tool == "create_webhook" {
					kind, endpointID = "webhook.created", response.ID
					if !webhooksecret.IsGeneratedSecret(response.Secret) {
						t.Fatal("committed webhook lacks strong one-time signing secret")
					}
					var plaintext string
					var ciphertext []byte
					if err := f.pool.QueryRow(f.ctx, `SELECT secret,secret_ciphertext FROM webhook_endpoints WHERE id=$1 AND org_id=$2`, endpointID, f.org).Scan(&plaintext, &ciphertext); err != nil || plaintext != "" || len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte(response.Secret)) {
						t.Fatal("webhook signing secret not encrypted at rest")
					} //nolint:rawsql
					manager, err := webhooksecret.NewManager(f.pool, f.s.WebhookSecrets, "")
					if err != nil {
						t.Fatal(err)
					}
					url, secret, err := manager.Endpoint(f.ctx, endpointID)
					if err != nil || secret != response.Secret || url != "http://localhost:39489/new?secret=fixture-private-webhook-url" {
						t.Fatal("committed endpoint secret cannot be authenticated for dispatch")
					}
					listing := submitOwnerWebhookMCPE2E(f, f.ctx, "list_webhooks", fresh.Plaintext, uuid.Nil)
					if strings.Contains(fieldMCPTextE2E(t, listing, false), response.Secret) {
						t.Fatal("subsequent webhook listing disclosed signing secret")
					}
				} else if response.Deleted != f.webhookID.String() {
					t.Fatalf("wrong deleted webhook=%q", response.Deleted)
				}
				var actor uuid.UUID
				var gotKind, payload string
				if err := f.pool.QueryRow(f.ctx, `SELECT actor_user_id,kind,payload_json::text FROM events WHERE org_id=$1 ORDER BY id DESC LIMIT 1`, f.org).Scan(&actor, &gotKind, &payload); err != nil || actor != f.user.ID || gotKind != kind || !strings.Contains(payload, endpointID.String()) || !strings.Contains(payload, `"via": "mcp"`) {
					t.Fatalf("reviewed webhook audit wrong actor/kind/identity: %s %s %s err%v", actor, gotKind, payload, err)
				} //nolint:rawsql
				if strings.Contains(payload, "fixture-private-webhook-url") || (response.Secret != "" && strings.Contains(payload, response.Secret)) {
					t.Fatal("URL credential/signing secret entered immutable audit")
				}
				chain, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
				if err != nil {
					t.Fatal(err)
				}
				verifier := audit.NewChainVerifier()
				verifier.VerifyPage(chain)
				if got := verifier.Result(); !got.OK || !got.Complete || got.TotalChecked != 1 {
					t.Fatalf("webhook chain invalid: %+v", got)
				}
			})
		}
	}
}

type webhookLogCapture struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *webhookLogCapture) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(value)
}
func (b *webhookLogCapture) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func TestOwnerWebhookMCPSuppressesPrivateDiagnosticsAndCrossTenantTargetsE2E(t *testing.T) {
	for _, tool := range []string{"create_webhook", "delete_webhook"} {
		t.Run(tool, func(t *testing.T) {
			f := setupOwnerWebhookMCPE2E(t)
			mint, _ := mintOwnerBrandingKeyE2E(t, f)
			before := ownerOrgSnapshotE2E(t, f)
			drop := ownerOrgAuditFaultE2E(t, f, false)
			capture := &webhookLogCapture{}
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(capture, nil)))
			defer slog.SetDefault(previous)
			w := submitOwnerWebhookMCPE2E(f, f.ctx, tool, mint.Plaintext, f.webhookID)
			if fieldMCPTextE2E(t, w, true) != "webhook mutation failed" {
				t.Fatal("webhook failed to suppress private audit diagnostics")
			}
			for _, marker := range []string{"fixture private owner audit failure", "fixture-private-webhook-url", "SQLSTATE", "secret_ciphertext"} {
				if strings.Contains(w.Body.String(), marker) || strings.Contains(capture.String(), marker) {
					t.Fatalf("private diagnostic escaped response/log: %q", marker)
				}
			}
			assertOwnerOrgUnchangedE2E(t, f, before)
			drop()
		})
	}
	f := setupOwnerWebhookMCPE2E(t)
	other := setupOwnerWebhookMCPE2E(t)
	mint, _ := mintOwnerBrandingKeyE2E(t, f)
	before, foreign := ownerOrgSnapshotE2E(t, f), ownerOrgSnapshotE2E(t, other)
	if text := fieldMCPTextE2E(t, submitOwnerWebhookMCPE2E(f, f.ctx, "delete_webhook", mint.Plaintext, other.webhookID), true); text != "webhook endpoint not found" {
		t.Fatalf("cross-tenant webhook response=%q", text)
	}
	assertOwnerOrgUnchangedE2E(t, f, before)
	assertOwnerOrgUnchangedE2E(t, other, foreign)
}
