//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

func setupRoutingTierSenderE2E(t *testing.T) ownerPolicyFixture {
	t.Helper()
	f := setupOwnerPolicyE2E(t)
	user, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"})
	if err != nil {
		t.Fatal(err)
	}
	f.user = user
	return f
}

func TestRoutingTierOriginalSenderCredentialsAfterDocumentWaitE2E(t *testing.T) {
	for _, transport := range []string{"rest", "org-key", "document-key"} {
		changes := []string{"demotion", "revocation", "expiry"}
		if transport == "org-key" {
			changes = append(changes, "scope-reduction")
		}
		for _, change := range changes {
			t.Run(transport+"/"+change, func(t *testing.T) {
				f := setupRoutingTierSenderE2E(t)
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, ttl)
				var key string
				var keyID uuid.UUID
				if transport != "rest" {
					mint, id := mintDocumentMetadataKeyE2E(t, f.lifecycleAuthorizationFixture, transport == "document-key")
					key, keyID = mint.Plaintext, id
				}
				// Token insertion takes a document FK lock. Mint it before this
				// fixture holds the parent, then exercise only the request's wait.
				blocked := holdDocumentMetadataParentE2E(t, f.lifecycleAuthorizationFixture)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					if transport == "rest" {
						result <- f.submit(f.ctx, "routing-tier", cookie)
					} else {
						result <- f.submitMCP(f.ctx, "routing-tier", key)
					}
				}()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
				var err error
				want := auth.ErrMutationPermissionRevoked.Error()
				switch change {
				case "demotion":
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
				case "revocation":
					switch transport {
					case "rest":
						_, err = f.q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: 0})
					case "org-key":
						_, err = f.q.DeleteAPIKey(f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: f.user.ID})
					case "document-key":
						_, err = f.q.RevokeDocAgentToken(f.ctx, generated.RevokeDocAgentTokenParams{ID: keyID, OrgID: f.org})
					}
				case "scope-reduction":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID) //nolint:rawsql -- original scope reduced after admission
				case "expiry":
					want = auth.ErrMutationCredentialExpired.Error()
					switch transport {
					case "rest":
						awaitSessionCookieExpiryE2E(t, f.s, cookie)
					case "org-key":
						_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID) //nolint:rawsql
					case "document-key":
						_, err = f.pool.Exec(f.ctx, `UPDATE document_agent_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID) //nolint:rawsql
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				before := f.snapshot(t)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				w := receiveSessionOperationE2E(t, result)
				if transport == "rest" {
					wantStatus := http.StatusForbidden
					if change == "expiry" {
						wantStatus = http.StatusUnauthorized
					}
					if w.Code != wantStatus {
						t.Fatalf("stale routing session=%d want%d %s", w.Code, wantStatus, w.Body.String())
					}
				} else if got := fieldMCPTextE2E(t, w, true); got != want {
					t.Fatalf("stale routing credential=%q want%q", got, want)
				}
				f.assertUnchanged(t, before)
				if transport == "document-key" {
					var uses int
					if err := f.pool.QueryRow(f.ctx, `SELECT used_count FROM document_agent_tokens WHERE id=$1`, keyID).Scan(&uses); err != nil || uses != 1 { //nolint:rawsql -- authorization may not reclaim the final admitted use
						t.Fatalf("original document credential uses=%d err%v", uses, err)
					}
				}
			})
		}
	}
}

func TestRoutingTierAuditRollbackAndSenderSuccessE2E(t *testing.T) {
	for _, transport := range []string{"rest", "org-key", "document-key"} {
		for _, failure := range []string{"audit-error", "audit-no-row", "expiry"} {
			t.Run(transport+"/"+failure, func(t *testing.T) {
				f := setupRoutingTierSenderE2E(t)
				mint, keyID := mintDocumentMetadataKeyE2E(t, f.lifecycleAuthorizationFixture, transport == "document-key")
				ttl := time.Hour
				if failure == "expiry" {
					ttl = time.Second
					if transport == "org-key" {
						if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil { //nolint:rawsql -- natural original-key expiry while retained
							t.Fatal(err)
						}
					} else if transport == "document-key" {
						if _, err := f.pool.Exec(f.ctx, `UPDATE document_agent_tokens SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil { //nolint:rawsql
							t.Fatal(err)
						}
					}
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, ttl)
				submit := func(ctx context.Context, cookie, key string) *httptest.ResponseRecorder {
					if transport == "rest" {
						return f.submit(ctx, "routing-tier", cookie)
					}
					return f.submitMCP(ctx, "routing-tier", key)
				}
				before := f.snapshot(t)
				var w *httptest.ResponseRecorder
				if strings.HasPrefix(failure, "audit-") {
					drop := ownerOrgAuditFaultE2E(t, f.ownerOrgMutationFixture, failure == "audit-no-row")
					w = submit(f.ctx, cookie, mint.Plaintext)
					drop()
				} else {
					blocked := ownerOrgLockE2E(t, f.ownerOrgMutationFixture, true)
					result := make(chan *httptest.ResponseRecorder, 1)
					go func() { result <- submit(f.ctx, cookie, mint.Plaintext) }()
					awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
					if transport == "rest" {
						awaitSessionCookieExpiryE2E(t, f.s, cookie)
					} else if transport == "org-key" {
						awaitOwnerPolicyKeyExpiryE2E(t, f, keyID)
					} else {
						deadline := time.Now().Add(3 * time.Second)
						for {
							var expired bool
							if err := f.pool.QueryRow(f.ctx, `SELECT expires_at<=clock_timestamp() FROM document_agent_tokens WHERE id=$1`, keyID).Scan(&expired); err != nil { //nolint:rawsql
								t.Fatal(err)
							}
							if expired {
								break
							}
							if time.Now().After(deadline) {
								t.Fatal("original document routing credential did not expire")
							}
							time.Sleep(10 * time.Millisecond)
						}
					}
					if err := blocked.Commit(f.ctx); err != nil {
						t.Fatal(err)
					}
					w = receiveSessionOperationE2E(t, result)
				}
				if transport != "rest" {
					got := fieldMCPTextE2E(t, w, true)
					if failure == "expiry" && got != auth.ErrMutationCredentialExpired.Error() {
						t.Fatalf("expired routing key=%q", got)
					}
				} else {
					want := http.StatusInternalServerError
					if failure == "expiry" {
						want = http.StatusUnauthorized
					}
					if w.Code != want {
						t.Fatalf("routing audit rollback=%d want%d %s", w.Code, want, w.Body.String())
					}
				}
				f.assertUnchanged(t, before)
				fresh, freshID := mintDocumentMetadataKeyE2E(t, f.lifecycleAuthorizationFixture, transport == "document-key")
				w = submit(f.ctx, dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Hour), fresh.Plaintext)
				if transport == "rest" {
					if w.Code != http.StatusOK {
						t.Fatalf("live sender routing=%d %s", w.Code, w.Body.String())
					}
				} else {
					fieldMCPTextE2E(t, w, false)
				}
				if transport == "document-key" {
					var uses int
					if err := f.pool.QueryRow(f.ctx, `SELECT used_count FROM document_agent_tokens WHERE id=$1`, freshID).Scan(&uses); err != nil || uses != 1 { //nolint:rawsql
						t.Fatalf("successful routing receipt claimed use twice: %d %v", uses, err)
					}
				}
			})
		}
	}
}

func TestRoutingTierRejectsForeignTenantAndPreservesSESOnlyE2E(t *testing.T) {
	for _, transport := range []string{"rest", "org-key", "document-key"} {
		t.Run(transport, func(t *testing.T) {
			f, other := setupRoutingTierSenderE2E(t), setupOwnerPolicyE2E(t)
			foreign := f
			foreign.doc = other.doc
			mint, _ := mintDocumentMetadataKeyE2E(t, f.lifecycleAuthorizationFixture, transport == "document-key")
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Hour)
			before, otherBefore := f.snapshot(t), other.snapshot(t)
			if transport == "rest" {
				if w := foreign.submit(f.ctx, "routing-tier", cookie); w.Code != http.StatusNotFound {
					t.Fatalf("foreign routing document=%d %s", w.Code, w.Body.String())
				}
				op := f.operation("routing-tier")
				op.body = `{"routing_tier":"AES"}`
				if w := submitOwnerOrgE2E(f.ownerOrgMutationFixture, f.ctx, op, cookie); w.Code != http.StatusConflict {
					t.Fatalf("sender activated unavailable AES=%d %s", w.Code, w.Body.String())
				}
			} else {
				fieldMCPTextE2E(t, foreign.submitMCP(f.ctx, "routing-tier", mint.Plaintext), true)
			}
			f.assertUnchanged(t, before)
			other.assertUnchanged(t, otherBefore)
		})
	}
}
