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

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
)

type staffAIActionE2E struct {
	name, method, path, body, event string
	provider                        bool
}

func setupGuardedAIAppsRESTE2E(t *testing.T, sent, blocking bool) guardedAIAppsFixture {
	t.Helper()
	f := setupStaffAIAppsHTTP300E2E(t, sent, blocking)
	shield, err := ai.NewLocalShield(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	runtime := ai.New(f.q, shield, nil, f.nativeProvider)
	f.s.Negotiator = &aiapps.Negotiator{Runtime: runtime}
	f.s.Bilingual = &aiapps.Bilingual{Runtime: runtime}
	f.s.RiskAnalyzer = &aiapps.RiskAnalyzer{Runtime: runtime}
	return f
}
func staffAIActionsE2E(f guardedAIAppsFixture) []staffAIActionE2E {
	base := "/api/v1/documents/" + f.doc.ID.String()
	return []staffAIActionE2E{
		{"create", "POST", base + "/proposals", fmt.Sprintf(`{"block_id":"agreement","proposal_kind":"counter","proposed_text":"Human reviewed clause","parent_id":"%s"}`, f.proposalID), "negotiation.proposed", false},
		{"status", "PATCH", "/api/v1/proposals/" + f.proposalID.String() + "/status", `{"status":"accepted"}`, "negotiation.status_changed", false},
		{"negotiation", "PATCH", base + "/negotiation-enabled", `{"enabled":true}`, "negotiation.setting_changed", false},
		{"bilingual-target", "PATCH", base + "/bilingual-target", `{"lang":"en-GB"}`, "bilingual.target_changed", false},
		{"suggest", "POST", base + "/proposals/suggest", `{"block_id":"agreement","concern":"Lifecycle signer alice@example.com payment date"}`, "ai.result_ready", true},
		{"bilingual", "POST", base + "/bilingual/equivalence", `{"block_id":"agreement","clause_b":"Betala inom trettio dagar"}`, "bilingual.checked", true},
		{"risk", "POST", base + "/risk-analysis", `{}`, "risk.analyzed", true},
	}
}
func staffAISubmitE2E(f guardedAIAppsFixture, ctx context.Context, op staffAIActionE2E, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(op.method, f.s.PublicURL+op.path, strings.NewReader(op.body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.s.PublicURL)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, req)
	return w
}
func staffAIActionForE2E(t *testing.T, f guardedAIAppsFixture, name string) staffAIActionE2E {
	t.Helper()
	for _, op := range staffAIActionsE2E(f) {
		if op.name == name {
			return op
		}
	}
	t.Fatal("unknown staff AI action")
	return staffAIActionE2E{}
}
func assertStaffAIChainE2E(t *testing.T, f guardedAIAppsFixture) {
	t.Helper()
	rows, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(rows)
	if result := verifier.Result(); !result.OK || !result.Complete {
		t.Fatalf("AI chain invalid: %+v", result)
	}
}

func TestAIAppsRESTOriginalSessionAfterDocumentWaitE2E(t *testing.T) {
	for _, name := range []string{"create", "status", "negotiation", "bilingual-target", "suggest", "bilingual", "risk"} {
		for _, change := range []string{"demotion", "revocation", "expiry"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				f := setupGuardedAIAppsRESTE2E(t, false, false)
				op := staffAIActionForE2E(t, f, name)
				blocked := holdAuthoringDocumentMCPE2E(t, f.lifecycleAuthorizationFixture, f.doc.ID)
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
				done, cancel, joined := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return staffAISubmitE2E(f, ctx, op, cookie) })
				defer guardedAICleanup264(t, blocked, cancel, joined)
				query := "-- name: LockManualNegotiationRootV1"
				if op.provider {
					query = "-- name: LockDocumentAIRootV1"
				}
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, query, "transactionid")
				var err error
				want := http.StatusForbidden
				switch change {
				case "demotion":
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
				case "revocation":
					_, err = f.q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration})
				default:
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
					want = http.StatusUnauthorized
				}
				if err != nil {
					t.Fatal(err)
				}
				before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
				if err = blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				w := receiveSessionOperationE2E(t, done)
				if w.Code != want {
					t.Fatalf("stale REST AI=%d want%d %s", w.Code, want, w.Body.String())
				}
				if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
					t.Fatal("refused original session mutated or dispatched")
				}
			})
		}
	}
}

func TestAIAppsRESTMutationExpiryAfterAuditWaitAndAtomicAuditE2E(t *testing.T) {
	for _, name := range []string{"create", "status", "negotiation", "bilingual-target"} {
		t.Run(name, func(t *testing.T) {
			f := setupGuardedAIAppsRESTE2E(t, false, false)
			op := staffAIActionForE2E(t, f, name)
			before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer nativeReminderRollback255(t, blocked)
			if err = f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
			done, cancel, joined := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return staffAISubmitE2E(f, ctx, op, cookie) })
			defer guardedAICleanup264(t, blocked, cancel, joined)
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, f.s, cookie)
			if err = blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if w := receiveSessionOperationE2E(t, done); w.Code != http.StatusUnauthorized {
				t.Fatalf("expired mutation=%d %s", w.Code, w.Body.String())
			}
			if authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
				t.Fatal("expired audit wait committed mutation")
			}
			cookie = dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			drop := aiAppAuditFaultE2E(t, f, op.event, true)
			if w := staffAISubmitE2E(f, f.ctx, op, cookie); w.Code != http.StatusInternalServerError {
				t.Fatalf("no-row audit=%d %s", w.Code, w.Body.String())
			}
			drop()
			if authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
				t.Fatal("missing audit committed mutation")
			}
			if w := staffAISubmitE2E(f, f.ctx, op, cookie); w.Code != http.StatusOK && w.Code != http.StatusCreated {
				t.Fatalf("fresh mutation=%d %s", w.Code, w.Body.String())
			}
			assertStaffAIChainE2E(t, f)
		})
	}
}

func TestAIAppsRESTProviderExpiryTruthfulCostAndResultRefusalE2E(t *testing.T) {
	for _, name := range []string{"suggest", "bilingual", "risk"} {
		t.Run(name, func(t *testing.T) {
			f := setupGuardedAIAppsRESTE2E(t, false, true)
			op := staffAIActionForE2E(t, f, name)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
			done, cancel, joined := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return staffAISubmitE2E(f, ctx, op, cookie) })
			defer guardedAICleanup264(t, nil, cancel, joined)
			req := awaitAIProviderE2E(t, f.provider)
			if strings.Contains(req.User, "alice@example.com") || strings.Contains(req.User, "Lifecycle signer") {
				t.Fatal("staff adapter lost Shield/recipient lookup")
			}
			awaitSessionCookieExpiryE2E(t, f.s, cookie)
			close(f.provider.release)
			w := receiveSessionOperationE2E(t, done)
			if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "Reviewed AI suggestion") {
				t.Fatalf("expired provider result=%d %s", w.Code, w.Body.String())
			}
			assertStaffAIHTTPReceiptCost300E2E(t, f, 2)
			assertStaffAIChainE2E(t, f)
		})
	}
}

func TestAIAppsRESTRequiredProviderEvidenceAndActiveNegotiationE2E(t *testing.T) {
	for _, name := range []string{"suggest", "bilingual", "risk"} {
		t.Run(name, func(t *testing.T) {
			f := setupGuardedAIAppsRESTE2E(t, false, false)
			op := staffAIActionForE2E(t, f, name)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
			drop := aiAppAuditFaultE2E(t, f, "ai.requested", false)
			w := staffAISubmitE2E(f, f.ctx, op, cookie)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("missing request=%d", w.Code)
			}
			drop()
			if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
				t.Fatal("provider dispatched without durable authority receipt")
			}
			drop = aiAppAuditFaultE2E(t, f, op.event, true)
			w = staffAISubmitE2E(f, f.ctx, op, cookie)
			if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "Reviewed AI suggestion") {
				t.Fatalf("missing result=%d %s", w.Code, w.Body.String())
			}
			drop()
			assertStaffAIHTTPReceiptCost300E2E(t, f, 2)
			if w = staffAISubmitE2E(f, f.ctx, op, cookie); w.Code != http.StatusOK || !json.Valid(w.Body.Bytes()) {
				t.Fatalf("fresh provider=%d %s", w.Code, w.Body.String())
			}
			if f.provider.calls.Load() != 2 {
				t.Fatal("guarded staff provider reused unscoped cached cost")
			}
			assertStaffAIChainE2E(t, f)
		})
	}
	for _, status := range []string{"sent", "in_progress", "changes_requested"} {
		t.Run(status, func(t *testing.T) {
			f := setupGuardedAIAppsRESTE2E(t, true, false)
			if status != "sent" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET status=$2 WHERE id=$1`, f.doc.ID, status); err != nil {
					t.Fatal(err)
				}
			} //nolint:rawsql -- actual sent ceremony precedes valid active negotiation state
			doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			for _, op := range staffAIActionsE2E(f) {
				w := staffAISubmitE2E(f, f.ctx, op, cookie)
				if w.Code != http.StatusOK && w.Code != http.StatusCreated {
					t.Fatalf("active %s/%s=%d %s", status, op.name, w.Code, w.Body.String())
				}
			}
			fresh, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
			if err != nil || fresh.Status != status || string(fresh.BlocksJson) != string(doc.BlocksJson) || string(fresh.VariablesJson) != string(doc.VariablesJson) {
				t.Fatal("negotiation action changed frozen prose or ceremony", err)
			}
			assertStaffAIChainE2E(t, f)
		})
	}
}

func TestAIAppsRESTTenantParentBlockAndPrivacyBoundariesE2E(t *testing.T) {
	f := setupGuardedAIAppsRESTE2E(t, false, false)
	other := setupGuardedAIAppsRESTE2E(t, false, false)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
	foreignBefore := authoringMCPStateE2E(t, other.lifecycleAuthorizationFixture)
	for _, op := range staffAIActionsE2E(other) {
		w := staffAISubmitE2E(f, f.ctx, op, cookie)
		if w.Code != http.StatusNotFound {
			t.Fatalf("cross tenant %s=%d %s", op.name, w.Code, w.Body.String())
		}
	}
	for _, op := range staffAIActionsE2E(f) {
		if op.name != "create" && op.name != "suggest" && op.name != "bilingual" {
			continue
		}
		op.body = strings.ReplaceAll(op.body, "agreement", "absent")
		if w := staffAISubmitE2E(f, f.ctx, op, cookie); w.Code != http.StatusNotFound {
			t.Fatalf("missing block %s=%d %s", op.name, w.Code, w.Body.String())
		}
	}
	// Provider requests that fail block validation may append a truthful request
	// receipt, but must not dispatch or create proposal/usage/result evidence.
	var usage, proposals int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM ai_completion_audit WHERE org_id=$1),(SELECT count(*) FROM document_proposals WHERE org_id=$1)`, f.org).Scan(&usage, &proposals); err != nil || usage != 0 || proposals != 1 || f.provider.calls.Load() != 0 {
		t.Fatal("invalid block dispatched or mutated", usage, proposals, err)
	} //nolint:rawsql
	if authoringMCPStateE2E(t, other.lifecycleAuthorizationFixture) != foreignBefore {
		t.Fatal("cross tenant mutated foreign state")
	}
	sibling, err := guardedAISiblingNative264(t, f.lifecycleAuthorizationFixture, "Sibling proposal boundary")
	if err != nil {
		t.Fatal(err)
	}
	op := staffAIActionForE2E(t, f, "create")
	op.path = strings.ReplaceAll(op.path, f.doc.ID.String(), sibling.ID.String())
	before = authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
	if w := staffAISubmitE2E(f, f.ctx, op, cookie); w.Code != http.StatusNotFound {
		t.Fatalf("foreign parent=%d %s", w.Code, w.Body.String())
	}
	if authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
		t.Fatal("sibling parent chain mutated")
	}
	if _, err = f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, DocumentID: pgtype.UUID{Bytes: f.doc.ID, Valid: true}, SubjectEmail: "fixture@privacy.test", SubjectName: "Fixture", Kind: "erasure", RequestedVia: "sender", PayloadJson: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	before = authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
	for _, op := range staffAIActionsE2E(f) {
		if w := staffAISubmitE2E(f, f.ctx, op, cookie); w.Code != http.StatusConflict {
			t.Fatalf("privacy-held %s=%d %s", op.name, w.Code, w.Body.String())
		}
	}
	if authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before || f.provider.calls.Load() != 0 {
		t.Fatal("privacy held staff request dispatched or mutated")
	}
}
