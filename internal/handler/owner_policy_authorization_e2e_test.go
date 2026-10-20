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
	"github.com/bright-interaction/hash/internal/compliance"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type ownerPolicyFixture struct {
	ownerOrgMutationFixture
	rule *generated.EidasRoutingRule
	flag *generated.ComplianceFlag
	item compliance.FeedItem
}

type ownerPolicyFeed struct {
	items   []compliance.FeedItem
	entered chan struct{}
	release <-chan struct{}
}

func (f ownerPolicyFeed) Fetch(ctx context.Context, _ time.Time) ([]compliance.FeedItem, error) {
	if f.entered != nil {
		close(f.entered)
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.items, ctx.Err()
}

func setupOwnerPolicyE2E(t *testing.T, sharedDatabase ...string) ownerPolicyFixture {
	t.Helper()
	f := setupOwnerPolicyNative441E2E(t, sharedDatabase...)
	f.s.EIDAS = eidas.New(f.q)
	f.s.Compliance = compliance.New(f.q, f.s.EIDAS)
	f.s.ComplianceFlagger = compliance.NewFlagger(f.q)
	item := compliance.FeedItem{ID: "policy-" + uuid.NewString(), Title: "Synthetic guidance", Topic: "agreement", PublishedAt: time.Now().UTC()}
	f.s.ComplianceFeed = ownerPolicyFeed{items: []compliance.FeedItem{item}}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Send: f.s.Send, EIDAS: f.s.EIDAS, Compliance: f.s.Compliance, PublicURL: f.s.PublicURL, Environment: f.s.Environment})
	rule, err := f.q.InsertEIDASRule(f.ctx, generated.InsertEIDASRuleParams{
		OrgID: f.org, Name: "Existing SES policy", Priority: 10, PredicateJson: json.RawMessage(`{"field":"country","op":"==","value":"SE"}`), RequiredTier: "SES", Reason: "Original policy reason", Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerPolicyPrepareRule441E2E(t, f, rule)
	flag, err := f.q.InsertComplianceFlag(f.ctx, generated.InsertComplianceFlagParams{
		OrgID: f.org, DocumentID: pgtype.UUID{Bytes: f.doc.ID, Valid: true}, UpdateRef: "existing-" + uuid.NewString(), UpdateTitle: "Existing review", AffectedTopic: "agreement", Severity: "review", SuggestedAction: "Review",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.q.UpsertComplianceBaseline(f.ctx, generated.UpsertComplianceBaselineParams{
		OrgID: f.org, BusinessType: "saas", Jurisdiction: "SE", RecordsDocID: pgtype.UUID{Bytes: f.doc.ID, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(), `DELETE FROM compliance_feed_items WHERE id=$1`, item.ID); err != nil { //nolint:rawsql -- fixture-owned feed record
			t.Error(err)
		}
	})
	return ownerPolicyFixture{f, rule, flag, item}
}

func (f ownerPolicyFixture) operation(name string) ownerOrgOperation {
	switch name {
	case "rule-create":
		return ownerOrgOperation{name, http.MethodPost, "/api/v1/eidas-rules", `{"name":"New SES policy","priority":20,"predicate_json":{"field":"country","op":"==","value":"SE"},"required_tier":"SES"}`, http.StatusCreated}
	case "rule-update":
		return ownerOrgOperation{name, http.MethodPatch, "/api/v1/eidas-rules/" + f.rule.ID.String(), `{"name":"Updated policy"}`, http.StatusOK}
	case "rule-delete":
		return ownerOrgOperation{name, http.MethodDelete, "/api/v1/eidas-rules/" + f.rule.ID.String(), "", http.StatusNoContent}
	case "baseline-seed":
		return ownerOrgOperation{name, http.MethodPost, "/api/v1/compliance/seed", `{"business_type":"consulting","jurisdiction":"SE"}`, http.StatusOK}
	case "flag-status":
		return ownerOrgOperation{name, http.MethodPatch, "/api/v1/compliance/flags/" + f.flag.ID.String(), `{"status":"resolved"}`, http.StatusOK}
	case "flag-run":
		return ownerOrgOperation{name, http.MethodPost, "/api/v1/compliance/flag-run", "", http.StatusOK}
	case "routing-tier":
		return ownerOrgOperation{name, http.MethodPatch, "/api/v1/documents/" + f.doc.ID.String() + "/routing-tier", `{"routing_tier":"SES"}`, http.StatusOK}
	case "seed-sweden":
		return ownerOrgOperation{name, http.MethodPost, "/api/v1/eidas-rules/seed-sweden", "", http.StatusConflict}
	default:
		panic("unknown policy test operation")
	}
}

func (f ownerPolicyFixture) snapshot(t *testing.T) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
 'rules',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM eidas_routing_rules r WHERE org_id=$1),
 'rule_measurements',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY rule_id),'[]'::jsonb) FROM eidas_rule_wire_sizes_v1 s WHERE org_id=$1),
 'baseline',(SELECT row_to_json(b) FROM compliance_baselines b WHERE org_id=$1),
 'flags',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY id),'[]'::jsonb) FROM compliance_flags c WHERE org_id=$1),
 'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
 'templates',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]'::jsonb) FROM templates t WHERE org_id=$1),
 'feed',(SELECT row_to_json(i) FROM compliance_feed_items i WHERE id=$2),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1))::text`, f.org, f.item.ID).Scan(&state); err != nil { //nolint:rawsql -- exact policy/artifact/audit rollback snapshot
		t.Fatal(err)
	}
	return state
}

func (f ownerPolicyFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before {
		t.Fatal("refused policy mutation changed rules, intrinsic measurements, baseline artifacts, flags, feed cache or audit")
	}
}

func (f ownerPolicyFixture) submit(ctx context.Context, name, cookie string) *httptest.ResponseRecorder {
	return submitOwnerOrgE2E(f.ownerOrgMutationFixture, ctx, f.operation(name), cookie)
}

func (f ownerPolicyFixture) submitMCP(ctx context.Context, name, key string) *httptest.ResponseRecorder {
	op := f.operation(name)
	var args map[string]any
	if op.body != "" {
		_ = json.Unmarshal([]byte(op.body), &args)
	} else {
		args = map[string]any{}
	}
	tool := ""
	switch name {
	case "rule-create":
		tool = "create_eidas_rule"
	case "rule-delete":
		tool, args["rule_id"] = "delete_eidas_rule", f.rule.ID
	case "baseline-seed":
		tool = "seed_compliance_baseline"
	case "flag-status":
		tool, args["flag_id"] = "set_compliance_flag_status", f.flag.ID
	case "routing-tier":
		tool, args["document_id"] = "set_document_routing_tier", f.doc.ID
	case "seed-sweden":
		tool = "seed_swedish_eidas_defaults"
	default:
		panic("unsupported policy MCP test operation")
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func TestOwnerPolicyRESTOriginalOwnerAndSessionAfterOrgWaitE2E(t *testing.T) {
	for _, name := range []string{"rule-create", "rule-update", "rule-delete", "baseline-seed", "flag-status", "flag-run"} {
		for _, change := range []string{"demotion", "logout", "expiry"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				f := setupOwnerPolicyE2E(t)
				blocked := ownerOrgLockE2E(t, f.ownerOrgMutationFixture, false)
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, ttl)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- f.submit(f.ctx, name, cookie) }()
				awaitOwnerPolicyOrgLock441E2E(t, f, name)
				var err error
				want := http.StatusForbidden
				switch change {
				case "demotion":
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"})
				case "logout":
					_, err = f.q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: 0})
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
					want = http.StatusUnauthorized
				}
				if err != nil {
					t.Fatal(err)
				}
				before := f.snapshot(t)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				w := receiveSessionOperationE2E(t, result)
				if w.Code != want {
					t.Fatalf("stale policy session=%d want%d %s", w.Code, want, w.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestOwnerPolicyMCPOriginalOwnerAndKeyAfterOrgWaitE2E(t *testing.T) {
	for _, name := range []string{"rule-create", "rule-delete", "baseline-seed", "flag-status"} {
		for _, change := range []string{"demotion", "key-revocation", "scope-reduction", "key-expiry"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				f := setupOwnerPolicyE2E(t)
				mint, keyID := mintOwnerBrandingKeyE2E(t, f.ownerOrgMutationFixture)
				blocked := ownerOrgLockE2E(t, f.ownerOrgMutationFixture, false)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- f.submitMCP(f.ctx, name, mint.Plaintext) }()
				awaitOwnerPolicyOrgLock441E2E(t, f, name)
				var err error
				want := auth.ErrMutationPermissionRevoked.Error()
				switch change {
				case "demotion":
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"})
				case "key-revocation":
					_, err = f.q.DeleteAPIKey(f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: f.user.ID})
				case "scope-reduction":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID) //nolint:rawsql -- synthetic original credential reduction
				case "key-expiry":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID) //nolint:rawsql
					want = auth.ErrMutationCredentialExpired.Error()
				}
				if err != nil {
					t.Fatal(err)
				}
				before := f.snapshot(t)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if text := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); text != want {
					t.Fatalf("stale policy key=%q want%q", text, want)
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestOwnerPolicyAuditFaultsRollbackAndValidOwnerSucceedsE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		names := []string{"rule-create", "rule-update", "rule-delete", "baseline-seed", "flag-status", "flag-run"}
		if transport == "mcp" {
			names = []string{"rule-create", "rule-delete", "baseline-seed", "flag-status"}
		}
		for _, name := range names {
			for _, noRow := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/no-row-%t", transport, name, noRow), func(t *testing.T) {
					f := setupOwnerPolicyE2E(t)
					mint, _ := mintOwnerBrandingKeyE2E(t, f.ownerOrgMutationFixture)
					cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Hour)
					submit := func() *httptest.ResponseRecorder {
						if transport == "mcp" {
							return f.submitMCP(f.ctx, name, mint.Plaintext)
						}
						return f.submit(f.ctx, name, cookie)
					}
					before := f.snapshot(t)
					drop := ownerOrgAuditFaultE2E(t, f.ownerOrgMutationFixture, noRow)
					w := submit()
					if transport == "mcp" {
						if got := fieldMCPTextE2E(t, w, true); got != "internal error" {
							t.Fatalf("audit failure misclassified=%q", got)
						}
					} else if w.Code != http.StatusInternalServerError {
						t.Fatalf("audit fault=%d %s", w.Code, w.Body.String())
					}
					f.assertUnchanged(t, before)
					drop()
					w = submit()
					if transport == "mcp" {
						fieldMCPTextE2E(t, w, false)
					} else if w.Code != f.operation(name).success {
						t.Fatalf("valid policy owner=%d %s", w.Code, w.Body.String())
					}
					var actor uuid.UUID
					var count int
					if err := f.pool.QueryRow(f.ctx, `SELECT count(*), min(actor_user_id::text)::uuid FROM events WHERE org_id=$1`, f.org).Scan(&count, &actor); err != nil || count != 1 || actor != f.user.ID { //nolint:rawsql
						t.Fatalf("committed policy audit count%d actor%s err%v", count, actor, err)
					}
					chain, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
					if err != nil {
						t.Fatal(err)
					}
					verifier := audit.NewChainVerifier()
					verifier.VerifyPage(chain)
					if got := verifier.Result(); !got.OK || !got.Complete || got.TotalChecked != 1 {
						t.Fatalf("policy audit chain=%+v", got)
					}
					assertOwnerPolicySuccessE2E(t, f, name)
				})
			}
		}
	}
}

func assertOwnerPolicySuccessE2E(t *testing.T, f ownerPolicyFixture, name string) {
	t.Helper()
	switch name {
	case "baseline-seed":
		baseline, err := f.q.GetComplianceBaseline(f.ctx, f.org)
		if err != nil || baseline.BusinessType != "consulting" || !baseline.DpaTemplateID.Valid || !baseline.PrivacyNoticeID.Valid || baseline.RecordsDocID.Bytes != f.doc.ID {
			t.Fatalf("baseline artifacts not committed: %+v %v", baseline, err)
		}
		var higher int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM eidas_routing_rules WHERE org_id=$1 AND active AND required_tier<>'SES'`, f.org).Scan(&higher); err != nil || higher != 0 { //nolint:rawsql
			t.Fatal("baseline seeded unavailable assurance tiers")
		}
	case "flag-status":
		var status string
		var resolved bool
		if err := f.pool.QueryRow(f.ctx, `SELECT status,resolved_at IS NOT NULL FROM compliance_flags WHERE id=$1`, f.flag.ID).Scan(&status, &resolved); err != nil || status != "resolved" || !resolved { //nolint:rawsql
			t.Fatal("flag resolution not committed")
		}
	case "flag-run":
		var count int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM compliance_flags WHERE org_id=$1 AND update_ref=$2`, f.org, f.item.ID).Scan(&count); err != nil || count != 1 { //nolint:rawsql
			t.Fatal("fresh tenant flag not committed")
		}
	case "rule-create":
		var count int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM eidas_routing_rules WHERE org_id=$1 AND name='New SES policy' AND active AND required_tier='SES'`, f.org).Scan(&count); err != nil || count != 1 { //nolint:rawsql
			t.Fatal("SES policy not committed")
		}
	case "rule-update":
		row, err := f.q.GetEIDASRule(f.ctx, generated.GetEIDASRuleParams{ID: f.rule.ID, OrgID: f.org})
		if err != nil || row.Name != "Updated policy" {
			t.Fatal("policy update not committed")
		}
	case "rule-delete":
		var count int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM eidas_routing_rules WHERE id=$1`, f.rule.ID).Scan(&count); err != nil || count != 0 { //nolint:rawsql
			t.Fatal("policy deletion not committed")
		}
	}
}

func awaitOwnerPolicyKeyExpiryE2E(t *testing.T, f ownerPolicyFixture, id uuid.UUID) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var expired bool
		if err := f.pool.QueryRow(f.ctx, `SELECT expires_at<=clock_timestamp() FROM api_keys WHERE id=$1`, id).Scan(&expired); err != nil { //nolint:rawsql -- observe actual database expiry while original key stays retained
			t.Fatal(err)
		}
		if expired {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("original policy API key did not expire")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOwnerPolicyFinalCredentialRecheckAfterAuditWaitE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		names := []string{"rule-create", "rule-update", "rule-delete", "baseline-seed", "flag-status", "flag-run"}
		if transport == "mcp" {
			names = []string{"rule-create", "rule-delete", "baseline-seed", "flag-status"}
		}
		for _, name := range names {
			for _, failure := range []string{"expiry", "cancellation"} {
				t.Run(transport+"/"+name+"/"+failure, func(t *testing.T) {
					f := setupOwnerPolicyE2E(t)
					mint, keyID := mintOwnerBrandingKeyE2E(t, f.ownerOrgMutationFixture)
					ttl := time.Hour
					if failure == "expiry" {
						ttl = time.Second
						if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil { //nolint:rawsql -- original key naturally expires behind audit wait
							t.Fatal(err)
						}
					}
					cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, ttl)
					before := f.snapshot(t)
					blocked := ownerOrgLockE2E(t, f.ownerOrgMutationFixture, true)
					ctx, cancel := context.WithCancel(f.ctx)
					defer cancel()
					result := make(chan *httptest.ResponseRecorder, 1)
					go func() {
						if transport == "mcp" {
							result <- f.submitMCP(ctx, name, mint.Plaintext)
						} else {
							result <- f.submit(ctx, name, cookie)
						}
					}()
					awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
					var w *httptest.ResponseRecorder
					if failure == "cancellation" {
						cancel()
						w = receiveSessionOperationE2E(t, result)
					} else if transport == "mcp" {
						awaitOwnerPolicyKeyExpiryE2E(t, f, keyID)
					} else {
						awaitSessionCookieExpiryE2E(t, f.s, cookie)
					}
					if err := blocked.Commit(f.ctx); err != nil {
						t.Fatal(err)
					}
					if w == nil {
						w = receiveSessionOperationE2E(t, result)
					}
					if transport == "mcp" {
						got := fieldMCPTextE2E(t, w, true)
						if failure == "expiry" && got != auth.ErrMutationCredentialExpired.Error() {
							t.Fatalf("expired retained policy key=%q", got)
						}
					} else {
						want := http.StatusInternalServerError
						if failure == "expiry" {
							want = http.StatusUnauthorized
						}
						if w.Code != want {
							t.Fatalf("final policy check=%d want%d %s", w.Code, want, w.Body.String())
						}
					}
					f.assertUnchanged(t, before)
				})
			}
		}
	}
}

func TestOwnerPolicyPatchUsesFreshDefaultsUnderOrgLockE2E(t *testing.T) {
	f := setupOwnerPolicyE2E(t)
	blocked := ownerOrgLockE2E(t, f.ownerOrgMutationFixture, true)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Hour)
	// A genuine complete PATCH owns the org fence, updates AND intrinsically
	// measures the new source, then waits at the existing audit lock.
	concurrent := f.operation("rule-update")
	concurrent.body = `{"name":"Concurrent fresh policy","priority":31,"predicate_json":{"field":"country","op":"==","value":"NO"},"required_tier":"QES","reason":"Fresh migration reason","active":false}`
	fresh := make(chan *httptest.ResponseRecorder, 1)
	go func() { fresh <- submitOwnerOrgE2E(f.ownerOrgMutationFixture, f.ctx, concurrent, cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- f.submit(f.ctx, "rule-update", cookie) }()
	awaitOwnerPolicyOrgLock441E2E(t, f, "rule-update")
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if w := receiveSessionOperationE2E(t, fresh); w.Code != http.StatusOK {
		t.Fatalf("genuine concurrent fresh policy PATCH=%d %s", w.Code, w.Body.String())
	}
	w := receiveSessionOperationE2E(t, result)
	if w.Code != http.StatusOK {
		t.Fatalf("fresh policy merge=%d %s", w.Code, w.Body.String())
	}
	row, err := f.q.GetEIDASRule(f.ctx, generated.GetEIDASRuleParams{ID: f.rule.ID, OrgID: f.org})
	if err != nil || row.Name != "Updated policy" || row.Priority != 31 || row.RequiredTier != "QES" || row.Active || row.Reason != "Fresh migration reason" || !strings.Contains(string(row.PredicateJson), "NO") {
		t.Fatalf("omitted policy fields used stale values: %+v %v", row, err)
	}
	var wire int64
	var current bool
	if err := f.pool.QueryRow(f.ctx, `SELECT s.predicate_wire_bytes,s.rule_created_at=r.created_at AND s.rule_updated_at=r.updated_at AND s.measurement_server_version_num=current_setting('server_version_num')::integer FROM eidas_rule_wire_sizes_v1 s JOIN eidas_routing_rules r ON r.id=s.rule_id WHERE s.rule_id=$1 AND s.org_id=$2`, f.rule.ID, f.org).Scan(&wire, &current); err != nil || !current || wire != int64(len(row.PredicateJson)) { //nolint:rawsql -- genuine concurrent producer kept exact intrinsic source stamps/bytes
		t.Fatal("fresh omitted-field merge lacks matching actual source measurement", wire, current, err)
	}
	// Unlike the old direct UPDATE fixture, both genuine PATCHes append audit.
	ownerPolicyAssertTwoPatchAudits441E2E(t, f)
	op := f.operation("rule-update")
	op.body = `{"active":true}`
	before := f.snapshot(t)
	if w := submitOwnerOrgE2E(f.ownerOrgMutationFixture, f.ctx, op, cookie); w.Code != http.StatusConflict {
		t.Fatalf("unavailable QES activated: %d %s", w.Code, w.Body.String())
	}
	f.assertUnchanged(t, before)
}

func TestOwnerPolicyCrossTenantTargetsAndSESRefusalsE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			f := setupOwnerPolicyE2E(t)
			other := setupOwnerPolicyE2E(t, f.pool.Config().ConnConfig.Database)
			var targetsPresent bool
			if err := f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM eidas_routing_rules WHERE id=$1 AND org_id=$2) AND EXISTS(SELECT 1 FROM compliance_flags WHERE id=$3 AND org_id=$2)`, other.rule.ID, other.org, other.flag.ID).Scan(&targetsPresent); err != nil || !targetsPresent { //nolint:rawsql -- foreign targets genuinely exist in the SAME owned database
				t.Fatal("cross-tenant policy fixture lacks actual foreign targets", targetsPresent, err)
			}
			foreign := f
			foreign.rule, foreign.flag = other.rule, other.flag
			mint, _ := mintOwnerBrandingKeyE2E(t, f.ownerOrgMutationFixture)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Hour)
			before, otherBefore := f.snapshot(t), other.snapshot(t)
			for _, name := range []string{"rule-update", "rule-delete", "flag-status"} {
				if transport == "mcp" {
					if name == "rule-update" {
						continue
					}
					got := fieldMCPTextE2E(t, foreign.submitMCP(f.ctx, name, mint.Plaintext), true)
					if got != "rule not found" && got != "flag not found" {
						t.Fatalf("foreign policy result=%q", got)
					}
				} else if w := foreign.submit(f.ctx, name, cookie); w.Code != http.StatusNotFound {
					t.Fatalf("foreign policy target=%d %s", w.Code, w.Body.String())
				}
			}
			if transport == "mcp" {
				if got := fieldMCPTextE2E(t, f.submitMCP(f.ctx, "seed-sweden", mint.Plaintext), true); !strings.Contains(got, "Swedish defaults are unavailable") {
					t.Fatalf("Swedish SES refusal=%q", got)
				}
			} else if w := f.submit(f.ctx, "seed-sweden", cookie); w.Code != http.StatusConflict {
				t.Fatalf("Swedish SES refusal=%d %s", w.Code, w.Body.String())
			}
			f.assertUnchanged(t, before)
			other.assertUnchanged(t, otherBefore)
		})
	}
}

func TestOwnerPolicyManualFeedWaitExpiryAndCancellationRollbackE2E(t *testing.T) {
	for _, failure := range []string{"expiry", "cancellation"} {
		t.Run(failure, func(t *testing.T) {
			f := setupOwnerPolicyE2E(t)
			entered, release := make(chan struct{}), make(chan struct{})
			f.s.ComplianceFeed = ownerPolicyFeed{items: []compliance.FeedItem{f.item}, entered: entered, release: release}
			ttl := time.Hour
			if failure == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, ttl)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			before := f.snapshot(t)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit(ctx, "flag-run", cookie) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("authorized policy refresh did not reach feed wait")
			}
			want := http.StatusInternalServerError
			if failure == "expiry" {
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				want = http.StatusUnauthorized
			} else {
				cancel()
			}
			close(release)
			if w := receiveSessionOperationE2E(t, result); w.Code != want {
				t.Fatalf("post-feed original policy credential=%d want%d %s", w.Code, want, w.Body.String())
			}
			f.assertUnchanged(t, before)
		})
	}
}
