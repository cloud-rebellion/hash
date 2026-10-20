//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type guardedAIProviderE2E struct {
	calls   atomic.Int32
	entered chan ai.Request
	release chan struct{}
}

func (*guardedAIProviderE2E) Name() string     { return "guarded-eu-fixture" }
func (*guardedAIProviderE2E) Model() string    { return "synthetic-model" }
func (*guardedAIProviderE2E) Endpoint() string { return "https://api.mistral.ai/v1" }
func (p *guardedAIProviderE2E) Complete(ctx context.Context, req ai.Request) (ai.Response, error) {
	p.calls.Add(1)
	p.entered <- req
	response := ai.Response{Provider: p.Name(), Model: p.Model(), InputTokens: 23, OutputTokens: 11, Text: "Reviewed AI suggestion\nRationale: fixture"}
	switch req.PromptName {
	case "risk_analyzer":
		response.Text = `[{"block_id":"agreement","category":"payment_terms","severity":"low","summary":"Review payment dates","suggestion":"Specify due date"}]`
	case "bilingual_equivalence":
		response.Text = `{"equivalent":true,"drift":[],"confidence":0.95}`
	}
	if p.release != nil {
		select {
		case <-p.release:
		case <-ctx.Done():
			return response, ctx.Err()
		}
	}
	return response, nil
}

type guardedAIAppsFixture struct {
	lifecycleAuthorizationFixture
	provider       *guardedAIProviderE2E
	nativeProvider ai.Provider // staff HTTP fixture only; legacy generic consumers keep provider
	proposalID     uuid.UUID
	baselineEvents map[uuid.UUID]string
	owned          *ownedPublicReadFixtureV1
}

func setupGuardedAIAppsMCPE2E(t *testing.T, sent, blocking bool) guardedAIAppsFixture {
	t.Helper()
	return setupGuardedAIAppsMCPWithOwned324E2E(t, sent, blocking, newOwnedAutomationAuthorizationFixtureV1(t))
}

// The actual allocation/tracer is fixed before pool/runtime/document birth.
// Existing default callers retain the exact original constructor and profile.
func setupGuardedAIAppsMCPWithOwned324E2E(t *testing.T, sent, blocking bool, owned *ownedPublicReadFixtureV1) guardedAIAppsFixture {
	t.Helper()
	if owned == nil {
		t.Fatal("actual owned fixture required")
	}
	f := setupNativeLifecycleAuthorizationWithFixture257d(t, "sender", sent, false, owned)
	provider := &guardedAIProviderE2E{entered: make(chan ai.Request, 16)}
	if blocking {
		provider.release = make(chan struct{})
	}
	shield, err := ai.NewLocalShield(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	runtime := ai.New(f.q, shield, nil, provider)
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, PublicURL: f.s.PublicURL,
		Clarifier: &aiapps.Clarifier{Runtime: runtime}, Negotiator: &aiapps.Negotiator{Runtime: runtime}, RiskAnalyzer: &aiapps.RiskAnalyzer{Runtime: runtime}, Bilingual: &aiapps.Bilingual{Runtime: runtime}, PDFCreationSessions: owned.runtime.SessionsV1()})
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	response := submitSessionOperationE2E(f.s, "POST", "/api/v1/documents/"+f.doc.ID.String()+"/proposals", `{"block_id":"agreement","proposal_kind":"counter","proposed_text":"Reviewed original proposal","rationale":"fixture"}`, cookie)
	var proposal struct{ ID uuid.UUID }
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &proposal) != nil || proposal.ID == uuid.Nil {
		t.Fatal("actual native authorization parent proposal", response.Code, response.Body.String())
	}
	f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return guardedAIAppsFixture{lifecycleAuthorizationFixture: f, provider: provider, proposalID: proposal.ID, baselineEvents: aiAppEventSnapshotE2E(t, f), owned: owned}
}

func completeGuardedAIAppsDocumentE2E(t *testing.T, f *guardedAIAppsFixture) {
	t.Helper()
	response := f.lifecycleAuthorizationFixture.submit("send", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
	var sent sendDocumentResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &sent) != nil || sent.Status != "sent" || len(sent.Links) != 1 || sent.Links[0].RecipientID != f.recipient.ID {
		t.Fatal("actual AI terminal-fixture Send failed", response.Code, response.Body.String())
	}
	link, err := url.Parse(sent.Links[0].URL)
	if err != nil || !strings.HasPrefix(link.Path, "/sign/") {
		t.Fatal("actual AI terminal-fixture invitation absent", err)
	}
	result, err := ordinaryPreparationSign249(t, f.owned, strings.TrimPrefix(link.Path, "/sign/"), sent.Links[0].Name)
	if err != nil || result == nil || !result.Completed {
		t.Fatal("actual AI terminal-fixture signing/report failed", err)
	}
	f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil || f.doc.Status != "completed" {
		t.Fatal("actual AI terminal-fixture completion absent", err)
	}
	f.owned.f = f.lifecycleAuthorizationFixture
}

// Real native source/proposal birth now has its own immutable audit history.
// Preserve every full original row while counting all later events, including
// unexpected non-AI events. Never delete history or filter only expected kinds.
func aiAppEventSnapshotE2E(t *testing.T, f lifecycleAuthorizationFixture) map[uuid.UUID]string {
	t.Helper()
	rows, err := f.pool.Query(f.ctx, `SELECT e.id,encode(sha256(convert_to(to_jsonb(e)::text,'UTF8')),'hex') FROM events e WHERE e.org_id=$1`, f.org)
	if err != nil {
		t.Fatal("read genuine AI fixture event baseline", err)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]string)
	for rows.Next() {
		var id uuid.UUID
		var digest string
		if err := rows.Scan(&id, &digest); err != nil {
			t.Fatal(err)
		}
		result[id] = digest
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertAISetupEventsUnchangedE2E(t *testing.T, f guardedAIAppsFixture) {
	t.Helper()
	current := aiAppEventSnapshotE2E(t, f.lifecycleAuthorizationFixture)
	for id, digest := range f.baselineEvents {
		if current[id] != digest {
			t.Fatal("AI action changed or removed original native setup event", id)
		}
	}
}
func (f guardedAIAppsFixture) args(tool string) map[string]any {
	switch tool {
	case "clarify_clause":
		return map[string]any{"document_id": f.doc.ID, "clause_text": "Liability for Lifecycle signer alice@example.com"}
	case "suggest_counter_clause":
		return map[string]any{"document_id": f.doc.ID, "block_id": "agreement", "concern": "Unclear payment date"}
	case "propose_counter_clause":
		return map[string]any{"document_id": f.doc.ID, "block_id": "agreement", "proposal_kind": "counter", "proposed_text": "Human reviewed proposed text", "parent_id": f.proposalID}
	case "set_proposal_status":
		return map[string]any{"proposal_id": f.proposalID, "status": "accepted"}
	case "run_risk_analysis":
		return map[string]any{"document_id": f.doc.ID}
	default:
		return map[string]any{"document_id": f.doc.ID, "clause_a": "Pay in thirty days", "clause_b": "Betala inom trettio dagar"}
	}
}
func (f guardedAIAppsFixture) submit(ctx context.Context, tool, key string) *httptest.ResponseRecorder {
	return submitAuthoringMCPE2E(f.lifecycleAuthorizationFixture, ctx, tool, key, f.args(tool))
}
func awaitAIProviderE2E(t *testing.T, p *guardedAIProviderE2E) ai.Request {
	t.Helper()
	select {
	case req := <-p.entered:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("guarded AI provider never entered")
		return ai.Request{}
	}
}
func waitAIKeyExpiryE2E(t *testing.T, f lifecycleAuthorizationFixture, keyID uuid.UUID) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for {
		var expired bool
		if err := f.pool.QueryRow(f.ctx, `SELECT expires_at<=clock_timestamp() FROM api_keys WHERE id=$1`, keyID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("AI key did not naturally expire")
		}
		time.Sleep(10 * time.Millisecond)
	} //nolint:rawsql
}
func aiAppAuditFaultE2E(t *testing.T, f guardedAIAppsFixture, kind string, noRow bool) func() {
	t.Helper()
	name := "hash_ai_fault_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	fail := "RAISE EXCEPTION 'fixture private AI upstream credential';"
	if noRow {
		fail = "RETURN NULL;"
	}
	if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='%s'::uuid AND NEW.kind='%s' THEN %s END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION %s()`, name, f.org, kind, fail, name, name)); err != nil {
		t.Fatal(err)
	} //nolint:rawsql,gosec -- generated identifiers, UUID org, fixed caller-controlled kind
	drop := func() {
		if _, err := f.pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON events; DROP FUNCTION IF EXISTS %s()`, name, name)); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(drop)
	return drop //nolint:rawsql,gosec
}

func TestAIAppsMCPOriginalAuthorityAfterDocumentWaitE2E(t *testing.T) {
	for _, tool := range []string{"clarify_clause", "suggest_counter_clause", "propose_counter_clause", "set_proposal_status", "run_risk_analysis", "check_bilingual_equivalence"} {
		for _, change := range []string{"key-delete", "scope-reduction", "demotion"} {
			t.Run(tool+"/"+change, func(t *testing.T) {
				f := setupStaffAIAppsHTTP300E2E(t, false, false)
				mint, keyID := mintAuthoringMCPE2E(t, f.lifecycleAuthorizationFixture)
				blocked := holdAuthoringDocumentMCPE2E(t, f.lifecycleAuthorizationFixture, f.doc.ID)
				result, cancel, joined := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return f.submit(ctx, tool, mint.Plaintext) })
				defer guardedAICleanup264(t, blocked, cancel, joined)
				query := "-- name: LockDocumentAIRootV1"
				if tool == "propose_counter_clause" || tool == "set_proposal_status" {
					query = "-- name: LockManualNegotiationRootV1"
				}
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, query, "transactionid")
				var err error
				switch change {
				case "key-delete":
					_, err = f.q.DeleteAPIKey(f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: f.user.ID})
				case "scope-reduction":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID) //nolint:rawsql
				default:
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
				}
				if err != nil {
					t.Fatal(err)
				}
				before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != auth.ErrMutationPermissionRevoked.Error() {
					t.Fatalf("original AI authority=%q", got)
				}
				if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
					t.Fatal("refused AI call mutated state or dispatched provider")
				}
			})
		}
	}
}

func TestAIAppsMCPProposalAuditRollbackAndActiveNegotiationE2E(t *testing.T) {
	for _, tool := range []string{"propose_counter_clause", "set_proposal_status"} {
		for _, sent := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/sent-%t", tool, sent), func(t *testing.T) {
				f := setupStaffAIAppsHTTP300E2E(t, sent, false)
				mint, _ := mintAuthoringMCPE2E(t, f.lifecycleAuthorizationFixture)
				before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
				kind := "negotiation.proposed"
				if tool == "set_proposal_status" {
					kind = "negotiation.status_changed"
				}
				drop := aiAppAuditFaultE2E(t, f, kind, true)
				if got := fieldMCPTextE2E(t, f.submit(f.ctx, tool, mint.Plaintext), true); got != "AI or negotiation operation failed" {
					t.Fatalf("audit no-row misclassified=%q", got)
				}
				drop()
				if authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
					t.Fatal("proposal audit failure changed state")
				}
				_ = fieldMCPTextE2E(t, f.submit(f.ctx, tool, mint.Plaintext), false)
				doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
				if err != nil {
					t.Fatal(err)
				}
				if string(doc.BlocksJson) != string(f.doc.BlocksJson) || string(doc.VariablesJson) != string(f.doc.VariablesJson) || doc.Status != f.doc.Status {
					t.Fatal("negotiation proposal changed frozen document source/status")
				}
				rows, err := f.q.ListProposalsByDocument(f.ctx, generated.ListProposalsByDocumentParams{DocumentID: f.doc.ID, Limit: 10})
				if err != nil {
					t.Fatal(err)
				}
				if tool == "propose_counter_clause" {
					if len(rows) != 2 || !rows[0].ParentID.Valid || uuid.UUID(rows[0].ParentID.Bytes) != f.proposalID {
						t.Fatal("proposal parent chain missing")
					}
				} else {
					if len(rows) != 1 || rows[0].Status != "accepted" {
						t.Fatal("proposal status missing")
					}
				}
				if f.provider.calls.Load() != 0 {
					t.Fatal("human reviewed proposal called AI provider")
				}
			})
		}
	}
}

func TestAIAppsMCPProviderExpiryRetainsTruthfulUsageAndRefusesResultE2E(t *testing.T) {
	for _, tool := range []string{"clarify_clause", "suggest_counter_clause", "run_risk_analysis", "check_bilingual_equivalence"} {
		t.Run(tool, func(t *testing.T) {
			f := setupStaffAIAppsHTTP300E2E(t, false, true)
			mint, keyID := mintAuthoringMCPE2E(t, f.lifecycleAuthorizationFixture)
			if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil {
				t.Fatal(err)
			} //nolint:rawsql
			result, cancel, joined := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return f.submit(ctx, tool, mint.Plaintext) })
			defer guardedAICleanup264(t, nil, cancel, joined)
			req := awaitAIProviderE2E(t, f.provider)
			if strings.Contains(req.User, "alice@example.com") || strings.Contains(req.User, "Lifecycle signer") {
				t.Fatal("retained adapter lost Shield or recipient PII context")
			}
			waitAIKeyExpiryE2E(t, f.lifecycleAuthorizationFixture, keyID)
			close(f.provider.release)
			w := receiveSessionOperationE2E(t, result)
			if got := fieldMCPTextE2E(t, w, true); got != auth.ErrMutationCredentialExpired.Error() {
				t.Fatalf("provider-wait expiry=%q", got)
			}
			if strings.Contains(w.Body.String(), "Reviewed AI suggestion") {
				t.Fatal("expired request disclosed result")
			}
			assertStaffAIHTTPReceiptCost300E2E(t, f, 2)
		})
	}
}
func assertAIReceiptCostE2E(t *testing.T, f guardedAIAppsFixture, eventCount int) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var in, out, count int
	var actor, doc uuid.UUID
	var provider, model string
	var active bool
	if err := f.pool.QueryRow(f.ctx, `SELECT a.id,a.input_tokens,a.output_tokens,a.actor_user_id,a.document_id,a.provider,a.model,a.shield_active FROM ai_completion_audit a JOIN events e ON e.id=a.id AND e.org_id=a.org_id AND e.document_id=a.document_id AND e.actor_user_id=a.actor_user_id AND e.kind='ai.requested' WHERE a.org_id=$1`, f.org).Scan(&id, &in, &out, &actor, &doc, &provider, &model, &active); err != nil || in != 23 || out != 11 || actor != f.user.ID || doc != f.doc.ID || provider != f.provider.Name() || model != f.provider.Model() || !active {
		t.Fatalf("truthful receipt-linked usage invalid: %s %d %d %v", id, in, out, err)
	} //nolint:rawsql
	assertAISetupEventsUnchangedE2E(t, f)
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1`, f.org).Scan(&count); err != nil || count-len(f.baselineEvents) != eventCount {
		t.Fatalf("AI request/cost/result event count=%d want%d err%v", count-len(f.baselineEvents), eventCount, err)
	} //nolint:rawsql
	return id
}

func TestAIAppsMCPRequiredRequestResultAuditAndSuccessfulProviderE2E(t *testing.T) {
	for _, tool := range []string{"clarify_clause", "suggest_counter_clause", "run_risk_analysis", "check_bilingual_equivalence"} {
		t.Run(tool, func(t *testing.T) {
			f := setupStaffAIAppsHTTP300E2E(t, false, false)
			mint, _ := mintAuthoringMCPE2E(t, f.lifecycleAuthorizationFixture)
			before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
			drop := aiAppAuditFaultE2E(t, f, "ai.requested", false)
			if got := fieldMCPTextE2E(t, f.submit(f.ctx, tool, mint.Plaintext), true); got != "AI or negotiation operation failed" {
				t.Fatal("request audit diagnostic disclosed", got)
			}
			drop()
			if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
				t.Fatal("provider dispatched without request audit")
			}
			resultKind := "ai.result_ready"
			if tool == "run_risk_analysis" {
				resultKind = "risk.analyzed"
			}
			drop = aiAppAuditFaultE2E(t, f, resultKind, true)
			if got := fieldMCPTextE2E(t, f.submit(f.ctx, tool, mint.Plaintext), true); got != "AI or negotiation operation failed" {
				t.Fatal("result audit no-row misclassified", got)
			}
			drop()
			assertStaffAIHTTPReceiptCost300E2E(t, f, 2)
			// A new request is dispatched rather than reusing an unscoped cached result.
			_ = fieldMCPTextE2E(t, f.submit(f.ctx, tool, mint.Plaintext), false)
			if f.provider.calls.Load() != 2 {
				t.Fatal("audited request incorrectly reused provider cost/cache")
			}
			var count int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM ai_completion_audit WHERE org_id=$1`, f.org).Scan(&count); err != nil || count != 2 {
				t.Fatal("second successful usage missing", err)
			} //nolint:rawsql
			assertAISetupEventsUnchangedE2E(t, f)
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1`, f.org).Scan(&count); err != nil || count-len(f.baselineEvents) != 5 {
				t.Fatal("successful AI request/result evidence missing", count-len(f.baselineEvents), err)
			} //nolint:rawsql
		})
	}
}

func TestAIAppsMCPReceiptScopeAndTerminalPrivacyGuardsE2E(t *testing.T) {
	f := setupStaffAIAppsHTTP300E2E(t, false, false)
	mint, _ := mintAuthoringMCPE2E(t, f.lifecycleAuthorizationFixture)
	_ = fieldMCPTextE2E(t, f.submit(f.ctx, "clarify_clause", mint.Plaintext), false)
	request := assertStaffAIHTTPReceiptCost300E2E(t, f, 3)
	other := setupStaffAIAppsHTTP300E2E(t, false, false)
	params := generated.InsertRequestedAICompletionAuditParams{RequestEventID: request, OrgID: f.org, DocumentID: f.doc.ID, ActorUserID: f.user.ID, Provider: "duplicate", Model: "duplicate", PromptName: "duplicate", Success: true, Error: "", TransferJurisdiction: "local"}
	before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
	for _, change := range []string{"duplicate", "foreign-org", "foreign-document", "foreign-actor", "missing"} {
		bad := params
		switch change {
		case "foreign-org":
			bad.OrgID = other.org
		case "foreign-document":
			bad.DocumentID = other.doc.ID
		case "foreign-actor":
			bad.ActorUserID = other.user.ID
		case "missing":
			bad.RequestEventID = uuid.New()
		}
		if _, err := f.q.InsertRequestedAICompletionAudit(f.ctx, bad); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("invalid AI receipt accepted", change, err)
		}
	}
	if authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
		t.Fatal("invalid receipt changed usage")
	}
	foreignBefore := authoringMCPStateE2E(t, other.lifecycleAuthorizationFixture)
	for _, tool := range []string{"clarify_clause", "suggest_counter_clause", "propose_counter_clause", "set_proposal_status", "run_risk_analysis", "check_bilingual_equivalence"} {
		_ = fieldMCPTextE2E(t, submitAuthoringMCPE2E(f.lifecycleAuthorizationFixture, f.ctx, tool, mint.Plaintext, other.args(tool)), true)
	}
	if f.provider.calls.Load() != 1 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before || authoringMCPStateE2E(t, other.lifecycleAuthorizationFixture) != foreignBefore {
		t.Fatal("cross tenant AI tool disclosed/dispatched/mutated")
	}
	for _, state := range []string{"sealing", "finalizing", "completed", "voided", "deleted", "privacy"} {
		t.Run(state, func(t *testing.T) {
			f := setupStaffAIAppsHTTP300E2E(t, state != "privacy" && state != "deleted" && state != "sealing" && state != "completed", false)
			mint, _ := mintAuthoringMCPE2E(t, f.lifecycleAuthorizationFixture)
			if state == "privacy" {
				if _, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, DocumentID: pgtype.UUID{Bytes: f.doc.ID, Valid: true}, SubjectEmail: "fixture@privacy.test", SubjectName: "Fixture", Kind: "erasure", RequestedVia: "sender", PayloadJson: []byte(`{}`)}); err != nil {
					t.Fatal(err)
				}
			} else if state == "deleted" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1`, f.doc.ID); err != nil {
					t.Fatal(err)
				}
			} else if state == "sealing" {
				seedCompleteFrozenBrandingHandlerE2E(t, f.ctx, f.pool, f.doc.ID)
				if _, err := f.q.CreateSendSealingIntent(f.ctx, generated.CreateSendSealingIntentParams{DocumentID: f.doc.ID, OrgID: f.org, ActorUserID: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ActorEmail: f.user.Email, ActorIp: "127.0.0.1", Via: "e2e", Tool: "AI-sealing-fixture"}); err != nil {
					t.Fatal(err)
				}
				if _, err := f.q.BeginDocumentSendSealing(f.ctx, generated.BeginDocumentSendSealingParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
			} else if state == "completed" {
				completeGuardedAIAppsDocumentE2E(t, &f)
			} else if state == "finalizing" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET status='in_progress' WHERE id=$1`, f.doc.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.q.BeginDocumentFinalization(f.ctx, generated.BeginDocumentFinalizationParams{ID: f.doc.ID, OrgID: f.org, RetentionYears: 7}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET status=$2 WHERE id=$1`, f.doc.ID, state); err != nil {
					t.Fatal(err)
				}
			} //nolint:rawsql -- actual completion or Send precedes the remaining synthetic refusal-only states
			before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
			for _, tool := range []string{"propose_counter_clause", "set_proposal_status", "clarify_clause", "run_risk_analysis"} {
				_ = fieldMCPTextE2E(t, f.submit(f.ctx, tool, mint.Plaintext), true)
			}
			if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
				t.Fatal("closed/privacy-held document used AI or changed negotiation")
			}
		})
	}
}

func TestAIAppsMCPProviderCancellationRetainsUsageE2E(t *testing.T) {
	f := setupStaffAIAppsHTTP300E2E(t, false, true)
	mint, _ := mintAuthoringMCPE2E(t, f.lifecycleAuthorizationFixture)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	result, requestCancel, joined := guardedAIAsync264(ctx, func(call context.Context) *httptest.ResponseRecorder {
		return f.submit(call, "clarify_clause", mint.Plaintext)
	})
	defer guardedAICleanup264(t, nil, requestCancel, joined)
	awaitAIProviderE2E(t, f.provider)
	cancel()
	w := receiveSessionOperationE2E(t, result)
	if fieldMCPTextE2E(t, w, true) != "AI or negotiation operation failed" {
		t.Fatal("cancelled AI request disclosed diagnostic")
	}
	// The actual HTTP response was not received before cancellation. Numeric
	// usage is therefore 0/0, unlike the old fake that returned 23/11 on error.
	usage := assertStaffAIHTTPNumericCost300E2E(t, f, 2, 0, 0)
	assertStaffAIHTTPFailedUsage300E2E(t, f, usage)
}

func TestAIAppsMCPDocumentTokenOneClaimAndProposalBindingE2E(t *testing.T) {
	f := setupStaffAIAppsHTTP300E2E(t, false, false)
	token, err := auth.MintDocumentAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	row, err := f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{DocumentID: f.doc.ID, OrgID: f.org, Name: "One-use scoped AI", Prefix: token.Prefix, KeyHash: token.Hash, Scopes: []string{"write:authoring"}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: 1, CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	_ = fieldMCPTextE2E(t, f.submit(f.ctx, "clarify_clause", token.Plaintext), false)
	var uses int
	if err := f.pool.QueryRow(f.ctx, `SELECT used_count FROM document_agent_tokens WHERE id=$1`, row.ID).Scan(&uses); err != nil || uses != 1 {
		t.Fatal("AI checks consumed scoped token again", uses, err)
	} //nolint:rawsql
	mint, _ := mintAuthoringMCPE2E(t, f.lifecycleAuthorizationFixture)
	args := f.args("propose_counter_clause")
	args["block_id"] = "missing"
	before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
	_ = fieldMCPTextE2E(t, submitAuthoringMCPE2E(f.lifecycleAuthorizationFixture, f.ctx, "propose_counter_clause", mint.Plaintext, args), true)
	otherDoc, err := guardedAISiblingNative264(t, f.lifecycleAuthorizationFixture, "Sibling proposal")
	if err != nil {
		t.Fatal(err)
	}
	args = f.args("propose_counter_clause")
	args["document_id"] = otherDoc.ID
	before = authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
	if got := fieldMCPTextE2E(t, submitAuthoringMCPE2E(f.lifecycleAuthorizationFixture, f.ctx, "propose_counter_clause", mint.Plaintext, args), true); got != "proposal not found in document" {
		t.Fatal("cross-document parent chain accepted", got)
	}
	if authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
		t.Fatal("invalid chain changed proposal/audit")
	}
	// Confirm responses remain serializable with the receipt-bound provider path.
	if !json.Valid(f.submit(f.ctx, "list_proposals", mint.Plaintext).Body.Bytes()) {
		t.Fatal("proposal list invalid JSON")
	}
}

func TestAIAppsMCPCostAuditFailureRetainsUsageAndSuppressesDiagnosticsE2E(t *testing.T) {
	f := setupStaffAIAppsHTTP300E2E(t, false, false)
	mint, _ := mintAuthoringMCPE2E(t, f.lifecycleAuthorizationFixture)
	drop := aiAppAuditFaultE2E(t, f, "ai.completed", false)
	capture := &webhookLogCapture{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(capture, nil)))
	defer slog.SetDefault(previous)
	w := f.submit(f.ctx, "clarify_clause", mint.Plaintext)
	if fieldMCPTextE2E(t, w, true) != "AI or negotiation operation failed" {
		t.Fatal("cost audit failure disclosed result")
	}
	drop()
	assertStaffAIHTTPReceiptCost300E2E(t, f, 1)
	for _, marker := range []string{"fixture private AI upstream credential", "SQLSTATE", "Reviewed AI suggestion"} {
		if strings.Contains(w.Body.String(), marker) || strings.Contains(capture.String(), marker) {
			t.Fatal("private AI diagnostic/result escaped response or logs", marker)
		}
	}
}

func TestAIAppsMCPUsageInsertFailureRefusesResultE2E(t *testing.T) {
	f := setupStaffAIAppsHTTP300E2E(t, false, false)
	mint, _ := mintAuthoringMCPE2E(t, f.lifecycleAuthorizationFixture)
	name := "hash_ai_usage_fault_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='%s'::uuid THEN RETURN NULL; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON ai_completion_audit FOR EACH ROW EXECUTE FUNCTION %s()`, name, f.org, name, name)); err != nil {
		t.Fatal(err)
	} //nolint:rawsql,gosec -- generated identifiers, UUID-only predicate
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON ai_completion_audit; DROP FUNCTION IF EXISTS %s()`, name, name)); err != nil {
			t.Error(err)
		}
	}) //nolint:rawsql,gosec
	w := f.submit(f.ctx, "clarify_clause", mint.Plaintext)
	if fieldMCPTextE2E(t, w, true) != "AI or negotiation operation failed" || strings.Contains(w.Body.String(), "Reviewed AI suggestion") {
		t.Fatal("missing usage evidence disclosed result")
	}
	var requests, costs int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events WHERE org_id=$1 AND kind='ai.requested'),(SELECT count(*) FROM ai_completion_audit WHERE org_id=$1)`, f.org).Scan(&requests, &costs); err != nil || requests != 1 || costs != 0 || f.provider.calls.Load() != 1 {
		t.Fatal("missing usage evidence lost request provenance", requests, costs, err)
	} //nolint:rawsql
}
