//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
)

const crmSourceDealE2E = "f26cuid2crmdeal"
const crmSourceTitleE2E = "Reviewed CRM agreement fixture"
const crmSourceValueE2E = "1290.2500"

type crmSourcePeerE2E struct {
	server     *httptest.Server
	accounts   atomic.Int64
	deals      atomic.Int64
	unexpected atomic.Int64
	mu         sync.Mutex
	deal       json.RawMessage
	next       *crmConnectionPauseE2E
}

func newCRMSourcePeerE2E(t *testing.T) *crmSourcePeerE2E {
	t.Helper()
	p := &crmSourcePeerE2E{}
	p.setDeal(t, crmSourceTitleE2E)
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+crmConnectionTokenE2E {
			p.unexpected.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/me":
			p.accounts.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": crmConnectionUserE2E, "team_id": crmConnectionTeamE2E, "is_active": true, "role": "ADMIN"})
		case "/api/v1/deals/" + crmSourceDealE2E:
			p.deals.Add(1)
			p.mu.Lock()
			body, pause := append([]byte(nil), p.deal...), p.next
			p.next = nil
			p.mu.Unlock()
			if pause != nil {
				close(pause.entered)
				select {
				case <-pause.release:
				case <-r.Context().Done():
					return
				}
			}
			_, _ = w.Write(body)
		default:
			p.unexpected.Add(1)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(func() {
		p.server.Close()
		if p.unexpected.Load() != 0 {
			t.Error("CRM source made an unexpected endpoint or credential request")
		}
	})
	return p
}

func (p *crmSourcePeerE2E) setDeal(t *testing.T, title string) {
	t.Helper()
	// The record body uses inspected BrightCRM native fields. Decimal text is
	// a JSON number rather than a fabricated amount/string alias. This is a
	// synthetic time-of-read provider response, not live-provider acceptance.
	body, err := json.Marshal(map[string]any{"id": crmSourceDealE2E, "team_id": crmConnectionTeamE2E,
		"updated_at": time.Now().UTC().Format(time.RFC3339Nano), "title": title, "value": json.Number(crmSourceValueE2E),
		"currency": "SEK", "stage": "negotiation", "company_id": nil, "contact_id": nil, "assigned_to_id": nil})
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.deal = body
	p.mu.Unlock()
}

func (p *crmSourcePeerE2E) pauseRecord(t *testing.T) *crmConnectionPauseE2E {
	t.Helper()
	paused := &crmConnectionPauseE2E{entered: make(chan struct{}), release: make(chan struct{})}
	p.mu.Lock()
	if p.next != nil {
		p.mu.Unlock()
		t.Fatal("another CRM record pause is pending")
	}
	p.next = paused
	p.mu.Unlock()
	t.Cleanup(paused.finish)
	return paused
}

type crmSourceFixtureE2E struct {
	crmConnectionFixtureE2E
	source *crmSourcePeerE2E
}

func setupCRMSourceAuthorizationE2E(t *testing.T) crmSourceFixtureE2E {
	t.Helper()
	f := setupCRMConnectionE2E(t)
	p := newCRMSourcePeerE2E(t)
	client, err := crmconnection.NewClient(p.server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	f.s.CRMOrigin, f.s.CRMClient = p.server.URL, client
	f.active(t) // Actual owner enrollment, confirmation, HTTP verification and resealing.
	for _, binding := range []struct{ name, path string }{{"customer", "title"}, {"amount", "value"}} {
		if _, err := f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{DocumentID: f.doc.ID,
			VariableName: binding.name, SourceKind: "crm.deal", SourceRef: crmSourceDealE2E, SourcePath: binding.path}); err != nil {
			t.Fatal(err)
		}
	}
	values, err := json.Marshal(map[string]string{"customer": crmSourceTitleE2E, "amount": crmSourceValueE2E})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.pool.Exec(f.ctx, `UPDATE documents SET variables_json=$3,updated_at=clock_timestamp() WHERE id=$1 AND org_id=$2 AND status='draft'`, f.doc.ID, f.org, values) //nolint:rawsql -- explicitly reviewed synthetic static draft, not an automatic CRM prose replacement
	if err != nil || rows.RowsAffected() != 1 {
		t.Fatal("could not seed the reviewed static agreement", err)
	}
	f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	r := resolver.New(f.q)
	r.CRM = &resolver.CRMRecords{Store: f.q, Client: client, Keys: f.s.CRMKeys, Origin: p.server.URL}
	f.s.Resolver, f.s.Send.Resolver = r, r
	return crmSourceFixtureE2E{f, p}
}

func (f crmSourceFixtureE2E) preview(ctx context.Context) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, f.s.PublicURL+"/api/v1/documents/"+f.doc.ID.String()+"/resolve-preview", nil).WithContext(ctx)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: f.cookie})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func (f crmSourceFixtureE2E) assertNoDocumentEffects(t *testing.T, before string) {
	t.Helper()
	if f.lifecycleAuthorizationFixture.snapshot(t) != before {
		t.Fatal("refused CRM source wrote document/binding observations, tokens, intent, audit, notice or outbox")
	}
}

func TestCRMSourceGroupedPreviewReadsOneRecordForTwoDeclaredValuesE2E(t *testing.T) {
	f := setupCRMSourceAuthorizationE2E(t)
	before, accounts, records := f.lifecycleAuthorizationFixture.snapshot(t), f.source.accounts.Load(), f.source.deals.Load()
	w := f.preview(f.ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("grouped actual CRM preview=%d", w.Code)
	}
	var answer struct {
		Variables map[string]string        `json:"variables"`
		Report    []resolver.ResolveReport `json:"report"`
		Frozen    bool                     `json:"frozen"`
	}
	if json.Unmarshal(w.Body.Bytes(), &answer) != nil || answer.Frozen || len(answer.Report) != 2 || answer.Variables["customer"] != crmSourceTitleE2E || answer.Variables["amount"] != crmSourceValueE2E {
		t.Fatal("grouped CRM preview lost exact decimal or native title")
	}
	first := answer.Report[0].CRMObservation
	second := answer.Report[1].CRMObservation
	if first == nil || second == nil || first.BodySHA256 != second.BodySHA256 || !first.ObservedAt.Equal(second.ObservedAt) || first.ConnectionID != second.ConnectionID || first.Generation != "2" || first.Origin != f.source.server.URL || second.Origin != f.source.server.URL || first.CRMTeamID != crmConnectionTeamE2E || first.CRMUserID != crmConnectionUserE2E {
		t.Fatal("two fields did not retain one exact account/record observation")
	}
	if strings.Contains(w.Body.String(), crmConnectionTokenE2E) || strings.Contains(w.Body.String(), `"title":`) || strings.Contains(w.Body.String(), `"updated_at":`) {
		t.Fatal("CRM preview exposed a credential or an unselected raw record body")
	}
	if f.source.accounts.Load() != accounts+2 || f.source.deals.Load() != records+1 {
		t.Fatal("grouped preview did not bracket one record fetch with the original account verification")
	}
	f.assertNoDocumentEffects(t, before)
}

func TestCRMSourcePreviewRejectsConnectionChangesDuringRecordReadE2E(t *testing.T) {
	for _, change := range []string{"revoked", "generation-replaced"} {
		t.Run(change, func(t *testing.T) {
			f := setupCRMSourceAuthorizationE2E(t)
			before := f.lifecycleAuthorizationFixture.snapshot(t)
			paused := f.source.pauseRecord(t)
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- f.preview(f.ctx) }()
			paused.await(t)
			method, body := http.MethodDelete, crmConnectionRevokeBodyE2E(2)
			if change == "generation-replaced" {
				method, body = http.MethodPut, crmConnectionPutBodyE2E(2)
			}
			assertCRMConnectionSafeResponseE2E(t, f.submit(f.ctx, method, "", body, f.cookie), http.StatusOK)
			paused.finish()
			w := receiveSessionOperationE2E(t, done)
			if w.Code != http.StatusConflict {
				t.Fatalf("preview adopted a obsolete connection observation: status=%d", w.Code)
			}
			f.assertNoDocumentEffects(t, before)
		})
	}
}

func TestCRMSourceSendRejectsRevocationBeforeFinalAdmissionE2E(t *testing.T) {
	for _, wait := range []string{"record", "document-lock"} {
		t.Run(wait, func(t *testing.T) {
			f := setupCRMSourceAuthorizationE2E(t)
			before := f.lifecycleAuthorizationFixture.snapshot(t)
			var release func()
			if wait == "record" {
				paused := f.source.pauseRecord(t)
				release = paused.finish
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- f.lifecycleAuthorizationFixture.submit("send", f.cookie) }()
				paused.await(t)
				assertCRMConnectionSafeResponseE2E(t, f.submit(f.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(2), f.cookie), http.StatusOK)
				release()
				if w := receiveSessionOperationE2E(t, done); w.Code != http.StatusServiceUnavailable {
					t.Fatalf("Send accepted revoked in-flight record: status=%d", w.Code)
				}
			} else {
				tx, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(context.Background()) }()
				if _, err := f.q.WithTx(tx).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- f.lifecycleAuthorizationFixture.submit("send", f.cookie) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
				assertCRMConnectionSafeResponseE2E(t, f.submit(f.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(2), f.cookie), http.StatusOK)
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if w := receiveSessionOperationE2E(t, done); w.Code != http.StatusServiceUnavailable {
					t.Fatalf("Send accepted revoked connection after parent lock wait: status=%d", w.Code)
				}
			}
			f.assertNoDocumentEffects(t, before)
		})
	}
}

func TestCRMSourceSendRequiresReviewWhenCurrentValueChangedE2E(t *testing.T) {
	f := setupCRMSourceAuthorizationE2E(t)
	f.source.setDeal(t, "New unreviewed CRM agreement title")
	before := f.lifecycleAuthorizationFixture.snapshot(t)
	w := f.lifecycleAuthorizationFixture.submit("send", f.cookie)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "review") {
		t.Fatalf("changed CRM value did not require draft review: status=%d", w.Code)
	}
	f.assertNoDocumentEffects(t, before)
}

func TestCRMSourceReviewedSendFreezesExactValuesAndAuditLineageE2E(t *testing.T) {
	f := setupCRMSourceAuthorizationE2E(t)
	accounts, records := f.source.accounts.Load(), f.source.deals.Load()
	w := f.lifecycleAuthorizationFixture.submit("send", f.cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("actual reviewed CRM send=%d", w.Code)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil || doc.Status != "sent" {
		t.Fatal("accepted reviewed send did not reach durable sent state", err)
	}
	var values map[string]string
	if json.Unmarshal(doc.VariablesJson, &values) != nil || values["customer"] != crmSourceTitleE2E || values["amount"] != crmSourceValueE2E || f.source.accounts.Load() != accounts+2 || f.source.deals.Load() != records+1 {
		t.Fatal("accepted send did not freeze the exact grouped original-account observation")
	}
	bindings, err := f.q.ListVariableBindings(f.ctx, f.doc.ID)
	if err != nil || len(bindings) != 2 {
		t.Fatal("reviewed CRM bindings were not retained", err)
	}
	for _, binding := range bindings {
		if binding.LastValue != values[binding.VariableName] || !binding.LastResolved.Valid || binding.LastError != "" {
			t.Fatal("durable binding observation differs from the frozen reviewed variable")
		}
	}
	var observed, sent, invited, outbox, intents, wrongActor int
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind='crm.variables.observed' AND payload_json->>'assurance'='time-of-read'),
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.sent'),
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind='recipient.invited'),
		(SELECT count(*) FROM email_deliveries WHERE to_email=$2),
		(SELECT count(*) FROM send_sealing_intents WHERE document_id=$1),
		(SELECT count(*) FROM events WHERE document_id=$1 AND actor_user_id IS DISTINCT FROM $3)`, f.doc.ID, f.recipient.Email, f.user.ID).Scan(&observed, &sent, &invited, &outbox, &intents, &wrongActor); err != nil { //nolint:rawsql -- exact synthetic completed send ledger, no mail consumed
		t.Fatal(err)
	}
	if observed != 1 || sent != 1 || invited != 1 || outbox != 1 || intents != 0 || wrongActor != 0 {
		t.Fatal("reviewed send did not preserve exact CRM audit/actor/invitation/intention lineage")
	}
	var payload []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT payload_json FROM events WHERE document_id=$1 AND kind='crm.variables.observed'`, f.doc.ID).Scan(&payload); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	var proof struct {
		Observations []struct {
			Variable     string    `json:"variable"`
			ConnectionID uuid.UUID `json:"connection_id"`
			Generation   string    `json:"generation"`
			SourceRef    string    `json:"source_ref"`
			Origin       string    `json:"origin"`
			CRMTeamID    string    `json:"crm_team_id"`
			CRMUserID    string    `json:"crm_user_id"`
			ValueSHA256  string    `json:"value_sha256"`
		} `json:"observations"`
	}
	row, err := f.q.GetCRMConnectionByOrg(f.ctx, f.org)
	if err != nil || json.Unmarshal(payload, &proof) != nil || len(proof.Observations) != 2 || strings.Contains(string(payload), crmConnectionTokenE2E) || strings.Contains(string(payload), crmSourceTitleE2E) || strings.Contains(string(payload), crmSourceValueE2E) || strings.Contains(string(payload), `"title":`) || strings.Contains(string(payload), `"updated_at":`) {
		t.Fatal("invalid or private CRM send provenance", err)
	}
	for _, item := range proof.Observations {
		sum := sha256.Sum256([]byte(values[item.Variable]))
		if item.ConnectionID != row.ID || item.Generation != "2" || item.Origin != f.source.server.URL || item.SourceRef != crmSourceDealE2E || item.CRMTeamID != crmConnectionTeamE2E || item.CRMUserID != crmConnectionUserE2E || item.ValueSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("CRM send provenance lost exact account, source or frozen scalar digest")
		}
	}
	events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	if result := verifier.Result(); !result.OK || !result.Complete || result.TotalChecked != len(events) {
		t.Fatal("CRM enrollment and send durable audit chain is invalid")
	}
	before := f.lifecycleAuthorizationFixture.snapshot(t)
	accounts, records = f.source.accounts.Load(), f.source.deals.Load()
	if w := f.preview(f.ctx); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"frozen":true`) {
		t.Fatal("sent CRM document did not retain a frozen readable preview")
	}
	if f.source.accounts.Load() != accounts || f.source.deals.Load() != records {
		t.Fatal("historical frozen preview fetched live CRM data")
	}
	f.assertNoDocumentEffects(t, before)
}

func TestCRMSourceSendHoldsConnectionThroughAuditIntentCommitE2E(t *testing.T) {
	f := setupCRMSourceAuthorizationE2E(t)
	blocked := ownerOrgLockE2E(t, ownerOrgMutationFixture{lifecycleAuthorizationFixture: f.lifecycleAuthorizationFixture}, true)
	admission := make(chan *httptest.ResponseRecorder, 1)
	go func() { admission <- f.lifecycleAuthorizationFixture.submit("send", f.cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	revocation := make(chan *httptest.ResponseRecorder, 1)
	go func() { revocation <- f.submit(f.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(2), f.cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: RevokeCRMConnection", "transactionid")
	select {
	case <-revocation:
		t.Fatal("credential revocation crossed the final retained connection SHARE lock")
	default:
	}
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	assertCRMConnectionSafeResponseE2E(t, receiveSessionOperationE2E(t, revocation), http.StatusOK)
	if w := receiveSessionOperationE2E(t, admission); w.Code != http.StatusOK {
		t.Fatalf("earlier exact retained observation could not finish its committed ceremony: status=%d", w.Code)
	}
	row, err := f.q.GetCRMConnectionByOrg(f.ctx, f.org)
	if err != nil || row.Status != "revoked" || row.Generation != 3 || row.CredentialCiphertext != nil {
		t.Fatal("later authorized connection revocation was not durable", err)
	}
	var retained int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind='crm.variables.observed' AND payload_json->'observations'->0->>'generation'='2'`, f.doc.ID).Scan(&retained); err != nil || retained != 1 { //nolint:rawsql -- earlier durable time-of-read proof remains historical after a later revocation
		t.Fatal("later revocation rewrote or erased the accepted earlier source proof", err)
	}
}

func TestCRMSourceSendRechecksObservationDeadlineAfterAuditWaitE2E(t *testing.T) {
	f := setupCRMSourceAuthorizationE2E(t)
	var elapsed atomic.Bool
	// Advance only the existing engine admission clock after the actual DB wait.
	// The HTTP provider observations and owner cookie remain real/current. This
	// proves the final deadline branch without a 45-second wall-clock load test.
	f.s.Send.Now = func() time.Time {
		now := time.Now()
		if elapsed.Load() {
			return now.Add(resolver.CRMObservationMaxAge + time.Second)
		}
		return now
	}
	before := f.lifecycleAuthorizationFixture.snapshot(t)
	blocked := ownerOrgLockE2E(t, ownerOrgMutationFixture{lifecycleAuthorizationFixture: f.lifecycleAuthorizationFixture}, true)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f.lifecycleAuthorizationFixture.submit("send", f.cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	elapsed.Store(true)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if w := receiveSessionOperationE2E(t, done); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expired source observation reached durable intent after audit wait: status=%d", w.Code)
	}
	f.assertNoDocumentEffects(t, before)
}
