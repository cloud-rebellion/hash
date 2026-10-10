//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/crmreview"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Actual middleware, protected account/record reads, PostgreSQL transactions,
// immutable source/history and exact-version S3 compensation are exercised.
// CRM, S3 and renderer peers are synthetic; this renderer records HTML and
// returns a valid fixed PDF. These cases do not prove rendered layout, live
// providers, malware-scanner operations, Object Lock, signing or legal approval.
type crmTemplateCreationFixtureE2E struct {
	lifecycleAuthorizationFixture
	template        *generated.Template
	renderer        *htmlCreationRendererE2E
	storage         *htmlCreationStorageE2E
	source          *crmSourcePeerE2E
	cookie          string
	storageBaseline int64
}

func setupCRMTemplateCreationE2E(t *testing.T) crmTemplateCreationFixtureE2E {
	t.Helper()
	renderer := &htmlCreationRendererE2E{}
	f, storage := setupHTMLDocumentCreationE2E(t, renderer)
	t.Setenv("HASH_ENVIRONMENT", "development")
	f.s.PublicURL = "http://localhost:39487"
	peer := newCRMSourcePeerE2E(t)
	client, err := crmconnection.NewClient(peer.server.URL, true)
	if err != nil {
		t.Fatal("configure protected synthetic CRM client")
	}
	keys, err := crmconnection.NewKeyring(crmConnectionKeyE2E, "")
	if err != nil {
		t.Fatal("configure synthetic CRM keyring")
	}
	f.s.CRMOrigin, f.s.CRMClient, f.s.CRMKeys = peer.server.URL, client, keys
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	enrollment := crmConnectionFixtureE2E{lifecycleAuthorizationFixture: f, cookie: cookie}
	enrollment.active(t)
	master := htmlmaster.Master{SchemaVersion: 1,
		HTML: `<p><span data-hash-value="customer"></span></p><p><span data-hash-value="amount"></span> <span data-hash-value="currency"></span></p><p><span data-hash-value="manual"></span></p><div data-hash-section="scope"></div>`,
		Values: []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 200}, {Name: "amount", Required: true, MaxChars: 200},
			{Name: "currency", MaxChars: 200}, {Name: "manual", Required: true, MaxChars: 200}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Approved reusable scope", MaxChars: 500}}}
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal("encode synthetic approved master")
	}
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "CRM initial population fixture", HTMLMasterJSON: raw,
		VariablesJSON: json.RawMessage(`{"customer":"Approved default AB","amount":"1000","manual":"Approved static value"}`)}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create initial-population template status=%d", w.Code)
	}
	var out templateResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.ID == uuid.Nil {
		t.Fatal("created template has no identity")
	}
	template, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: out.ID, OrgID: f.org})
	if err != nil {
		t.Fatal("read created template")
	}
	approveHTMLCreationTemplateE2E(t, f, template)
	return crmTemplateCreationFixtureE2E{lifecycleAuthorizationFixture: f, template: template, renderer: renderer, storage: storage, source: peer, cookie: cookie, storageBaseline: storage.requests.Load()}
}

func (f crmTemplateCreationFixtureE2E) request(t *testing.T, method, suffix, cookie string, input any) *httptest.ResponseRecorder {
	t.Helper()
	body := ""
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal("encode CRM template command")
		}
		body = string(raw)
	}
	w := submitSessionOperationE2E(f.s, method, "/api/v1/templates/"+f.template.ID.String()+"/html/crm/"+suffix, body, cookie)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("CRM template response is cacheable")
	}
	for _, private := range []string{crmConnectionTokenE2E, crmConnectionKeyE2E, "credential_ciphertext", "Bearer "} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("CRM template response leaked credentials")
		}
	}
	return w
}

func (f crmTemplateCreationFixtureE2E) witness(t *testing.T) CRMTemplateWitness {
	t.Helper()
	w := f.request(t, http.MethodGet, "context?expected_template_version="+strconv.Itoa(int(f.template.Version))+"&expected_template_content_sha256="+hex.EncodeToString(f.template.HtmlContentSha256), f.cookie, nil)
	var out struct {
		crmTemplateResponseWitness
		Available bool `json:"available"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Available || out.Connection == nil ||
		out.OrgID != f.org || out.UserID != f.user.ID || out.TemplateID != f.template.ID || out.Connection.Generation != "2" {
		t.Fatalf("current approved CRM template context status=%d", w.Code)
	}
	return CRMTemplateWitness{ExpectedOrgID: out.OrgID, ExpectedUserID: out.UserID, ExpectedTemplateVersion: out.TemplateVersion,
		ExpectedTemplateContentSHA256: out.TemplateContentSHA256, ExpectedTemplateApprovedBy: out.TemplateApprovedBy,
		ExpectedTemplateApprovedAt: out.TemplateApprovedAt, ExpectedConnectionID: out.Connection.ID.String(), ExpectedConnectionGeneration: out.Connection.Generation}
}

func crmTemplateCandidateE2E() CRMTemplateCandidate {
	return CRMTemplateCandidate{Name: "Initial CRM contract", Values: htmlStringMap{"customer": "Manual current customer", "amount": "1000", "manual": "Manually reviewed ÅÄÖ <clause>"},
		Sections: htmlStringMap{"scope": "Manually reviewed scope.\nRetain line two."}}
}

func crmTemplateMappingsE2E() []crmDocumentMapping {
	return []crmDocumentMapping{{Variable: "customer", SourceKind: "crm.deal", SourceRef: crmSourceDealE2E, SourcePath: "title"},
		{Variable: "amount", SourceKind: "crm.deal", SourceRef: crmSourceDealE2E, SourcePath: "value"},
		{Variable: "currency", SourceKind: "crm.deal", SourceRef: crmSourceDealE2E, SourcePath: "currency"}}
}

func (f crmTemplateCreationFixtureE2E) command(t *testing.T) (htmlDocumentInput, crmTemplateObservation) {
	t.Helper()
	return f.commandFor(t, crmTemplateCandidateE2E())
}

func (f crmTemplateCreationFixtureE2E) commandFor(t *testing.T, candidate CRMTemplateCandidate) (htmlDocumentInput, crmTemplateObservation) {
	t.Helper()
	witness := f.witness(t)
	w := f.request(t, http.MethodPost, "observations", f.cookie, CRMTemplateObservationRequest{CRMTemplateWitness: witness, Candidate: &candidate, Mappings: crmTemplateMappingsE2E()})
	var out crmTemplateObservation
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.CanCreate || out.ReviewReceipt == "" || !htmlPreviewSHA256(out.ReviewDigest) || len(out.Items) != 3 {
		t.Fatalf("fresh initial population observation status=%d", w.Code)
	}
	in := htmlCreationInputE2E(f.template)
	in.Name, in.Values, in.Sections, in.ExpiresAt, in.RequestID = candidate.Name, candidate.Values, candidate.Sections, candidate.ExpiresAt, uuid.New()
	in.CRMPopulation = &CRMTemplatePopulationInput{CRMTemplateWitness: witness, Mappings: crmTemplateMappingsE2E(), ReviewedDigest: out.ReviewDigest, ReviewReceipt: out.ReviewReceipt, Confirmed: true}
	return in, out
}

func (f crmTemplateCreationFixtureE2E) inventory(t *testing.T) string {
	t.Helper()
	var extra string
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'creation_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY actor_user_id,request_id),'[]'::jsonb) FROM html_document_creation_requests r WHERE org_id=$1),
		'materializations',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id),'[]'::jsonb) FROM html_document_materializations m WHERE org_id=$1),
		'snapshots',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM html_document_materialization_snapshots s WHERE org_id=$1),
		'reviews',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY document_id),'[]'::jsonb) FROM document_crm_mapping_reviews r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1))::text`, f.org).Scan(&extra) //nolint:rawsql -- full exact disposable tenant inventory; never emitted
	if err != nil {
		t.Fatal("read creation/evidence inventory")
	}
	return htmlTemplateSnapshotE2E(t, f.lifecycleAuthorizationFixture) + f.lifecycleAuthorizationFixture.snapshot(t) + extra
}

func (f crmTemplateCreationFixtureE2E) unchanged(t *testing.T, before string) {
	t.Helper()
	if before != f.inventory(t) {
		t.Fatal("refused/read-only command changed template, document, initial pins, source/history, mapping/review, audit or outbox")
	}
}

type crmTemplateCreationResponseE2E struct {
	OrgID          uuid.UUID         `json:"org_id"`
	UserID         uuid.UUID         `json:"user_id"`
	Document       *documentResponse `json:"document"`
	PageCount      int               `json:"page_count"`
	ReviewRequired bool              `json:"review_required"`
	Replayed       bool              `json:"replayed"`
	RequestID      uuid.UUID         `json:"request_id"`
	InputDigest    string            `json:"input_digest"`
	Creation       htmlCreationPins  `json:"creation"`
}

func decodeCRMTemplateCreationE2E(t *testing.T, w *httptest.ResponseRecorder, want int) crmTemplateCreationResponseE2E {
	t.Helper()
	var out crmTemplateCreationResponseE2E
	if w.Code != want || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.OrgID == uuid.Nil || out.UserID == uuid.Nil || out.RequestID == uuid.Nil || !htmlPreviewSHA256(out.InputDigest) || out.Creation.DocumentID == uuid.Nil || out.Creation.HTMLMaterializationID == uuid.Nil || out.Creation.PageCount != 1 {
		t.Fatalf("CRM creation/replay response status=%d want=%d", w.Code, want)
	}
	return out
}

func (f crmTemplateCreationFixtureE2E) recovery(t *testing.T, requestID uuid.UUID, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/templates/"+f.template.ID.String()+"/html/document-requests/"+requestID.String(), "", cookie)
	if w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), crmConnectionTokenE2E) {
		t.Fatal("creation readback is cacheable or leaked private material")
	}
	return w
}

func TestCRMTemplateDiscoveryHasNoCreationEffectsE2E(t *testing.T) {
	f := setupCRMTemplateCreationE2E(t)
	before := f.inventory(t)
	accounts, records := f.source.accounts.Load(), f.source.deals.Load()
	witness := f.witness(t)
	if f.source.accounts.Load() != accounts || f.source.deals.Load() != records {
		t.Fatal("template context fetched confidential provider data")
	}
	w := f.request(t, http.MethodPost, "records/search", f.cookie, struct {
		CRMTemplateWitness
		Kind   string `json:"kind"`
		Query  string `json:"query"`
		Offset int    `json:"offset"`
	}{witness, "crm.deal", "Reviewed", 0})
	var choices struct {
		Choices []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"choices"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &choices) != nil || len(choices.Choices) != 1 || choices.Choices[0].ID != crmSourceDealE2E || choices.Choices[0].Label != crmSourceTitleE2E {
		t.Fatalf("typed selected-record search status=%d", w.Code)
	}
	_, observation := f.command(t)
	if f.source.accounts.Load() != accounts+4 || f.source.deals.Load() != records+2 || len(observation.Items) != 3 ||
		observation.Items[0].CRMObservation == nil || observation.Items[0].CRMObservation.Origin != f.source.server.URL {
		t.Fatal("search and grouped observation did not use exact protected account reads")
	}
	f.unchanged(t, before)
	if len(f.renderer.sources()) != 0 || f.storage.requests.Load() != f.storageBaseline {
		t.Fatal("context/search/observation created a placeholder or invoked PDF/storage")
	}
	assertImportStorageE2E(t, f.storage.importStoragePeer, 0, 0, 0)
	if w := f.recovery(t, uuid.New(), f.cookie); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"state":"unconfirmed"`) {
		t.Fatal("unknown request readback falsely claimed a committed document")
	}
	f.unchanged(t, before)
}

func TestCRMTemplatePopulationCreationCommitsAtomicEvidenceE2E(t *testing.T) {
	f := setupCRMTemplateCreationE2E(t)
	in, observation := f.command(t)
	accounts, records := f.source.accounts.Load(), f.source.deals.Load()
	out := decodeCRMTemplateCreationE2E(t, submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie), http.StatusCreated)
	if out.Replayed || out.OrgID != f.org || out.UserID != f.user.ID || out.Document == nil || !out.ReviewRequired || out.Document.ID != out.Creation.DocumentID || out.RequestID != in.RequestID ||
		f.source.accounts.Load() != accounts+2 || f.source.deals.Load() != records+1 {
		t.Fatal("new CRM creation lost confirmation, fresh protected read or required exact PDF review")
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: out.Document.ID, OrgID: f.org})
	if err != nil || htmlsource.Validate(doc, false) != nil || !errors.Is(htmlsource.Validate(doc, true), htmlsource.ErrReviewRequired) {
		t.Fatal("created current source is invalid")
	}
	source, err := htmlsource.InputForCurrent(doc)
	if err != nil || source.Values["customer"] != crmSourceTitleE2E || source.Values["amount"] != crmSourceValueE2E || source.Values["currency"] != "SEK" ||
		source.Values["manual"] != in.Values["manual"] || !reflect.DeepEqual(source.Sections, map[string]string(in.Sections)) ||
		source.TemplateContentSHA256 != in.ExpectedTemplateContentSHA256 || source.TemplateApprovedBy != f.user.ID || !doc.ExpiresAt.Valid && in.ExpiresAt != "" {
		t.Fatal("initial source changed manual text/sections, lost exact decimal or approved design pins")
	}
	html := f.renderer.sources()
	if len(html) != 1 || !strings.Contains(html[0], crmSourceValueE2E) || !strings.Contains(html[0], "Manually reviewed ÅÄÖ &lt;clause&gt;") || !strings.Contains(html[0], "Retain line two.") {
		t.Fatal("prepared HTML did not contain the exact reviewed scalar overlay and preserved wording")
	}
	bindings, err := f.q.ListCRMMappingBindingsForShare(f.ctx, generated.ListCRMMappingBindingsForShareParams{DocumentID: doc.ID, OrgID: f.org})
	if err != nil || len(bindings) != 3 {
		t.Fatal("initial mappings did not commit atomically")
	}
	review, err := f.q.GetDocumentCRMMappingReview(f.ctx, generated.GetDocumentCRMMappingReviewParams{DocumentID: doc.ID, OrgID: f.org})
	connection, connErr := f.q.GetCRMConnectionByOrg(f.ctx, f.org)
	matched, matchErr := crmreview.ReviewMatches(doc, bindings, review, connection)
	if err != nil || connErr != nil || matchErr != nil || !matched || review.ReviewedBy != f.user.ID || review.ConnectionGeneration.Int64 != 2 || review.Origin != f.source.server.URL {
		t.Fatal("durable mapping review does not bind the admitted actor/account/content")
	}
	row, err := f.q.GetHTMLDocumentCreationRequest(f.ctx, generated.GetHTMLDocumentCreationRequestParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: in.RequestID})
	commitment, sourceErr := htmlsource.Commitment(doc)
	if err != nil || sourceErr != nil || htmlCreationRequestPins(row) != out.Creation || out.Creation.HTMLSourceCommitment != commitment || out.Creation.PDFSHA256 != hex.EncodeToString(doc.PdfSha256) || row.OriginalDocumentID != doc.ID {
		t.Fatal("recovery pins are not the exact committed initial artifact")
	}
	var payload []byte
	var created, versions, materializations, emails int
	if err := f.pool.QueryRow(f.ctx, `SELECT payload_json FROM events WHERE document_id=$1 AND kind='crm.template.population.created'`, doc.ID).Scan(&payload); err != nil { //nolint:rawsql -- exact synthetic audit evidence
		t.Fatal("missing initial population evidence")
	}
	var evidence struct {
		HumanConfirmed bool   `json:"human_confirmed"`
		Assurance      string `json:"assurance"`
		ReviewDigest   string `json:"review_digest"`
		Observations   []struct {
			Proof *resolver.CRMValueObservation `json:"proof"`
		} `json:"observations"`
	}
	if json.Unmarshal(payload, &evidence) != nil || !evidence.HumanConfirmed || evidence.Assurance != "time-of-read" || evidence.ReviewDigest != observation.ReviewDigest || len(evidence.Observations) != 3 {
		t.Fatal("population evidence omitted original confirmation or source provenance")
	}
	f.source.mu.Lock()
	providerSHA := sha256.Sum256(f.source.deal)
	f.source.mu.Unlock()
	for _, item := range evidence.Observations {
		if item.Proof == nil || item.Proof.Origin != f.source.server.URL || item.Proof.Generation != "2" || item.Proof.BodySHA256 != hex.EncodeToString(providerSHA[:]) || item.Proof.CRMTeamID != crmConnectionTeamE2E || item.Proof.CRMUserID != crmConnectionUserE2E {
			t.Fatal("persisted proof is not the fresh exact provider body/account")
		}
	}
	for _, private := range []string{in.CRMPopulation.ReviewReceipt, crmConnectionTokenE2E, in.Values["manual"], `"title":`, `"value":`} {
		if bytes.Contains(payload, []byte(private)) {
			t.Fatal("population audit retained opaque confirmation, credential, entered text or raw record")
		}
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.created'),
		(SELECT count(*) FROM document_versions WHERE document_id=$1),(SELECT count(*) FROM html_document_materializations WHERE document_id=$1),
		(SELECT count(*) FROM email_deliveries WHERE to_email IN(SELECT email FROM recipients WHERE document_id=$1))`, doc.ID).Scan(&created, &versions, &materializations, &emails); err != nil || created != 1 || versions != 1 || materializations != 1 || emails != 0 { //nolint:rawsql -- creation is atomic and cannot dispatch a ceremony
		t.Fatal("initial creation/version/audit/source cardinality or zero-dispatch invariant failed")
	}
	events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	if result := verifier.Result(); err != nil || !result.OK || !result.Complete || result.TotalChecked != len(events) {
		t.Fatal("committed creation/provenance chain is invalid")
	}
	assertImportStorageE2E(t, f.storage.importStoragePeer, 1, 0, 1)
}

func TestCRMTemplatePopulationCreationRefusesDriftE2E(t *testing.T) {
	for _, change := range []string{"provider_value", "template_revision", "original_actor", "connection_generation"} {
		t.Run(change, func(t *testing.T) {
			f := setupCRMTemplateCreationE2E(t)
			in, _ := f.command(t)
			cookie := f.cookie
			switch change {
			case "provider_value":
				f.source.setDeal(t, "Changed provider agreement")
			case "template_revision":
				w := submitHTMLTemplateE2E(t, f.lifecycleAuthorizationFixture, "update", f.template.ID, htmlTemplateInputE2E(t, f.template.Version, "New approved-design candidate"), f.cookie)
				if w.Code != http.StatusOK {
					t.Fatal("advance saved template revision")
				}
			case "original_actor":
				other := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
				user, err := f.q.GetUser(f.ctx, other)
				if err != nil {
					t.Fatal("read foreign original-actor fixture")
				}
				cookie = dsrSessionCookieE2E(t, f.s, other, user.SessionGeneration, time.Hour)
			case "connection_generation":
				owner := crmConnectionFixtureE2E{lifecycleAuthorizationFixture: f.lifecycleAuthorizationFixture, cookie: f.cookie}
				assertCRMConnectionSafeResponseE2E(t, owner.submit(f.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(2), f.cookie), http.StatusOK)
			}
			before := f.inventory(t)
			w := submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, cookie)
			want := http.StatusConflict
			if change == "original_actor" {
				want = http.StatusBadRequest
			}
			if w.Code != want {
				t.Fatalf("changed initial admission status=%d want=%d", w.Code, want)
			}
			f.unchanged(t, before)
			if len(f.renderer.sources()) != 0 || f.storage.requests.Load() != f.storageBaseline {
				t.Fatal("refused admission reached renderer/storage")
			}
			assertImportStorageE2E(t, f.storage.importStoragePeer, 0, 0, 0)
		})
	}
	for _, field := range []string{"expected_org", "expected_user"} {
		t.Run("manual_"+field, func(t *testing.T) {
			f := setupCRMTemplateCreationE2E(t)
			in := htmlCreationInputE2E(f.template)
			in.RequestID, in.ExpectedOrgID, in.ExpectedUserID = uuid.New(), f.org, f.user.ID
			if field == "expected_org" {
				in.ExpectedOrgID = uuid.New()
			} else {
				in.ExpectedUserID = uuid.New()
			}
			before := f.inventory(t)
			accounts, records := f.source.accounts.Load(), f.source.deals.Load()
			if w := submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie); w.Code != http.StatusConflict {
				t.Fatalf("manual original-actor witness status=%d want409", w.Code)
			}
			f.unchanged(t, before)
			if len(f.renderer.sources()) != 0 || f.storage.requests.Load() != f.storageBaseline || f.source.accounts.Load() != accounts || f.source.deals.Load() != records {
				t.Fatal("manual actor mismatch reached provider/render/storage")
			}
		})
	}
}

func (f crmTemplateCreationFixtureE2E) admission(t *testing.T, in htmlDocumentInput) (authoring.Actor, *crmTemplatePopulationAdmission) {
	t.Helper()
	ctx := context.WithValue(f.ctx, auth.UserIDKey, f.user.ID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, f.org)
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	r := httptest.NewRequest(http.MethodPost, "/synthetic-initial-create", nil).WithContext(ctx)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: f.cookie})
	authorize, err := f.s.sessionDraftAuthorization(r, f.org, f.user.ID)
	if err != nil {
		t.Fatal("admit original signed session")
	}
	actor := authoring.Actor{OrgID: f.org, UserID: f.user.ID, Authorize: authorize}
	admission, err := f.s.prepareCRMTemplatePopulation(f.ctx, r, actor, f.template.ID, in)
	if err != nil {
		t.Fatal("prepare protected initial admission")
	}
	return actor, admission
}

func TestCRMTemplatePopulationCreationRechecksRendererAndAuditWaitsE2E(t *testing.T) {
	for _, change := range []string{"member_demotion", "connection_revocation", "template_revision"} {
		t.Run("renderer_"+change, func(t *testing.T) {
			f := setupCRMTemplateCreationE2E(t)
			in, _ := f.command(t)
			release := make(chan struct{})
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			t.Cleanup(finish)
			f.renderer.entered, f.renderer.release = make(chan struct{}, 1), release
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie)
			}()
			select {
			case <-f.renderer.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("creation did not reach renderer wait")
			}
			// These writes must finish while rendering is blocked: the prepared
			// read transaction may not retain member/account/template locks.
			ctx, cancel := context.WithTimeout(f.ctx, time.Second)
			defer cancel()
			switch change {
			case "member_demotion":
				if _, err := f.q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
					t.Fatal("member mutation blocked behind renderer")
				}
			case "connection_revocation":
				if _, err := f.pool.Exec(ctx, `UPDATE crm_connections SET status='revoked',generation=generation+1,credential_ciphertext=NULL WHERE org_id=$1 AND generation=2`, f.org); err != nil {
					t.Fatal("connection mutation blocked behind renderer")
				} //nolint:rawsql -- exact scoped synthetic owner revocation
			case "template_revision":
				if _, err := f.pool.Exec(ctx, `UPDATE templates SET version=version+1 WHERE id=$1 AND org_id=$2`, f.template.ID, f.org); err != nil {
					t.Fatal("template mutation blocked behind renderer")
				} //nolint:rawsql -- exact scoped saved-version drift during external work
			}
			before := f.inventory(t)
			finish()
			want := http.StatusConflict
			if change == "member_demotion" {
				want = http.StatusForbidden
			}
			if w := receiveSessionOperationE2E(t, done); w.Code != want {
				t.Fatalf("renderer drift status=%d want=%d", w.Code, want)
			}
			f.unchanged(t, before)
			assertImportStorageE2E(t, f.storage.importStoragePeer, 0, 0, 0)
		})
	}
	for _, failureMode := range []string{"exception", "no_row"} {
		t.Run("audit_"+failureMode+"_exact_owned_cleanup", func(t *testing.T) {
			f := setupCRMTemplateCreationE2E(t)
			in, _ := f.command(t)
			function := "crm_initial_fail_" + strings.ReplaceAll(f.org.String(), "-", "")
			action := "RAISE EXCEPTION 'synthetic initial audit failure';"
			if failureMode == "no_row" {
				action = "RETURN NULL;"
			}
			if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION "%s"() RETURNS trigger LANGUAGE plpgsql AS $body$ BEGIN IF NEW.org_id='%s'::uuid AND NEW.kind='document.created' THEN %s END IF; RETURN NEW; END $body$`, function, f.org, action)); err != nil {
				t.Fatal("install scoped synthetic audit failure")
			} //nolint:rawsql,gosec -- generated UUID-only SQL names/literals in a disposable DB
			if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE TRIGGER "%s" BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION "%s"()`, function, function)); err != nil {
				t.Fatal("install scoped synthetic audit trigger")
			} //nolint:rawsql,gosec
			before := f.inventory(t)
			if w := submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie); w.Code != http.StatusInternalServerError {
				t.Fatalf("audit failure status=%d want500", w.Code)
			}
			f.unchanged(t, before)
			assertImportStorageE2E(t, f.storage.importStoragePeer, 1, 1, 0)
		})
	}
	t.Run("deadline_after_real_audit_lock", func(t *testing.T) {
		f := setupCRMTemplateCreationE2E(t)
		in, _ := f.command(t)
		actor, admission := f.admission(t, in)
		var elapsed atomic.Bool
		admission.now = func() time.Time {
			now := time.Now()
			if elapsed.Load() {
				return now.Add(resolver.CRMObservationMaxAge + time.Second)
			}
			return now
		}
		before := f.inventory(t)
		blocked := ownerOrgLockE2E(t, ownerOrgMutationFixture{lifecycleAuthorizationFixture: f.lifecycleAuthorizationFixture}, true)
		digest, _ := hex.DecodeString(in.ExpectedTemplateContentSHA256)
		inputDigest, err := crmTemplateCreateInputDigest(actor, f.template.ID, in)
		if err != nil {
			t.Fatal("commit canonical original command")
		}
		done := make(chan error, 1)
		go func() {
			_, err := f.s.instantiateHTMLDocument(f.ctx, actor, f.template.ID, in, digest, generated.Document{}.ExpiresAt, admission, inputDigest)
			done <- err
		}()
		awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
		elapsed.Store(true)
		if err := blocked.Commit(f.ctx); err != nil {
			t.Fatal("release actual audit lock")
		}
		select {
		case err := <-done:
			if !errors.Is(err, errCRMTemplateChanged) {
				t.Fatal("expired original/fresh observation crossed final audit deadline")
			}
		case <-time.After(4 * time.Second):
			t.Fatal("deadline refusal did not complete")
		}
		f.unchanged(t, before)
		assertImportStorageE2E(t, f.storage.importStoragePeer, 1, 1, 0)
	})
}

func TestCRMTemplateCreationRequestReplayAndTombstoneE2E(t *testing.T) {
	f := setupCRMTemplateCreationE2E(t)
	candidate := crmTemplateCandidateE2E()
	candidate.ExpiresAt = time.Now().UTC().Add(5 * time.Second).Format(time.RFC3339)
	in, _ := f.commandFor(t, candidate)
	out := decodeCRMTemplateCreationE2E(t, submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie), http.StatusCreated)
	if out.Document == nil || out.OrgID != f.org || out.UserID != f.user.ID {
		t.Fatal("fresh committed creation has no document")
	}
	other := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
	user, err := f.q.GetUser(f.ctx, other)
	if err != nil {
		t.Fatal("read other authenticated owner")
	}
	foreignCookie := dsrSessionCookieE2E(t, f.s, other, user.SessionGeneration, time.Hour)
	if w := f.recovery(t, in.RequestID, foreignCookie); w.Code != http.StatusNotFound {
		t.Fatal("owner could inspect another original actor's request")
	}
	w := f.recovery(t, in.RequestID, f.cookie)
	var readback struct {
		OrgID    uuid.UUID         `json:"org_id"`
		UserID   uuid.UUID         `json:"user_id"`
		State    string            `json:"state"`
		Document *documentResponse `json:"document"`
		Creation htmlCreationPins  `json:"creation"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &readback) != nil || readback.OrgID != f.org || readback.UserID != f.user.ID || readback.State != "committed" || readback.Document == nil || readback.Creation != out.Creation {
		t.Fatal("original actor cannot inspect immutable committed pins")
	}
	if w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/templates/"+f.template.ID.String()+"/html/document-requests/"+in.RequestID.String(), "", "invalid-synthetic-session"); w.Code != http.StatusUnauthorized {
		t.Fatal("committed readback bypassed live authentication")
	}
	// Produce a genuinely expired purpose token with the same semantic command.
	// Recovery must not verify it or fetch/render/store anything anew.
	raw, err := f.s.Cookies.VerifyPurpose(crmTemplateReceiptPurpose, in.CRMPopulation.ReviewReceipt)
	if err != nil {
		t.Fatal("read synthetic purpose receipt")
	}
	var old crmTemplateReceipt
	if json.Unmarshal(raw, &old) != nil {
		t.Fatal("decode synthetic receipt")
	}
	old.ObservedAt, old.IssuedAt = time.Now().Add(-2*resolver.CRMObservationMaxAge), time.Now().Add(-2*resolver.CRMObservationMaxAge)
	old.ExpiresAt = old.ObservedAt.Add(resolver.CRMObservationMaxAge)
	raw, _ = json.Marshal(old)
	in.CRMPopulation.ReviewReceipt, err = f.s.Cookies.MintPurpose(crmTemplateReceiptPurpose, raw, time.Nanosecond)
	_, transportErr := f.s.Cookies.VerifyPurpose(crmTemplateReceiptPurpose, in.CRMPopulation.ReviewReceipt)
	if err != nil || transportErr == nil || old.validate(time.Now()) == nil {
		t.Fatal("expired confirmation fixture is not actually expired")
	}
	if w := submitHTMLTemplateE2E(t, f.lifecycleAuthorizationFixture, "update", f.template.ID, htmlTemplateInputE2E(t, f.template.Version, "Later current design"), f.cookie); w.Code != http.StatusOK {
		t.Fatal("advance current template after committed creation")
	}
	owner := crmConnectionFixtureE2E{lifecycleAuthorizationFixture: f.lifecycleAuthorizationFixture, cookie: f.cookie}
	assertCRMConnectionSafeResponseE2E(t, owner.submit(f.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(2), f.cookie), http.StatusOK)
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET name='Current edited document' WHERE id=$1 AND org_id=$2`, out.Document.ID, f.org); err != nil {
		t.Fatal("edit current document metadata")
	} //nolint:rawsql -- current-view witness after creation pins were committed
	f.s.CRMClient, f.s.CRMKeys, f.s.Sign.PDF = nil, nil, nil
	expires, err := time.Parse(time.RFC3339, in.ExpiresAt)
	if err != nil {
		t.Fatal("parse original document expiry")
	}
	for time.Now().Before(expires) {
		time.Sleep(10 * time.Millisecond)
	}
	before := f.inventory(t)
	accounts, records, storeRequests := f.source.accounts.Load(), f.source.deals.Load(), f.storage.requests.Load()
	replay := decodeCRMTemplateCreationE2E(t, submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie), http.StatusOK)
	if !replay.Replayed || replay.Document == nil || replay.Document.Name != "Current edited document" || replay.InputDigest != out.InputDigest || replay.Creation != out.Creation {
		t.Fatal("exact replay did not return current document and original creation pins")
	}
	changed := in
	changed.Name += " changed semantic command"
	if w := submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, changed, f.cookie); w.Code != http.StatusConflict {
		t.Fatal("same request UUID accepted a different semantic command")
	}
	f.unchanged(t, before)
	if f.source.accounts.Load() != accounts || f.source.deals.Load() != records || f.storage.requests.Load() != storeRequests || len(f.renderer.sources()) != 1 {
		t.Fatal("committed replay or conflict performed provider/render/storage work")
	}
	if err := f.q.DeleteDraftDocument(f.ctx, generated.DeleteDraftDocumentParams{ID: out.Document.ID, OrgID: f.org}); err != nil {
		t.Fatal("soft-delete original document")
	}
	before = f.inventory(t)
	tombstone := decodeCRMTemplateCreationE2E(t, submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie), http.StatusOK)
	if !tombstone.Replayed || tombstone.OrgID != f.org || tombstone.UserID != f.user.ID || tombstone.Document != nil || tombstone.Creation != out.Creation {
		t.Fatal("soft-deleted committed request recreated or adopted a different document")
	}
	w = f.recovery(t, in.RequestID, f.cookie)
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &readback) != nil || readback.OrgID != f.org || readback.UserID != f.user.ID || readback.Document != nil || readback.Creation != out.Creation {
		t.Fatal("soft-deleted request lost its committed tombstone")
	}
	f.unchanged(t, before)
	if f.storage.requests.Load() != storeRequests || f.source.accounts.Load() != accounts || f.source.deals.Load() != records {
		t.Fatal("tombstone recovery touched provider/storage")
	}
	assertImportStorageE2E(t, f.storage.importStoragePeer, 1, 0, 1)
}

func TestCRMTemplateCreationConcurrentRequestAndDatabaseGuardsE2E(t *testing.T) {
	f := setupCRMTemplateCreationE2E(t)
	in, _ := f.command(t)
	// One HTTP process deliberately admits only one import per organization.
	// Two independently prepared private admissions represent already admitted
	// jobs in separate process-local gates. The real final quota transaction,
	// original signed-session checks and compensator remain unchanged.
	actor, firstAdmission := f.admission(t, in)
	secondActor, secondAdmission := f.admission(t, in)
	digest, _ := hex.DecodeString(in.ExpectedTemplateContentSHA256)
	inputDigest, err := crmTemplateCreateInputDigest(actor, f.template.ID, in)
	if err != nil {
		t.Fatal("commit canonical concurrent command")
	}
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	f.renderer.entered, f.renderer.release = make(chan struct{}, 2), release
	type completed struct {
		result *htmlCreationOutcome
		err    error
	}
	done := make(chan completed, 2)
	for _, job := range []struct {
		actor     authoring.Actor
		admission *crmTemplatePopulationAdmission
	}{{actor, firstAdmission}, {secondActor, secondAdmission}} {
		go func() {
			result, err := f.s.instantiateHTMLDocument(f.ctx, job.actor, f.template.ID, in, digest, generated.Document{}.ExpiresAt, job.admission, inputDigest)
			done <- completed{result, err}
		}()
	}
	for range 2 {
		select {
		case <-f.renderer.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("both same-UUID requests did not prepare before final commit")
		}
	}
	finish()
	receive := func() *htmlCreationOutcome {
		select {
		case out := <-done:
			if out.err != nil || out.result == nil {
				t.Fatal("concurrent prepared creation did not finish")
			}
			return out.result
		case <-time.After(4 * time.Second):
			t.Fatal("concurrent prepared creation timed out")
			return nil
		}
	}
	a, b := receive(), receive()
	if a.replayed {
		a, b = b, a
	}
	response := func(result *htmlCreationOutcome, status int) crmTemplateCreationResponseE2E {
		w := httptest.NewRecorder()
		writeJSON(w, status, result.response())
		return decodeCRMTemplateCreationE2E(t, w, status)
	}
	fresh, replay := response(a, http.StatusCreated), response(b, http.StatusOK)
	if fresh.Replayed || !replay.Replayed || fresh.Document == nil || replay.Document == nil || fresh.Document.ID != replay.Document.ID || fresh.Creation != replay.Creation || fresh.InputDigest != replay.InputDigest {
		t.Fatal("concurrent request UUID created two committed documents")
	}
	var requests, created, populations int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM html_document_creation_requests WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3),
		(SELECT count(*) FROM events WHERE document_id=$4 AND kind='document.created'),(SELECT count(*) FROM events WHERE document_id=$4 AND kind='crm.template.population.created')`, f.org, f.user.ID, in.RequestID, fresh.Document.ID).Scan(&requests, &created, &populations); err != nil || requests != 1 || created != 1 || populations != 1 {
		t.Fatal("concurrent preparation duplicated creation or audit evidence")
	} //nolint:rawsql -- exact committed command cardinality
	assertImportStorageE2E(t, f.storage.importStoragePeer, 2, 1, 1)
	before := f.inventory(t)
	for _, mutation := range []struct{ name, sql string }{
		{"pin_rewrite", `UPDATE html_document_creation_requests SET html_source_commitment=repeat('0',64) WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3`},
		{"detach_live_document", `UPDATE html_document_creation_requests SET current_document_id=NULL WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3`},
		{"delete_replay_protection", `DELETE FROM html_document_creation_requests WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3`},
		{"forged_initial_pins", `INSERT INTO html_document_creation_requests(org_id,actor_user_id,request_id,input_digest,template_id,original_document_id,current_document_id,html_materialization_id,html_source_commitment,pdf_sha256,page_count) SELECT org_id,actor_user_id,gen_random_uuid(),input_digest,template_id,original_document_id,current_document_id,html_materialization_id,html_source_commitment,pdf_sha256,2 FROM html_document_creation_requests WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			_, err := f.pool.Exec(f.ctx, mutation.sql, f.org, f.user.ID, in.RequestID) //nolint:rawsql -- deliberately refused exact-row corruption
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
				t.Fatal("durable creation pin mutation was not refused with23514")
			}
			f.unchanged(t, before)
		})
	}
	t.Run("retained_down_refusal", func(t *testing.T) {
		raw, err := os.ReadFile("../db/migrations/00079_html_document_creation_requests.sql")
		if err != nil {
			t.Fatal("read current migration79")
		}
		parts := strings.SplitN(string(raw), "-- +goose Down", 2)
		if len(parts) != 2 {
			t.Fatal("missing migration79 Down")
		}
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal("begin isolated Down refusal")
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		_, err = tx.Exec(f.ctx, parts[1])
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "P0001" {
			t.Fatal("retained request history did not reach explicit destructive Down refusal")
		}
		if err := tx.Rollback(f.ctx); err != nil {
			t.Fatal("rollback failed Down")
		}
		f.unchanged(t, before)
	})
}
