//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
)

type crmDocumentContextE2E struct {
	crmDocumentResponseWitness
	Supported             bool         `json:"supported"`
	MappingReviewRequired bool         `json:"mapping_review_required"`
	Bindings              []bindingDTO `json:"bindings"`
}

func crmDocumentRequestE2E(t *testing.T, f lifecycleAuthorizationFixture, ctx context.Context, method, suffix, cookie string, input any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if input != nil {
		var err error
		raw, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, f.s.PublicURL+"/api/v1/documents/"+f.doc.ID.String()+"/crm/"+suffix, bytes.NewReader(raw)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("CRM document response cacheable")
	}
	if strings.Contains(w.Body.String(), crmConnectionTokenE2E) || strings.Contains(w.Body.String(), crmConnectionKeyE2E) {
		t.Fatal("CRM document response exposed credential material")
	}
	return w
}
func crmDocumentReadContextE2E(t *testing.T, f lifecycleAuthorizationFixture, cookie string) crmDocumentContextE2E {
	t.Helper()
	w := crmDocumentRequestE2E(t, f, f.ctx, http.MethodGet, "context", cookie, nil)
	var out crmDocumentContextE2E
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.OrgID != f.org || out.UserID != f.user.ID || out.DocumentID != f.doc.ID {
		t.Fatalf("CRM context=%d %s", w.Code, w.Body.String())
	}
	return out
}
func CRMDocumentWitnessE2E(c crmDocumentContextE2E) CRMDocumentWitness {
	in := CRMDocumentWitness{ExpectedOrgID: c.OrgID, ExpectedUserID: c.UserID, ExpectedUpdatedAt: c.UpdatedAt, ExpectedHTMLSourceCommitment: c.HTMLSourceCommitment, ExpectedBindingFingerprint: c.BindingFingerprint, ExpectedConnectionGeneration: "0"}
	if c.Connection != nil {
		in.ExpectedConnectionID = c.Connection.ID.String()
		in.ExpectedConnectionGeneration = c.Connection.Generation
	}
	return in
}
func crmDocumentObserveE2E(t *testing.T, f lifecycleAuthorizationFixture, cookie string, in CRMMappingRequest) crmDocumentObservation {
	t.Helper()
	w := crmDocumentRequestE2E(t, f, f.ctx, http.MethodPost, "observations", cookie, in)
	var out crmDocumentObservation
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.CanApply {
		t.Fatalf("CRM observations=%d %s", w.Code, w.Body.String())
	}
	return out
}
func crmDocumentApplyInputE2E(in CRMMappingRequest, digest string) any {
	return struct {
		CRMMappingRequest
		ReviewedDigest string `json:"reviewed_digest"`
		Confirmed      bool   `json:"confirmed"`
	}{in, digest, true}
}
func crmDocumentStateE2E(t *testing.T, f lifecycleAuthorizationFixture) string {
	t.Helper()
	var raw []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object('review',(SELECT to_jsonb(r) FROM document_crm_mapping_reviews r WHERE r.document_id=$1),'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.variable_name),'[]') FROM document_variable_bindings b WHERE b.document_id=$1))`, f.doc.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- exact fixture-owned effect inventory
	return f.snapshot(t) + string(raw)
}
func crmDocumentDefaultMappingsE2E() []crmDocumentMapping {
	return []crmDocumentMapping{{"customer", "crm.deal", crmSourceDealE2E, "title"}, {"amount", "crm.deal", crmSourceDealE2E, "value"}}
}
func applyCRMSourceFixtureReviewE2E(t *testing.T, f lifecycleAuthorizationFixture, cookie string) {
	t.Helper()
	f.s.Versions = versions.New(f.q)
	c := crmDocumentReadContextE2E(t, f, cookie)
	in := CRMMappingRequest{CRMDocumentWitnessE2E(c), crmDocumentDefaultMappingsE2E()}
	observation := crmDocumentObserveE2E(t, f, cookie, in)
	w := crmDocumentRequestE2E(t, f, f.ctx, http.MethodPost, "apply", cookie, crmDocumentApplyInputE2E(in, observation.ReviewDigest))
	if w.Code != 200 {
		t.Fatalf("explicit fixture CRM mapping review=%d %s", w.Code, w.Body.String())
	}
}

func TestCRMDocumentReviewedBlocksApplyPreservesManualTextAndSendLineageE2E(t *testing.T) {
	f := setupCRMSourceAuthorizationE2E(t)
	var err error
	f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	var manual map[string]string
	if err := json.Unmarshal(f.doc.VariablesJson, &manual); err != nil {
		t.Fatal(err)
	}
	manual["manual"] = "Human approved scope"
	variables, err := json.Marshal(manual)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the actual manual editor before the separate CRM review; a raw
	// source UPDATE would invalidate its receipts before Apply even begins.
	f.doc, err = nativeRevisionEditE2E(t, f.lifecycleAuthorizationFixture, f.doc, f.doc.BlocksJson, variables)
	if err != nil {
		t.Fatal(err)
	}
	f.source.setDeal(t, "New reviewed CRM AB")
	c := crmDocumentReadContextE2E(t, f.lifecycleAuthorizationFixture, f.cookie)
	if !c.MappingReviewRequired {
		t.Fatal("manual edit did not invalidate mapped content review")
	}
	in := CRMMappingRequest{CRMDocumentWitnessE2E(c), crmDocumentDefaultMappingsE2E()}
	before := crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture)
	observation := crmDocumentObserveE2E(t, f.lifecycleAuthorizationFixture, f.cookie, in)
	if !observation.ContentChanged || crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture) != before {
		t.Fatal("read-only observations mutated the document")
	}
	w := crmDocumentRequestE2E(t, f.lifecycleAuthorizationFixture, f.ctx, http.MethodPost, "apply", f.cookie, crmDocumentApplyInputE2E(in, observation.ReviewDigest))
	if w.Code != 200 {
		t.Fatalf("reviewed apply=%d %s", w.Code, w.Body.String())
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]string
	if json.Unmarshal(doc.VariablesJson, &values) != nil || values["customer"] != "New reviewed CRM AB" || values["amount"] != crmSourceValueE2E || values["manual"] != "Human approved scope" {
		t.Fatal("reviewed apply lost exact values or manual scope")
	}
	if crmDocumentReadContextE2E(t, f.lifecycleAuthorizationFixture, f.cookie).MappingReviewRequired {
		t.Fatal("durable applied review absent")
	}
	if w := f.lifecycleAuthorizationFixture.submit("send", f.cookie); w.Code != 200 {
		t.Fatalf("reviewed mapped Send=%d %s", w.Code, w.Body.String())
	}
	var events int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind='crm.variables.applied'`, f.doc.ID).Scan(&events); err != nil || events != 2 {
		t.Fatal("fresh apply audit lineage absent", err)
	} //nolint:rawsql
}

func TestCRMDocumentApplyRejectsValueOrBindingDriftWithoutEffectsE2E(t *testing.T) {
	for _, change := range []string{"provider value", "ledger membership"} {
		t.Run(change, func(t *testing.T) {
			f := setupCRMSourceAuthorizationE2E(t)
			c := crmDocumentReadContextE2E(t, f.lifecycleAuthorizationFixture, f.cookie)
			in := CRMMappingRequest{CRMDocumentWitnessE2E(c), crmDocumentDefaultMappingsE2E()}
			observation := crmDocumentObserveE2E(t, f.lifecycleAuthorizationFixture, f.cookie, in)
			if change == "provider value" {
				f.source.setDeal(t, "Changed after human preview")
			} else {
				if err := f.q.DeleteVariableBinding(f.ctx, generated.DeleteVariableBindingParams{DocumentID: f.doc.ID, VariableName: "amount"}); err != nil {
					t.Fatal(err)
				}
			}
			before := crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture)
			w := crmDocumentRequestE2E(t, f.lifecycleAuthorizationFixture, f.ctx, http.MethodPost, "apply", f.cookie, crmDocumentApplyInputE2E(in, observation.ReviewDigest))
			if w.Code != 409 || crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture) != before {
				t.Fatalf("drift admission=%d or effects escaped rollback", w.Code)
			}
		})
	}
}

func TestCRMDocumentDeletedMappingCannotBypassSendAndExplicitUnlinkWorksWithoutProviderE2E(t *testing.T) {
	f := setupCRMSourceAuthorizationE2E(t)
	for _, name := range []string{"customer", "amount"} {
		if err := f.q.DeleteVariableBinding(f.ctx, generated.DeleteVariableBindingParams{DocumentID: f.doc.ID, VariableName: name}); err != nil {
			t.Fatal(err)
		}
	}
	before := crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture)
	if w := f.lifecycleAuthorizationFixture.submit("send", f.cookie); w.Code != 409 {
		t.Fatalf("raw delete bypassed retained CRM review: %d", w.Code)
	}
	if crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture) != before {
		t.Fatal("unreviewed deleted mapping created Send effects")
	}
	f.s.CRMClient, f.s.CRMKeys = nil, nil
	c := crmDocumentReadContextE2E(t, f.lifecycleAuthorizationFixture, f.cookie)
	in := CRMMappingRequest{CRMDocumentWitnessE2E(c), []crmDocumentMapping{}}
	observation := crmDocumentObserveE2E(t, f.lifecycleAuthorizationFixture, f.cookie, in)
	w := crmDocumentRequestE2E(t, f.lifecycleAuthorizationFixture, f.ctx, http.MethodPost, "apply", f.cookie, crmDocumentApplyInputE2E(in, observation.ReviewDigest))
	if w.Code != 200 {
		t.Fatalf("reviewed explicit unlink=%d %s", w.Code, w.Body.String())
	}
	if w := f.lifecycleAuthorizationFixture.submit("send", f.cookie); w.Code != 200 {
		t.Fatalf("static reviewed unlinked Send=%d %s", w.Code, w.Body.String())
	}
}

func TestCRMDocumentObservationsRecheckOriginalAuthorAndAccountE2E(t *testing.T) {
	for _, change := range []string{"role", "account", "binding"} {
		t.Run(change, func(t *testing.T) {
			f := setupCRMSourceAuthorizationE2E(t)
			c := crmDocumentReadContextE2E(t, f.lifecycleAuthorizationFixture, f.cookie)
			in := CRMMappingRequest{CRMDocumentWitnessE2E(c), crmDocumentDefaultMappingsE2E()}
			pause := f.source.pauseRecord(t)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- crmDocumentRequestE2E(t, f.lifecycleAuthorizationFixture, f.ctx, http.MethodPost, "observations", f.cookie, in)
			}()
			pause.await(t)
			want := 409
			switch change {
			case "role":
				want = 403
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET role='viewer' WHERE id=$1`, f.user.ID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql
			case "account":
				assertCRMConnectionSafeResponseE2E(t, f.submit(f.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(2), f.cookie), 200)
			case "binding":
				if err := f.q.DeleteVariableBinding(f.ctx, generated.DeleteVariableBindingParams{DocumentID: f.doc.ID, VariableName: "amount"}); err != nil {
					t.Fatal(err)
				}
			}
			before := crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture)
			pause.finish()
			select {
			case w := <-result:
				if w.Code != want || crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture) != before {
					t.Fatalf("stale observation=%d want%d or effects escaped", w.Code, want)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("observation did not drain")
			}
		})
	}
}

func TestCRMDocumentHTMLApplyRebuildsImmutableSourceAndPreservesApprovedSectionsE2E(t *testing.T) {
	f, renderer, _, old, cookie := setupHTMLRevisionE2E(t)
	p := newCRMSourcePeerE2E(t)
	client, err := crmconnection.NewClient(p.server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crmconnection.NewKeyring(crmConnectionKeyE2E, "")
	if err != nil {
		t.Fatal(err)
	}
	f.s.CRMOrigin, f.s.CRMClient, f.s.CRMKeys = p.server.URL, client, keys
	enrollment := crmConnectionFixtureE2E{lifecycleAuthorizationFixture: f, cookie: cookie}
	enrollment.active(t)
	c := crmDocumentReadContextE2E(t, f, cookie)
	in := CRMMappingRequest{CRMDocumentWitnessE2E(c), []crmDocumentMapping{{"customer", "crm.deal", crmSourceDealE2E, "title"}}}
	observation := crmDocumentObserveE2E(t, f, cookie, in)
	w := crmDocumentRequestE2E(t, f, f.ctx, http.MethodPost, "apply", cookie, crmDocumentApplyInputE2E(in, observation.ReviewDigest))
	if w.Code != 200 {
		t.Fatalf("HTML CRM Apply=%d %s", w.Code, w.Body.String())
	}
	var reply struct {
		Document                documentResponse `json:"document"`
		ReviewRequired          bool             `json:"review_required"`
		PlacementReset          bool             `json:"placement_reset"`
		MaterializationRevision int32            `json:"materialization_revision"`
	}
	if json.Unmarshal(w.Body.Bytes(), &reply) != nil || !reply.ReviewRequired || !reply.PlacementReset || reply.MaterializationRevision != 2 {
		t.Fatal("HTML fresh PDF review/placement not required")
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	input, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		t.Fatal(err)
	}
	oldInput, err := htmlsource.InputForCurrent(old)
	if err != nil {
		t.Fatal(err)
	}
	oldSections, _ := json.Marshal(oldInput.Sections)
	newSections, _ := json.Marshal(input.Sections)
	if input.Values["customer"] != crmSourceTitleE2E || !bytes.Equal(oldSections, newSections) || !bytes.Equal(old.HtmlSourceJson, doc.HtmlSourceJson) || old.PdfStorageKey == doc.PdfStorageKey || doc.HtmlReviewedBy.Valid {
		t.Fatal("CRM Apply corrupted retained original, approved scope, immutable PDF or review")
	}
	sources := renderer.sources()
	if len(sources) != 2 || !strings.Contains(sources[1], crmSourceTitleE2E) || !strings.Contains(sources[1], "Approved scope") {
		t.Fatal("renderer did not receive fresh mapped values plus approved scope")
	}
	if crmDocumentReadContextE2E(t, f, cookie).MappingReviewRequired {
		t.Fatal("HTML materialization not durably linked to reviewed mappings")
	}
}

func TestCRMDocumentContextRejectsViewerAndNonOwningSenderBeforeProviderE2E(t *testing.T) {
	for _, role := range []string{"viewer", "sender"} {
		t.Run(role, func(t *testing.T) {
			f := setupCRMSourceAuthorizationE2E(t)
			other, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@fixture.test", Name: "Another colleague", Role: role})
			if err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, other.ID, other.SessionGeneration, time.Hour)
			accounts := f.source.accounts.Load()
			before := crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture)
			w := crmDocumentRequestE2E(t, f.lifecycleAuthorizationFixture, f.ctx, http.MethodGet, "context", cookie, nil)
			if w.Code != 403 || f.source.accounts.Load() != accounts || crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture) != before {
				t.Fatal("non-author discovery admitted or invoked provider")
			}
		})
	}
}

func TestCRMDocumentSearchIsScopedAndReadOnlyE2E(t *testing.T) {
	f := setupCRMSourceAuthorizationE2E(t)
	c := crmDocumentReadContextE2E(t, f.lifecycleAuthorizationFixture, f.cookie)
	in := struct {
		CRMDocumentWitness
		Kind   string `json:"kind"`
		Query  string `json:"query"`
		Offset int    `json:"offset"`
	}{CRMDocumentWitnessE2E(c), "crm.deal", "Reviewed", 0}
	before := crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture)
	accounts, records := f.source.accounts.Load(), f.source.deals.Load()
	w := crmDocumentRequestE2E(t, f.lifecycleAuthorizationFixture, f.ctx, http.MethodPost, "records/search", f.cookie, in)
	var result struct {
		Choices []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"choices"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Choices) != 1 || result.Choices[0].ID != crmSourceDealE2E || result.Choices[0].Label != crmSourceTitleE2E || crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture) != before || f.source.accounts.Load() != accounts+2 || f.source.deals.Load() != records+1 {
		t.Fatalf("typed scoped discovery=%d or observation/durable effects mismatch", w.Code)
	}
	in.ExpectedUserID = uuid.New()
	accounts = f.source.accounts.Load()
	w = crmDocumentRequestE2E(t, f.lifecycleAuthorizationFixture, f.ctx, http.MethodPost, "records/search", f.cookie, in)
	if w.Code != 409 || f.source.accounts.Load() != accounts || crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture) != before {
		t.Fatal("foreign actor witness reached discovery")
	}
}

func TestCRMDocumentHTMLApplyRejectsLedgerAndAccountChangesDuringRenderE2E(t *testing.T) {
	for _, change := range []string{"ledger without document timestamp", "account revocation"} {
		t.Run(change, func(t *testing.T) {
			f, renderer, peer, _, cookie := setupHTMLRevisionE2E(t)
			p := newCRMSourcePeerE2E(t)
			client, err := crmconnection.NewClient(p.server.URL, true)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := crmconnection.NewKeyring(crmConnectionKeyE2E, "")
			if err != nil {
				t.Fatal(err)
			}
			f.s.CRMOrigin, f.s.CRMClient, f.s.CRMKeys = p.server.URL, client, keys
			enrollment := crmConnectionFixtureE2E{lifecycleAuthorizationFixture: f, cookie: cookie}
			enrollment.active(t)
			c := crmDocumentReadContextE2E(t, f, cookie)
			in := CRMMappingRequest{CRMDocumentWitnessE2E(c), []crmDocumentMapping{{"customer", "crm.deal", crmSourceDealE2E, "title"}}}
			observation := crmDocumentObserveE2E(t, f, cookie, in)
			release := make(chan struct{})
			renderer.entered = make(chan struct{}, 1)
			renderer.release = release
			defer closeUnlessClosedRevisionE2E(release)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- crmDocumentRequestE2E(t, f, f.ctx, http.MethodPost, "apply", cookie, crmDocumentApplyInputE2E(in, observation.ReviewDigest))
			}()
			select {
			case <-renderer.entered:
			case <-time.After(4 * time.Second):
				t.Fatal("CRM Apply did not reach renderer")
			}
			if change == "account revocation" {
				assertCRMConnectionSafeResponseE2E(t, enrollment.submit(f.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(2), cookie), 200)
			} else {
				if _, err := f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{DocumentID: f.doc.ID, VariableName: "customer", SourceKind: "static", Fallback: "Another binding"}); err != nil {
					t.Fatal(err)
				}
			}
			before, requests := crmDocumentStateE2E(t, f)+string(revisionStateE2E(t, f)), peer.requests.Load()
			close(release)
			select {
			case w := <-result:
				if w.Code != 409 || crmDocumentStateE2E(t, f)+string(revisionStateE2E(t, f)) != before {
					t.Fatalf("late CRM admission=%d or database effects escaped", w.Code)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("CRM renderer result did not drain")
			}
			if peer.requests.Load() < requests {
				t.Fatal("invalid storage counter")
			}
			// The renderer may already have produced an owned immutable candidate;
			// any failed admission must compensate it exactly, never delete the old PDF.
			peer.importStoragePeer.mu.Lock()
			objects := len(peer.importStoragePeer.objects)
			peer.importStoragePeer.mu.Unlock()
			if objects != 1 {
				t.Fatal("failed CRM admission left an orphan or deleted the original object")
			}
		})
	}
}

func TestCRMDocumentContractPreviewRequiresAppliedCurrentValuesE2E(t *testing.T) {
	f := setupCRMSourceAuthorizationE2E(t)
	f.source.setDeal(t, "Unreviewed customer change")
	before := crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture)
	w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+f.doc.ID.String()+"/preview", "", f.cookie)
	if w.Code != 409 || strings.Contains(w.Body.String(), "Unreviewed customer change") || crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture) != before {
		t.Fatal("contract preview silently presented unreviewed CRM prose")
	}
}
