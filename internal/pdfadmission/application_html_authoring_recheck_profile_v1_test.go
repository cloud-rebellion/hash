// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestHTMLStoredTemplateFixedPurposeCoverageV1(t *testing.T) {
	for _, got := range []htmlStoredTemplatePurposeV1{htmlStoredTemplateCurrentV1, htmlStoredTemplateRecheckV1, htmlStoredTemplatePreparationV1, 255} {
		for _, want := range []htmlStoredTemplatePurposeV1{htmlStoredTemplateCurrentV1, htmlStoredTemplateRecheckV1, htmlStoredTemplatePreparationV1, 255} {
			expected := got <= htmlStoredTemplatePreparationV1 && want <= htmlStoredTemplatePreparationV1 && got >= want
			if got.coversV1(want) != expected {
				t.Fatalf("purpose %d covers %d", got, want)
			}
		}
	}
	// A fresh exact SQL source carries the ORIGINAL credit class, never a promotion.
	r := &ApplicationHTMLAuthoringReaderV1{}
	id := uuid.New()
	digest := make([]byte, 32)
	s := htmlAuthoringCanonicalSourceV1{id: id, version: 1, revision: true, master: []byte("{}"), defaults: []byte("{}"), digestValid: true, ready: true, purpose: htmlStoredTemplateRecheckV1}
	r.canonicalSources[0] = s
	r.canonicalCount = 1
	if err := r.rememberCanonicalSourceV1(id, 1, true, s.master, s.defaults, digest); err != nil {
		t.Fatal(err)
	}
	fresh := r.canonicalSources[1]
	if !fresh.reused || !fresh.ready || fresh.started || fresh.delivered || fresh.purpose.coversV1(htmlStoredTemplatePreparationV1) {
		t.Fatal("fresh recheck input promoted to full credit or lost one-shot gate")
	}
}

func TestHTMLStoredTemplateRecheckHasOneCompileAndNoMaterializationV1(t *testing.T) {
	ctx := context.Background()
	m := htmlmaster.Master{SchemaVersion: 1, HTML: "<p><span data-hash-value=\"customer\"></span></p><p><span data-hash-value=\"amount\"></span> <span data-hash-value=\"currency\"></span></p><p><span data-hash-value=\"manual\"></span></p><div data-hash-section=\"scope\"></div>", Values: []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 200}, {Name: "amount", Required: true, MaxChars: 200}, {Name: "currency", MaxChars: 200}, {Name: "manual", Required: true, MaxChars: 200}}, Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Approved reusable scope", MaxChars: 500}}}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	content, err := htmlmaster.CanonicalTemplate(raw, []byte("{\"customer\":\"Approved default AB\",\"amount\":\"1000\",\"manual\":\"Approved static value\"}"))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := htmlInputCanonicalInspectV1(ctx, canonical)
	if err != nil {
		t.Fatal(err)
	}
	scratch, err := htmlInputCanonicalResourcesV1(content.MasterJSON, content.DefaultsJSON, canonical, stats)
	if err != nil {
		t.Fatal(err)
	}
	outputBound, err := htmlStoredCanonicalOutputUpperV1(content.MasterJSON, content.DefaultsJSON, canonical, stats)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlStoredPreparedCompiledRetentionV1(canonical, stats, outputBound)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := htmlStoredPreparedMasterRetentionV1(canonical)
	if err != nil {
		t.Fatal(err)
	}
	one := compiled + typed
	materialize, err := htmlStoredTemplateMaterializationResourcesV1(canonical, stats)
	if err != nil {
		t.Fatal(err)
	}
	check, err := htmlStoredTemplateFutureResourcesV1(htmlStoredTemplateRecheckV1, content.MasterJSON, content.DefaultsJSON, canonical, stats)
	if err != nil {
		t.Fatal(err)
	}
	full, err := htmlStoredTemplateFutureResourcesV1(htmlStoredTemplatePreparationV1, content.MasterJSON, content.DefaultsJSON, canonical, stats)
	if err != nil {
		t.Fatal(err)
	}
	readinessScratch, readinessRetained, err := htmlStoredTemplateFutureReadinessResourcesV1(htmlStoredTemplatePreparationV1, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if check != one || full != 2*one+2*materialize+readinessRetained {
		t.Fatalf("fixed later topology differs: check=%d full=%d retained_compile=%d materialize=%d", check, full, one, materialize)
	}
	output, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputMasterV1, content.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, content.DefaultsJSON)
	if err != nil {
		t.Fatal(err)
	}
	masterPass, err := htmlAuthoringInputParserArenaV1(output, 1)
	if err != nil {
		t.Fatal(err)
	}
	defaultsPass, err := htmlAuthoringInputParserArenaV1(defaults, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual CRM fixture logical bytes: raw_master=%d canonical_master=%d defaults=%d tokens=%d compile=%d materialize=%d full_future=%d recheck_future=%d full_minus_recheck=%d", len(raw), len(content.MasterJSON), len(content.DefaultsJSON), stats.tokens, one, materialize, full, check, full-check+10*masterPass+2*defaultsPass)
	t.Logf("serialized canonical/readiness scratch peak=%d; separate retained compiled=%d master=%d readiness=%d", max(scratch, readinessScratch), compiled, typed, readinessRetained)
	for _, bad := range []htmlStoredTemplatePurposeV1{htmlStoredTemplateCurrentV1, 255} {
		if _, err = htmlStoredTemplateFutureResourcesV1(bad, content.MasterJSON, content.DefaultsJSON, canonical, stats); err == nil {
			t.Fatalf("unsupported future purpose accepted: %d", bad)
		}
	}
}

func TestHTMLStoredScratchPeakRetainsActualConsumerConjunctionV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	factory, coordinator := htmlInputFactoryTestV1(t, 1<<20)
	org := uuid.New()
	// Private cost/lifetime unit only: the paired actual native PG case proves
	// construction. No native session retirement or SQL authority is fabricated.
	h := &ApplicationSessionV1{state: &applicationOwnedSessionV1{factory: factory.state, org: org}}
	c := &applicationHTMLCanonicalModelConsumerV1{session: h, factory: factory.state, active: 1}
	c.self = c
	factory.state.mu.Lock()
	factory.state.htmlCanonicalConsumers[c] = struct{}{}
	factory.state.mu.Unlock()
	for _, n := range []int64{200, 100, 300, 300} {
		if err := c.holdScratchV1(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.holdV1(ctx, 64); err != nil {
		t.Fatal(err)
	}
	if got := coordinator.SnapshotV1(org); got.Organisation.ParentBytes != 364 || got.OrganisationGrants != 1 {
		t.Fatalf("scratch summed or retained credit omitted: %+v", got)
	}
	c.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Organisation.ParentBytes != 364 {
		t.Fatalf("unjoined CPU borrower refunded: %+v", got)
	}
	c.finishV1()
	if got := coordinator.SnapshotV1(org); got.Organisation.ParentBytes != 0 || got.OrganisationGrants != 0 {
		t.Fatalf("joined final consumer leaked: %+v", got)
	}
	if err := factory.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}
