// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
)

// This is a logical producer/consumer unit, not a fabricated SQL retirement or
// an RSS assertion. The unchanged real branded preview/creation journeys are
// the required native PG regression and retain their actual route consumers.
func TestHTMLStoredBrandedReadinessScratchAndRetainedOutputsV1(t *testing.T) {
	source, _, _ := testfixture.BrandedHTMLContract(t)
	master, err := htmlmaster.Decode(source.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	content, err := htmlmaster.CanonicalTemplate(source.MasterJSON, source.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stats, err := htmlInputCanonicalInspectV1(ctx, canonical)
	if err != nil {
		t.Fatal(err)
	}
	scratch, retained, err := htmlStoredTemplateFutureReadinessResourcesV1(htmlStoredTemplatePreparationV1, canonical)
	if err != nil {
		t.Fatal(err)
	}
	ceiling, err := htmlStoredTemplateReadinessCeilingV1(canonical)
	if err != nil || scratch != ceiling {
		t.Fatalf("one-call conservative ceiling changed: scratch%d ceiling%d err%v", scratch, ceiling, err)
	}
	one, err := htmlRevisionContractReadinessComponentsForV1(canonical, htmlmaster.Input{Values: source.Values, Sections: source.Sections})
	if err != nil || scratch < one.parentBytes || retained != 5*one.retainedResultBytes {
		t.Fatalf("fixed schema3 work/result split: scratch%d retained%d actual%+v err%v", scratch, retained, one, err)
	}
	// Keep ALL five real results live, independently checking the returned arrays,
	// digests and messages against the separately retained component.
	results := make([]htmlmaster.ContractReadiness, 0, 5)
	actualRetained := int64(0)
	for range 5 {
		result, err := compiled.ContractReadiness(htmlmaster.Input{Values: source.Values, Sections: source.Sections})
		if err != nil || !result.Complete {
			t.Fatal("genuine fixture readiness failed", err)
		}
		actualRetained += readinessActualOwnedResultBytesV1(result)
		results = append(results, result)
	}
	if retained < actualRetained || len(results) != 5 {
		t.Fatalf("retained outputs omitted: charged%d actual%d", retained, actualRetained)
	}
	for _, purpose := range []htmlStoredTemplatePurposeV1{htmlStoredTemplateRecheckV1, htmlStoredTemplateCurrentV1, 255} {
		s, r, err := htmlStoredTemplateFutureReadinessResourcesV1(purpose, canonical)
		if purpose == htmlStoredTemplateRecheckV1 {
			if err != nil || s != 0 || r != 0 {
				t.Fatal("recheck granted materialization readiness", s, r, err)
			}
		} else if err == nil {
			t.Fatal("unsupported purpose accepted", purpose)
		}
	}
	// Price both entire canonical producers using the exact source/parser stages
	// and all existing later outputs. Native header/body and renderer/PDF provider
	// costs are deliberately separate; the real original PG journey proves that
	// complete route overlap. No fixture or production capacity is increased here.
	originalShape, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputMasterV1, source.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	originalDefaults, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, source.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	futureShape, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputMasterV1, content.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	futureDefaults, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, content.DefaultsJSON)
	if err != nil {
		t.Fatal(err)
	}
	additive := int64(0)
	for _, stage := range []struct {
		shape  htmlAuthoringInputShapeV1
		passes int64
	}{{originalShape, 10}, {originalDefaults, 2}, {futureShape, 20}, {futureDefaults, 4}} {
		n, err := htmlAuthoringInputParserArenaV1(stage.shape, stage.passes)
		if err != nil || !htmlInputAddV1(&additive, n, 1) {
			t.Fatal("parser component", err)
		}
	}
	for _, m := range []htmlmaster.Master{master, canonical} {
		n, err := htmlInputCanonicalInspectionResourcesV1(m)
		if err != nil || !htmlInputAddV1(&additive, n, 1) {
			t.Fatal("inspection component", err)
		}
	}
	output, err := htmlStoredTemplateResultRetentionV1(content)
	if err != nil || !htmlInputAddV1(&additive, output, 1) {
		t.Fatal("canonical retained output", err)
	}
	future, err := htmlStoredTemplateFutureResourcesV1(htmlStoredTemplatePreparationV1, content.MasterJSON, content.DefaultsJSON, canonical, stats)
	if err != nil || !htmlInputAddV1(&additive, future, 1) {
		t.Fatal("future retained work", err)
	}
	canonicalScratch, err := htmlInputCanonicalResourcesV1(content.MasterJSON, content.DefaultsJSON, canonical, stats)
	if err != nil {
		t.Fatal(err)
	}
	originalStats, err := htmlInputCanonicalInspectV1(ctx, master)
	if err != nil {
		t.Fatal(err)
	}
	originalScratch, err := htmlInputCanonicalResourcesV1(source.MasterJSON, source.DefaultVarsJSON, master, originalStats)
	if err != nil {
		t.Fatal(err)
	}
	peak := max(scratch, canonicalScratch, originalScratch)
	const limit int64 = 2 << 30
	if 2*5*scratch <= limit {
		t.Fatal("fixture no longer exercises prior five-call additive refusal")
	}
	if 2*(peak+additive) >= limit {
		t.Fatalf("corrected two-producer overlap exceeds unchanged logical limit: peak%d additive%d", peak, additive)
	}
	factory, coordinator := htmlInputFactoryTestV1(t, limit)
	org := uuid.New()
	var owners [2]*applicationHTMLCanonicalModelConsumerV1
	var finished [2]bool
	t.Cleanup(func() {
		for i, c := range owners {
			if c != nil {
				c.CloseConsumerV1()
				if !finished[i] {
					c.finishV1()
				}
			}
		}
	})
	for i := range owners {
		h := &ApplicationSessionV1{state: &applicationOwnedSessionV1{factory: factory.state, org: org}}
		c := &applicationHTMLCanonicalModelConsumerV1{session: h, factory: factory.state, active: 1}
		c.self = c
		owners[i] = c
		factory.state.mu.Lock()
		factory.state.htmlCanonicalConsumers[c] = struct{}{}
		factory.state.mu.Unlock()
		if err := c.holdScratchV1(ctx, originalScratch); err != nil {
			t.Fatal(err)
		}
		if err := c.holdScratchV1(ctx, canonicalScratch); err != nil {
			t.Fatal(err)
		}
		if err := c.holdScratchV1(ctx, scratch); err != nil {
			t.Fatal(err)
		}
		if err := c.holdV1(ctx, additive); err != nil {
			t.Fatal(err)
		}
	}
	expected := 2 * (peak + additive)
	if got := coordinator.SnapshotV1(org); got.Organisation.ParentBytes != expected {
		t.Fatalf("serialized scratch or retained work lost: %+v expected%d", got, expected)
	}
	owners[0].CloseConsumerV1()
	owners[1].finishV1()
	finished[1] = true
	if got := coordinator.SnapshotV1(org); got.Organisation.ParentBytes != expected {
		t.Fatalf("either live conjunction refunded: %+v", got)
	}
	owners[0].finishV1()
	finished[0] = true
	owners[0] = nil
	owners[1].CloseConsumerV1()
	owners[1] = nil
	if got := coordinator.SnapshotV1(org); got.Organisation.ParentBytes != 0 || got.OrganisationGrants != 0 {
		t.Fatalf("final joined consumers leaked: %+v", got)
	}
	if err := factory.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("schema3 two-producer logical peak=%d, previous readiness-only charge=%d; one readiness scratch=%d, all five retained outputs=%d", expected, 2*5*scratch, scratch, retained)
}
