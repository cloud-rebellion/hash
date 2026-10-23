// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// Real coordinator/resource ownership regression, not native SQL/source
// authority. Distinct synthetic consumers keep independent private credits.
func TestHTMLCanonicalSingleCreditChargesFullSumAndKeepsRetirementV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	limit := workguard.VectorV1{ParentBytes: 128}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limit, Organisation: limit, MaxGrants: 1, MaxOrganisationGrants: 1})
	if err != nil {
		t.Fatal(err)
	}
	work, err := NewWorkAdmissionV1(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	org := uuid.New()
	makeConsumer := func() *applicationHTMLCanonicalModelConsumerV1 {
		h := &ApplicationSessionV1{state: &applicationOwnedSessionV1{factory: factory.state, org: org}}
		c := &applicationHTMLCanonicalModelConsumerV1{session: h, factory: factory.state, active: 1}
		c.self = c
		factory.state.mu.Lock()
		factory.state.htmlCanonicalConsumers[c] = struct{}{}
		factory.state.mu.Unlock()
		return c
	}
	c := makeConsumer()
	for _, n := range []int64{0, -1} {
		if err := c.holdV1(ctx, n); !errors.Is(err, workguard.ErrUnavailableV1) || c.parentCredit != nil || coordinator.SnapshotV1(org) != (workguard.SnapshotV1{}) {
			t.Fatal("invalid first credit changed original admission semantics")
		}
	}
	for _, n := range []int64{16, 8, 12} {
		if err := c.holdV1(ctx, n); err != nil {
			t.Fatal("same-owner additive work fragmented grant count", err)
		}
	}
	credit := c.parentCredit
	for _, n := range []int64{20, 12, 30} {
		if err := c.holdScratchV1(ctx, n); err != nil {
			t.Fatal("same-owner scratch growth fragmented grant count", err)
		}
	}
	full := coordinator.SnapshotV1(org)
	if c.parentCredit != credit || c.scratch != 30 || full.Global.ParentBytes != 66 || full.Organisation.ParentBytes != 66 || full.GlobalGrants != 1 || full.OrganisationGrants != 1 {
		t.Fatal("full sum/high-water was discounted or owner credit replaced")
	}
	second := makeConsumer()
	secondContext := WithHTMLCanonicalDiagnosticV1(ctx)
	if err := second.holdAtV1(secondContext, 1, "parse_hold"); !errors.Is(err, workguard.ErrUnavailableV1) {
		t.Fatal("distinct owner bypassed one-grant limit")
	}
	denied := HTMLCanonicalDiagnosticV1(secondContext)
	if denied.Stage != "parse_hold" || !denied.AtomicDecision || denied.Reason != uint8(workguard.AdmissionGlobalGrantCountV1) || denied.GlobalGrants != 1 || denied.GlobalGrantLimit != 1 || second.parentCredit != nil || coordinator.SnapshotV1(org) != full {
		t.Fatal("second owner refusal changed accounting or lost exact first-acquire decision")
	}
	second.CloseConsumerV1()
	second.finishV1()
	growthContext := WithHTMLCanonicalDiagnosticV1(ctx)
	if err := c.holdAtV1(growthContext, 63, "future_retention_hold"); !errors.Is(err, workguard.ErrUnavailableV1) {
		t.Fatal("grown byte cap was waived")
	}
	growth := HTMLCanonicalDiagnosticV1(growthContext)
	if growth.Stage != "future_retention_hold" || !growth.AtomicDecision || growth.Reason != uint8(workguard.AdmissionGlobalResourceV1) || growth.Dimension != uint8(workguard.AdmissionParentBytesV1) || growth.RequestedParentBytes != 63 || growth.GlobalParentBytes != 66 || growth.GlobalParentLimit != 128 || growth.GlobalGrants != 1 || growth.GlobalGrantLimit != 1 {
		t.Fatal("growth observation was not the same original byte decision")
	}
	for _, n := range []int64{0, -1, (1 << 40) + 1} {
		if err := c.holdV1(ctx, n); !errors.Is(err, workguard.ErrUnavailableV1) {
			t.Fatal("invalid additive amount accepted")
		}
	}
	if err := c.holdScratchV1(ctx, -1); !errors.Is(err, ErrHTMLAuthoringReadV1) {
		t.Fatal("negative scratch accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	for _, call := range []context.Context{nil, context.Background(), canceled} {
		if err := c.holdV1(call, 1); !errors.Is(err, ErrHTMLAuthoringReadV1) {
			t.Fatal("original owner context guard changed")
		}
	}
	canceledObserved := WithHTMLCanonicalDiagnosticV1(canceled)
	if g, err := htmlCanonicalChargeV1(canceledObserved, work, org, credit, 1, "inspection_hold"); g != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("same growth decision lost cancellation fence")
	}
	if got := HTMLCanonicalDiagnosticV1(canceledObserved); !got.AtomicDecision || got.Reason != uint8(workguard.AdmissionContextV1) {
		t.Fatal("canceled growth fabricated capacity refusal")
	}
	if c.parentCredit != credit || c.scratch != 30 || coordinator.SnapshotV1(org) != full {
		t.Fatal("failed growth or context changed retained credit")
	}
	c.CloseConsumerV1()
	if coordinator.SnapshotV1(org) != full {
		t.Fatal("open active producer refunded unknown retirement")
	}
	if err := c.holdV1(ctx, 1); !errors.Is(err, ErrHTMLAuthoringReadV1) || coordinator.SnapshotV1(org) != full {
		t.Fatal("closed consumer grew or released credit")
	}
	c.finishV1()
	if c.parentCredit != nil || !c.retired || coordinator.SnapshotV1(org) != (workguard.SnapshotV1{}) {
		t.Fatal("joined owner did not retire its complete grown credit")
	}
	closedContext := WithHTMLCanonicalDiagnosticV1(ctx)
	if g, err := htmlCanonicalChargeV1(closedContext, work, org, credit, 1, "inspection_hold"); g != nil || !errors.Is(err, workguard.ErrUnavailableV1) || coordinator.SnapshotV1(org) != (workguard.SnapshotV1{}) {
		t.Fatal("closed original credit resurrected accounting")
	}
	if got := HTMLCanonicalDiagnosticV1(closedContext); !got.AtomicDecision || got.Reason != uint8(workguard.AdmissionCoordinatorUnavailableV1) {
		t.Fatal("closed growth lost actual refusal provenance")
	}
	// The reverse conjunction order also retains credit through actual last use.
	reverse := makeConsumer()
	if err := reverse.holdV1(ctx, 7); err != nil {
		t.Fatal(err)
	}
	reverse.finishV1()
	if coordinator.SnapshotV1(org).Organisation.ParentBytes != 7 {
		t.Fatal("CPU return refunded a still-live result consumer")
	}
	reverse.CloseConsumerV1()
	reverse.CloseConsumerV1()
	if coordinator.SnapshotV1(org) != (workguard.SnapshotV1{}) {
		t.Fatal("final consumer did not close credit exactly once")
	}
	if err := factory.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}
