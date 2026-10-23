// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// Actual coordinator arithmetic and the real model hold/scratch methods are
// exercised. This private resource fixture does NOT fabricate SQL/source
// authority; the unchanged genuine API journey proves native construction.
func TestHTMLCanonicalDiagnosticSameDecisionPrivacyAndContextIsolationV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	factory, coordinator := htmlInputFactoryTestV1(t, 64)
	org := uuid.MustParse("d731ca6e-0034-4fb3-8c26-ec74193fb487")
	h := &ApplicationSessionV1{state: &applicationOwnedSessionV1{factory: factory.state, org: org}}
	c := &applicationHTMLCanonicalModelConsumerV1{session: h, factory: factory.state, active: 1}
	c.self = c
	factory.state.mu.Lock()
	factory.state.htmlCanonicalConsumers[c] = struct{}{}
	factory.state.mu.Unlock()
	if err := c.holdV1(ctx, 16); err != nil {
		t.Fatal(err)
	}
	if err := c.holdScratchV1(ctx, 16); err != nil {
		t.Fatal(err)
	}
	before := coordinator.SnapshotV1(org)
	if before.Organisation.ParentBytes != 32 || before.OrganisationGrants != 1 {
		t.Fatal("fixture did not retain both genuine costs in one owner credit")
	}
	ordinary := c.holdAtV1(ctx, 33, "inspection_hold")
	if !errors.Is(ordinary, ErrHTMLAuthoringReadV1) || !errors.Is(ordinary, workguard.ErrUnavailableV1) || htmlCanonicalFailureV1(ctx, "parse_hold", ordinary) != ordinary {
		t.Fatal("ordinary identity/classification changed")
	}
	observed := WithHTMLCanonicalDiagnosticV1(ctx)
	failure := c.holdAtV1(observed, 33, "inspection_hold")
	got := HTMLCanonicalDiagnosticV1(observed)
	if failure == nil || failure.Error() != ordinary.Error() || !errors.Is(failure, ErrHTMLAuthoringReadV1) || !errors.Is(failure, workguard.ErrUnavailableV1) {
		t.Fatal("observed acquire changed original refusal")
	}
	if got.Stage != "inspection_hold" || !got.AtomicDecision || got.Reason != uint8(workguard.AdmissionGlobalResourceV1) || got.Dimension != uint8(workguard.AdmissionParentBytesV1) || got.RequestedParentBytes != 33 || got.GlobalParentBytes != 32 || got.OrganisationParentBytes != 32 || got.GlobalParentLimit != 64 || got.OrganisationParentLimit != 64 || got.GlobalGrants != 1 || got.OrganisationGrants != 1 || got.GlobalGrantLimit != 16 || got.OrganisationGrantLimit != 16 {
		t.Fatal("projection was not the original exact rejecting decision")
	}
	scratch := WithHTMLCanonicalDiagnosticV1(ctx)
	if err := c.holdScratchAtV1(scratch, 49, "readiness_scratch"); !errors.Is(err, workguard.ErrUnavailableV1) {
		t.Fatal("actual scratch delta should refuse")
	}
	sg := HTMLCanonicalDiagnosticV1(scratch)
	if sg.Stage != "readiness_scratch" || !sg.AtomicDecision || sg.RequestedParentBytes != 33 || sg.GlobalParentBytes != 32 || c.scratch != 16 || c.parentCredit == nil || coordinator.SnapshotV1(org) != before {
		t.Fatal("scratch refused at a different cost or changed real accounting")
	}
	clean := WithHTMLCanonicalDiagnosticV1(ctx)
	if err := c.holdScratchAtV1(clean, 8, "readiness_scratch"); err != nil || HTMLCanonicalDiagnosticV1(clean) != (HTMLCanonicalDiagnosticSnapshotV1{}) {
		t.Fatal("covered scratch invented an admission decision")
	}
	const secret = "private-source-capability-marker"
	typed := &fs.PathError{Op: "open", Path: secret, Err: ErrHTMLAuthoringReadV1}
	if htmlCanonicalFailureV1(observed, "future_decode", typed) != typed || HTMLCanonicalDiagnosticV1(observed) != got {
		t.Fatal("later failure replaced first decision or original error")
	}
	if htmlCanonicalFailureV1(ctx, "parse_decode", typed) != typed || htmlCanonicalFailureV1(nil, "parse_decode", typed) != typed || htmlCanonicalFailureV1(observed, "parse_decode", nil) != nil {
		t.Fatal("missing observation or nil changed error identity")
	}
	htmlCanonicalFailureV1(clean, secret, typed)
	if HTMLCanonicalDiagnosticV1(clean) != (HTMLCanonicalDiagnosticSnapshotV1{}) {
		t.Fatal("foreign label reached observation")
	}
	htmlCanonicalFailureV1(clean, "reader_scope", typed)
	if g := HTMLCanonicalDiagnosticV1(clean); g.Stage != "reader_scope" || g.AtomicDecision || g.Reason != 0 || g.RequestedParentBytes != 0 {
		t.Fatal("direct reader refusal invented capacity evidence")
	}
	child, stop := context.WithCancel(observed)
	stop()
	if HTMLCanonicalDiagnosticV1(child) != got || HTMLCanonicalDiagnosticV1(ctx) != (HTMLCanonicalDiagnosticSnapshotV1{}) || HTMLCanonicalDiagnosticV1(WithHTMLCanonicalDiagnosticV1(ctx)) != (HTMLCanonicalDiagnosticSnapshotV1{}) || WithHTMLCanonicalDiagnosticV1(nil) != nil {
		t.Fatal("context observation leaked or lost parent cancellation propagation")
	}
	wire, err := json.Marshal(got)
	if err != nil || strings.Contains(string(wire), secret) || strings.Contains(string(wire), org.String()) || strings.Contains(string(wire), "Path") || strings.Contains(string(wire), "error") {
		t.Fatal("diagnostic retained private data or causes")
	}
	if err := c.holdScratchAtV1(observed, 17, "canonical_scratch"); err != nil {
		t.Fatal(err)
	}
	if HTMLCanonicalDiagnosticV1(observed) != got {
		t.Fatal("immutable refusal was reconstructed from later live accounting")
	}
	c.CloseConsumerV1()
	if coordinator.SnapshotV1(org).Organisation.ParentBytes != 33 {
		t.Fatal("observation changed live producer conjunction")
	}
	c.finishV1()
	if coordinator.SnapshotV1(org) != (workguard.SnapshotV1{}) {
		t.Fatal("original joined consumer did not release")
	}
	if err := factory.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}
