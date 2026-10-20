// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"errors"
	"github.com/bright-interaction/hash/internal/workguard"
	"testing"
)

// The existing actual HTTP/native owner fixture has an unchanged1GiB Parent
// coordinator. It supplies explicitly synthetic already-open SQL rows, never
// public PG/source/intent authority. The real stream producer, coordinator,
// exact native body borrower and original retention/verification all execute.
func TestHistoricalEvidenceActualStreamingFitsWithoutFullBodyReservationV1(t *testing.T) {
	_, evidence, fixture, coordinator, ctx, gets := historicalFinalizationEvidenceFixtureV1(t)
	baseline := coordinator.SnapshotV1(fixture.scope.OrgID)
	const originalFixtureParent int64 = 1 << 30
	const remainingParent int64 = 96 << 20
	hold := originalFixtureParent - baseline.Global.ParentBytes - remainingParent
	if hold <= 0 {
		t.Fatal("original native fixture leaves no positive pressure lane", baseline)
	}
	occupied, err := coordinator.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ParentBytes: hold})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	calls := gets.Load()
	// This original full128MiB retained producer recipe cannot fit. The new
	// producer must genuinely stream; merely lowering this cost for the same
	// full-body allocation would fail its concrete storage ownership tests.
	limits := evidence.limits
	old := 4*(limits.ObjectBytes+1) + 4*limits.MetadataBytes + 4*limits.HeaderBytes + 2*limits.VersionIDBytes
	if g, err := coordinator.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ParentBytes: old, ProviderStreams: 1}); g != nil || !errors.Is(err, workguard.ErrUnavailableV1) {
		if g != nil {
			g.Close()
		}
		t.Fatal("pressure did not reject original full body recipe", err)
	}
	if coordinator.SnapshotV1(fixture.scope.OrgID) != before || gets.Load() != calls {
		t.Fatal("control refusal mutated or issued IO")
	}
	if err = evidence.VerifyIntentArtifactsV1(); err != nil {
		t.Fatal("real streamed exact four artifacts refused", err)
	}
	if gets.Load() != calls+4 || coordinator.SnapshotV1(fixture.scope.OrgID) != before {
		t.Fatal("stream results/provider did not join and drain", gets.Load()-calls, coordinator.SnapshotV1(fixture.scope.OrgID))
	}
	if err = evidence.RetainIntentArtifactsV1(); err != nil {
		t.Fatal("real original retention and postverify refused", err)
	}
	if gets.Load() != calls+12 || coordinator.SnapshotV1(fixture.scope.OrgID) != before {
		t.Fatal("original retention order/count or actual stream join changed", gets.Load()-calls, coordinator.SnapshotV1(fixture.scope.OrgID))
	}
	occupied.Close()
	if coordinator.SnapshotV1(fixture.scope.OrgID) != baseline {
		t.Fatal("actual pressure grant failed to drain")
	}
}
