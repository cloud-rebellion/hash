// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"errors"
	"github.com/bright-interaction/hash/internal/workguard"
	"testing"
)

// Existing synthetic SQL fixture exercises the genuine native Evidence owner,
// positive retained control, actual shared coordinator and concrete provider.
// It does not establish actual public PG/intent or deployment capacity.
func TestHistoricalEvidenceExactDenialFrameAndErrorCompatibilityV1(t *testing.T) {
	_, evidence, fixture, coordinator, ctx, gets := historicalFinalizationEvidenceFixtureV1(t)
	occupied, err := coordinator.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	calls := gets.Load()
	err = evidence.VerifyIntentArtifactsV1()
	var detail *HistoricalFinalizationEvidenceCapacityErrorV1
	if !errors.As(err, &detail) || !errors.Is(err, workguard.ErrUnavailableV1) || !errors.Is(err, ErrHistoricalFinalizationEvidenceV1) || err.Error() != ErrHistoricalFinalizationEvidenceV1.Error()+"\n"+workguard.ErrUnavailableV1.Error() {
		t.Fatal("original error chain/string changed", err)
	}
	d := detail.DenialV1()
	if d.Reason != workguard.AdmissionGlobalResourceV1 || d.Dimension != workguard.AdmissionProviderStreamsV1 || d.Before.Global.ParentBytes <= before.Global.ParentBytes || d.Before.Organisation.ParentBytes <= before.Organisation.ParentBytes || d.Before.Global.DBStagingBytes != before.Global.DBStagingBytes || d.Before.Organisation.DBStagingBytes != before.Organisation.DBStagingBytes || d.Before.GlobalGrants != before.GlobalGrants+1 || d.Before.OrganisationGrants != before.OrganisationGrants+1 || d.Before.Global.ProviderStreams != 1 || d.Requested.ProviderStreams != 1 || d.Requested.ParentBytes != 0 || d.Requested.DBStagingBytes != 0 {
		t.Fatal("wrong exact refusal", d)
	}
	if gets.Load() != calls || coordinator.SnapshotV1(fixture.scope.OrgID) != before {
		t.Fatal("denial issued IO or changed debt")
	}
	copy := d
	d.Before.Global.ParentBytes = 999
	if detail.DenialV1() != copy {
		t.Fatal("external mutation changed observation")
	}
	occupied.Close()
	if err := evidence.VerifyIntentArtifactsV1(); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != calls+4 {
		t.Fatal("denied observation acquired authority or blocked later genuine call")
	}
}
