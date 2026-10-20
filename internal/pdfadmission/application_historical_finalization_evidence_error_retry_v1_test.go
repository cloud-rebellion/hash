// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"testing"
	"time"
)

// Actual HTTP failure outputs are retained by the genuine native owner.
// Re-entry cannot overwrite either live opaque error handle or issue new IO;
// only the original error consumer Close may retire that actual debt.
func TestHistoricalEvidenceStickyErrorAcrossVerifyAndRetainV1(t *testing.T) {
	for _, retentionFirst := range []bool{false, true} {
		name := "verify"
		if retentionFirst {
			name = "retain"
		}
		t.Run(name, func(t *testing.T) {
			gate := &historicalEvidencePeerGateV1{failure: true}
			_, evidence, fixture, coordinator, _, gets := historicalFinalizationEvidenceFixtureWithPeerV1(t, gate)
			var err error
			if retentionFirst {
				err = evidence.RetainIntentArtifactsV1()
			} else {
				err = evidence.VerifyIntentArtifactsV1()
			}
			if err == nil {
				t.Fatal("actual provider failure accepted")
			}
			firstVerify, firstRetain := evidence.verificationError, evidence.retentionError
			if (firstVerify == nil) == (firstRetain == nil) {
				t.Fatal("original actual error handle missing or duplicated")
			}
			before := coordinator.SnapshotV1(fixture.scope.OrgID)
			// An actual caller deadline can return the error before closeIO joins.
			// Its private stream MUST remain charged during that real interval. Wait
			// only for the actual shared coordinator event, never infer cancel=join or
			// change the original fixture deadline/production resource decision.
			deadline := time.Now().Add(time.Second)
			for before.Global.ProviderStreams != 0 {
				if before.Global.ParentBytes <= 0 {
					t.Fatal("unjoined actual error IO lost Parent", before)
				}
				if time.Now().After(deadline) {
					t.Fatal("actual error local IO failed to join", before)
				}
				time.Sleep(time.Millisecond)
				before = coordinator.SnapshotV1(fixture.scope.OrgID)
			}
			calls := gets.Load()
			if before.Global.ParentBytes <= 0 || before.Global.ProviderStreams != 0 {
				t.Fatal("actual error Parent/localIO lifetime changed", before)
			}
			if err = evidence.VerifyIntentArtifactsV1(); err == nil {
				t.Fatal("re-entry verification accepted a live prior error")
			}
			if err = evidence.RetainIntentArtifactsV1(); err == nil {
				t.Fatal("cross-call retention accepted a live prior error")
			}
			if evidence.verificationError != firstVerify || evidence.retentionError != firstRetain || gets.Load() != calls || coordinator.SnapshotV1(fixture.scope.OrgID) != before {
				t.Fatal("re-entry replaced/lost error debt or issued IO")
			}
		})
	}
}
