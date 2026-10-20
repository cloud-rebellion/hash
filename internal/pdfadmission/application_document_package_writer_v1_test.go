// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"errors"
	"math"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// These are private scalar preflight and native-state observation tests.
// Actual writer/auth/provider/COMMIT evidence comes from the PostgreSQL suite.
func TestDocumentPackageWriteV1RefusesUnavailableDraftBeforeWork(t *testing.T) {
	for _, tc := range []struct {
		name  string
		draft *applicationDocumentPackageDraftSnapshotV1
	}{
		{"no package-aware snapshot", nil},
		{"full package", &applicationDocumentPackageDraftSnapshotV1{count: 16}},
		{"generation exhausted", &applicationDocumentPackageDraftSnapshotV1{present: true, header: generated.DocumentPackagesV1{DraftGeneration: math.MaxInt64}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &applicationDocumentPackageOperationStateV1{draft: tc.draft}
			if e := s.prepareAttachmentV1(DocumentPackageAttachmentIntentV1{Ordinal: 1, Title: "DPA"}, "", ""); !errors.Is(e, ErrDocumentPackageWriteV1) || s.selectionLoan != nil {
				t.Fatal("reached work without eligible package", e)
			}
		})
	}
}
func TestDocumentPackageCommitAcknowledgementUsesActualFinalSessionV1(t *testing.T) {
	if (*ApplicationDocumentPackageOperationV1)(nil).CommitAcknowledgedV1() {
		t.Fatal("nil acknowledged")
	}
	for _, attempted := range []bool{false, true} {
		for _, ended := range []bool{false, true} {
			for _, unknown := range []bool{false, true} {
				native := &applicationOwnedSessionV1{commitAttempted: attempted, ended: ended, commitUnknown: unknown}
				state := &applicationDocumentPackageOperationStateV1{}
				state.stages[1].session = &ApplicationSessionV1{state: native}
				op := &ApplicationDocumentPackageOperationV1{state: state}
				if got := op.CommitAcknowledgedV1(); got != (attempted && ended && !unknown) {
					t.Fatal("dispatch/rollback/unknown confused with acknowledgement", attempted, ended, unknown, got)
				}
			}
		}
	}
}
