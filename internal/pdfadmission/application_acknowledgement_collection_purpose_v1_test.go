// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import "testing"

func TestAcknowledgementUsesActualHistoricalCollectionSQLSuiteV1(t *testing.T) {
	// Pure dispatch selector only, never a synthetic DBTX/session or authority.
	// Actual PG acceptance must prove the same scoped header/pins and original
	// GetRecipient run in the real native sent/in_progress transaction.
	if (&ApplicationHTMLSendWorkV1{}).historicalSigningCollectionsV1() {
		t.Fatal("missing stage selected live ceremony collection suite")
	}
	// Stage now performs genuine M109 capture/recovery signing-page checks on
	// finalizing roots. Its actual PostgreSQL completion/recovery regression is
	// TestOrdinaryFinalizationFrozenPreparationRecoveryV1E2E; this pure selector
	// check also guards that fixing it does not change ordinary Send dispatch.
	for _, purpose := range []HTMLSendSQLPurposeV1{HTMLBlockSignPreparationV1, HTMLBlockSignMutationV1, HTMLHistoricalFinalizationClaimV1, HTMLHistoricalFinalizationStageV1, HTMLHistoricalFinalizationResumeV1, HTMLHistoricalFinalizationPublicationV1, HTMLHistoricalFinalizationSourceV1, HTMLAcknowledgementMutationV1} {
		work := &ApplicationHTMLSendWorkV1{stage: &ApplicationHTMLSendSQLStageV1{purpose: purpose}}
		if !work.historicalSigningCollectionsV1() {
			t.Fatal("actual historical mutation routed through draft/sealing-only header", purpose)
		}
	}
	for _, purpose := range []HTMLSendSQLPurposeV1{HTMLSendPreparationV1, HTMLSendAdmissionV1, HTMLSendSnapshotV1, HTMLSendCompletionV1, HTMLSendIntentReadV1, HTMLSendIntentMarkV1, HTMLSendAbortV1, HTMLSendPinV1, HTMLSendCompletedV1, HTMLSendSourceV1, HTMLSendQuotaV1, HTMLSendEIDASV1, HTMLSendSnapshotFieldsV1} {
		work := &ApplicationHTMLSendWorkV1{stage: &ApplicationHTMLSendSQLStageV1{purpose: purpose}}
		if work.historicalSigningCollectionsV1() {
			t.Fatal("original Send draft/sealing suite widened", purpose)
		}
	}
}
