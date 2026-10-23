// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestHistoricalSourceDiagnosticPreservesOriginalCauseAndClosedNestedStageV1(t *testing.T) {
	private := errors.New("synthetic private source /objects/opaque and SQL value")
	original := errors.Join(ErrHistoricalFinalizationSourceV1, private)
	got := historicalSourceDiagnosticV1("source_delegated", historicalSourceDiagnosticV1("delegated_document", original))
	if !errors.Is(got, private) || !errors.Is(got, ErrHistoricalFinalizationSourceV1) || got.Error() != original.Error() || HistoricalFinalizationSourceFailureStageV1(fmt.Errorf("existing outer: %w", got)) != "delegated_document" {
		t.Fatal("original source error or closed nested stage changed")
	}
	if historicalSourceDiagnosticV1("source_scope", nil) != nil || HistoricalFinalizationSourceFailureStageV1(nil) != "" || HistoricalFinalizationSourceFailureStageV1(private) != "" || HistoricalFinalizationSourceFailureStageV1(&historicalSourceStageFailureV1{stage: private.Error(), cause: original}) != "" {
		t.Fatal("nil/foreign/unknown error acquired stage authority")
	}
	var work *ApplicationHTMLSendWorkV1
	owner, err := work.NewHistoricalFinalizationSourceEvidenceV1(context.Background(), nil)
	if owner != nil || !errors.Is(err, ErrHistoricalFinalizationSourceV1) || err.Error() != ErrHistoricalFinalizationSourceV1.Error() || HistoricalFinalizationSourceFailureStageV1(err) != "source_new_scope" {
		t.Fatal("actual unissued native owner changed refusal or stage")
	}
}
