// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func TestSignerReadDiagnosticFitsOriginalBoundedScopeClassV1(t *testing.T) {
	if applicationSignerScopeHeaderBytesV1 != 8<<20 || applicationSessionMaxWorkV1 != 128 {
		t.Fatal("diagnostics changed original control allocation or registry cap")
	}
	if applicationSignerReadDiagnosticControlBytesV1 <= 128*int64(unsafe.Sizeof(applicationSignerReadDiagnosticV1{})) || applicationSignerReadDiagnosticControlBytesV1 > 8<<20 {
		t.Fatal("all constructor/control/log-copy frames do not fit original scope reservation")
	}
}

// Shells are negative controls only. No fabricated scope/session/grant is ever
// accepted as a positive owner, and these checks perform no SQL or dispatch.
func TestSignerReadDiagnosticRejectsUnregisteredAndCopiedShellsV1(t *testing.T) {
	coordinator, work := applicationSessionResourcesTestV1(t, 2)
	factory, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(original)
	shell := &ApplicationSignerReaderV1{factory: factory, finishScope: func() { t.Error("negative shell acquired close authority") }}
	shell.self = shell
	copy := &ApplicationSignerReaderV1{self: shell, factory: factory, finishScope: shell.finishScope}
	for _, candidate := range []*ApplicationSignerReaderV1{nil, {}, shell, copy} {
		for _, route := range []SignerReadDiagnosticRouteV1{SignerReadDiagnosticFieldsV1, SignerReadDiagnosticPDFV1, SignerReadDiagnosticCommentsV1, SignerReadDiagnosticViewV1, SignerReadDiagnosticPackageV1} {
			candidate.LogRefusalV1(context.Background(), route, SignerReadDiagnosticLookupV1, SignerReadDiagnosticOpenV1)
			candidate.LogRefusalV1(context.Background(), route, SignerReadDiagnosticViewMutationV1, SignerReadDiagnosticViewMutationPhaseV1)
		}
	}
	if output.Len() != 0 {
		t.Fatal("unregistered/copied owner emitted a trusted diagnostic")
	}
	if got := coordinator.SnapshotV1(uuid.Nil); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 || factory.PendingV1().WorkSessions != 0 {
		t.Fatal("diagnostics granted resource or SQL authority", got)
	}
}

// Diagnostic labels only select the existing bounded numeric observation. A
// package descriptor lookup/recheck cannot acquire View mutation or unknown
// operation/phase authority through that label. Preserve prior numeric values.
func TestSignerPackageDiagnosticLabelsRemainFiniteV1(t *testing.T) {
	if SignerReadDiagnosticOtherV1 != 0 || SignerReadDiagnosticFieldsV1 != 1 || SignerReadDiagnosticPDFV1 != 2 || SignerReadDiagnosticCommentsV1 != 3 || SignerReadDiagnosticViewV1 != 4 || SignerReadDiagnosticPackageV1 != 5 {
		t.Fatal("existing diagnostic route values changed")
	}
	for _, operation := range []SignerReadDiagnosticOperationV1{SignerReadDiagnosticLookupV1, SignerReadDiagnosticRecheckV1} {
		for _, phase := range []SignerReadDiagnosticPhaseV1{SignerReadDiagnosticOpenV1, SignerReadDiagnosticModelsV1, SignerReadDiagnosticCommitV1, SignerReadDiagnosticCloseSQLV1} {
			if !validSignerReadDiagnosticLabelsV1(SignerReadDiagnosticPackageV1, operation, phase) {
				t.Fatal("genuine package read diagnostic label refused", operation, phase)
			}
		}
	}
	for _, labels := range []struct {
		route     SignerReadDiagnosticRouteV1
		operation SignerReadDiagnosticOperationV1
		phase     SignerReadDiagnosticPhaseV1
	}{
		{SignerReadDiagnosticOtherV1, SignerReadDiagnosticLookupV1, SignerReadDiagnosticModelsV1},
		{255, SignerReadDiagnosticLookupV1, SignerReadDiagnosticModelsV1},
		{SignerReadDiagnosticPackageV1, SignerReadDiagnosticViewMutationV1, SignerReadDiagnosticViewMutationPhaseV1},
		{SignerReadDiagnosticPackageV1, SignerReadDiagnosticLookupV1, SignerReadDiagnosticViewMutationPhaseV1},
		{SignerReadDiagnosticPackageV1, SignerReadDiagnosticViewMutationV1, SignerReadDiagnosticModelsV1},
		{SignerReadDiagnosticPackageV1, 0, SignerReadDiagnosticModelsV1},
		{SignerReadDiagnosticPackageV1, 255, SignerReadDiagnosticModelsV1},
		{SignerReadDiagnosticPackageV1, SignerReadDiagnosticLookupV1, 0},
		{SignerReadDiagnosticPackageV1, SignerReadDiagnosticLookupV1, 255},
	} {
		if validSignerReadDiagnosticLabelsV1(labels.route, labels.operation, labels.phase) {
			t.Fatal("crossed/unknown package diagnostic labels accepted", labels)
		}
	}
	if !validSignerReadDiagnosticLabelsV1(SignerReadDiagnosticViewV1, SignerReadDiagnosticViewMutationV1, SignerReadDiagnosticViewMutationPhaseV1) {
		t.Fatal("existing genuine View mutation diagnostic changed")
	}
}
