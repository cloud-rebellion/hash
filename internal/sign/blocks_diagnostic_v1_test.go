// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"strings"
	"testing"
)

type foreignBlockSignatureStageV1 struct{ error }

func (foreignBlockSignatureStageV1) StageV1() string { return "recipient_recheck" }

func TestBlockSignatureDiagnosticPreservesActualMapperAndPrivateCauseV1(t *testing.T) {
	private := errors.New("synthetic private route /sign/opaque-token and SQL value")
	original := errors.Join(pdfadmission.ErrBlockSignatureRequestV1, private)
	got := blockSignatureFailureV1(blockSignatureDiagnosticV1("signature_request", original))
	if !errors.Is(got, ErrSigningAdmissionUnavailableV1) || !errors.Is(got, private) || !errors.Is(got, pdfadmission.ErrBlockSignatureRequestV1) {
		t.Fatal("diagnostic changed actual admission mapping or original cause")
	}
	if got.Error() != blockSignatureFailureV1(original).Error() {
		t.Fatal("diagnostic changed original client error text")
	}
	if stage := BlockSignatureFailureStageV1(fmt.Errorf("existing outer: %w", got)); stage != "signature_request" || strings.Contains(stage, "opaque") {
		t.Fatal("closed stage lost or private text projected")
	}
	cleanup := blockSignatureDiagnosticV1("deferred_close", pdfadmission.ErrApplicationSessionUnknownV1)
	for _, tc := range []struct {
		err         error
		want        string
		wantPrivate bool
	}{
		{blockSignatureFailureV1(blockSignatureDiagnosticV1("mutation_fields", errors.Join(blockSignatureDiagnosticV1("mutation_fields", private), cleanup))), "mutation_fields", true},
		{blockSignatureFailureV1(blockSignatureDiagnosticV1("retain_publication", errors.Join(nil, cleanup))), "deferred_close", false},
		{blockSignatureFailureV1(blockSignatureDiagnosticV1("mutation_fields", errors.Join(blockSignatureDiagnosticV1("store_evidence", original), cleanup))), "store_evidence", true},
	} {
		if BlockSignatureFailureStageV1(tc.err) != tc.want || errors.Is(tc.err, private) != tc.wantPrivate {
			t.Fatal("outer mapper/join lost closed first cause or sentinel")
		}
	}
	if blockSignatureDiagnosticV1("scope", nil) != nil || BlockSignatureFailureStageV1(nil) != "" || BlockSignatureFailureStageV1(foreignBlockSignatureStageV1{private}) != "" {
		t.Fatal("nil or foreign error acquired diagnostic authority")
	}
	if BlockSignatureFailureStageV1(&blockSignatureStageFailureV1{stage: private.Error(), cause: original}) != "" || BlockSignatureFailureStageV1(blockSignatureDiagnosticV1(private.Error(), original)) != "scope" {
		t.Fatal("unknown label escaped fixed set")
	}
}
func TestBlockSignatureOwnedEntryDiagnosticKeepsUnavailableResultV1(t *testing.T) {
	var engine *Engine
	result, err := engine.signBlocksOwnedV1(context.Background(), nil, SignInput{})
	if result != nil || !errors.Is(err, ErrSigningAdmissionUnavailableV1) || BlockSignatureFailureStageV1(err) != "scope" || err.Error() != ErrSigningAdmissionUnavailableV1.Error() {
		t.Fatal("actual entry changed unavailable result, sentinel, text or closed stage")
	}
}
