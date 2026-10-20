// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
)

func TestResponseReportCapacityRemainsDistinctFromUnavailableV1(t *testing.T) {
	if responseReportAdmissionErrorV1(nil) != nil {
		t.Fatal("nil refusal")
	}
	if got := responseReportAdmissionErrorV1(pdfadmission.ErrParticipantReportCapacityV1); !errors.Is(got, ErrParticipantReportCapacityV1) || errors.Is(got, ErrSigningAdmissionUnavailableV1) {
		t.Fatalf("measured capacity classification: %v", got)
	}
	for _, err := range []error{render.ErrParticipantReportV1, pdfadmission.ErrHTMLSendWorkV1, context.Canceled, errors.New("measurement unavailable")} {
		got := responseReportAdmissionErrorV1(err)
		if !errors.Is(got, err) || !errors.Is(got, ErrSigningAdmissionUnavailableV1) || errors.Is(got, ErrParticipantReportCapacityV1) {
			t.Fatalf("noncapacity error %v classified as %v", err, got)
		}
	}
}
