// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSignerFieldsFailureKeepsStatementErrorsDistinctFromAdmissionV1(t *testing.T) {
	databaseError := &pgconn.PgError{Code: "P0001", Message: "synthetic private database diagnostic"}
	for _, tc := range []struct {
		name        string
		failure     error
		unavailable bool
	}{
		{"nil", nil, false},
		{"ordinary", errors.New("synthetic ordinary failure"), false},
		{"statement", errors.Join(pdfadmission.ErrApplicationSessionV1, databaseError), false},
		{"measurement-statement", errors.Join(pdfadmission.ErrHTMLAuditEventV1, pdfadmission.ErrApplicationSessionV1, databaseError), false},
		{"admission", pdfadmission.ErrApplicationSessionV1, true},
		{"request", pdfadmission.ErrSignerFieldsRequestV1, true},
		{"request-and-statement", errors.Join(pdfadmission.ErrSignerFieldsRequestV1, databaseError), true},
		{"retirement-unknown", errors.Join(pdfadmission.ErrApplicationSessionV1, pdfadmission.ErrApplicationSessionUnknownV1, databaseError), true},
		{"commit-unknown", errors.Join(pdfadmission.ErrApplicationSessionV1, pdfadmission.ErrApplicationSessionCommitUnknownV1, databaseError), true},
		{"canceled", errors.Join(pdfadmission.ErrApplicationSessionV1, context.Canceled, databaseError), true},
		{"deadline", errors.Join(pdfadmission.ErrApplicationSessionV1, context.DeadlineExceeded, databaseError), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := signerFieldsFailureV1(tc.failure)
			if (got == nil) != (tc.failure == nil) || errors.Is(got, ErrSigningAdmissionUnavailableV1) != tc.unavailable {
				t.Fatal("field failure lost its original server/admission distinction")
			}
			if tc.failure != nil && !errors.Is(got, tc.failure) {
				t.Fatal("field failure lost its original private cause")
			}
		})
	}
}
