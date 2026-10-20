// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdftemplateauthoring

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
)

// This tests only error taxonomy, never a physical-retirement proof. The real
// trigger-error rollback and genuine wait regression qualify the actual owner.
func TestPDFCreationStatementTaxonomyDoesNotHideUnknownOrCapacityV1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, code := range []string{"P0001", "23514", "23505"} {
		err := errors.Join(pdfadmission.ErrApplicationSessionV1, &pgconn.PgError{Severity: "ERROR", Code: code, Message: "synthetic ordinary statement failure"})
		if !ordinaryPDFCreateStatementV1(ctx, err) {
			t.Fatal("ordinary structured server failure lost", code)
		}
		known := &retiredPDFCreateStatementFailureV1{cause: err}
		if !IsRetiredCreateStatementFailureV1(known) {
			t.Fatal("private original statement classification lost")
		}
		for _, extra := range []error{pdfadmission.ErrApplicationSessionUnknownV1, pdfadmission.ErrApplicationAdmissionV1} {
			if ordinaryPDFCreateStatementV1(ctx, errors.Join(err, extra)) || IsRetiredCreateStatementFailureV1(errors.Join(known, extra)) {
				t.Fatal("unknown or admission debt was hidden", extra)
			}
		}
	}
	for _, code := range []string{"08006", "53300", "54000", "55P03", "57014", "58000", "XX000"} {
		err := errors.Join(pdfadmission.ErrApplicationSessionV1, &pgconn.PgError{Severity: "ERROR", Code: code})
		if ordinaryPDFCreateStatementV1(ctx, err) {
			t.Fatal("native connection/resource/lock/cancel/system failure became ordinary500", code)
		}
	}
	for _, err := range []error{nil, errors.New("untyped driver failure"), &pgconn.PgError{Severity: "ERROR", Code: "P0001"}, errors.Join(pdfadmission.ErrApplicationSessionV1, &pgconn.PgError{Severity: "FATAL", Code: "P0001"})} {
		if ordinaryPDFCreateStatementV1(ctx, err) || IsRetiredCreateStatementFailureV1(err) {
			t.Fatal("unowned/untyped error supplied statement classification", err)
		}
	}
	cancel()
	if ordinaryPDFCreateStatementV1(ctx, errors.Join(pdfadmission.ErrApplicationSessionV1, &pgconn.PgError{Severity: "ERROR", Code: "P0001"})) {
		t.Fatal("canceled source became ordinary statement failure")
	}
}
