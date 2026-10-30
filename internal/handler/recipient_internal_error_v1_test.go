// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Only the private completed-write tag can select500. An arbitrary server
// error/no-row, missing cache, cancellation or uncertain outcome cannot gain it.
// Real fixed-statement500 paths retain their actual PG rollback/retry E2E tests.
func TestRecipientNativeUntaggedFailuresKeepAvailabilityFenceV1(t *testing.T) {
	for _, cause := range []error{pgx.ErrNoRows, &pgconn.PgError{Code: "P0001", Message: "PRIVATE synthetic database detail"}, &pgconn.PgError{Code: "40001"}, &pgconn.PgError{Code: "55P03"}, context.Canceled, context.DeadlineExceeded, io.EOF, pdfadmission.ErrApplicationSessionUnknownV1, pdfadmission.ErrApplicationSessionCommitUnknownV1, pdfadmission.ErrHTMLRevisionReadV1, pdfadmission.ErrPlainRecipientWriterV1, pdfadmission.ErrHTMLAuditEventV1} {
		w := httptest.NewRecorder()
		(&Server{}).writeRecipientMutationError(w, "synthetic recipient mutation", errors.Join(pdfadmission.ErrApplicationSessionV1, cause))
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "PRIVATE") {
			t.Fatalf("untagged failure escaped availability/privacy fence: %d %s", w.Code, w.Body.String())
		}
	}
}
