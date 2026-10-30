// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Existing native session/SQL test seams qualify only fixed write provenance.
// The real upload/fields/audit-fault E2E retains actual source/cache/rollback
// acceptance; these synthetic rows do not establish PostgreSQL receipts.
func TestPDFTemplateFieldsAuditTagsOnlyCompletedIdentityWriteV1(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cause    error
		head     bool
		internal bool
	}{
		{"write exception", &pgconn.PgError{Code: "P0001"}, false, true},
		{"write no row", pgx.ErrNoRows, false, true},
		{"write cancel", context.Canceled, false, false},
		{"write deadlock", &pgconn.PgError{Code: "40P01"}, false, false},
		{"head exception", &pgconn.PgError{Code: "P0001"}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, session, _ := applicationRequestLoanFixtureV1(t)
			session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
			tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: []pgx.Row{htmlRevisionReadRowTestV1{err: pgx.ErrNoRows}, htmlRevisionReadRowTestV1{err: tc.cause}}}
			if tc.head {
				tx.rows = []pgx.Row{htmlRevisionReadRowTestV1{err: tc.cause}}
			}
			session.state.tx = tx
			ctx := applicationTestContextV1(t)
			var reader *ApplicationHTMLAuthoringReaderV1
			var source *ApplicationPDFTemplateSourceV1
			var writer *ApplicationPDFTemplateFieldsMutationV1
			t.Cleanup(func() {
				if writer != nil {
					writer.CloseConsumerV1()
				} else if source != nil {
					source.CloseConsumerV1()
				}
				if reader != nil {
					reader.CloseConsumerV1()
				}
				if !applicationDoneV1(f.done) {
					close(f.done)
				}
				cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = f.adapter.CloseV1(cleanup)
			})
			err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
				var err error
				reader, err = session.NewHTMLAuthoringReaderV1(call)
				if err != nil {
					return err
				}
				source, err = session.NewPDFTemplateSourceV1(call, reader)
				if err != nil {
					return err
				}
				// Explicit synthetic already-measured source, never caller authority.
				source.state.template = &generated.Template{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, SourceKind: "pdf"}
				source.state.updateLocked = true
				writer, err = session.NewPDFTemplateFieldsMutationV1(call, source)
				if err != nil {
					return err
				}
				writer.state.mutated, writer.state.measured = true, true
				return writer.LogUpdatedV1(call, &audit.Logger{}, uuid.New())
			})
			wantCalls := 2
			if tc.head {
				wantCalls = 1
			}
			if !errors.Is(err, tc.cause) || IsInternalApplicationWriteFailureV1(err) != tc.internal || tx.calls != wantCalls || len(tx.rows) != 0 {
				t.Fatalf("actual PDF audit boundary lost cause/classification: internal=%t calls=%d", IsInternalApplicationWriteFailureV1(err), tx.calls)
			}
		})
	}
}
