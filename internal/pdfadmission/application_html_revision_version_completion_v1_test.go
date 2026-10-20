// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestHTMLRevisionVersionFailureCannotSatisfyActualResponseCompletionV1(t *testing.T) {
	for _, mode := range []string{"max_error", "max_overflow", "latest_error", "latest_no_rows", "latest_foreign_org", "insert_error", "insert_empty_id", "insert_foreign_document", "insert_foreign_org", "insert_wrong_number", "context_ended_after_insert"} {
		t.Run(mode, func(t *testing.T) {
			withHTMLRevisionConstructedWriterFixtureV1(t, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
				// This actual fresh measurement completes its independent prerequisite;
				// no boolean is forged to manufacture a response-ready writer.
				policy, report := htmlRevisionFreshMeasurementRowsTestV1(f)
				f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: policy}, htmlRevisionReadRowTestV1{record: report})
				if err := f.writer.MeasureFreshPolicyV1(call); err != nil {
					t.Fatal(err)
				}
				failure := errors.New("synthetic version SQL failure")
				next := generated.DocumentVersion{ID: uuid.New(), DocumentID: f.document.ID, OrgID: f.document.OrgID, VersionNo: 1}
				wantCalls := 2
				switch mode {
				case "max_error":
					f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{err: failure})
					wantCalls = 1
				case "max_overflow":
					f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: struct{ No int32 }{math.MaxInt32}})
					wantCalls = 1
				case "latest_error", "latest_no_rows":
					latestErr := failure
					if mode == "latest_no_rows" {
						latestErr = pgx.ErrNoRows
					}
					f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: struct{ No int32 }{1}}, htmlRevisionReadRowTestV1{err: latestErr})
				case "latest_foreign_org":
					f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: struct{ No int32 }{1}}, htmlRevisionReadRowTestV1{record: generated.GetHTMLRevisionLatestVersionIdentityV1Row{ID: uuid.New(), DocumentID: f.document.ID, OrgID: uuid.New(), VersionNo: 1}})
				default:
					f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: struct{ No int32 }{0}})
					switch mode {
					case "insert_error":
						f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{err: failure})
					case "insert_empty_id":
						next.ID = uuid.Nil
						f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: next})
					case "insert_foreign_document":
						next.DocumentID = uuid.New()
						f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: next})
					case "insert_foreign_org":
						next.OrgID = uuid.New()
						f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: next})
					case "insert_wrong_number":
						next.VersionNo++
						f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: next})
					case "context_ended_after_insert":
						f.tx.rows = append(f.tx.rows, htmlRevisionCollectionObserveRowTestV1{row: htmlRevisionReadRowTestV1{record: next}, beforeScan: f.source.state.cancel})
					}
				}
				calls, held := f.tx.calls, f.coordinator.SnapshotV1(f.document.OrgID)
				err := f.writer.SnapshotVersionV1(call)
				if err == nil || !f.writer.versionAttempted || f.writer.versionWritten || f.tx.calls != calls+wantCalls {
					t.Fatal("failed/inconsistent version became completed", mode, err, f.tx.calls-calls)
				}
				if mode == "max_error" || mode == "latest_error" || mode == "insert_error" {
					if !errors.Is(err, failure) {
						t.Fatal("actual original SQL error lost", err)
					}
				}
				if mode == "latest_no_rows" && !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("actual latest-row absence became acknowledgment", err)
				}
				if f.coordinator.SnapshotV1(f.document.OrgID) != held {
					t.Fatal("version refusal credited original native loans")
				}
				beforeRetry := f.tx.calls
				if err = f.writer.SnapshotVersionV1(call); !errors.Is(err, ErrHTMLRevisionWriterV1) || f.tx.calls != beforeRetry {
					t.Fatal("failed version attempted replacement SQL", err)
				}
				models, finish, err := f.writer.BorrowResultV1(call)
				if err == nil || models != nil || finish != nil || f.writer.responseBorrowed {
					if finish != nil {
						finish()
					}
					t.Fatal("failed version satisfied actual native response completion gate")
				}
			})
		})
	}
}
func TestHTMLRevisionAcknowledgedVersionEnablesOneRetainedResponseV1(t *testing.T) {
	withHTMLRevisionConstructedWriterFixtureV1(t, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
		policy, report := htmlRevisionFreshMeasurementRowsTestV1(f)
		f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: policy}, htmlRevisionReadRowTestV1{record: report})
		if err := f.writer.MeasureFreshPolicyV1(call); err != nil {
			t.Fatal(err)
		}
		row := generated.DocumentVersion{ID: uuid.New(), DocumentID: f.document.ID, OrgID: f.document.OrgID, VersionNo: 1}
		f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: struct{ No int32 }{0}}, htmlRevisionReadRowTestV1{record: row})
		calls := f.tx.calls
		if err := f.writer.SnapshotVersionV1(call); err != nil || !f.writer.versionAttempted || !f.writer.versionWritten || f.tx.calls != calls+2 {
			t.Fatal("actual version acknowledgment did not complete", err)
		}
		models, finish, err := f.writer.BorrowResultV1(call)
		if err != nil || models == nil || finish == nil || models.Document.ID != row.DocumentID || models.Document.OrgID != row.OrgID {
			t.Fatal("actual acknowledged version did not enable response", err)
		}
		defer finish()
		originalName := f.writer.updated.Name
		models.Document.Name = "caller response replacement"
		if f.writer.updated.Name != originalName {
			t.Fatal("mutable response replaced actual retained projection")
		}
		if again, release, err := f.writer.BorrowResultV1(call); err == nil || again != nil || release != nil {
			if release != nil {
				release()
			}
			t.Fatal("response borrow was minted twice")
		}
		if err := f.writer.SnapshotVersionV1(call); !errors.Is(err, ErrHTMLRevisionWriterV1) || f.tx.calls != calls+2 {
			t.Fatal("successful version was replayed", err)
		}
		held := f.coordinator.SnapshotV1(row.OrgID)
		f.writer.CloseConsumerV1()
		if f.writer.resourcesClosed || f.coordinator.SnapshotV1(row.OrgID) != held {
			t.Fatal("closed consumer credited an active original response")
		}
		finish()
		finish()
		if !f.writer.resourcesClosed || f.writer.updated != nil || f.writer.row != nil {
			t.Fatal("actual response join did not clear its original models")
		}
		if f.coordinator.SnapshotV1(row.OrgID) != held {
			t.Fatal("consumer-only response join invented backend retirement")
		}
	})
}
