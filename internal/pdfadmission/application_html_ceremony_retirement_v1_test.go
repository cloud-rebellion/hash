// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Actual workflow, reader, source, collections and coordinator operations use
// typed synthetic SQL acknowledgements and a synthetic backend witness. This
// regression proves neither PostgreSQL capture nor the full signing journey.
func TestHTMLCeremonyRetirementUsesSameSuccessfulCurrentValidationV1(t *testing.T) {
	for _, mode := range []string{"validated", "skipped", "failed"} {
		t.Run(mode, func(t *testing.T) {
			actor := uuid.New()
			work, f, _, _, tx, _ := htmlCeremonyWorkflowFixtureV1(t, HTMLCeremonyRetireV1, actor, nil)
			input, document, _ := testfixture.HTMLContract(t)
			document.ID, document.OrgID, document.SenderID = f.scope.DocumentID, f.scope.OrgID, actor
			document.Status = "changes_requested"
			document.UpdatedAt = pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 0, 0, 0, 1, time.UTC), Valid: true}
			document.BlocksJson, document.Metadata, document.MetadataRedactionReport = []byte("[]"), []byte("{}"), []byte("{}")
			var err error
			document.HtmlSourceJson, err = htmlsource.New(input, document)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "failed" {
				// The normalized source itself is valid; its separately read row
				// has the wrong PDF pin, so actual Current validation must fail.
				document.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
				document.HtmlCurrentSourceJson = append([]byte(nil), document.HtmlSourceJson...)
				document.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 1, Valid: true}
				document.HtmlCurrentPageCount = pgtype.Int4{Int32: 1, Valid: true}
				document.HtmlReviewedMaterializationID = document.HtmlCurrentMaterializationID
			}
			member := generated.User{ID: actor, OrgID: document.OrgID, Name: "Owner", Email: "owner@example.test", Role: "owner"}
			tx.rows = htmlCeremonyReadRowsV1(*document, member, true)
			if mode == "failed" {
				dh := tx.rows[0].(htmlRevisionReadRowTestV1).record.(generated.GetHTMLRevisionDocumentReadHeaderV1Row)
				dh.HtmlCurrentWireBytes = int64(len(document.HtmlCurrentSourceJson))
				tx.rows[0] = htmlRevisionReadRowTestV1{record: dh}
				current := generated.ReadSignerCurrentMaterializationV1Row{ID: uuid.UUID(document.HtmlCurrentMaterializationID.Bytes), DocumentID: document.ID, OrgID: document.OrgID,
					Sequence: 1, PageCount: 1, PdfKey: "different-pdf-key", PdfVersionID: document.PdfStorageVersionID.String, PdfSha256: document.PdfSha256, SourceJson: document.HtmlCurrentSourceJson}
				mh := generated.GetSignerCurrentMaterializationHeaderV1Row{MaterializationID: current.ID, DocumentID: document.ID, OrgID: document.OrgID,
					SourceWireBytes: int64(len(current.SourceJson)), RawTextBytes: signerMaterializationRawBytesV1(&current), MeasurementServerVersionNum: 160015, ServerVersionNum: 160015}
				last := tx.rows[len(tx.rows)-1]
				tx.rows = append(tx.rows[:len(tx.rows)-1], htmlRevisionReadRowTestV1{record: mh}, last, htmlRevisionReadRowTestV1{record: current})
			}
			header := generated.GetHTMLRevisionSnapshotSizeHeaderV1Row{ID: document.ID, OrgID: document.OrgID, UpdatedAt: document.UpdatedAt, ServerVersionNum: 160015}
			tx.rows = append(tx.rows,
				htmlRevisionReadRowTestV1{record: header},
				htmlRevisionReadRowTestV1{record: generated.LockHTMLRevisionSnapshotSizeCachesV1Row{}},
				htmlRevisionReadRowTestV1{record: header})
			if mode == "validated" {
				id := uuid.New()
				tx.rows = append(tx.rows, htmlRevisionReadRowTestV1{record: struct{ ID uuid.UUID }{id}}, htmlRevisionReadRowTestV1{record: generated.HtmlRevisionSnapshotSizesV1{
					SnapshotID: id, DocumentID: document.ID, OrgID: document.OrgID,
					SourceWireBytes: int64(len(document.HtmlSourceJson)), ReportWireBytes: int64(len(document.MetadataRedactionReport)),
					MeasurementServerVersionNum: 160015,
				}})
			}
			err = work.WithTxV1(func(call context.Context, _ generated.DBTX, reader *ApplicationHTMLRevisionReaderV1) error {
				_, err := work.ReadActorDocumentV1(call, func(a HTMLRevisionReadAccessV1) error { return nil }, func(_ HTMLRevisionReadAccessV1, user *generated.User) error {
					if user == nil || user.ID != actor || user.Role != "owner" {
						return errors.New("original actor changed")
					}
					return nil
				})
				if err != nil {
					return err
				}
				source, err := work.NewSourceV1(call)
				if err != nil {
					return err
				}
				defer source.CloseConsumerV1()
				if err = source.ValidateV1(); err != nil {
					return err
				}
				if err = source.ValidateRetirementReviewV1(); err != nil {
					return err
				}
				if mode != "skipped" {
					err = source.ValidateCurrentV1()
					if (mode == "failed") != (err != nil) {
						t.Fatalf("original Current validation mode=%s error=%v", mode, err)
					}
				}
				collections, err := reader.NewCollectionsV1(call)
				if err != nil {
					return err
				}
				defer collections.CloseConsumerV1()
				before := tx.calls
				err = work.CaptureRetiredV1(call, source, collections)
				if mode == "validated" {
					if err != nil || tx.calls != before+2 || !work.capturedRetired {
						t.Fatalf("validated retirement failed: calls=%d error=%v", tx.calls-before, err)
					}
					if err := source.ValidateCurrentV1(); err == nil {
						t.Fatal("capture made one-shot Current validation generally reusable")
					}
					return nil
				}
				if !errors.Is(err, ErrHTMLRevisionSourceV1) || tx.calls != before || work.capturedRetired {
					t.Fatalf("unvalidated source reached capture: mode=%s calls=%d error=%v", mode, tx.calls-before, err)
				}
				return nil
			})
			if err != nil || len(tx.rows) != 0 {
				t.Fatalf("actual retirement regression failed: mode=%s remaining=%d error=%v", mode, len(tx.rows), err)
			}
		})
	}
}
