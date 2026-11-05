// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package pdfadmission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// These SQL rows are synthetic witnesses around the real native callback and
// coordinator. The real PostgreSQL notification journey proves the M67 clock;
// this regression proves which acknowledged stamp reaches the generated CAS.
type htmlReportClockTxV1 struct {
	*htmlRevisionReadTxTestV1
	expectedFreeze pgtype.Timestamptz
	freezeCalls    int
}

func (x *htmlReportClockTxV1) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "-- name: FreezeDocumentVariables") {
		x.freezeCalls++
		if len(args) != 4 || args[3] != x.expectedFreeze {
			return htmlRevisionReadRowTestV1{err: pgx.ErrNoRows}
		}
	}
	return x.htmlRevisionReadTxTestV1.QueryRow(ctx, sql, args...)
}

func TestHTMLCreationReportClockReachesPurposeAndVariablesCASV1(t *testing.T) {
	for _, purpose := range []documentpurpose.Purpose{"", documentpurpose.Signing} {
		t.Run(string(purpose), func(t *testing.T) {
			f, session, coordinator := applicationRequestLoanFixtureV1(t)
			session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
			ctx := applicationTestContextV1(t)
			doc := generated.Document{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, TemplateID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, Name: "Approved HTML contract", SenderID: uuid.New(), Status: "draft", SourceKind: "pdf", VariablesJson: []byte(`{}`), Metadata: []byte(`{}`), MetadataRedactionReport: []byte(`{}`), UpdatedAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}}
			reported := doc
			reported.MetadataRedactionReport = []byte(`{"schema_version": 1}`)
			reported.UpdatedAt.Time = reported.UpdatedAt.Time.Add(time.Microsecond)
			purposeRow := reported
			rows := []pgx.Row{htmlRevisionReadRowTestV1{record: doc}, htmlRevisionReadRowTestV1{record: reported}}
			if purpose != "" {
				purposeRow.Metadata = []byte(`{"hash:document-purpose:v1": {"schema_version": 1, "purpose": "signing"}}`)
				purposeRow.UpdatedAt.Time = purposeRow.UpdatedAt.Time.Add(time.Microsecond)
				rows = append(rows, htmlRevisionReadRowTestV1{record: purposeRow}, htmlRevisionReadRowTestV1{record: generated.HtmlCreationResponseSizesV1{DocumentID: doc.ID, OrgID: doc.OrgID, MetadataWireBytes: int64(len(purposeRow.Metadata)), MeasurementServerVersionNum: 160015}})
			}
			frozen := purposeRow
			frozen.UpdatedAt.Time = frozen.UpdatedAt.Time.Add(time.Microsecond)
			rows = append(rows, htmlRevisionReadRowTestV1{record: frozen})
			tx := &htmlReportClockTxV1{htmlRevisionReadTxTestV1: &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: rows}, expectedFreeze: purposeRow.UpdatedAt}
			session.state.tx = tx
			var writer *ApplicationHTMLCreationWriterV1
			t.Cleanup(func() {
				if writer != nil {
					writer.CloseConsumerV1()
				}
				if !applicationDoneV1(f.done) {
					close(f.done)
				}
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				_ = f.adapter.CloseV1(cleanup)
				if coordinator.SnapshotV1(doc.OrgID) != (workguard.SnapshotV1{}) {
					t.Error("native report-clock debt survived joined cleanup")
				}
			})
			err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
				var err error
				writer, err = session.NewHTMLCreationWriterV1(call, HTMLCreationInputsV1{StoredMaster: []byte(`{}`), StoredDefaults: []byte(`{}`), CanonicalMaster: []byte(`{}`), CanonicalDefaults: []byte(`{}`), Variables: []byte(`{}`), Sections: []byte(`{}`)})
				if err != nil {
					return err
				}
				if _, err = writer.CreatePDFDocument(call, generated.CreatePDFDocumentParams{OrgID: doc.OrgID, TemplateID: doc.TemplateID, Name: doc.Name, SenderID: doc.SenderID, PdfStorageKey: pgtype.Text{String: "owned/source", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "owned-version", Valid: true}, PdfSha256: make([]byte, 32), EvidenceVersionPinsRequired: true}); err != nil {
					return err
				}
				if err = writer.UpdateMetadataRedactionReport(call, generated.UpdateMetadataRedactionReportParams{ID: doc.ID, MetadataRedactionReport: []byte(`{"schema_version":1}`)}); err != nil {
					return err
				}
				current, err := writer.RecordPurposeV1(call, purpose)
				if err != nil {
					return err
				}
				if current.UpdatedAt != purposeRow.UpdatedAt || string(current.MetadataRedactionReport) != string(reported.MetadataRedactionReport) {
					t.Fatal("purpose recording returned the INSERT stamp or lost the acknowledged report")
				}
				_, err = writer.FreezeVariablesV1(call, current.UpdatedAt)
				return err
			})
			if err != nil || tx.freezeCalls != 1 || len(tx.rows) != 0 {
				t.Fatal("current report/purpose stamp did not reach exact variables CAS", err, tx.freezeCalls, len(tx.rows))
			}
		})
	}
}

func TestHTMLCreationReportRefreshRefusesDifferentOwnedRowV1(t *testing.T) {
	for _, changed := range []string{"document", "tenant", "source", "report-bound", "read-failure"} {
		t.Run(changed, func(t *testing.T) {
			f, session, _ := applicationRequestLoanFixtureV1(t)
			session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
			ctx := applicationTestContextV1(t)
			doc := generated.Document{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, TemplateID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, SenderID: uuid.New(), Name: "Owned fresh source", Status: "draft", SourceKind: "pdf", VariablesJson: []byte(`{}`), MetadataRedactionReport: []byte(`{}`), UpdatedAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}}
			row := doc
			row.UpdatedAt.Time = row.UpdatedAt.Time.Add(time.Microsecond)
			switch changed {
			case "document":
				row.ID = uuid.New()
			case "tenant":
				row.OrgID = uuid.New()
			case "source":
				row.SourceKind = "blocks"
			case "report-bound":
				row.MetadataRedactionReport = []byte(`{"unexpected": true}`)
			}
			witness := htmlRevisionReadRowTestV1{record: row}
			if changed == "read-failure" {
				witness.err = pgx.ErrNoRows
			}
			tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: []pgx.Row{htmlRevisionReadRowTestV1{record: doc}, witness}}
			session.state.tx = tx
			var writer *ApplicationHTMLCreationWriterV1
			t.Cleanup(func() {
				if writer != nil {
					writer.CloseConsumerV1()
				}
				if !applicationDoneV1(f.done) {
					close(f.done)
				}
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				_ = f.adapter.CloseV1(cleanup)
			})
			err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
				var err error
				writer, err = session.NewHTMLCreationWriterV1(call, HTMLCreationInputsV1{StoredMaster: []byte(`{}`), StoredDefaults: []byte(`{}`), CanonicalMaster: []byte(`{}`), CanonicalDefaults: []byte(`{}`), Variables: []byte(`{}`), Sections: []byte(`{}`)})
				if err != nil {
					return err
				}
				if _, err = writer.CreatePDFDocument(call, generated.CreatePDFDocumentParams{OrgID: doc.OrgID, TemplateID: doc.TemplateID, Name: doc.Name, SenderID: doc.SenderID, PdfStorageKey: pgtype.Text{String: "owned/source", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "owned-version", Valid: true}, PdfSha256: make([]byte, 32), EvidenceVersionPinsRequired: true}); err != nil {
					return err
				}
				err = writer.UpdateMetadataRedactionReport(call, generated.UpdateMetadataRedactionReportParams{ID: doc.ID, MetadataRedactionReport: []byte(`{}`)})
				if err == nil || writer.doc.UpdatedAt != doc.UpdatedAt || writer.doc.ID != doc.ID || writer.doc.OrgID != doc.OrgID || writer.reportWireUpperBound != 2 {
					t.Fatal("failed refresh replaced original private writer state")
				}
				if changed == "read-failure" && !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("source read failure was hidden", err)
				}
				return nil
			})
			if err != nil || len(tx.rows) != 0 {
				t.Fatal(err, len(tx.rows))
			}
		})
	}
}
