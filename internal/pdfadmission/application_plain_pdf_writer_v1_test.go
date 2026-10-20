// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Generated methods and the real native callback/coordinator are exercised.
// SQL rows/backend completion below are explicit synthetic witnesses, not
// PostgreSQL trigger correctness, PDF inspection or deployed route acceptance.
func TestPlainPDFFreshCreationV1OwnsActualInputsAndMeasurement(t *testing.T) {
	f, session, coordinator := applicationRequestLoanFixtureV1(t)
	session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	ctx := applicationTestContextV1(t)
	stamp := pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	doc := generated.Document{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, Name: "Exact uploaded contract", SenderID: uuid.New(), Status: "draft", SourceKind: "pdf", VariablesJson: []byte("{}"), Metadata: []byte("{}"), MetadataRedactionReport: []byte("{}"), UpdatedAt: stamp}
	report := []byte(`{"assets": []}`)
	updated := doc
	updated.VariablesJson = bytes.Clone(doc.VariablesJson)
	updated.MetadataRedactionReport = bytes.Clone(report)
	updated.UpdatedAt.Time = updated.UpdatedAt.Time.Add(time.Microsecond)
	tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: []pgx.Row{
		htmlRevisionReadRowTestV1{record: doc}, htmlRevisionReadRowTestV1{record: updated},
		htmlRevisionReadRowTestV1{record: generated.DocumentSigningPolicySizesV1{DocumentID: doc.ID, OrgID: doc.OrgID, VariablesWireBytes: 2, MeasurementServerVersionNum: 160015}},
		htmlRevisionReadRowTestV1{record: generated.HtmlCreationResponseSizesV1{DocumentID: doc.ID, OrgID: doc.OrgID, MetadataWireBytes: 2, MeasurementServerVersionNum: 160015}},
		htmlRevisionReadRowTestV1{record: generated.DocumentReadReportSizesV1{DocumentID: doc.ID, OrgID: doc.OrgID, ReportWireBytes: int64(len(report)), MeasurementServerVersionNum: 160015}},
	}}
	session.state.tx = tx
	var reader *ApplicationHTMLAuthoringReaderV1
	var writer *ApplicationPlainPDFCreationWriterV1
	t.Cleanup(func() {
		if writer != nil {
			writer.CloseConsumerV1()
		}
		if reader != nil {
			reader.CloseConsumerV1()
		}
		if !applicationDoneV1(f.done) {
			close(f.done)
		}
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := f.adapter.CloseV1(cleanup); err != nil {
			t.Error(err)
		}
		if got := coordinator.SnapshotV1(doc.OrgID); got != (workguard.SnapshotV1{}) {
			t.Error("native debt did not join", got)
		}
	})
	err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var err error
		reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		writer, err = session.NewPlainPDFCreationWriterV1(call, reader)
		if err != nil {
			return err
		}
		got, err := writer.CreatePDFDocument(call, generated.CreatePDFDocumentParams{OrgID: doc.OrgID, Name: doc.Name, SenderID: doc.SenderID})
		if err != nil {
			return err
		}
		got.VariablesJson[0] = '[' // caller-exposed model cannot replace private output
		if err = writer.UpdateMetadataRedactionReport(call, generated.UpdateMetadataRedactionReportParams{ID: doc.ID, MetadataRedactionReport: report}); err != nil {
			return err
		}
		if err = writer.MeasureFreshPolicyV1(call); err != nil {
			return err
		}
		before := tx.calls
		if err = writer.MeasureFreshPolicyV1(call); err == nil {
			t.Fatal("old row could be measured again")
		}
		if tx.calls != before {
			t.Fatal("duplicate measure dispatched SQL")
		}
		if got := coordinator.SnapshotV1(doc.OrgID); got.Global.ParentBytes <= 0 || got.Global.DBStagingBytes <= 0 {
			t.Fatal("fresh inputs were never charged", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.rows) != 0 {
		t.Fatal("unused generated receipts", len(tx.rows))
	}
	writer.CloseConsumerV1()
	reader.CloseConsumerV1()
	if got := coordinator.SnapshotV1(doc.OrgID); got.GlobalGrants == 0 {
		t.Fatal("logical close refunded an unjoined original client")
	}
	close(f.done)
	if _, err = f.adapter.ReconcileCleanupV1(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestPlainPDFFieldBatchV1OnlyMeasuresItsExactFreshInsert(t *testing.T) {
	f, session, coordinator := applicationRequestLoanFixtureV1(t)
	session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	ctx := applicationTestContextV1(t)
	id := uuid.New()
	row := generated.DocumentField{ID: id, DocumentID: f.scope.DocumentID, Type: "text", OptionsJson: []byte("{}")}
	tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: []pgx.Row{htmlRevisionReadRowTestV1{record: row}, htmlRevisionReadRowTestV1{record: generated.FieldSigningPolicySizesV1{FieldID: id, DocumentID: f.scope.DocumentID, OrgID: f.scope.OrgID, OptionsWireBytes: 2, MeasurementServerVersionNum: 160015}}}}
	session.state.tx = tx
	var reader *ApplicationHTMLAuthoringReaderV1
	var batch *ApplicationPlainPDFFieldBatchV1
	t.Cleanup(func() {
		if batch != nil {
			batch.CloseConsumerV1()
		}
		if reader != nil {
			reader.CloseConsumerV1()
		}
		if !applicationDoneV1(f.done) {
			close(f.done)
		}
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := f.adapter.CloseV1(cleanup); err != nil {
			t.Error(err)
		}
		if got := coordinator.SnapshotV1(f.scope.OrgID); got != (workguard.SnapshotV1{}) {
			t.Error("field debt did not join", got)
		}
	})
	err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var err error
		reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		number := func(n int64) pgtype.Numeric { return pgtype.Numeric{Int: big.NewInt(n), Exp: -4, Valid: true} }
		p := generated.CreateDraftFieldParams{DocumentID: f.scope.DocumentID, OrgID: f.scope.OrgID, Type: "text", Page: 1, XPct: number(0), YPct: number(0), WPct: number(10000), HPct: number(10000), OptionsJson: []byte("{}")}
		foreign := p
		foreign.OrgID = uuid.New()
		before := tx.calls
		if b, e := session.newPlainPDFFieldBatchV1(call, reader, []generated.CreateDraftFieldParams{foreign}); b != nil || e == nil {
			t.Fatal("foreign field accepted")
		}
		if tx.calls != before {
			t.Fatal("foreign field dispatched SQL")
		}
		batch, err = session.newPlainPDFFieldBatchV1(call, reader, []generated.CreateDraftFieldParams{p})
		if err != nil {
			return err
		}
		p.OptionsJson[0] = '['
		p.WPct.Int.SetInt64(999999) // private typed inputs are detached
		if string(batch.state.fields[0].OptionsJson) != "{}" || batch.state.fields[0].WPct.Int.Int64() != 10000 {
			t.Fatal("caller replaced fresh field inputs")
		}
		got, err := batch.CreateNextV1(call)
		if err != nil {
			return err
		}
		if got.ID != id {
			t.Fatal("fresh result identity changed")
		}
		before = tx.calls
		if _, err = batch.CreateNextV1(call); err == nil {
			t.Fatal("batch reused to measure an old field")
		}
		if tx.calls != before {
			t.Fatal("finished batch dispatched SQL")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.rows) != 0 {
		t.Fatal("unused actual generated method receipts")
	}
}
