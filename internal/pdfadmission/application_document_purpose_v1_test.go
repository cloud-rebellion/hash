// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

type purposeTransitionWitnessV1 struct{ Recipients, Fields, Packages, Annex, Children, SigningProfile bool }

func TestDocumentPurposeNativeFreshPDFV1(t *testing.T) {
	f, session, c := applicationRequestLoanFixtureV1(t)
	session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	ctx := applicationTestContextV1(t)
	doc := generated.Document{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, Name: "ordinary document", SenderID: uuid.New(), Status: "draft", SourceKind: "pdf", VariablesJson: []byte(`{}`), Metadata: []byte(`{}`), MetadataRedactionReport: []byte(`{}`), UpdatedAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}}
	updated := doc
	updated.Metadata = []byte(`{"hash:document-purpose:v1": {"schema_version": 1, "purpose": "document"}}`)
	updated.UpdatedAt.Time = updated.UpdatedAt.Time.Add(time.Microsecond)
	response := generated.HtmlCreationResponseSizesV1{DocumentID: doc.ID, OrgID: doc.OrgID, MetadataWireBytes: int64(len(updated.Metadata)), MeasurementServerVersionNum: 160015}
	tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: []pgx.Row{htmlRevisionReadRowTestV1{record: doc}, htmlRevisionReadRowTestV1{record: purposeTransitionWitnessV1{}}, htmlRevisionReadRowTestV1{record: updated}, htmlRevisionReadRowTestV1{record: response}, htmlRevisionReadRowTestV1{record: generated.DocumentSigningPolicySizesV1{DocumentID: doc.ID, OrgID: doc.OrgID, VariablesWireBytes: 2, MeasurementServerVersionNum: 160015}}, htmlRevisionReadRowTestV1{record: response}, htmlRevisionReadRowTestV1{record: generated.DocumentReadReportSizesV1{DocumentID: doc.ID, OrgID: doc.OrgID, ReportWireBytes: 2, MeasurementServerVersionNum: 160015}}}}
	session.state.tx = tx
	var r *ApplicationHTMLAuthoringReaderV1
	var w *ApplicationPlainPDFCreationWriterV1
	t.Cleanup(func() {
		if w != nil {
			w.CloseConsumerV1()
		}
		if r != nil {
			r.CloseConsumerV1()
		}
		if !applicationDoneV1(f.done) {
			close(f.done)
		}
		closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = f.adapter.CloseV1(closeCtx)
		if c.SnapshotV1(doc.OrgID) != (workguard.SnapshotV1{}) {
			t.Error("native purpose debt did not retire")
		}
	})
	err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var err error
		r, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		w, err = session.NewPlainPDFCreationWriterV1(call, r)
		if err != nil {
			return err
		}
		if _, err = w.CreatePDFDocument(call, generated.CreatePDFDocumentParams{OrgID: doc.OrgID, Name: doc.Name, SenderID: doc.SenderID}); err != nil {
			return err
		}
		got, err := w.RecordPurposeV1(call, documentpurpose.Document)
		if err != nil {
			return err
		}
		if documentpurpose.Response(got.Metadata) != documentpurpose.Document || !bytes.Equal(got.VariablesJson, doc.VariablesJson) {
			t.Fatal("mode altered source")
		}
		if c.SnapshotV1(doc.OrgID).Global.ParentBytes <= 0 {
			t.Fatal("no genuine native retained grant")
		}
		return w.MeasureFreshPolicyV1(call)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.rows) != 0 {
		t.Fatal("unused expected SQL", len(tx.rows))
	}
	w.CloseConsumerV1()
	r.CloseConsumerV1()
	if c.SnapshotV1(doc.OrgID).GlobalGrants == 0 {
		t.Fatal("unjoined client refunded capacity")
	}
}
func TestDocumentPurposeTransitionRefusesBeforeWriteV1(t *testing.T) {
	for i := 0; i < 6; i++ {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			v := purposeTransitionWitnessV1{}
			switch i {
			case 0:
				v.Recipients = true
			case 1:
				v.Fields = true
			case 2:
				v.Packages = true
			case 3:
				v.Annex = true
			case 4:
				v.Children = true
			case 5:
				v.SigningProfile = true
			}
			tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: []pgx.Row{htmlRevisionReadRowTestV1{record: v}}}
			old := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), Status: "draft", Metadata: []byte(`{}`)}
			_, err := applyDocumentPurposeV1(context.Background(), tx, generated.New(tx), old, documentpurpose.Document, func(context.Context, int64, int64) error { return nil })
			if !errors.Is(err, documentpurpose.ErrTransition) || tx.calls != 1 {
				t.Fatal("workflow state permitted purpose write", err, tx.calls)
			}
		})
	}
	tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}}
	sentinel := errors.New("admission refused")
	_, err := applyDocumentPurposeV1(context.Background(), tx, generated.New(tx), &generated.Document{Status: "draft", Metadata: []byte(`{}`)}, documentpurpose.Document, func(context.Context, int64, int64) error { return sentinel })
	if !errors.Is(err, sentinel) || tx.calls != 0 {
		t.Fatal("SQL before admission", err, tx.calls)
	}
}
func TestDocumentPurposeBlockFieldGuardsV1(t *testing.T) {
	for _, kind := range []blocks.Type{blocks.TypeSignatureField, blocks.TypeInitialField, blocks.TypeTextField, blocks.TypeDateField, blocks.TypeCheckbox} {
		tree := &blocks.Tree{Version: 1, Blocks: []blocks.Block{{Type: blocks.TypeParagraph, Content: []blocks.Block{{Type: kind}}}}}
		for _, p := range []documentpurpose.Purpose{documentpurpose.Document, documentpurpose.Presentation} {
			if !errors.Is(validateBlockTreePurposeV1(context.Background(), p, tree), documentpurpose.ErrSigningRequired) {
				t.Fatal("nested field admitted", p, kind)
			}
		}
		if err := validateBlockTreePurposeV1(context.Background(), documentpurpose.Signing, tree); err != nil {
			t.Fatal("legacy signing rejected", err)
		}
	}
	tree := &blocks.Tree{Version: 1, Blocks: []blocks.Block{{Type: blocks.TypeParagraph, Text: "content"}}}
	if err := validateBlockTreePurposeV1(context.Background(), documentpurpose.Document, tree); err != nil {
		t.Fatal(err)
	}
}
