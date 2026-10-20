// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// A real native input/reader/source/candidate/collection/NewWriter/Append path
// with explicit synthetic typed SQL receipts and backend witness. It exercises
// native ownership/provenance checks, not PostgreSQL row/trigger/provider or
// four-transaction route acceptance. No READY/fake cache is installed in C.
type htmlRevisionWriterFixtureV1 struct {
	native      *applicationFixtureV1
	session     *ApplicationSessionV1
	coordinator *workguard.CoordinatorV1
	tx          *htmlRevisionWriterTxTestV1
	operation   *ApplicationHTMLRevisionOperationV1
	writer      *ApplicationHTMLRevisionWriterV1
	collections *ApplicationHTMLRevisionCollectionsV1
	source      *ApplicationHTMLRevisionSourceV1
	candidate   *ApplicationHTMLRevisionCandidateV1
	document    *generated.Document
}
type htmlRevisionWriterTxTestV1 struct {
	*htmlRevisionReadTxTestV1
}

func (x *htmlRevisionWriterTxTestV1) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return htmlRevisionWriterEmptyRowsV1{}, nil
}

type htmlRevisionWriterEmptyRowsV1 struct{}

func (htmlRevisionWriterEmptyRowsV1) Close()                                       {}
func (htmlRevisionWriterEmptyRowsV1) Err() error                                   { return nil }
func (htmlRevisionWriterEmptyRowsV1) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (htmlRevisionWriterEmptyRowsV1) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (htmlRevisionWriterEmptyRowsV1) Next() bool                                   { return false }
func (htmlRevisionWriterEmptyRowsV1) Scan(...any) error {
	return errors.New("empty synthetic collection")
}
func (htmlRevisionWriterEmptyRowsV1) Values() ([]any, error) {
	return nil, errors.New("empty synthetic collection")
}
func (htmlRevisionWriterEmptyRowsV1) RawValues() [][]byte { return nil }
func (htmlRevisionWriterEmptyRowsV1) Conn() *pgx.Conn     { return nil }

func withHTMLRevisionConstructedWriterFixtureV1(t *testing.T, use func(context.Context, *htmlRevisionWriterFixtureV1)) {
	withHTMLRevisionConstructedWriterVariantV1(t, 0, use)
}
func withHTMLRevisionConstructedWriterVariantV1(t *testing.T, variant int, use func(context.Context, *htmlRevisionWriterFixtureV1)) {
	t.Helper()
	f, session, coordinator := applicationRequestLoanFixtureV1(t)
	factory := &ApplicationSessionFactoryV1{state: session.state.factory}
	factory.state.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	factory.state.htmlInputProducers = make(map[*applicationHTMLAuthoringInputStateV1]struct{})
	ctx := applicationTestContextV1(t)
	in, doc, _ := testfixture.HTMLContract(t)
	// Genuine schema1 generic design: recipient/field collections really are
	// empty in this component fixture, rather than omitted from a contract.
	master, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	master.SchemaVersion = htmlmaster.SchemaVersion
	master.ContractProfile = nil
	if variant == 1 {
		master.Values = append(master.Values, htmlmaster.Value{Name: "future_note", MaxChars: 500})
		master.HTML += `<p><span data-hash-value="future_note"></span></p>`
	}
	rawMaster, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(rawMaster, in.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	in.MasterJSON = canonical.MasterJSON
	in.DefaultVarsJSON = canonical.DefaultsJSON
	in.TemplateContentSHA256 = canonical.SHA256
	in.PartyBindings = nil
	doc.ID = f.scope.DocumentID
	doc.OrgID = f.scope.OrgID
	doc.Status = "draft"
	doc.BlocksJson = []byte("[]")
	doc.Metadata = []byte("{}")
	doc.MetadataRedactionReport = []byte("{}")
	doc.HtmlSourceJson, err = htmlsource.New(in, doc)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	oldDigest, err := hex.DecodeString(commitment)
	if err != nil {
		t.Fatal(err)
	}
	// Current12 is an explicitly synthetic typed input. All exact tuple/source
	// checks still run; no production cache/approval or external row is fabricated.
	originID := uuid.New()
	doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: originID, Valid: true}
	doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 1, Valid: true}
	doc.HtmlCurrentSourceJson = bytes.Clone(doc.HtmlSourceJson)
	doc.HtmlCurrentPageCount = pgtype.Int4{Int32: 1, Valid: true}
	doc.HtmlEffectiveSourceCommitment = pgtype.Text{String: commitment, Valid: true}
	current := generated.ReadSignerCurrentMaterializationV1Row{ID: originID, DocumentID: doc.ID, OrgID: doc.OrgID, Sequence: 1, PageCount: 1,
		PdfKey: doc.PdfStorageKey.String, PdfVersionID: doc.PdfStorageVersionID.String, PdfSha256: bytes.Clone(doc.PdfSha256), SourceCommitment: oldDigest, OriginCommitment: bytes.Clone(oldDigest), SourceJson: bytes.Clone(doc.HtmlCurrentSourceJson), MetadataRedactionReport: []byte("{}")}
	header := generated.GetHTMLRevisionDocumentReadHeaderV1Row{ID: doc.ID, OrgID: doc.OrgID, SenderID: doc.SenderID, UpdatedAt: doc.UpdatedAt, IsDraft: true, HasHtmlSource: true,
		RawTextBytes: signerDocumentRawBytesV1(doc), HtmlOriginWireBytes: int64(len(doc.HtmlSourceJson)), HtmlCurrentWireBytes: int64(len(doc.HtmlCurrentSourceJson)), VariablesWireBytes: int64(len(doc.VariablesJson)),
		BlocksWireBytes: 2, MetadataWireBytes: 2, ReportWireBytes: 2, PolicyMeasurementServerVersionNum: 160015, ResponseMeasurementServerVersionNum: 160015, ReportMeasurementServerVersionNum: 160015, ServerVersionNum: 160015}
	mh := generated.GetSignerCurrentMaterializationHeaderV1Row{MaterializationID: originID, DocumentID: doc.ID, OrgID: doc.OrgID, RawTextBytes: signerMaterializationRawBytesV1(&current),
		SourceWireBytes: int64(len(current.SourceJson)), ReportWireUpperBound: 65536, MeasurementServerVersionNum: 160015, ServerVersionNum: 160015}
	collectionsHeader := generated.GetHTMLRevisionSnapshotSizeHeaderV1Row{ID: doc.ID, OrgID: doc.OrgID, UpdatedAt: doc.UpdatedAt, ServerVersionNum: 160015,
		NoticeRawTextBytes: int64(len(doc.Article13NoticeSchema) + len(doc.LawfulBasis))}
	receipts := []pgx.Row{
		htmlRevisionReadRowTestV1{record: header}, htmlRevisionReadRowTestV1{record: generated.GetHTMLAuthoringActorHeaderV1Row{UserID: doc.SenderID, OrgID: doc.OrgID, RawTextBytes: 4}},
		htmlRevisionReadRowTestV1{record: mh}, htmlRevisionReadRowTestV1{record: *doc}, htmlRevisionReadRowTestV1{record: current},
		htmlRevisionReadRowTestV1{record: collectionsHeader}, htmlRevisionReadRowTestV1{record: generated.LockHTMLRevisionSnapshotSizeCachesV1Row{}}, htmlRevisionReadRowTestV1{record: collectionsHeader},
	}
	tx := &htmlRevisionWriterTxTestV1{htmlRevisionReadTxTestV1: &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: receipts}}
	session.state.tx = tx
	changes := map[string]string{"scope": "Actual newly declared synthetic revision"}
	if variant == 1 {
		changes = map[string]string{"future_note": ""}
	}
	if variant == 2 {
		changes = map[string]string{"scope": in.Values["scope"]}
	}
	request, err := json.Marshal(map[string]any{"expected_updated_at": doc.UpdatedAt.Time.Format(time.RFC3339Nano), "expected_html_source_commitment": commitment, "values": changes, "sections": map[string]string{}, "summary": "Owned writer fixture"})
	if err != nil {
		t.Fatal(err)
	}
	var input *ApplicationHTMLAuthoringInputV1
	var operation *ApplicationHTMLRevisionOperationV1
	fixture := &htmlRevisionWriterFixtureV1{native: f, session: session, coordinator: coordinator, tx: tx, document: doc}
	t.Cleanup(func() {
		if fixture.collections != nil {
			fixture.collections.CloseConsumerV1()
		}
		if operation != nil {
			operation.CloseConsumerV1()
		}
		if input != nil {
			input.CloseConsumerV1()
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
			t.Error("joined constructed-writer fixture retained original loans", got)
		}
	})
	input, err = factory.NewHTMLAuthoringInputV1(ctx, doc.OrgID, HTMLDocumentRevisionInputV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = input.ReadBodyV1(ctx, io.NopCloser(bytes.NewReader(request))); err != nil {
		t.Fatal(err)
	}
	operation, err = factory.NewHTMLRevisionOperationV1(ctx, doc.OrgID, doc.ID, doc.SenderID, input)
	if err != nil {
		t.Fatal(err)
	}
	state := &applicationHTMLRevisionSQLV1{operation: operation.state, purpose: HTMLRevisionMutationV1, ctx: ctx, cancel: func() {}, session: session, admission: f.adapter}
	stage := &ApplicationHTMLRevisionSQLV1{state: state}
	operation.state.stages[state] = struct{}{}
	fixture.operation = operation

	err = session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		reader, e := session.NewHTMLRevisionReaderV1(call)
		if e != nil {
			return e
		}
		state.reader = reader
		if _, e = reader.ReadDocumentV1(call, doc.SenderID, func(HTMLRevisionReadAccessV1) error { return nil }); e != nil {
			return e
		}
		source, e := stage.NewSourceV1(call)
		if e != nil {
			return e
		}
		fixture.source = source
		if e = source.ValidateV1(); e != nil {
			return e
		}
		if e = source.ValidateCurrentV1(); e != nil {
			return e
		}
		collections, e := reader.NewCollectionsV1(call)
		if e != nil {
			return e
		}
		fixture.collections = collections
		if e = source.ValidateSigningPageStateV1(call, collections, 0); e != nil {
			return e
		}
		if e = source.MaterializeRevisionV1(); e != nil {
			if variant == 2 && errors.Is(e, ErrHTMLRevisionNoChangeV1) {
				use(call, fixture)
				return nil
			}
			return e
		}
		if variant == 2 {
			return errors.New("unchanged declaration was accepted")
		}
		sum := sha256.Sum256([]byte("new synthetic PDF bytes, no renderer proof"))
		candidate, e := source.NewCandidateV1(HTMLRevisionPDFOutputV1{Key: "org/synthetic/new.pdf", VersionID: "new-synthetic-version", SHA256: sum[:], PageCount: 1, PreviousPageCount: 1, MetadataRedactionReport: []byte("{}")})
		if e != nil {
			return e
		}
		fixture.candidate = candidate
		writer, e := stage.NewWriterV1(call, source, candidate, collections)
		if e != nil {
			return e
		}
		fixture.writer = writer
		// These are synthetic acknowledgments to the actual generated APIs; every
		// returned scope/sequence/source/report decision is still production code.
		nextID, snapshotID := uuid.New(), uuid.New()
		nextCommit, e := candidate.state.validation.CommitmentV1()
		if e != nil {
			return e
		}
		nextDigest, e := hex.DecodeString(nextCommit)
		if e != nil {
			return e
		}
		row := generated.HtmlDocumentMaterialization{ID: nextID, DocumentID: doc.ID, OrgID: doc.OrgID, Sequence: 2, ParentID: pgtype.UUID{Bytes: originID, Valid: true}, ParentCommitment: bytes.Clone(oldDigest), OriginCommitment: bytes.Clone(oldDigest),
			SourceJson: bytes.Clone(candidate.state.sourceJSON), SourceCommitment: nextDigest, PdfKey: candidate.state.document.PdfStorageKey.String, PdfVersionID: candidate.state.document.PdfStorageVersionID.String, PdfSha256: bytes.Clone(sum[:]), PageCount: 1, Summary: candidate.state.summary, CreatedBy: doc.SenderID, MetadataRedactionReport: []byte("{}")}
		updated := htmlRevisionCloneDocumentV1(candidate.state.document)
		updated.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: nextID, Valid: true}
		updated.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 2, Valid: true}
		updated.HtmlCurrentPageCount = pgtype.Int4{Int32: 1, Valid: true}
		updated.HtmlCurrentSourceJson = bytes.Clone(candidate.state.sourceJSON)
		updated.HtmlEffectiveSourceCommitment = pgtype.Text{String: nextCommit, Valid: true}
		updated.MetadataRedactionReport = []byte("{}")
		updated.HtmlReviewedPdfSha256 = nil
		updated.HtmlReviewedBy = pgtype.UUID{}
		updated.HtmlReviewedAt = pgtype.Timestamptz{}
		updated.UpdatedAt = pgtype.Timestamptz{Time: doc.UpdatedAt.Time.Add(time.Microsecond), Valid: true}
		tx.rows = append(tx.rows, htmlRevisionReadRowTestV1{record: struct{ ID uuid.UUID }{snapshotID}},
			htmlRevisionReadRowTestV1{record: generated.HtmlRevisionSnapshotSizesV1{SnapshotID: snapshotID, DocumentID: doc.ID, OrgID: doc.OrgID, SourceWireBytes: int64(len(doc.HtmlCurrentSourceJson)), FieldsWireBytes: 2, RecipientsWireBytes: 2, NoticeWireBytes: 2, CeremonyEventsWireBytes: 2, ReportWireBytes: 2, MeasurementServerVersionNum: 160015}},
			htmlRevisionReadRowTestV1{record: row}, htmlRevisionReadRowTestV1{record: *updated})
		if e = writer.AppendV1(call); e != nil {
			return e
		}
		if _, e = writer.UpdatePartiesAndFieldsV1(call); e != nil {
			return e
		}
		if len(tx.rows) != 0 {
			return errors.New("unexpected unused constructed writer receipts")
		}
		use(call, fixture)
		return nil
	})
	if err != nil {
		t.Fatal("actual native constructed writer fixture failed", err)
	}
}
