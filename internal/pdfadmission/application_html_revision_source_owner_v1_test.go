// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// This exercises the ACTUAL native input/operation/reader/source/admission and
// shared coordinator methods. Its typed SQL rows and original backend witness
// are explicitly synthetic; stage registration uses that fixed fixture rather
// than claiming public network Open, PostgreSQL caches, actor policy or PDF
// evidence. Actual public Open/Commit/retirement and route acceptance stay PG.
func TestHTMLRevisionSourceActualStagesOriginalInputAndJoinedConsumersV1(t *testing.T) {
	for _, physicalFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(physicalFirst), func(t *testing.T) {
			fixture, session, coordinator := applicationRequestLoanFixtureV1(t)
			factory := &ApplicationSessionFactoryV1{state: session.state.factory}
			factory.state.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
			factory.state.htmlInputProducers = make(map[*applicationHTMLAuthoringInputStateV1]struct{})
			ctx := applicationTestContextV1(t)
			sourceInput, doc, _ := testfixture.HTMLContract(t)
			doc.ID = fixture.scope.DocumentID
			doc.OrgID = fixture.scope.OrgID
			doc.SenderID = uuid.New()
			doc.Name = "original immutable local source"
			doc.Status = "draft"
			doc.SourceKind = "pdf"
			doc.UpdatedAt = pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 0, 0, 0, 1, time.UTC), Valid: true}
			doc.BlocksJson = []byte("[]")
			doc.Metadata = []byte("{}")
			doc.MetadataRedactionReport = []byte("{}")
			var err error
			doc.HtmlSourceJson, err = htmlsource.New(sourceInput, doc)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := htmlsource.Commitment(doc)
			if err != nil {
				t.Fatal(err)
			}
			request, err := json.Marshal(map[string]any{"expected_updated_at": doc.UpdatedAt.Time.Format(time.RFC3339Nano), "expected_html_source_commitment": expected,
				"values": map[string]string{"scope": "Changed declared scope from the original actual request"}, "sections": map[string]string{}, "summary": "Owned source fixture"})
			if err != nil {
				t.Fatal(err)
			}
			input, err := factory.NewHTMLAuthoringInputV1(ctx, doc.OrgID, HTMLDocumentRevisionInputV1)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := input.ReadBodyV1(ctx, io.NopCloser(bytes.NewReader(request)))
			if err != nil {
				t.Fatal(err)
			}
			op, err := factory.NewHTMLRevisionOperationV1(ctx, doc.OrgID, doc.ID, doc.SenderID, input)
			if err != nil {
				t.Fatal(err)
			}
			// The native declaration is already detached from returned mutable input.
			at := bytes.Index(raw, []byte("Changed declared scope"))
			if at < 0 {
				t.Fatal("request fixture missing")
			}
			raw[at] = '!'
			header := generated.GetHTMLRevisionDocumentReadHeaderV1Row{ID: doc.ID, OrgID: doc.OrgID, SenderID: doc.SenderID, UpdatedAt: doc.UpdatedAt, IsDraft: true, HasHtmlSource: true,
				RawTextBytes: signerDocumentRawBytesV1(doc), HtmlOriginWireBytes: int64(len(doc.HtmlSourceJson)), HtmlCurrentWireBytes: int64(len(doc.HtmlCurrentSourceJson)),
				VariablesWireBytes: int64(len(doc.VariablesJson)), BlocksWireBytes: int64(len(doc.BlocksJson)), MetadataWireBytes: int64(len(doc.Metadata)), ReportWireBytes: int64(len(doc.MetadataRedactionReport)),
				PolicyMeasurementServerVersionNum: 160015, ResponseMeasurementServerVersionNum: 160015, ReportMeasurementServerVersionNum: 160015, ServerVersionNum: 160015}
			tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: []pgx.Row{
				htmlRevisionReadRowTestV1{record: header}, htmlRevisionReadRowTestV1{record: generated.GetHTMLAuthoringActorHeaderV1Row{UserID: doc.SenderID, OrgID: doc.OrgID, RawTextBytes: 4}}, htmlRevisionReadRowTestV1{record: *doc}}}
			session.state.tx = tx
			stageState := &applicationHTMLRevisionSQLV1{operation: op.state, purpose: HTMLRevisionInitialReadV1, ctx: ctx, cancel: func() {}, session: session, admission: fixture.adapter}
			stage := &ApplicationHTMLRevisionSQLV1{state: stageState}
			op.state.stages[stageState] = struct{}{} // explicit synthetic original stage
			var source *ApplicationHTMLRevisionSourceV1
			var reader *ApplicationHTMLRevisionReaderV1
			var releaseModels func()
			t.Cleanup(func() {
				if releaseModels != nil {
					releaseModels()
				}
				if source != nil {
					source.CloseConsumerV1()
				}
				if reader != nil {
					reader.CloseConsumerV1()
				}
				op.CloseConsumerV1()
				input.CloseConsumerV1()
				if !applicationDoneV1(fixture.done) {
					close(fixture.done)
				}
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				_ = fixture.adapter.CloseV1(cleanup)
			})
			err = session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
				var err error
				reader, err = session.NewHTMLRevisionReaderV1(call)
				if err != nil {
					return err
				}
				stageState.reader = reader
				models, err := reader.ReadDocumentV1(call, doc.SenderID, func(HTMLRevisionReadAccessV1) error { return nil })
				if err != nil {
					return err
				}
				// The new source binds the constructor's private original snapshot.
				models.Document.Name = "caller replacement"
				source, err = stage.NewSourceV1(call)
				return err
			})
			if err != nil || source == nil {
				t.Fatal("genuine fixed source birth failed", err)
			}
			before := coordinator.SnapshotV1(doc.OrgID)
			beforePending := fixture.adapter.PendingV1()
			parentLoan := source.state.parentLoan
			if parentLoan == nil || parentLoan.loan == nil || parentLoan.grant == nil {
				t.Fatal("actual source birth did not register its one native loan")
			}
			if err = source.ValidateV1(); err != nil {
				t.Fatal("original SQL callback cancellation shortened source operation", err)
			}
			got, err := source.CommitmentV1()
			if err != nil || got != expected {
				t.Fatal("original full source result changed", got, err)
			}
			if err = source.ValidateCurrentV1(); err != nil {
				t.Fatal(err)
			}
			if err = source.MaterializeRevisionV1(); err != nil {
				t.Fatal(err)
			}
			models, release, err := source.BorrowPreparedV1()
			if err != nil {
				t.Fatal(err)
			}
			releaseModels = release
			if models.Input.Values["scope"] != "Changed declared scope from the original actual request" || !strings.Contains(models.Rendered.HTML, "Changed declared scope") {
				t.Fatal("later mutable body or caller model replaced captured original declaration")
			}
			models.Input.Values["scope"] = "caller changed prepared copy"
			models.Input.MasterJSON[0] = '!'
			if source.state.prepared.input.Values["scope"] == models.Input.Values["scope"] || source.state.prepared.input.MasterJSON[0] == '!' {
				t.Fatal("mutable projection replaced native prepared input")
			}
			held := coordinator.SnapshotV1(doc.OrgID)
			if held.Global.ParentBytes <= before.Global.ParentBytes || source.state.maxScratch == 0 || held.Global.DBStagingBytes != before.Global.DBStagingBytes {
				t.Fatal("actual fixed stages did not share Parent-only grants", before, held)
			}
			pending := fixture.adapter.PendingV1()
			if source.state.parentLoan != parentLoan || held.GlobalGrants != before.GlobalGrants || pending.Loans != beforePending.Loans ||
				pending.WorkingBytes-beforePending.WorkingBytes != held.Global.ParentBytes-before.Global.ParentBytes {
				t.Fatal("actual staged growth replaced a loan, changed grant count or omitted cumulative bytes", before, held, beforePending, pending)
			}
			if physicalFirst {
				close(fixture.done)
				if _, err = fixture.adapter.ReconcileCleanupV1(ctx); err != nil {
					t.Fatal(err)
				}
			}
			input.CloseConsumerV1()
			op.CloseConsumerV1()
			if source.state.retired || reader.resourcesClosed || source.state.validation == nil || source.state.prepared == nil || coordinator.SnapshotV1(doc.OrgID) != held {
				t.Fatal("Close/cancellation credited a still-used original render/source result")
			}
			source.state.mu.Lock()
			uses := source.state.active
			source.state.mu.Unlock()
			if uses != 1 {
				t.Fatalf("actual prepared use lost: %d", uses)
			}
			models = nil
			releaseModels()
			releaseModels()
			releaseModels = nil
			if !source.state.retired || source.state.snapshot != nil || source.state.validation != nil || source.state.prepared != nil || !reader.resourcesClosed {
				t.Fatal("joined final use did not clear original backing")
			}
			if !physicalFirst {
				if _, err = fixture.adapter.ReconcileCleanupV1(ctx); err != nil {
					t.Fatal(err)
				}
				if coordinator.SnapshotV1(doc.OrgID) == (workguard.SnapshotV1{}) {
					t.Fatal("consumer-only closure credited synthetic unretired backend")
				}
				close(fixture.done)
			}
			if _, err = fixture.adapter.ReconcileCleanupV1(ctx); err != nil {
				t.Fatal(err)
			}
			if coordinator.SnapshotV1(doc.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("actual coordinator conjunction did not release all fixture loans", coordinator.SnapshotV1(doc.OrgID))
			}
		})
	}
}

func TestHTMLRevisionSourceZeroShellAndOpaqueGrantRefusalV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	var source ApplicationHTMLRevisionSourceV1
	source.CloseConsumerV1()
	if err := source.ValidateV1(); err == nil {
		t.Fatal("zero source validated")
	}
	if _, _, err := source.BorrowPreparedV1(); err == nil {
		t.Fatal("zero source borrowed")
	}
	_, work := workAdmissionTestV1(t)
	b := ApplicationBudgetV1{Phase: "owned-html-revision-source", OrgID: uuid.New(), DocumentID: uuid.New(), WorkingBytes: 1}
	if release, err := work.ApplicationV1(ctx, b); release != nil || err == nil {
		if release != nil {
			release()
		}
		t.Fatal("caller WorkingBytes minted source work")
	}
}
