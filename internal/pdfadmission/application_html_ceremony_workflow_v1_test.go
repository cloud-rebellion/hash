// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// The real workflow constructor/reader/stage callback/body/result/release methods
// use the actual shared coordinator. ONLY the original opened SQL stage and
// typed SQL/backend receipts are synthetic, as in the existing reader fixture.
// This is not an Open/PG/credential/capture/commit or physical-retirement proof.
func htmlCeremonyWorkflowFixtureV1(t *testing.T, purpose HTMLCeremonyWorkflowPurposeV1, actor uuid.UUID, rows []pgx.Row) (*ApplicationHTMLCeremonyWorkflowV1, *applicationFixtureV1, *ApplicationSessionV1, *workguard.CoordinatorV1, *htmlRevisionReadTxTestV1, context.Context) {
	t.Helper()
	f, session, coordinator := applicationRequestLoanFixtureV1(t)
	factory := &ApplicationSessionFactoryV1{state: session.state.factory}
	factory.state.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	ctx := applicationTestContextV1(t)
	work, err := factory.NewHTMLCeremonyWorkflowV1(ctx, f.scope.OrgID, f.scope.DocumentID, actor, purpose)
	if err != nil {
		t.Fatal(err)
	}
	tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: rows}
	session.state.tx = tx
	var reader *ApplicationHTMLRevisionReaderV1
	if err = session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var err error
		reader, err = session.NewHTMLRevisionReaderV1(call)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	op := work.operation.state
	stage := &applicationHTMLRevisionSQLV1{operation: op, purpose: HTMLRevisionInitialReadV1, ctx: op.ctx, cancel: func() {}, session: session, admission: f.adapter, reader: reader}
	// Explicit synthetic already-opened stage witness; no test claim that an
	// injected session was minted by actual public factory Open.
	op.stages[stage] = struct{}{}
	op.attempted[HTMLRevisionInitialReadV1-1] = true
	work.stage = &ApplicationHTMLRevisionSQLV1{state: stage}
	work.reader = reader
	work.attempted = true
	t.Cleanup(func() {
		work.CloseConsumerV1()
		if !applicationDoneV1(f.done) {
			close(f.done)
		}
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = f.adapter.CloseV1(cleanup)
	})
	return work, f, session, coordinator, tx, ctx
}
func htmlCeremonyReadRowsV1(document generated.Document, actor generated.User, measured bool) []pgx.Row {
	header := generated.GetHTMLRevisionDocumentReadHeaderV1Row{ID: document.ID, OrgID: document.OrgID, SenderID: document.SenderID, UpdatedAt: document.UpdatedAt,
		IsDraft: document.Status == "draft", IsChangesRequested: document.Status == "changes_requested", HasHtmlSource: document.HtmlSourceJson != nil, ServerVersionNum: 160015,
		RawTextBytes: signerDocumentRawBytesV1(&document), HtmlOriginWireBytes: int64(len(document.HtmlSourceJson)), VariablesWireBytes: int64(len(document.VariablesJson)),
		BlocksWireBytes: int64(len(document.BlocksJson)), MetadataWireBytes: int64(len(document.Metadata)), ReportWireBytes: int64(len(document.MetadataRedactionReport))}
	if measured {
		header.PolicyMeasurementServerVersionNum = 160015
		header.ResponseMeasurementServerVersionNum = 160015
		header.ReportMeasurementServerVersionNum = 160015
	}
	rows := []pgx.Row{htmlRevisionReadRowTestV1{record: header}}
	if actor.ID != uuid.Nil {
		rows = append(rows, htmlRevisionReadRowTestV1{record: generated.GetHTMLAuthoringActorHeaderV1Row{UserID: actor.ID, OrgID: actor.OrgID, RawTextBytes: int64(len(actor.Name) + len(actor.Email) + len(actor.Role) + len(actor.ZitadelSub.String))}}, htmlRevisionReadRowTestV1{record: actor})
	}
	if measured {
		rows = append(rows, htmlRevisionReadRowTestV1{record: document})
	}
	return rows
}
func TestHTMLCeremonyWorkflowActualResultConsumerJoinsOriginalBodyDebtV1(t *testing.T) {
	for _, physicalFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(physicalFirst), func(t *testing.T) {
			actor := uuid.New()
			work, f, _, coordinator, tx, ctx := htmlCeremonyWorkflowFixtureV1(t, HTMLCeremonyReviewV1, actor, nil)
			stamp := pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 0, 0, 0, 1, time.UTC), Valid: true}
			document := generated.Document{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, SenderID: actor, Name: "original result", Status: "draft", SourceKind: "pdf", UpdatedAt: stamp,
				HtmlSourceJson: []byte("{}"), VariablesJson: []byte("{}"), BlocksJson: []byte("[]"), Metadata: []byte("{}"), MetadataRedactionReport: []byte("{}")}
			member := generated.User{ID: actor, OrgID: document.OrgID, Name: "Owner", Email: "owner@example.test", Role: "owner"}
			tx.rows = htmlCeremonyReadRowsV1(document, member, true)
			reviewed := document
			reviewed.HtmlReviewedPdfSha256 = make([]byte, 32)
			tx.rows = append(tx.rows, htmlRevisionReadRowTestV1{record: reviewed})
			var result *generated.Document
			var release func()
			t.Cleanup(func() {
				if release != nil {
					release()
				}
			})
			if err := work.WithTxV1(func(call context.Context, _ generated.DBTX, _ *ApplicationHTMLRevisionReaderV1) error {
				_, err := work.ReadActorDocumentV1(call, func(a HTMLRevisionReadAccessV1) error { return nil }, func(a HTMLRevisionReadAccessV1, u *generated.User) error {
					if u == nil || u.ID != actor || u.Role != "owner" {
						return errors.New("actual actor changed")
					}
					return nil
				})
				if err != nil {
					return err
				}
				if _, err = work.MarkReviewedV1(call, stamp.Time, make([]byte, 32)); err != nil {
					return err
				}
				result, release, err = work.BorrowDocumentV1(call)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if result == nil || result.Name != "original result" || tx.calls != 5 || len(tx.rows) != 0 {
				t.Fatal("actual reader/review/borrow sequence changed", tx.calls)
			}
			before := coordinator.SnapshotV1(document.OrgID)
			if before.GlobalGrants != 4 || f.adapter.PendingV1().Loans != 4 || before.Global.ParentBytes <= 0 || before.Global.DBStagingBytes <= 0 {
				t.Fatal("actual header/actor/body/returned-row loans missing", before)
			}
			if physicalFirst {
				close(f.done)
				if pending, err := f.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 4 {
					t.Fatal("physical-only witness credited a live result", pending, err)
				}
			}
			copied := &ApplicationHTMLCeremonyWorkflowV1{self: work, operation: work.operation}
			copied.CloseConsumerV1()
			if coordinator.SnapshotV1(document.OrgID) != before {
				t.Fatal("copied workflow shell closed original loans")
			}
			work.CloseConsumerV1()
			if work.resourcesClosed || work.updated == nil || work.snapshot == nil || work.reader.resourcesClosed || coordinator.SnapshotV1(document.OrgID) != before {
				t.Fatal("route cancellation released live response backing")
			}
			if document, again, err := work.BorrowDocumentV1(ctx); err == nil || document != nil || again != nil {
				t.Fatal("closed workflow minted a new result")
			}
			result = nil
			release()
			release()
			if !work.resourcesClosed || work.updated != nil || work.snapshot != nil || !work.reader.resourcesClosed {
				t.Fatal("last actual response use retained private model references")
			}
			if !physicalFirst {
				if pending, err := f.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 4 || coordinator.SnapshotV1(document.OrgID) != before {
					t.Fatal("consumer-only close credited unretired original physical owner", pending, err)
				}
				close(f.done)
			}
			if pending, err := f.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 0 {
				t.Fatal("joined original debt did not reconcile", pending, err)
			}
			if coordinator.SnapshotV1(document.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("original real coordinator retained joined debt")
			}
		})
	}
}
func TestHTMLCeremonyActualDecisionOpenRefusalPrecedesMissingBodyCachesV1(t *testing.T) {
	closed := errors.New("original already-resolved change")
	for _, mode := range []string{"staff closed", "capability closed", "staff open missing caches"} {
		t.Run(mode, func(t *testing.T) {
			actor := uuid.New()
			if mode == "capability closed" {
				actor = uuid.Nil
			}
			work, f, _, coordinator, tx, _ := htmlCeremonyWorkflowFixtureV1(t, HTMLCeremonyChangeDecisionV1, actor, nil)
			document := generated.Document{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, SenderID: uuid.New(), Status: "changes_requested", HtmlSourceJson: []byte("{}"), UpdatedAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}}
			member := generated.User{ID: actor, OrgID: document.OrgID, Name: "Owner", Role: "owner"}
			tx.rows = htmlCeremonyReadRowsV1(document, member, false)
			change := uuid.New()
			isOpen := mode == "staff open missing caches"
			tx.rows = append(tx.rows, htmlRevisionReadRowTestV1{record: generated.GetHTMLChangeRequestReadHeaderV1Row{ChangeRequestID: change, DocumentID: document.ID, OrgID: document.OrgID, IsOpen: isOpen, RawTextBytes: 23}})
			err := work.WithTxV1(func(call context.Context, _ generated.DBTX, _ *ApplicationHTMLRevisionReaderV1) error {
				gate := func(a HTMLRevisionReadAccessV1) error {
					if !a.ChangesRequested {
						return errors.New("actual parent state changed")
					}
					return work.PreflightChangeV1(call, change, func(open bool) error {
						if !open {
							return closed
						}
						return nil
					})
				}
				_, err := work.ReadActorDocumentV1(call, func(a HTMLRevisionReadAccessV1) error {
					if actor == uuid.Nil {
						return gate(a)
					}
					return nil
				}, func(a HTMLRevisionReadAccessV1, u *generated.User) error {
					if u == nil || u.ID != actor || u.Role != "owner" {
						return errors.New("original role refused")
					}
					return gate(a)
				})
				return err
			})
			scans, loans := 4, 2
			if actor == uuid.Nil {
				scans, loans = 2, 1
			}
			if tx.calls != scans || len(tx.rows) != 0 || f.adapter.PendingV1().Loans != loans || coordinator.SnapshotV1(document.OrgID).GlobalGrants != int64(loans) {
				t.Fatal("original actor/open scalar staging changed", tx.calls, f.adapter.PendingV1())
			}
			if isOpen {
				if !errors.Is(err, ErrHTMLRevisionReadV1) {
					t.Fatal("valid open request did not retain genuine missing-cache refusal", err)
				}
			} else if !errors.Is(err, closed) {
				t.Fatal("genuine already-resolved policy was hidden by missing full-body cache", err)
			}
		})
	}
}
