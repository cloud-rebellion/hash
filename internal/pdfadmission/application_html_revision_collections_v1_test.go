// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type htmlRevisionCollectionObserveRowTestV1 struct {
	row        pgx.Row
	beforeScan func()
}

func (r htmlRevisionCollectionObserveRowTestV1) Scan(dest ...any) error {
	if r.beforeScan != nil {
		r.beforeScan()
	}
	return r.row.Scan(dest...)
}

// Real native coordinator/session/admission/reader methods, with explicitly
// synthetic typed scan data and backend-retirement witness. No PostgreSQL cache,
// source legality, policy permission or physical backend proof is claimed.
func TestHTMLRevisionCollectionsAdmitBeforePinsAndRetainOriginalBodyV1(t *testing.T) {
	for _, mode := range []string{"complete-empty-set", "uncached-event", "positive-capacity-denied", "pin-count-drift", "fresh-header-drift"} {
		t.Run(mode, func(t *testing.T) {
			f, session, coordinator := applicationRequestLoanFixtureV1(t)
			session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
			ctx := applicationTestContextV1(t)
			user := uuid.New()
			stamp := pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 0, 0, 0, 1, time.UTC), Valid: true}
			doc := generated.Document{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, SenderID: user, Name: "original", Status: "draft", SourceKind: "pdf", UpdatedAt: stamp, HtmlSourceJson: []byte("{}"), VariablesJson: []byte("{}"), BlocksJson: []byte("[]"), Metadata: []byte("{}"), MetadataRedactionReport: []byte("{}")}
			dh := generated.GetHTMLRevisionDocumentReadHeaderV1Row{ID: doc.ID, OrgID: doc.OrgID, SenderID: user, UpdatedAt: stamp, IsDraft: true, HasHtmlSource: true, RawTextBytes: signerDocumentRawBytesV1(&doc), HtmlOriginWireBytes: 2, VariablesWireBytes: 2, BlocksWireBytes: 2, MetadataWireBytes: 2, ReportWireBytes: 2, PolicyMeasurementServerVersionNum: 160015, ResponseMeasurementServerVersionNum: 160015, ReportMeasurementServerVersionNum: 160015, ServerVersionNum: 160015}
			ch := generated.GetHTMLRevisionSnapshotSizeHeaderV1Row{ID: doc.ID, OrgID: doc.OrgID, UpdatedAt: stamp, ServerVersionNum: 160015}
			if mode == "uncached-event" {
				ch.EventCount = 1
			}
			if mode == "positive-capacity-denied" {
				ch.RecipientCount = 1_000_000
			}
			tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: []pgx.Row{htmlRevisionReadRowTestV1{record: dh}, htmlRevisionReadRowTestV1{record: generated.GetHTMLAuthoringActorHeaderV1Row{UserID: user, OrgID: doc.OrgID, RawTextBytes: 4}}, htmlRevisionReadRowTestV1{record: doc}, htmlRevisionReadRowTestV1{record: ch}}}
			var beforePins workguard.SnapshotV1
			if mode != "uncached-event" && mode != "positive-capacity-denied" {
				pins := generated.LockHTMLRevisionSnapshotSizeCachesV1Row{}
				if mode == "pin-count-drift" {
					pins.LockedEventCacheCount = 1
				}
				tx.rows = append(tx.rows, htmlRevisionCollectionObserveRowTestV1{row: htmlRevisionReadRowTestV1{record: pins}, beforeScan: func() { beforePins = coordinator.SnapshotV1(doc.OrgID) }})
				if mode != "pin-count-drift" {
					current := ch
					if mode == "fresh-header-drift" {
						current.EventCount = 1
						current.MeasuredEventCount = 1
					}
					tx.rows = append(tx.rows, htmlRevisionReadRowTestV1{record: current})
				}
			}
			session.state.tx = tx
			var reader *ApplicationHTMLRevisionReaderV1
			var collection *ApplicationHTMLRevisionCollectionsV1
			t.Cleanup(func() {
				if collection != nil {
					collection.CloseConsumerV1()
				}
				if reader != nil {
					reader.CloseConsumerV1()
				}
				if !applicationDoneV1(f.done) {
					close(f.done)
				}
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				_ = f.adapter.CloseV1(cleanup)
			})
			var base workguard.SnapshotV1
			err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
				var err error
				reader, err = session.NewHTMLRevisionReaderV1(call)
				if err != nil {
					return err
				}
				if _, err = reader.ReadDocumentV1(call, user, func(HTMLRevisionReadAccessV1) error { return nil }); err != nil {
					return err
				}
				base = coordinator.SnapshotV1(doc.OrgID)
				collection, err = reader.NewCollectionsV1(call)
				return err
			})
			if len(tx.rows) != 0 {
				t.Fatal("owner did not consume the exact expected fixed scalar sequence", len(tx.rows))
			}
			if base.GlobalGrants != 3 {
				t.Fatal("actual original header/actor/body loans missing", base)
			}
			if mode == "complete-empty-set" {
				if err != nil || collection == nil || tx.calls != 6 {
					t.Fatal("actual complete-set owner did not finish", err, tx.calls)
				}
				// Even zero variable bytes/rows have fixed schema aggregation work.
				if beforePins.GlobalGrants != base.GlobalGrants+1 || beforePins.Global.DBStagingBytes <= base.Global.DBStagingBytes {
					t.Fatal("scalable cache pins ran before positive complete logical staging credit", beforePins, base)
				}
				reader.CloseConsumerV1()
				reader.mu.Lock()
				retained := reader.snapshot != nil && !reader.resourcesClosed && reader.sourceBorrowers == 1
				reader.mu.Unlock()
				if !retained || coordinator.SnapshotV1(doc.OrgID) != beforePins {
					t.Fatal("route close released the actual collection owner's original source/body")
				}
				canceled, stop := context.WithCancel(ctx)
				stop()
				if again, err := reader.NewCollectionsV1(canceled); again != nil || err == nil {
					t.Fatal("cancellation minted another collection owner")
				}
				if coordinator.SnapshotV1(doc.OrgID) != beforePins {
					t.Fatal("cancellation refunded retained collection/reader work")
				}
				// The owner retains its original body borrower until explicit last use.
				collection.CloseConsumerV1()
				collection.CloseConsumerV1()
				if collection.snapshot != nil || collection.queries != nil || collection.releaseBody != nil || !collection.resourcesClosed {
					t.Fatal("last use retained closed collection backing")
				}
			} else {
				if err == nil || collection != nil {
					t.Fatal("missing/stale/refused collection scope exposed an owner", err)
				}
				if mode == "uncached-event" || mode == "positive-capacity-denied" {
					if tx.calls != 4 || beforePins != (workguard.SnapshotV1{}) || coordinator.SnapshotV1(doc.OrgID) != base {
						t.Fatal("unmeasured/capacity-refused scalar scope reached pins or changed original debt", tx.calls, beforePins)
					}
				} else {
					if beforePins.GlobalGrants != base.GlobalGrants+1 {
						t.Fatal("real collection admission did not precede refused pins/header", beforePins)
					}
					if coordinator.SnapshotV1(doc.OrgID) != beforePins {
						t.Fatal("failed construction refunded physically live collection debt")
					}
				}
				reader.CloseConsumerV1()
			}
			// Consumer completion is not physical retirement. Until the explicit
			// synthetic witness closes, every original native loan remains charged.
			owed := coordinator.SnapshotV1(doc.OrgID)
			if owed.GlobalGrants < 3 {
				t.Fatal("consumer close credited an unretired physical owner", owed)
			}
			if _, err := f.adapter.ReconcileCleanupV1(ctx); err != nil {
				t.Fatal(err)
			}
			if coordinator.SnapshotV1(doc.OrgID) != owed {
				t.Fatal("reconcile inferred retirement from completed consumers")
			}
			close(f.done)
			if pending, err := f.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 0 {
				t.Fatal("complete original bookkeeping conjunction did not settle", pending, err)
			}
			if coordinator.SnapshotV1(doc.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("joined fixture left shared coordinator debt")
			}
		})
	}
}
func TestHTMLRevisionCollectionsRejectZeroAndCopiedShellsV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	id := uuid.New()
	var nilOwner *ApplicationHTMLRevisionCollectionsV1
	nilOwner.CloseConsumerV1()
	var zero ApplicationHTMLRevisionCollectionsV1
	zero.CloseConsumerV1()
	for _, o := range []*ApplicationHTMLRevisionCollectionsV1{nilOwner, &zero, &ApplicationHTMLRevisionCollectionsV1{self: &zero}} {
		if rows, err := o.ListRecipientsByDocument(ctx, id); rows != nil || err == nil {
			t.Fatal("unowned shell read recipient bodies")
		}
		if err := o.acquireStatementV1(ctx, htmlRevisionSnapshotCaptureStageV1); err == nil {
			t.Fatal("unowned shell minted capture staging")
		}
	}
}
