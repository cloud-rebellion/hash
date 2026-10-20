// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"reflect"
	"testing"
	"time"
)

// This pure DTO test proves detached value lifetime only, never SQL provenance,
// measured caches, native admission, legal source validity or retirement.
func TestHTMLRevisionPrivateSnapshotCoversAllActualVariableDocumentFieldsV1(t *testing.T) {
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New()}
	value := reflect.ValueOf(doc).Elem()
	variableFields := 0
	textType := reflect.TypeOf(pgtype.Text{})
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		switch {
		case field.Kind() == reflect.String:
			field.SetString("original " + value.Type().Field(i).Name + " é<&")
			variableFields++
		case field.Type() == textType:
			field.Set(reflect.ValueOf(pgtype.Text{String: "original " + value.Type().Field(i).Name + " é<&", Valid: true}))
			variableFields++
		case field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint8:
			field.SetBytes([]byte("original " + value.Type().Field(i).Name + " é<&"))
			variableFields++
		}
	}
	// Full current Document has34 raw fields+six JSON fields; schema drift must
	// explicitly update original SQL cost/projection and snapshot ownership too.
	if variableFields != 40 {
		t.Fatalf("actual full Document variable inventory changed: %d", variableFields)
	}
	detached := htmlRevisionCloneDocumentV1(doc)
	if detached == nil || !reflect.DeepEqual(doc, detached) {
		t.Fatal("private snapshot changed original complete values")
	}
	expected := fmt.Sprintf("%#v", *detached)
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		switch {
		case field.Kind() == reflect.String:
			field.SetString("caller replaced scalar")
		case field.Type() == textType:
			field.Set(reflect.ValueOf(pgtype.Text{String: "caller replaced optional scalar", Valid: true}))
		case field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint8:
			raw := field.Bytes()
			if len(raw) > 0 {
				raw[0] ^= 0xff
			}
		}
	}
	if fmt.Sprintf("%#v", *detached) != expected {
		t.Fatal("caller model/buffer mutation replaced private original source or PDF/digest pins")
	}
	if htmlRevisionCloneDocumentV1(nil) != nil {
		t.Fatal("legacy absent model fabricated")
	}
}
func TestHTMLRevisionPrivateCurrentRetainsAllPolicyValuesV1(t *testing.T) {
	current := &htmlmaterialization.CurrentReadProjectionV1{ID: uuid.New(), DocumentID: uuid.New(), OrgID: uuid.New(), Sequence: 9, PageCount: 4, PdfKey: "original/key", PdfVersionID: "original-version", PdfSha256: bytes.Repeat([]byte{1}, 32), SourceCommitment: bytes.Repeat([]byte{2}, 32), OriginCommitment: bytes.Repeat([]byte{3}, 32), SourceJson: []byte("original source"), MetadataRedactionReport: []byte("original report")}
	detached := htmlRevisionCloneCurrentV1(current)
	if !reflect.DeepEqual(detached, current) {
		t.Fatal("minimal Current12 values changed")
	}
	expected := fmt.Sprintf("%#v", *detached)
	for _, raw := range [][]byte{current.PdfSha256, current.SourceCommitment, current.OriginCommitment, current.SourceJson, current.MetadataRedactionReport} {
		raw[0] ^= 0xff
	}
	current.PdfKey = "replaced"
	current.PdfVersionID = "replaced"
	if fmt.Sprintf("%#v", *detached) != expected {
		t.Fatal("caller Current tuple/buffer mutation replaced original retained policy")
	}
	if htmlRevisionCloneCurrentV1(nil) != nil {
		t.Fatal("legacy no-current row fabricated")
	}
}
func TestHTMLRevisionReadV1ZeroShellHasNoSourceAuthority(t *testing.T) {
	ctx := applicationTestContextV1(t)
	var nilReader *ApplicationHTMLRevisionReaderV1
	nilReader.CloseConsumerV1()
	var zero ApplicationHTMLRevisionReaderV1
	zero.CloseConsumerV1()
	if source, release, err := zero.borrowHTMLRevisionSourceV1(ctx); source != nil || release != nil || err == nil {
		t.Fatal("zero reader minted native source borrower")
	}
	if models, err := zero.ReadDocumentV1(ctx, uuid.New(), func(HTMLRevisionReadAccessV1) error { return nil }); models != nil || err == nil {
		t.Fatal("zero reader minted full models")
	}
}

// Explicit native BOOKKEEPING fixture: mocked scalar/body scan values and
// synthetic backend retirement are data for lifetime testing only. They prove
// neither PostgreSQL provenance/cache correctness nor legal source validity.
type htmlRevisionReadTxTestV1 struct {
	*applicationSessionTxTestV1
	rows  []pgx.Row
	calls int
}

func (x *htmlRevisionReadTxTestV1) QueryRow(context.Context, string, ...any) pgx.Row {
	x.calls++
	if len(x.rows) == 0 {
		return htmlRevisionReadRowTestV1{err: errors.New("unexpected synthetic body read")}
	}
	row := x.rows[0]
	x.rows = x.rows[1:]
	return row
}

type htmlRevisionReadRowTestV1 struct {
	record any
	err    error
}

func (x htmlRevisionReadRowTestV1) Scan(dest ...any) error {
	if x.err != nil {
		return x.err
	}
	record := reflect.ValueOf(x.record)
	if record.Kind() != reflect.Struct || record.NumField() != len(dest) {
		return errors.New("synthetic scan/schema order mismatch")
	}
	for i, ptr := range dest {
		field := reflect.ValueOf(ptr)
		value := record.Field(i)
		if field.Kind() != reflect.Pointer || field.IsNil() || !value.Type().AssignableTo(field.Elem().Type()) {
			return errors.New("synthetic scan field mismatch")
		}
		field.Elem().Set(value)
	}
	return nil
}
func TestHTMLRevisionSourceBorrowersJoinOriginalReadLoansV1(t *testing.T) {
	for _, physicalFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("physical_first_%t", physicalFirst), func(t *testing.T) {
			f, session, coordinator := applicationRequestLoanFixtureV1(t)
			session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
			ctx := applicationTestContextV1(t)
			user := uuid.New()
			stamp := pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 0, 0, 0, 1, time.UTC), Valid: true}
			doc := generated.Document{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, SenderID: user, Name: "original", Status: "draft", SourceKind: "pdf", UpdatedAt: stamp, HtmlSourceJson: []byte("{}"), VariablesJson: []byte("{}"), BlocksJson: []byte("[]"), Metadata: []byte("{}"), MetadataRedactionReport: []byte("{}")}
			header := generated.GetHTMLRevisionDocumentReadHeaderV1Row{ID: doc.ID, OrgID: doc.OrgID, SenderID: user, UpdatedAt: stamp, IsDraft: true, HasHtmlSource: true, RawTextBytes: signerDocumentRawBytesV1(&doc), HtmlOriginWireBytes: 2, VariablesWireBytes: 2, BlocksWireBytes: 2, MetadataWireBytes: 2, ReportWireBytes: 2, PolicyMeasurementServerVersionNum: 160015, ResponseMeasurementServerVersionNum: 160015, ReportMeasurementServerVersionNum: 160015, ServerVersionNum: 160015}
			tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: []pgx.Row{htmlRevisionReadRowTestV1{record: header}, htmlRevisionReadRowTestV1{record: generated.GetHTMLAuthoringActorHeaderV1Row{UserID: user, OrgID: doc.OrgID, RawTextBytes: 4}}, htmlRevisionReadRowTestV1{record: doc}}}
			session.state.tx = tx
			var reader *ApplicationHTMLRevisionReaderV1
			var releaseFirst, releaseLast func()
			t.Cleanup(func() {
				if reader != nil {
					reader.CloseConsumerV1()
				}
				if releaseFirst != nil {
					releaseFirst()
				}
				if releaseLast != nil {
					releaseLast()
				}
				if !applicationDoneV1(f.done) {
					close(f.done)
				}
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				_ = f.adapter.CloseV1(cleanup)
			})
			preflight := 0
			err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
				var err error
				reader, err = session.NewHTMLRevisionReaderV1(call)
				if err != nil {
					return err
				}
				models, err := reader.ReadDocumentV1(call, user, func(a HTMLRevisionReadAccessV1) error {
					preflight++
					if a.DocumentID != doc.ID || a.OrgID != doc.OrgID || a.SenderID != user || !a.Draft {
						return errors.New("original scalar preflight scope changed")
					}
					return nil
				})
				if err != nil {
					return err
				}
				models.Document.Name = "mutable exposed model"
				models.Document.HtmlSourceJson[0] = '!'
				return nil
			})
			if err != nil || reader == nil || preflight != 1 || tx.calls != 3 || len(tx.rows) != 0 {
				t.Fatal("actual fixed native reader callback/scan did not complete", err, preflight, tx.calls)
			}
			borrowed, cancel := context.WithCancel(ctx)
			t.Cleanup(cancel)
			snapshot, release, err := reader.borrowHTMLRevisionSourceV1(borrowed)
			if err != nil {
				t.Fatal(err)
			}
			releaseFirst = release
			same, release, err := reader.borrowHTMLRevisionSourceV1(ctx)
			if err != nil || same != snapshot {
				t.Fatal("same original reader could not retain another actual source use", err)
			}
			releaseLast = release
			if snapshot.document.Name != "original" || string(snapshot.document.HtmlSourceJson) != "{}" {
				t.Fatal("mutable caller model replaced original source snapshot")
			}
			before := coordinator.SnapshotV1(doc.OrgID)
			// One actual fixed header plus independently positive complete actor
			// and document/current body loans survive BOTH original joins. No
			// per-body OtherWork floor or borrower release is invented here.
			wire := header.HtmlOriginWireBytes + header.HtmlCurrentWireBytes + header.VariablesWireBytes + header.BlocksWireBytes + header.MetadataWireBytes + header.ReportWireBytes
			bodyCost, err := htmlAuthoringRetainedBodyResourcesV1(header.RawTextBytes, wire)
			if err != nil {
				t.Fatal(err)
			}
			actorCost, err := htmlAuthoringRetainedBodyResourcesV1(4, 0)
			if err != nil {
				t.Fatal(err)
			}
			fixedAndWire := int64(32<<20) + bodyCost.DBStagingBytes + actorCost.DBStagingBytes
			if before.GlobalGrants != 3 || before.Global.DBStagingBytes != fixedAndWire || before.Global.ParentBytes-before.Global.DBStagingBytes != 8*(header.RawTextBytes+4) || f.adapter.PendingV1().Loans != 3 {
				t.Fatal("actual header/actor/body native grants missing", before)
			}
			cancel()
			reader.mu.Lock()
			borrowersAfterCancel := reader.sourceBorrowers
			reader.mu.Unlock()
			if borrowersAfterCancel != 2 {
				t.Fatal("caller cancellation ended an original active source borrower", borrowersAfterCancel)
			}
			if _, again, err := reader.borrowHTMLRevisionSourceV1(borrowed); err == nil || again != nil {
				t.Fatal("canceled context minted new source borrower")
			}
			copyShell := &ApplicationHTMLRevisionReaderV1{self: reader, session: session, authoring: reader.authoring, snapshot: reader.snapshot}
			copyShell.CloseConsumerV1()
			if physicalFirst {
				close(f.done)
				if pending, err := f.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 3 {
					t.Fatal("physical-first bookkeeping retired live source consumers", pending, err)
				}
			}
			reader.CloseConsumerV1()
			if _, again, err := reader.borrowHTMLRevisionSourceV1(ctx); err == nil || again != nil {
				t.Fatal("closed route minted a later source borrower")
			}
			if reader.snapshot != snapshot || reader.models == nil || reader.resourcesClosed || coordinator.SnapshotV1(doc.OrgID) != before {
				t.Fatal("route close or caller cancellation dropped borrowed original body")
			}
			releaseFirst()
			releaseFirst()
			if reader.snapshot != snapshot || reader.resourcesClosed || coordinator.SnapshotV1(doc.OrgID) != before {
				t.Fatal("one borrower credited another still-active original use")
			}
			snapshot = nil
			same = nil // fixed borrower has finished using the original model
			releaseLast()
			releaseLast()
			if reader.snapshot != nil || reader.models != nil || reader.authoring != nil || reader.closeConsumers != nil || !reader.resourcesClosed {
				t.Fatal("joined last use retained original backing after consumer closure")
			}
			if !physicalFirst {
				if pending, err := f.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 3 || coordinator.SnapshotV1(doc.OrgID) != before {
					t.Fatal("consumer-first bookkeeping credited unretired physical owner", pending, err)
				}
				close(f.done)
			}
			// This advances only the fixture's declared synthetic retirement witness.
			// Actual public factory/backend retirement remains a separate PG gate.
			if pending, err := f.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 0 {
				t.Fatal("joined original conjunction did not retire bookkeeping debt", pending, err)
			}
			if got := coordinator.SnapshotV1(doc.OrgID); got != (workguard.SnapshotV1{}) {
				t.Fatal("original shared coordinator debt remained after full conjunction", got)
			}
		})
	}
}

func TestHTMLRevisionLockedActorPolicyPrecedesMissingDocumentCachesV1(t *testing.T) {
	revoked := errors.New("original live actor credential or role refused")
	for _, mode := range []string{"revoked-role", "missing-member", "valid-actor-missing-cache", "invalid-actor-size", "actor-capacity-denied"} {
		t.Run(mode, func(t *testing.T) {
			// Same explicit synthetic bookkeeping boundary as the borrower fixture.
			f, session, coordinator := applicationRequestLoanFixtureV1(t)
			session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
			ctx := applicationTestContextV1(t)
			user := uuid.New()
			observedActorDenial := false
			if mode == "actor-capacity-denied" {
				acquire := f.adapter.acquire
				f.adapter.acquire = func(call context.Context, b ApplicationBudgetV1) (func(), error) {
					release, err := acquire(call, b)
					if b.HTMLAuthoringRawBytes == 256<<20 {
						observedActorDenial = release == nil && errors.Is(err, workguard.ErrUnavailableV1)
					}
					return release, err // preserve the actual fixed work adapter result
				}
			}
			member := generated.User{ID: user, OrgID: f.scope.OrgID, Email: "original@example.test", Name: "Original User", Role: "owner", ZitadelSub: pgtype.Text{String: "original-subject", Valid: true}}
			if mode == "revoked-role" {
				member.Role = "viewer"
			}
			raw := int64(len(member.Email) + len(member.Name) + len(member.Role) + len(member.ZitadelSub.String))
			header := generated.GetHTMLRevisionDocumentReadHeaderV1Row{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, SenderID: user, IsDraft: true, HasHtmlSource: true, UpdatedAt: pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 0, 0, 0, 1, time.UTC), Valid: true}, ServerVersionNum: 160015}
			actor := generated.GetHTMLAuthoringActorHeaderV1Row{UserID: user, OrgID: f.scope.OrgID, RawTextBytes: raw}
			actorRow := htmlRevisionReadRowTestV1{record: actor}
			if mode == "missing-member" {
				actorRow = htmlRevisionReadRowTestV1{err: pgx.ErrNoRows}
			}
			if mode == "invalid-actor-size" {
				actor.RawTextBytes = -1
				actorRow = htmlRevisionReadRowTestV1{record: actor}
			}
			if mode == "actor-capacity-denied" {
				actor.RawTextBytes = 256 << 20
				actorRow = htmlRevisionReadRowTestV1{record: actor}
				if cost, err := htmlAuthoringRetainedBodyResourcesV1(actor.RawTextBytes, 0); err != nil || cost.WorkingBytes <= 1<<30 {
					t.Fatal("positive actor cost did not exceed actual shared coordinator", cost, err)
				}
			}
			rows := []pgx.Row{htmlRevisionReadRowTestV1{record: header}, actorRow}
			if mode != "missing-member" && mode != "invalid-actor-size" && mode != "actor-capacity-denied" {
				rows = append(rows, htmlRevisionReadRowTestV1{record: member})
			}
			tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: rows}
			session.state.tx = tx
			var reader *ApplicationHTMLRevisionReaderV1
			t.Cleanup(func() {
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
			preflightCalls, actorCalls := 0, 0
			err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
				var err error
				reader, err = session.NewHTMLRevisionReaderV1(call)
				if err != nil {
					return err
				}
				models, err := reader.ReadDocumentWithActorV1(call, user, func(a HTMLRevisionReadAccessV1) error {
					preflightCalls++
					if !a.Draft || a.SenderID != user || a.OrgID != f.scope.OrgID || a.DocumentID != f.scope.DocumentID {
						return errors.New("real scalar parent changed")
					}
					return nil
				}, func(a HTMLRevisionReadAccessV1, locked *generated.User) error {
					actorCalls++
					if locked == nil {
						return revoked
					}
					if locked.ID != member.ID || locked.OrgID != member.OrgID || locked.Email != member.Email || locked.Name != member.Name || locked.Role != member.Role || locked.ZitadelSub != member.ZitadelSub {
						return errors.New("actual locked actor values changed")
					}
					// This stands in only for a fixed caller's original pure role decision;
					// it grants no real credential, user state or SQL provenance to the test.
					if locked.Role != "owner" && locked.Role != "sender" {
						return revoked
					}
					if a.SenderID != user {
						return revoked
					}
					return nil
				})
				if models != nil {
					return errors.New("missing body cache exposed full Document")
				}
				return err
			})
			expectedCalls := 3
			if mode == "missing-member" || mode == "invalid-actor-size" || mode == "actor-capacity-denied" {
				expectedCalls = 2
			}
			if tx.calls != expectedCalls || len(tx.rows) != 0 || preflightCalls != 1 {
				t.Fatal("scalar/actor stage read beyond original policy refusal", tx.calls, preflightCalls)
			}
			if mode == "revoked-role" || mode == "missing-member" {
				if !errors.Is(err, revoked) || actorCalls != 1 {
					t.Fatal("missing body cache masked the original live actor refusal", err, actorCalls)
				}
			} else {
				if !errors.Is(err, ErrHTMLRevisionReadV1) || errors.Is(err, revoked) {
					t.Fatal("true body/size admission refusal was misclassified as actor revocation", err)
				}
				wantActorCalls := 1
				if mode == "invalid-actor-size" || mode == "actor-capacity-denied" {
					wantActorCalls = 0
				}
				if actorCalls != wantActorCalls {
					t.Fatal("invalid resource metadata entered actor policy callback", actorCalls)
				}
			}
			if mode == "actor-capacity-denied" {
				if !observedActorDenial || !errors.Is(err, ErrApplicationAdmissionV1) {
					t.Fatal("actual coordinator denial or original sanitized failure missing", observedActorDenial, err)
				}
				actual := coordinator.SnapshotV1(f.scope.OrgID)
				if actual.GlobalGrants != 1 || actual.Global.ParentBytes != 32<<20 || actual.Global.DBStagingBytes != 32<<20 || f.adapter.PendingV1().Loans != 1 {
					t.Fatal("denied actor changed original header debt", actual)
				}
			}
			if reader.snapshot != nil || reader.models != nil || reader.bodyComplete {
				t.Fatal("policy/cache refusal manufactured original source authority")
			}
			reader.CloseConsumerV1()
			close(f.done)
			if pending, err := f.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 0 {
				t.Fatal("refused actor stage retained closed bookkeeping grants", pending, err)
			}
			if coordinator.SnapshotV1(f.scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("refused actor stage leaked shared bookkeeping capacity")
			}
		})
	}
}
