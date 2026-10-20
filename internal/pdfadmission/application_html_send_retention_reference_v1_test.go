// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
	"unsafe"
)

func TestSendRetentionScalarReferenceOutlivesOnlyActualRowConsumerV1(t *testing.T) {
	fixture, session, coordinator := applicationRequestLoanFixtureV1(t)
	factory := &ApplicationSessionFactoryV1{state: session.state.factory}
	factory.state.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	ctx := applicationTestContextV1(t)
	operation, err := factory.NewHTMLSendOperationV1(ctx, fixture.scope.OrgID, fixture.scope.DocumentID)
	if err != nil {
		t.Fatal(err)
	}
	stage := &ApplicationHTMLSendSQLStageV1{operation: operation, purpose: HTMLSendIntentReadV1, ctx: ctx, cancel: func() {}, session: session, active: true}
	stage.self = stage
	operation.stages = append(operation.stages, stage)
	at := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	var work *ApplicationHTMLSendWorkV1
	var retained *ApplicationHTMLSendRetentionStateV1
	// Existing explicit synthetic already-open protocol fixture: positive actual
	// native reader/admission/coordinator executes, not public SQL/body authority.
	err = session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var err error
		work, err = session.NewHTMLSendWorkV1(call, stage)
		if err != nil {
			return err
		}
		closeRow, err := work.actor.acquireOwnedRetainedBodyV1(call, 4*int64(unsafe.Sizeof(generated.SendSealingIntent{})), 0)
		if err != nil {
			return err
		}
		work.closes = append(work.closes, closeRow)
		work.sourceIntent = &generated.SendSealingIntent{DocumentID: fixture.scope.DocumentID, OrgID: fixture.scope.OrgID, Article13NoticeEpochAt: pgtype.Timestamptz{Time: at, Valid: true}, RetainUntil: pgtype.Timestamptz{Time: at.AddDate(7, 0, 0), Valid: true}}
		work.intentRead = true
		retained, err = work.CaptureSendRetentionStateV1(call)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if operation.retentionReference != nil {
			operation.retentionReference.closeV1()
		}
		work.CloseConsumerV1()
		if !applicationDoneV1(fixture.done) {
			close(fixture.done)
		}
		_ = fixture.adapter.CloseV1(ctx)
	})
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	projection, err := retained.SnapshotV1()
	if err != nil {
		t.Fatal(err)
	}
	projection.RetainUntil.Time = projection.RetainUntil.Time.Add(time.Hour)
	again, err := retained.SnapshotV1()
	if err != nil || !again.RetainUntil.Time.Equal(at.AddDate(7, 0, 0)) {
		t.Fatal("caller projection modified actual immutable native scalar", err)
	}
	copied := &ApplicationHTMLSendRetentionStateV1{owner: retained.owner, index: retained.index}
	if _, err = copied.SnapshotV1(); err == nil {
		t.Fatal("copied scalar shell accepted")
	}
	work.CloseConsumerV1()
	if work.sourceIntent != nil {
		t.Fatal("old actual full intent remained a consumer")
	}
	if _, err = retained.SnapshotV1(); err != nil {
		t.Fatal("independently retained scalar borrowed retired full row", err)
	}
	if coordinator.SnapshotV1(fixture.scope.OrgID) != before {
		t.Fatal("logical close credited unresolved physical debt")
	}
	retained.owner.closeV1()
	if _, err = retained.SnapshotV1(); err == nil {
		t.Fatal("closed scalar reference accepted")
	}
	after := coordinator.SnapshotV1(fixture.scope.OrgID)
	if after.Global.ParentBytes >= before.Global.ParentBytes || after.Global.DBStagingBytes != before.Global.DBStagingBytes {
		t.Fatal("fixed scalar Parent grant did not end independently of actual SQL/DB debt", before, after)
	}
}
