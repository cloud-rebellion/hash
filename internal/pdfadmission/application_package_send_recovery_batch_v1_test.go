// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestPackageRecoveryCursorHasNoImplicitScopeV1(t *testing.T) {
	stamp, id, e := packageSendRecoveryAfterV1(PackageSendRecoveryCursorV1{})
	if e != nil || !stamp.Valid || stamp.InfinityModifier != pgtype.NegativeInfinity || id != uuid.Nil {
		t.Fatal(stamp, id, e)
	}
	for _, c := range []PackageSendRecoveryCursorV1{{AttemptID: uuid.New()}, {CreatedAt: time.Now()}, {CreatedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), AttemptID: uuid.New()}} {
		if _, _, e := packageSendRecoveryAfterV1(c); e == nil {
			t.Fatal("incomplete cursor accepted", c)
		}
	}
	now := time.Now().UTC()
	want := uuid.New()
	stamp, id, e = packageSendRecoveryAfterV1(PackageSendRecoveryCursorV1{CreatedAt: now, AttemptID: want})
	if e != nil || !stamp.Time.Equal(now) || id != want {
		t.Fatal(stamp, id, e)
	}
}
func TestPackageRecoveryQueueOrderUsesFullTimestampAndUUIDV1(t *testing.T) {
	now := time.Now().UTC()
	stamp := pgtype.Timestamptz{Valid: true, Time: now}
	later := pgtype.Timestamptz{Valid: true, Time: now.Add(time.Microsecond)}
	a := uuid.MustParse("01000000-0000-0000-0000-000000000000")
	b := uuid.MustParse("01000000-0000-0000-0000-000000000001")
	if !packageSendRecoveryOrderedV1(stamp, a, stamp, b) || packageSendRecoveryOrderedV1(stamp, b, stamp, a) || packageSendRecoveryOrderedV1(stamp, a, stamp, a) || !packageSendRecoveryOrderedV1(stamp, b, later, a) || packageSendRecoveryOrderedV1(later, a, stamp, b) {
		t.Fatal("keyset order aliased or reversed")
	}
}
func TestPackageRecoveryCloseRetainsActualProcessGrantThroughJoinV1(t *testing.T) {
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 4096, DBStagingBytes: 4096, SQLSessions: 1}, Organisation: workguard.VectorV1{ParentBytes: 4096, DBStagingBytes: 4096, SQLSessions: 1}, MaxGrants: 4, MaxOrganisationGrants: 2}
	c, e := workguard.NewV1(limits)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	g, e := c.TryAcquireProcessV1(ctx, workguard.VectorV1{ParentBytes: 1024, DBStagingBytes: 1024})
	if e != nil {
		t.Fatal(e)
	}
	p := &applicationSessionFactoryStateV1{}
	f := &ApplicationSessionFactoryV1{state: p}
	s := &applicationPackageSendRecoveryBatchStateV1{factory: f, ctx: ctx, cancel: cancel, release: g.Close, active: true}
	p.packageRecoveryBatches[0] = s
	h := &ApplicationPackageSendRecoveryBatchV1{state: s}
	cleanup, finish := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer finish()
	if e := f.ReconcileCleanupV1(cleanup); e != nil {
		t.Fatal("open active work became cleanup debt", e)
	}
	copy := *h
	copy.CloseConsumerV1()
	h.CloseConsumerV1()
	if after := c.SnapshotV1(uuid.Nil); after.Global.ParentBytes != 1024 || p.packageRecoveryBatches[0] != s {
		t.Fatal("active close credited process debt", after)
	}
	if e := f.ReconcileCleanupV1(cleanup); !errors.Is(e, ErrApplicationSessionUnknownV1) || c.SnapshotV1(uuid.Nil).Global.ParentBytes != 1024 {
		t.Fatal("factory acknowledged closed callback debt before actual join", e)
	}
	s.mu.Lock()
	s.active = false
	s.reconciling = true
	s.mu.Unlock()
	if s.reconcileV1(nil) || c.SnapshotV1(uuid.Nil).Global.ParentBytes != 1024 {
		t.Fatal("recursive reconcile credited ownership")
	}
	if e := f.ReconcileCleanupV1(cleanup); !errors.Is(e, ErrApplicationSessionUnknownV1) {
		t.Fatal("factory acknowledged a concurrent unfinished reconciliation", e)
	}
	s.mu.Lock()
	s.reconciling = false
	s.mu.Unlock()
	if e := f.ReconcileCleanupV1(cleanup); e != nil || p.packageRecoveryBatches[0] != nil || c.SnapshotV1(uuid.Nil).GlobalGrants != 0 {
		t.Fatal("actual join did not retire registration/grant")
	}
}
func TestPackageRecoveryNilAndCopiedEmptyHandlesCannotInspectV1(t *testing.T) {
	called := false
	for _, h := range []*ApplicationPackageSendRecoveryBatchV1{nil, {}, {state: &applicationPackageSendRecoveryBatchStateV1{}}} {
		if more, e := h.WithNextObservationV1(func(HTMLSendPackageAttemptObservationV1) error { called = true; return nil }); more || e == nil {
			t.Fatal("unregistered scope inspected", more, e)
		}
		h.CloseConsumerV1()
	}
	if called {
		t.Fatal("invalid handle delivered output")
	}
}
