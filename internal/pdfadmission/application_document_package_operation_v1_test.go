// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"sync"
	"testing"
	"time"
)

func TestDocumentPackageOperationV1CloseRequiresActualConsumerJoin(t *testing.T) {
	for _, factoryClose := range []bool{false, true} {
		name := "owner"
		if factoryClose {
			name = "factory"
		}
		t.Run(name, func(t *testing.T) {
			org := uuid.New()
			limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 1 << 20}, Organisation: workguard.VectorV1{ParentBytes: 1 << 20}, MaxGrants: 4, MaxOrganisationGrants: 4}
			coordinator, err := workguard.NewV1(limits)
			if err != nil {
				t.Fatal(err)
			}
			testCtx, testCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer testCancel()
			ctx, cancel := context.WithCancel(testCtx)
			defer cancel()
			credit, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 4096})
			if err != nil {
				t.Fatal(err)
			}
			factory := &ApplicationSessionFactoryV1{state: &applicationSessionFactoryStateV1{}}
			entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			state := &applicationDocumentPackageOperationStateV1{factory: factory, ctx: ctx, cancel: cancel, org: org, control: credit, consumersDone: make(chan struct{})}
			state.releases[0] = func() { close(entered); <-release }
			op := &ApplicationDocumentPackageOperationV1{state: state}
			if !factory.registerDocumentPackageOperationV1(state) {
				t.Fatal("registry refused actual test owner")
			}
			go func() { defer close(joined); op.CloseConsumerV1() }()
			defer func() {
				once.Do(func() { close(release) })
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("retirement goroutine did not join")
				}
			}()
			select {
			case <-entered:
			case <-testCtx.Done():
				t.Fatal("retirement did not enter")
			}
			cleanup, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
			var closeErr error
			if factoryClose {
				closeErr = factory.CloseV1(cleanup)
			} else {
				closeErr = op.CloseV1(cleanup)
			}
			stop()
			if !errors.Is(closeErr, ErrApplicationSessionUnknownV1) || !errors.Is(closeErr, context.DeadlineExceeded) {
				t.Fatal("close returned before actual release", closeErr)
			}
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("original operation context not canceled")
			}
			select {
			case <-state.consumersDone:
				t.Fatal("completion fence closed before release joined")
			default:
			}
			if coordinator.SnapshotV1(org).Global.ParentBytes != 4096 || factory.PendingV1().DocumentPackageOperations != 1 {
				t.Fatal("claimed retirement refunded or hid live control")
			}
			once.Do(func() { close(release) })
			select {
			case <-joined:
			case <-testCtx.Done():
				t.Fatal("actual release did not join")
			}
			cleanup, stop = context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if factoryClose {
				closeErr = factory.CloseV1(cleanup)
			} else {
				closeErr = op.CloseV1(cleanup)
			}
			select {
			case <-state.consumersDone:
			default:
				t.Fatal("joined release did not close completion fence")
			}
			if err := op.CloseV1(cleanup); err != nil {
				t.Fatal("repeat close failed", err)
			}
			if closeErr != nil || coordinator.SnapshotV1(org).Global.ParentBytes != 0 || factory.PendingV1().DocumentPackageOperations != 0 {
				t.Fatal("joined retirement did not reconcile", closeErr)
			}
		})
	}
}
func TestDocumentPackageOperationV1RejectsUnownedHandles(t *testing.T) {
	for _, op := range []*ApplicationDocumentPackageOperationV1{nil, {}} {
		op.CloseConsumerV1()
		if op.CloseV1(nil) != nil {
			t.Fatal("empty close failed")
		}
		if !errors.Is(op.MeasurePDFsV1(), ErrDocumentPackageOperationV1) {
			t.Fatal("unowned measure accepted")
		}
		if _, err := op.MeasurementsV1(); !errors.Is(err, ErrDocumentPackageOperationV1) {
			t.Fatal("unowned receipt accepted")
		}
	}
}

// This in-memory lifecycle fixture uses actual coordinator grants and the actual
// registry; it makes no SQL, authentication or provider acceptance claim.
func TestDocumentPackageOperationV1FactoryCancelsAllBeforeRetirement(t *testing.T) {
	supervisor, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	org := uuid.New()
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 1 << 20}, Organisation: workguard.VectorV1{ParentBytes: 1 << 20}, MaxGrants: 4, MaxOrganisationGrants: 4}
	coordinator, err := workguard.NewV1(limits)
	if err != nil {
		t.Fatal(err)
	}
	factory := &ApplicationSessionFactoryV1{state: &applicationSessionFactoryStateV1{}}
	entered, resume, joined := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	var states [2]*applicationDocumentPackageOperationStateV1
	for i := range states {
		ctx, cancel := context.WithCancel(supervisor)
		defer cancel()
		grant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		states[i] = &applicationDocumentPackageOperationStateV1{factory: factory, ctx: ctx, cancel: cancel, org: org, control: grant, consumersDone: make(chan struct{})}
		if !factory.registerDocumentPackageOperationV1(states[i]) {
			t.Fatal("registry refused fixture")
		}
	}
	states[0].releases[0] = func() { close(entered); <-resume }
	go func() { joined <- factory.CloseV1(supervisor) }()
	defer func() {
		once.Do(func() { close(resume) })
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("factory cleanup did not join")
		}
	}()
	select {
	case <-entered:
	case <-supervisor.Done():
		t.Fatal("first retirement did not enter")
	}
	select {
	case <-states[1].ctx.Done():
	case <-supervisor.Done():
		t.Fatal("later owner cancellation blocked behind first retirement")
	}
	if factory.PendingV1().DocumentPackageOperations != 2 || coordinator.SnapshotV1(org).Global.ParentBytes != 8192 {
		t.Fatal("cancel-all refunded a live owner")
	}
	once.Do(func() { close(resume) })
	select {
	case err = <-joined:
		joined <- err
	case <-supervisor.Done():
		t.Fatal("factory cleanup did not finish")
	}
	if err != nil || factory.PendingV1().DocumentPackageOperations != 0 || coordinator.SnapshotV1(org).Global.ParentBytes != 0 {
		t.Fatal("factory did not reconcile both owners", err)
	}
}

// An in-memory opening-state fixture tests sweep progress after an immediate
// Unknown result; it supplies no backend or native retirement evidence.
func TestDocumentPackageOperationV1SweepContinuesAfterUnknownOwner(t *testing.T) {
	supervisor, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	org := uuid.New()
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 1 << 20}, Organisation: workguard.VectorV1{ParentBytes: 1 << 20}, MaxGrants: 4, MaxOrganisationGrants: 4}
	coordinator, err := workguard.NewV1(limits)
	if err != nil {
		t.Fatal(err)
	}
	factory := &ApplicationSessionFactoryV1{state: &applicationSessionFactoryStateV1{}}
	var owners [2]*ApplicationDocumentPackageOperationV1
	for i := range owners {
		ctx, cancel := context.WithCancel(supervisor)
		defer cancel()
		grant, e := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 4096})
		if e != nil {
			t.Fatal(e)
		}
		s := &applicationDocumentPackageOperationStateV1{factory: factory, ctx: ctx, cancel: cancel, org: org, control: grant, consumersDone: make(chan struct{})}
		owners[i] = &ApplicationDocumentPackageOperationV1{state: s}
		if !factory.registerDocumentPackageOperationV1(s) {
			t.Fatal("registry refused fixture")
		}
		owners[i].CloseConsumerV1()
	}
	owners[0].state.stages[0].opening = true
	err = factory.reconcileDocumentPackageOperationsV1(supervisor)
	if !errors.Is(err, ErrApplicationSessionUnknownV1) {
		t.Fatal("unresolved opening was not retained", err)
	}
	if factory.PendingV1().DocumentPackageOperations != 1 || coordinator.SnapshotV1(org).Global.ParentBytes != 0 {
		t.Fatal("later closed owner did not reconcile after first unknown")
	}
	owners[0].state.stages[0].opening = false
	if err = factory.reconcileDocumentPackageOperationsV1(supervisor); err != nil || factory.PendingV1().DocumentPackageOperations != 0 {
		t.Fatal("retry did not drain registry", err)
	}
}
