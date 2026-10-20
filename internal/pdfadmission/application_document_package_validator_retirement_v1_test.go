// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// Private in-memory lifetime fixture with actual coordinator/admission loans.
// Session/source bookkeeping and the backend witness are explicitly synthetic;
// these tests prove no SQL/auth/source-constructor or PDF acceptance authority.
// The separate genuine PostgreSQL/REST journey must qualify the positive flow.
type packageValidatorRetirementFixtureV1 struct {
	op          *ApplicationDocumentPackageOperationV1
	a           *ApplicationAdmissionV1
	coordinator *workguard.CoordinatorV1
	sources     [2]*applicationHTMLRevisionSourceOwnerV1
	releases    atomic.Int32
}

func packageValidatorRetirementFixture233(t *testing.T, draft bool) *packageValidatorRetirementFixtureV1 {
	t.Helper()
	native, session, coordinator := applicationRequestLoanFixtureV1(t)
	ctx, cancel := context.WithCancel(applicationTestContextV1(t))
	session.state.retired = true
	close(native.done) // Explicit synthetic backend witness only.
	s := &applicationDocumentPackageOperationStateV1{factory: &ApplicationSessionFactoryV1{state: session.state.factory}, ctx: ctx, cancel: cancel, org: native.scope.OrgID, actor: uuid.New(), ids: [2]uuid.UUID{native.scope.DocumentID, uuid.New()}, initialRead: true, measuredOK: true, finalAttempted: true, consumersDone: make(chan struct{})}
	f := &packageValidatorRetirementFixtureV1{op: &ApplicationDocumentPackageOperationV1{state: s}, a: native.adapter, coordinator: coordinator}
	makeLoan := func(n int64) (*applicationLoanV1, func()) {
		g, err := coordinator.TryAcquireV1(ctx, s.org, workguard.VectorV1{ParentBytes: n})
		if err != nil {
			t.Fatal(err)
		}
		loan := &applicationLoanV1{budget: ApplicationBudgetV1{Phase: "test-retained-frame", WorkingBytes: n}, release: g.Close}
		f.a.mu.Lock()
		f.a.loans[loan] = struct{}{}
		f.a.mu.Unlock()
		return loan, func() { f.a.mu.Lock(); loan.consumerClosed = true; f.a.mu.Unlock() }
	}
	_, bodyClose := makeLoan(8192)
	initial := &applicationDocumentPackageSelectionStateV1{session: session, ids: s.ids, readActor: s.actor, sourcesValidated: true, cancel: func() {}, closes: []func(){bodyClose}}
	s.stages[0] = applicationDocumentPackageStageV1{session: session, admission: f.a, selection: &ApplicationDocumentPackageSelectionV1{state: initial}}
	for i := range f.sources {
		snapshot := &applicationHTMLRevisionSourceSnapshotV1{document: &generated.Document{ID: s.ids[i], OrgID: s.org}}
		binding := &applicationHTMLRevisionSourceBindingV1{factory: s.factory.state, session: session, admission: f.a, org: s.org, document: s.ids[i], ctx: ctx}
		_, sourceCancel := context.WithCancel(ctx)
		loan, sourceClose := makeLoan(4096)
		source := &applicationHTMLRevisionSourceOwnerV1{purpose: htmlPackageSelectionSourcePurposeV1, binding: binding, snapshot: snapshot, cancel: sourceCancel, closes: []func(){sourceClose}, releaseBorrower: func() { f.releases.Add(1) }}
		source.self = source
		source.parentLoan = &applicationHTMLRevisionSourceLoanV1{owner: source, binding: binding, loan: loan}
		f.sources[i] = source
		initial.sources[i] = source
		s.snapshots[i] = snapshot
	}
	if draft {
		initial.draft = &applicationDocumentPackageDraftSnapshotV1{}
		initial.active = 1
		s.draft = initial.draft
		var once sync.Once
		s.releaseDraft = func() { once.Do(initial.finishV1) }
	}
	t.Cleanup(func() {
		f.op.CloseConsumerV1()
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if _, err := f.a.ReconcileCleanupV1(cleanup); err != nil {
			t.Error(err)
		}
		if coordinator.SnapshotV1(s.org).Global.ParentBytes != 0 {
			t.Error("bookkeeping fixture leaked retained debt")
		}
	})
	return f
}
func TestDocumentPackageValidatorRetirementPreservesSnapshotDebtV1(t *testing.T) {
	for _, mode := range []string{"without draft", "retained draft borrower", "closed retained draft borrower"} {
		t.Run(mode, func(t *testing.T) {
			draft := mode != "without draft"
			f := packageValidatorRetirementFixture233(t, draft)
			if mode == "closed retained draft borrower" {
				f.op.state.stages[0].selection.CloseConsumerV1()
			}
			s := f.op.state
			before := f.coordinator.SnapshotV1(s.org)
			if before.Global.ParentBytes != 16384 {
				t.Fatal("missing real fixture debt", before)
			}
			if err := s.retireInitialValidatorsV1(); err != nil {
				t.Fatal(err)
			}
			after := f.coordinator.SnapshotV1(s.org)
			if after.Global.ParentBytes != 8192 || after.GlobalGrants != 1 || f.a.PendingV1().Loans != 1 || f.releases.Load() != 2 {
				t.Fatal("validator cleanup refunded retained snapshots/draft or failed to release exact ended work", before, after)
			}
			for i, source := range f.sources {
				if !source.retired || !source.closed || source.active != 0 || source.snapshot != nil || s.snapshots[i] == nil || s.snapshots[i].document.ID != s.ids[i] {
					t.Fatal("validator/snapshot lifetimes were conflated")
				}
			}
			if draft && (s.draft == nil || s.releaseDraft == nil || s.stages[0].selection.state.active != 1) {
				t.Fatal("retained actual draft borrower was released")
			}
		})
	}
}
func TestDocumentPackageValidatorRetirementRefusesUnfinishedWorkV1(t *testing.T) {
	for _, mode := range []string{"source activity", "policy activity", "unknown SQL", "canceled", "missing prepared selection"} {
		t.Run(mode, func(t *testing.T) {
			f := packageValidatorRetirementFixture233(t, true)
			s := f.op.state
			s.finalAttempted = false
			selecting := false
			switch mode {
			case "source activity":
				f.sources[0].active = 1
				defer func() { f.sources[0].active = 0 }()
			case "policy activity":
				s.stages[0].selection.state.active++
				defer s.stages[0].selection.state.finishV1()
			case "unknown SQL":
				s.stages[0].session.state.commitUnknown = true
			case "canceled":
				s.cancel()
			case "missing prepared selection":
				selecting = true
				s.selectionAttempted = true
			}
			before := f.coordinator.SnapshotV1(s.org)
			var policyCalls atomic.Int32
			err := f.op.withVerifiedSourcesV1(func(context.Context, generated.DBTX, *ApplicationDocumentPackageSelectionV1) (func(context.Context) error, error) {
				policyCalls.Add(1)
				return nil, nil
			}, selecting, func(context.Context, generated.DBTX, *ApplicationDocumentPackageSelectionV1) error {
				t.Fatal("unfinished cleanup reached final callback")
				return nil
			})
			if err == nil || policyCalls.Load() != 0 || s.stages[1].session != nil || f.coordinator.SnapshotV1(s.org) != before || f.releases.Load() != 0 {
				t.Fatal("unfinished/unknown cleanup opened final work or refunded debt", err)
			}
		})
	}
}
func TestDocumentPackageValidatorRetirementJoinsWinningCleanupBatchV1(t *testing.T) {
	f := packageValidatorRetirementFixture233(t, true)
	s := f.op.state
	s.finalAttempted = false
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.sources[0].closes = append([]func(){func() { close(entered); <-resume }}, f.sources[0].closes...)
	var policyCalls atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- f.op.withVerifiedSourcesV1(func(context.Context, generated.DBTX, *ApplicationDocumentPackageSelectionV1) (func(context.Context) error, error) {
			policyCalls.Add(1)
			return nil, nil
		}, false, func(context.Context, generated.DBTX, *ApplicationDocumentPackageSelectionV1) error { return nil })
	}()
	defer func() {
		once.Do(func() { close(resume) })
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Error("winning cleanup did not join")
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup batch did not enter")
	}
	f.sources[0].mu.Lock()
	claimed := f.sources[0].retired
	f.sources[0].mu.Unlock()
	s.mu.Lock()
	finalOpened := s.stages[1].session != nil
	s.mu.Unlock()
	if !claimed || finalOpened || policyCalls.Load() != 0 || f.coordinator.SnapshotV1(s.org).Global.ParentBytes != 16384 {
		t.Fatal("visible retired flag allowed final dispatch/refund before actual cleanup")
	}
	f.op.CloseConsumerV1()
	if s.ctx.Err() == nil || f.coordinator.SnapshotV1(s.org).Global.ParentBytes != 16384 {
		t.Fatal("cancellation refunded unfinished cleanup")
	}
	once.Do(func() { close(resume) })
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled cleanup dispatched final stage")
		}
		result <- err
	case <-time.After(time.Second):
		t.Fatal("cleanup did not return")
	}
	if policyCalls.Load() != 0 || s.stages[1].session != nil || f.coordinator.SnapshotV1(s.org).Global.ParentBytes != 16384 {
		t.Fatal("canceled final path dispatched/refunded before explicit reconciliation")
	}
}
