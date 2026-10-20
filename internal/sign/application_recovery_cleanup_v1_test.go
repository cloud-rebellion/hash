// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

// Private spies prove only the production cleanup/handoff state machine. The
// zero opaque session/registry objects deliberately provide NO real retirement,
// admission, row proof or dispatch authority: dataV1 must still refuse them.
// Real coordinator/session/consumer conjunction is separately exercised by
// TestApplicationPolicyJournalLoanV1SurvivesLiveProjectedScan and real-owned PG.
type applicationCleanupStateSpyTestV1 struct {
	retired         bool
	retires, closes int
	onClose         func(context.Context) error
}

func (s *applicationCleanupStateSpyTestV1) retireV1(context.Context) error {
	s.retires++
	if !s.retired {
		return errApplicationBoundRequestUnknownV1
	}
	return nil
}
func (s *applicationCleanupStateSpyTestV1) retiredV1() bool { return s.retired }
func (s *applicationCleanupStateSpyTestV1) closeRegistryV1(ctx context.Context) error {
	s.closes++
	if s.onClose != nil {
		return s.onClose(ctx)
	}
	return ctx.Err()
}

type applicationCleanupStateFixtureTestV1 struct {
	journal                                     *applicationRequestJournalV1
	original, child                             *applicationRequestOperationV1
	oldCleanup, newCleanup                      *applicationCleanupStateSpyTestV1
	originalConsumerCloses, childConsumerCloses int
}

func newApplicationCleanupStateFixtureTestV1() *applicationCleanupStateFixtureTestV1 {
	key := applicationRequestKeyV1{uuid.New(), uuid.New(), uuid.New()}
	preparationID := uuid.New()
	j := &applicationRequestJournalV1{owners: make(map[applicationRequestKeyV1]*applicationRequestOperationV1)}
	meta := &generated.ReserveBoundSignatureFitRequestV1Row{PreparationID: preparationID, OrgID: key.org, DocumentID: key.document, RecipientID: key.recipient, BindingSha256: make([]byte, 32)}
	f := &applicationCleanupStateFixtureTestV1{journal: j, oldCleanup: &applicationCleanupStateSpyTestV1{retired: true}, newCleanup: &applicationCleanupStateSpyTestV1{retired: true}}
	// exactRowReconciled below is an explicitly synthetic state-machine premise;
	// production writes it only after the actual exact-row read/rebind/retirement.
	f.original = &applicationRequestOperationV1{journal: j, key: key, session: &pdfadmission.ApplicationSessionV1{}, admission: &pdfadmission.ApplicationAdmissionV1{}, cleanup: f.oldCleanup, metadata: meta, attempted: true, unknown: true, exactRowReconciled: true}
	childMeta := *meta
	childMeta.BindingSha256 = append([]byte(nil), meta.BindingSha256...)
	f.child = &applicationRequestOperationV1{journal: j, key: key, session: &pdfadmission.ApplicationSessionV1{}, admission: &pdfadmission.ApplicationAdmissionV1{}, cleanup: f.newCleanup, metadata: &childMeta, acknowledged: true}
	f.original.payload = &durableRequestPayloadV1{origin: []byte("synthetic original origin"), intent: []byte("synthetic original intent"), release: func() { f.originalConsumerCloses++ }}
	f.child.payload = &durableRequestPayloadV1{origin: []byte("synthetic retained exact origin"), intent: []byte("synthetic retained exact intent"), release: func() { f.childConsumerCloses++ }}
	f.original.recovery = f.child
	j.owners[key] = f.original
	return f
}
func TestApplicationRecoveryCleanupV1RetriesSameReconciledChildAfterRegistryFailure(t *testing.T) {
	f := newApplicationCleanupStateFixtureTestV1()
	expired := newPresentedCredentialTestFixtureV1(t)
	rc := expired.lookup(t)
	in := presentedCredentialTestInputV1(t, rc)
	intent, err := expired.engine.issueFittedSigningIntentV1(context.Background(), rc, in)
	if err != nil {
		t.Fatal(err)
	}
	f.child.context = rc
	f.child.intent = intent
	expired.now = expired.now.Add(time.Hour)
	first, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f.oldCleanup.onClose = func(ctx context.Context) error { cancel(); return ctx.Err() }
	got, err := f.journal.RecoverV1(first, f.original, rc, in)
	if got != f.child || !errors.Is(err, errApplicationBoundRequestUnknownV1) || f.original.payload != nil || f.originalConsumerCloses != 1 || f.original.recovery != f.child || f.journal.owners[f.original.key] != f.original || f.child.payload == nil || f.childConsumerCloses != 0 {
		t.Fatal("first registry failure lost reconciled owner/child proof", err)
	}
	fresh, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	f.oldCleanup.onClose = nil
	got, err = f.journal.RecoverV1(fresh, f.original, rc, in)
	if err != nil || got != f.child || f.journal.owners[f.original.key] != f.child || f.original.recovery != nil || !f.original.closed || f.originalConsumerCloses != 1 || f.childConsumerCloses != 0 || f.oldCleanup.closes != 2 {
		t.Fatal("fresh cleanup did not deliver same retained logical operation", err)
	}
	// The helper dispatched no new read/issuer: this journal has no factory.
	// Completing cleanup cannot refresh an expired original signing credential.
	if _, err := expired.engine.issueFittedSigningIntentV1(fresh, got.context, got.intent.inputV1(SignInput{})); !errors.Is(err, ErrMagicLinkExpired) {
		t.Fatal("cleanup revived expired original credential", err)
	}
	if _, _, _, err := got.dataV1(); !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatal("native cleanup spy manufactured actual session retirement")
	}
	if err := f.original.CloseV1(fresh); err != nil || f.journal.owners[f.original.key] != f.child {
		t.Fatal("closing obsolete owner removed handed-off child", err)
	}
	if err := f.child.CloseV1(fresh); err != nil || len(f.journal.owners) != 0 || f.childConsumerCloses != 1 {
		t.Fatal("same child did not close once", err)
	}
}
func TestApplicationRecoveryCleanupV1CloseRetriesBothRetainedOwners(t *testing.T) {
	f := newApplicationCleanupStateFixtureTestV1()
	first, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f.oldCleanup.onClose = func(ctx context.Context) error { cancel(); return ctx.Err() }
	if _, err := f.journal.RecoverV1(first, f.original, nil, SignInput{}); !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatal("first close premise did not fail", err)
	}
	f.oldCleanup.onClose = nil
	second, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	f.newCleanup.onClose = func(ctx context.Context) error { stop(); return ctx.Err() }
	if err := f.original.CloseV1(second); !errors.Is(err, errApplicationBoundRequestUnknownV1) || f.original.recovery != f.child || f.journal.owners[f.original.key] != f.original || f.child.payload != nil || f.childConsumerCloses != 1 {
		t.Fatal("child registry failure lost retained cleanup owner", err)
	}
	f.newCleanup.onClose = nil
	third, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	if err := f.original.CloseV1(third); err != nil || len(f.journal.owners) != 0 || f.original.recovery != nil || !f.original.closed || !f.child.closed || f.originalConsumerCloses != 1 || f.childConsumerCloses != 1 {
		t.Fatal("fresh close did not finish same original plus child", err)
	}
}
func TestApplicationRecoveryCleanupV1ShutdownKeepsChildReachable(t *testing.T) {
	f := newApplicationCleanupStateFixtureTestV1()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f.oldCleanup.onClose = func(context.Context) error {
		f.journal.mu.Lock()
		f.journal.closing = true
		f.journal.mu.Unlock()
		return nil
	}
	got, err := f.journal.RecoverV1(ctx, f.original, nil, SignInput{})
	if got != f.child || !errors.Is(err, errApplicationBoundRequestUnknownV1) || f.journal.owners[f.original.key] != f.original || f.original.recovery != f.child || !f.original.closed || f.childConsumerCloses != 0 {
		t.Fatal("shutdown lost child through premature handoff", err)
	}
	if err := f.original.CloseV1(ctx); err != nil || len(f.journal.owners) != 0 || f.childConsumerCloses != 1 {
		t.Fatal("shutdown could not reach and close child", err)
	}
}
func TestApplicationRecoveryCleanupV1UnretiredChildCannotCloseOriginal(t *testing.T) {
	f := newApplicationCleanupStateFixtureTestV1()
	f.newCleanup.retired = false
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := f.journal.RecoverV1(ctx, f.original, nil, SignInput{}); !errors.Is(err, errApplicationBoundRequestUnknownV1) || f.original.payload == nil || f.originalConsumerCloses != 0 || f.oldCleanup.closes != 0 {
		t.Fatal("unretired child consumed original proof or registry", err)
	}
}

func TestApplicationRecoveryCleanupV1AutomaticReconcileKeepsResultHandleReachable(t *testing.T) {
	f := newApplicationCleanupStateFixtureTestV1()
	first, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f.oldCleanup.onClose = func(ctx context.Context) error { cancel(); return ctx.Err() }
	if _, err := f.journal.RecoverV1(first, f.original, nil, SignInput{}); !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatal("reconciled cleanup premise did not fail", err)
	}
	f.oldCleanup.onClose = nil
	// The opaque zero factory supplies no transport authority; its reconciliation
	// refuses independently. The real driver still must retain the result handle
	// while its own cleanup-only branch executes before that factory call.
	f.journal.factory = &pdfadmission.ApplicationSessionFactoryV1{}
	fresh, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := f.journal.ReconcileCleanupV1(fresh); !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatal("zero factory unexpectedly proved physical transport cleanup", err)
	}
	if !f.original.closed || f.original.recovery != f.child || f.journal.owners[f.original.key] != f.original || f.childConsumerCloses != 0 {
		t.Fatal("automatic cleanup published unreachable child")
	}
	got, err := f.journal.RecoverV1(fresh, f.original, nil, SignInput{})
	if err != nil || got != f.child || f.journal.owners[f.original.key] != f.child {
		t.Fatal("explicit cleanup retry could not deliver same retained child", err)
	}
	if err := f.child.CloseV1(fresh); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationRecoveryCleanupV1AutomaticReconcileDisposesSeparatelyClosedChild(t *testing.T) {
	f := newApplicationCleanupStateFixtureTestV1()
	first, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f.oldCleanup.onClose = func(ctx context.Context) error { cancel(); return ctx.Err() }
	if _, err := f.journal.RecoverV1(first, f.original, nil, SignInput{}); !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatal("reconciled cleanup premise did not fail", err)
	}
	fresh, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := f.child.CloseV1(fresh); err != nil || !f.child.closed || f.childConsumerCloses != 1 || f.original.recovery != f.child {
		t.Fatal("separate child disposal premise failed", err)
	}
	f.oldCleanup.onClose = nil
	f.journal.factory = &pdfadmission.ApplicationSessionFactoryV1{}
	// Unknown zero factory is independent of the local cleanup transition.
	if err := f.journal.ReconcileCleanupV1(fresh); !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatal("zero factory unexpectedly proved transport cleanup", err)
	}
	if f.original.recovery != nil || !f.original.closed || len(f.journal.owners) != 0 || f.originalConsumerCloses != 1 || f.childConsumerCloses != 1 {
		t.Fatal("disposed child stranded original registry owner")
	}
}
