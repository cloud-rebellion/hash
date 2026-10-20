// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"reflect"
	"sync"
	"time"
	"unsafe"
)

var ErrDocumentPackageOperationV1 = errors.New("pdfadmission: owned document package operation unavailable")
var ErrDocumentPackageSourceChangedV1 = errors.New("pdfadmission: document package sources changed")

// Fixed application policy runs against BOTH actual native subjects. Its
// returned original-credential recheck remains in the same SQL callback through
// the final pre-COMMIT boundary. It supplies no rows, costs or resource credit.
type DocumentPackageSourcePolicyV1 func(context.Context, generated.DBTX, *ApplicationDocumentPackageSelectionV1) (func(context.Context) error, error)

type ApplicationDocumentPackageOperationV1 struct {
	state *applicationDocumentPackageOperationStateV1
}
type applicationDocumentPackageStageV1 struct {
	session   *ApplicationSessionV1
	admission *ApplicationAdmissionV1
	selection *ApplicationDocumentPackageSelectionV1
	ctx       context.Context
	cancel    context.CancelFunc
	opening   bool
}
type applicationDocumentPackageOperationStateV1 struct {
	mu                                                                          sync.Mutex
	factory                                                                     *ApplicationSessionFactoryV1
	client                                                                      *storage.Client
	ctx                                                                         context.Context
	cancel                                                                      context.CancelFunc
	org, actor                                                                  uuid.UUID
	ids                                                                         [2]uuid.UUID
	stages                                                                      [2]applicationDocumentPackageStageV1
	snapshots                                                                   [2]*applicationHTMLRevisionSourceSnapshotV1
	releases                                                                    [2]func()
	observations                                                                [documentpackage.MaxAnnexesV1 + 1]*storage.PinnedPDFReadV1
	measured                                                                    [2]DocumentPackagePDFMeasurementV1
	allMeasured                                                                 [documentpackage.MaxAnnexesV1 + 1]DocumentPackagePDFMeasurementV1
	draft                                                                       *applicationDocumentPackageDraftSnapshotV1
	releaseDraft                                                                func()
	selection                                                                   *applicationDocumentPackageWriteIntentV1
	selectionLoan                                                               *workguard.GrantV1
	selectionAttempted                                                          bool
	previewMode                                                                 bool
	preview                                                                     applicationDocumentPackagePreviewStateV1
	control                                                                     *workguard.GrantV1
	active                                                                      int
	initialAttempted, initialRead, measureAttempted, measuredOK, finalAttempted bool
	closed, retiring, retired                                                   bool
	consumersDone                                                               chan struct{}
}

// Born BEFORE initial SQL from the actual saved native factory and bounded
// request context. No later processing method accepts a replacement context.
func (f *ApplicationSessionFactoryV1) NewDocumentPackageOperationV1(ctx context.Context, org, root, source, actor uuid.UUID, client *storage.Client) (*ApplicationDocumentPackageOperationV1, error) {
	return f.newDocumentPackageOperationV1(ctx, org, root, source, actor, client, nil)
}
func (f *ApplicationSessionFactoryV1) newDocumentPackageOperationV1(ctx context.Context, org, root, source, actor uuid.UUID, client *storage.Client, preview *DocumentPackagePreviewExpectedV1) (*ApplicationDocumentPackageOperationV1, error) {
	if f == nil || f.state == nil || org == uuid.Nil || root == uuid.Nil || source == uuid.Nil || root == source || actor == uuid.Nil || client == nil || !applicationContextV1(ctx) {
		return nil, ErrDocumentPackageOperationV1
	}
	p := f.state
	p.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !p.closing && p.work != nil {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if coordinator == nil {
		return nil, ErrDocumentPackageOperationV1
	}
	metadata, err := client.PinnedPDFObservationParentWorkV1()
	if err != nil {
		return nil, ErrDocumentPackageOperationV1
	}
	typed := 4*int64(unsafe.Sizeof(applicationDocumentPackageOperationStateV1{})) + 4*int64(unsafe.Sizeof(ApplicationDocumentPackageOperationV1{})) + 4*int64(unsafe.Sizeof(applicationDocumentPackageStageV1{})) + 4*int64(unsafe.Sizeof(DocumentPackagePDFMeasurementV1{})) + 4096
	if !htmlInputAddV1(&typed, metadata, documentpackage.MaxAnnexesV1+1) {
		return nil, ErrDocumentPackageOperationV1
	}
	grant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: typed})
	if err != nil {
		return nil, errors.Join(ErrDocumentPackageOperationV1, err)
	}
	original, cancel := context.WithCancel(ctx)
	s := &applicationDocumentPackageOperationStateV1{factory: f, client: client, ctx: original, cancel: cancel, org: org, actor: actor, ids: [2]uuid.UUID{root, source}, control: grant, consumersDone: make(chan struct{})}
	if preview != nil {
		s.previewMode = true
		s.preview.expected = *preview
	}
	if !f.registerDocumentPackageOperationV1(s) {
		cancel()
		grant.Close()
		return nil, ErrDocumentPackageOperationV1
	}
	return &ApplicationDocumentPackageOperationV1{state: s}, nil
}
func (s *applicationDocumentPackageOperationStateV1) beginV1() error {
	if s == nil {
		return ErrDocumentPackageOperationV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retired || !applicationContextV1(s.ctx) || s.factory == nil || s.factory.state == nil {
		return ErrDocumentPackageOperationV1
	}
	p := s.factory.state
	p.mu.Lock()
	available := !p.closing && p.work != nil && p.work.coordinator != nil
	p.mu.Unlock()
	if !available {
		return ErrDocumentPackageOperationV1
	}
	s.active++
	return nil
}
func (s *applicationDocumentPackageOperationStateV1) finishV1() {
	s.mu.Lock()
	s.active--
	retire := s.closed && !s.retiring && s.active == 0
	if retire {
		s.retiring = true
	}
	s.mu.Unlock()
	if retire {
		s.retireConsumersV1()
	}
}
func (s *applicationDocumentPackageOperationStateV1) retireConsumersV1() {
	// No active read/worker/callback remains. Keep native stage handles for
	// cleanup-only reconciliation; body/source consumers are now genuinely done.
	for i := range s.stages {
		if s.stages[i].selection != nil {
			s.stages[i].selection.CloseConsumerV1()
		}
	}
	for i, release := range s.releases {
		if release != nil {
			release()
			s.releases[i] = nil
		}
	}
	for _, r := range s.preview.readers {
		if r != nil {
			r.CloseConsumerV1()
		}
	}
	clear(s.preview.body)
	s.preview.body = nil
	if s.preview.loan != nil {
		s.preview.loan.Close()
		s.preview.loan = nil
	}
	s.preview.pin = applicationDocumentPackagePreviewPinV1{}
	s.preview.readers = [2]*ApplicationHTMLRevisionReaderV1{}
	s.snapshots = [2]*applicationHTMLRevisionSourceSnapshotV1{}
	if s.releaseDraft != nil {
		s.releaseDraft()
		s.releaseDraft = nil
	}
	s.observations = [documentpackage.MaxAnnexesV1 + 1]*storage.PinnedPDFReadV1{}
	s.draft = nil
	s.selection = nil
	if s.selectionLoan != nil {
		s.selectionLoan.Close()
		s.selectionLoan = nil
	}
	if s.control != nil {
		s.control.Close()
		s.control = nil
	}
	s.mu.Lock()
	s.retired = true
	close(s.consumersDone)
	s.mu.Unlock()
}
func (h *ApplicationDocumentPackageOperationV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	s.closed = true
	s.cancel()
	retire := !s.retiring && s.active == 0
	if retire {
		s.retiring = true
	}
	s.mu.Unlock()
	if retire {
		s.retireConsumersV1()
	}
}
func (s *applicationDocumentPackageOperationStateV1) closeStageSQLV1(index int, cleanup context.Context) error {
	s.mu.Lock()
	stage := s.stages[index]
	s.mu.Unlock()
	if stage.cancel != nil {
		stage.cancel()
	}
	if stage.session == nil {
		if stage.opening {
			return ErrApplicationSessionUnknownV1
		}
		return nil
	}
	err := stage.session.CloseV1(cleanup)
	if stage.admission != nil {
		_, e := stage.admission.ReconcileCleanupV1(cleanup)
		err = errors.Join(err, e)
	}
	if stage.opening {
		return errors.Join(err, ErrApplicationSessionUnknownV1)
	}
	return err
}
func (h *ApplicationDocumentPackageOperationV1) CloseV1(cleanup context.Context) error {
	if h == nil || h.state == nil {
		return nil
	}
	h.CloseConsumerV1()
	s := h.state
	if !applicationContextV1(cleanup) {
		if cleanup != nil {
			return errors.Join(ErrApplicationSessionUnknownV1, cleanup.Err())
		}
		return ErrApplicationSessionUnknownV1
	}
	var result error
	for i := range s.stages {
		result = errors.Join(result, s.closeStageSQLV1(i, cleanup))
	}
	// Retirement intent, zero active calls and a canceled context are not joins.
	// Only the actual release completion below may permit a nil Close result.
	select {
	case <-s.consumersDone:
	default:
		select {
		case <-s.consumersDone:
		case <-cleanup.Done():
			return errors.Join(result, ErrApplicationSessionUnknownV1, cleanup.Err())
		}
	}
	for i := range s.stages {
		s.mu.Lock()
		a := s.stages[i].admission
		s.mu.Unlock()
		if a != nil {
			pending, err := a.ReconcileCleanupV1(cleanup)
			result = errors.Join(result, err)
			if pending != 0 {
				result = errors.Join(result, ErrApplicationSessionUnknownV1)
			}
		}
	}
	if result == nil && s.factory != nil {
		s.factory.unregisterDocumentPackageOperationV1(s)
	}
	return result
}

func (s *applicationDocumentPackageOperationStateV1) openStageV1(index int) (*ApplicationSessionV1, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	s.mu.Lock()
	s.stages[index].opening = true
	s.stages[index].cancel = cancel
	s.stages[index].ctx = ctx
	closed := s.closed
	s.mu.Unlock()
	if closed {
		cancel()
		s.mu.Lock()
		s.stages[index].opening = false
		s.mu.Unlock()
		return nil, ErrDocumentPackageOperationV1
	}
	session, err := s.factory.OpenV1(ctx, s.org, s.ids[0])
	s.mu.Lock()
	s.stages[index].session = session
	s.mu.Unlock()
	if err == nil {
		var a *ApplicationAdmissionV1
		a, err = session.NewAdmissionV1(ctx)
		s.mu.Lock()
		s.stages[index].admission = a
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.stages[index].opening = false
	closed = s.closed
	s.mu.Unlock()
	if err != nil || closed || ctx.Err() != nil {
		return session, errors.Join(ErrDocumentPackageOperationV1, err, ctx.Err())
	}
	return session, nil
}
func (s *applicationDocumentPackageOperationStateV1) stageContextV1(index int) context.Context {
	// The native session retains the original stage context. Processing never
	// accepts a context from this observer or uses cleanup to renew a deadline.
	s.mu.Lock()
	ctx := s.stages[index].ctx
	s.mu.Unlock()
	return ctx
}
func (s *applicationDocumentPackageOperationStateV1) runStageV1(index int, policy DocumentPackageSourcePolicyV1, consume func(context.Context, generated.DBTX, *ApplicationDocumentPackageSelectionV1) error) (failure error) {
	session, err := s.openStageV1(index)
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(s.ctx), 5*time.Second)
		defer stop()
		failure = errors.Join(failure, s.closeStageSQLV1(index, cleanup))
	}()
	if err != nil {
		return err
	}
	stageCtx := s.stageContextV1(index)
	err = session.WithTxV1(stageCtx, func(call context.Context, db generated.DBTX) error {
		owner, err := session.NewDocumentPackageSelectionV1(call, s.ids[1])
		s.mu.Lock()
		s.stages[index].selection = owner
		closed := s.closed
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if closed {
			return ErrDocumentPackageOperationV1
		}
		// Pin this actual owner across policy, handoff/comparison and recheck.
		// Concurrent shell close cannot clear still-consumed private snapshots.
		if err = owner.state.beginV1(call); err != nil {
			return err
		}
		defer owner.state.finishV1()
		recheck, err := policy(call, db, owner)
		if err != nil {
			return err
		}
		if recheck == nil {
			return ErrDocumentPackageOperationV1
		}
		owner.state.mu.Lock()
		valid := owner.state.sourcesValidated && owner.state.readActor == s.actor && !owner.state.closed.Load()
		owner.state.mu.Unlock()
		if !valid {
			return ErrDocumentPackageOperationV1
		}
		if err = consume(call, db, owner); err != nil {
			return err
		}
		if owner.state.closed.Load() {
			return ErrDocumentPackageOperationV1
		}
		if err = recheck(call); err != nil {
			return err
		}
		if owner.state.closed.Load() {
			return ErrDocumentPackageOperationV1
		}
		return call.Err()
	})
	if err != nil {
		return err
	}
	if index == 1 {
		return session.CommitV1(stageCtx)
	}
	return nil
}

// ReadSourcesV1 keeps the full paired owner and its independently charged
// metadata/source readers, plus private snapshot borrowers, across physical SQL
// retirement. External provider/parser work is forbidden until this succeeds.
func (h *ApplicationDocumentPackageOperationV1) ReadSourcesV1(policy DocumentPackageSourcePolicyV1) error {
	if h == nil || h.state == nil || policy == nil {
		return ErrDocumentPackageOperationV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	if s.previewMode || s.initialAttempted {
		s.mu.Unlock()
		return ErrDocumentPackageOperationV1
	}
	s.initialAttempted = true
	s.mu.Unlock()
	err := s.runStageV1(0, policy, func(call context.Context, _ generated.DBTX, owner *ApplicationDocumentPackageSelectionV1) error {
		for i, reader := range owner.state.readers {
			snap, release, err := reader.borrowHTMLRevisionSourceV1(s.ctx)
			if err != nil {
				return err
			}
			s.snapshots[i] = snap
			s.releases[i] = release
			if snap == nil || snap.document == nil || snap.document.ID != s.ids[i] || snap.document.OrgID != s.org {
				return ErrDocumentPackageOperationV1
			}
		}
		owner.state.mu.Lock()
		hasDraft := owner.state.draft != nil
		owner.state.mu.Unlock()
		if hasDraft {
			draft, release, err := owner.borrowDraftV1(s.ctx)
			if err != nil {
				return err
			}
			s.draft, s.releaseDraft = draft, release
		}
		return call.Err()
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	session := s.stages[0].session
	closed := s.closed
	s.mu.Unlock()
	if closed || session == nil || !session.RetiredV1() || session.CommitUnknownV1() {
		return ErrDocumentPackageOperationV1
	}
	s.mu.Lock()
	s.initialRead = true
	s.mu.Unlock()
	return s.ctx.Err()
}

// withVerifiedSourcesV1 is a private fixed-writer seam after all
// actual PDF reads/worker joins. Original policy runs again, then BOTH private
// complete document/current snapshots must still match; caller model edits
// cannot replace them. The callback is followed by original credential recheck
// and actual native COMMIT. One attempt; never replay after unknown commit.
func (h *ApplicationDocumentPackageOperationV1) withVerifiedSourcesV1(policy DocumentPackageSourcePolicyV1, selecting bool, consume func(context.Context, generated.DBTX, *ApplicationDocumentPackageSelectionV1) error) error {
	if h == nil || h.state == nil || policy == nil || consume == nil {
		return ErrDocumentPackageOperationV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	if s.finalAttempted || !s.measuredOK || selecting != s.selectionAttempted {
		s.mu.Unlock()
		return ErrDocumentPackageOperationV1
	}
	s.finalAttempted = true
	s.mu.Unlock()
	if err := s.retireInitialValidatorsV1(); err != nil {
		return err
	}
	return s.runStageV1(1, policy, func(call context.Context, db generated.DBTX, owner *ApplicationDocumentPackageSelectionV1) error {
		if !reflect.DeepEqual(s.draft, owner.state.draft) {
			return ErrDocumentPackageSourceChangedV1
		}
		for i := range s.ids {
			actual := owner.state.sources[i]
			expected := s.snapshots[i]
			if actual == nil || actual.snapshot == nil || expected == nil || !reflect.DeepEqual(actual.snapshot.document, expected.document) || !reflect.DeepEqual(actual.snapshot.current, expected.current) {
				return ErrDocumentPackageSourceChangedV1
			}
		}
		return consume(call, db, owner)
	})
}
func (h *ApplicationDocumentPackageOperationV1) CommitDispatchedV1() bool {
	if h == nil || h.state == nil {
		return false
	}
	h.state.mu.Lock()
	session := h.state.stages[1].session
	h.state.mu.Unlock()
	if session == nil || session.state == nil {
		return false
	}
	session.state.mu.Lock()
	attempted := session.state.commitAttempted
	session.state.mu.Unlock()
	return attempted
}

// RevalidateSourcesV1 performs the fresh policy/snapshot boundary without a
// caller mutation callback. A future selection writer derives every pin from
// this private measured state; source agreement is not generic SQL authority.
func (h *ApplicationDocumentPackageOperationV1) RevalidateSourcesV1(policy DocumentPackageSourcePolicyV1) error {
	return h.withVerifiedSourcesV1(policy, false, func(context.Context, generated.DBTX, *ApplicationDocumentPackageSelectionV1) error { return nil })
}

// CommitAcknowledgedV1 observes the actual final native session, independently
// of physical cleanup. Dispatch alone, rollback and unknown outcomes refuse.
func (h *ApplicationDocumentPackageOperationV1) CommitAcknowledgedV1() bool {
	if h == nil || h.state == nil {
		return false
	}
	h.state.mu.Lock()
	session := h.state.stages[1].session
	h.state.mu.Unlock()
	if session == nil || session.state == nil {
		return false
	}
	session.state.mu.Lock()
	defer session.state.mu.Unlock()
	return session.state.commitAttempted && session.state.ended && !session.state.commitUnknown
}
