// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Cursor is only a queue position. It grants no tenant, retry or recovery work
// authority. Zero starts a new pass; workers wrap after an exhausted page.
type PackageSendRecoveryCursorV1 struct {
	CreatedAt time.Time
	AttemptID uuid.UUID
}

type ApplicationPackageSendRecoveryBatchV1 struct {
	state *applicationPackageSendRecoveryBatchStateV1
}
type applicationPackageSendRecoveryEntryV1 struct {
	attempt, org, document uuid.UUID
	createdAt              pgtype.Timestamptz
}
type applicationPackageSendRecoveryBatchStateV1 struct {
	mu                                              sync.Mutex
	factory                                         *ApplicationSessionFactoryV1
	ctx                                             context.Context
	cancel                                          context.CancelFunc
	scan                                            *ApplicationSessionV1
	operation                                       *ApplicationHTMLSendOperationV1
	retention                                       *applicationPackageSendRetentionPlanV1
	entries                                         [50]applicationPackageSendRecoveryEntryV1
	count, next                                     int
	cursor                                          PackageSendRecoveryCursorV1
	release                                         func()
	active, resolved, closed, released, reconciling bool
}

// Only a live registered batch's private current slot can mint this proof.
// It is never exported, accepted from a caller or reconstructed from a UUID.
type applicationPackageSendRecoveryWorkScopeV1 struct {
	batch     *applicationPackageSendRecoveryBatchStateV1
	operation *ApplicationHTMLSendOperationV1
	entry     applicationPackageSendRecoveryEntryV1
}

func packageSendRecoveryAfterV1(c PackageSendRecoveryCursorV1) (pgtype.Timestamptz, uuid.UUID, error) {
	if c.AttemptID == uuid.Nil && c.CreatedAt.IsZero() {
		return pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.NegativeInfinity}, uuid.Nil, nil
	}
	s := pgtype.Timestamptz{Valid: true, Time: c.CreatedAt.UTC()}
	if c.AttemptID == uuid.Nil || !applicationStampV1(s) {
		return pgtype.Timestamptz{}, uuid.Nil, ErrHTMLSendPackageInspectionV1
	}
	return s, c.AttemptID, nil
}

func (f *ApplicationSessionFactoryV1) ScanPendingPackageSendRecoveryV1(ctx context.Context, after PackageSendRecoveryCursorV1) (*ApplicationPackageSendRecoveryBatchV1, error) {
	stamp, id, err := packageSendRecoveryAfterV1(after)
	if err != nil || f == nil || f.state == nil || !applicationContextV1(ctx) {
		return nil, ErrHTMLSendPackageInspectionV1
	}
	original, cancel := context.WithCancel(ctx)
	s := &applicationPackageSendRecoveryBatchStateV1{factory: f, ctx: original, cancel: cancel, cursor: after, active: true}
	h := &ApplicationPackageSendRecoveryBatchV1{state: s}
	p := f.state
	p.mu.Lock()
	index := -1
	if !p.closing && p.work != nil && p.work.coordinator != nil {
		for i, v := range p.packageRecoveryBatches {
			if v == nil {
				index = i
				break
			}
		}
	}
	if index < 0 {
		p.mu.Unlock()
		cancel()
		return nil, ErrHTMLSendPackageInspectionV1
	}
	p.packageRecoveryBatches[index] = s
	fixed := applicationSignerScopeHeaderBytesV1 + 8*int64(unsafe.Sizeof(applicationPackageSendRecoveryBatchStateV1{})) + 50*8*(int64(unsafe.Sizeof(generated.ListPendingDocumentPackageSendRecoveryV1Row{}))+int64(unsafe.Sizeof(applicationPackageSendRecoveryEntryV1{}))) + 4096
	grant, err := p.work.coordinator.TryAcquireProcessV1(original, workguard.VectorV1{ParentBytes: fixed, DBStagingBytes: fixed})
	if err == nil {
		s.release = grant.Close
	}
	p.mu.Unlock()
	if err == nil {
		session, openErr := f.openSignerProbeSessionV1(original)
		s.mu.Lock()
		s.scan = session
		closed := s.closed
		s.mu.Unlock()
		err = openErr
		if err == nil && !closed && session != nil {
			err = session.WithTxV1(original, func(call context.Context, db generated.DBTX) error {
				rows, e := generated.New(db).ListPendingDocumentPackageSendRecoveryV1(call, generated.ListPendingDocumentPackageSendRecoveryV1Params{AfterCreatedAt: stamp, AfterAttemptID: id})
				if e != nil {
					return e
				}
				if len(rows) > 50 {
					return ErrHTMLSendPackageInspectionV1
				}
				s.mu.Lock()
				defer s.mu.Unlock()
				if s.closed || original.Err() != nil {
					return ErrHTMLSendPackageInspectionV1
				}
				prevTime, prevID := stamp, id
				for i, r := range rows {
					if r == nil || r.AttemptID == uuid.Nil || r.OrgID == uuid.Nil || r.DocumentID == uuid.Nil || !applicationStampV1(r.CreatedAt) || !packageSendRecoveryOrderedV1(prevTime, prevID, r.CreatedAt, r.AttemptID) {
						return ErrHTMLSendPackageInspectionV1
					}
					s.entries[i] = applicationPackageSendRecoveryEntryV1{attempt: r.AttemptID, org: r.OrgID, document: r.DocumentID, createdAt: r.CreatedAt}
					prevTime, prevID = r.CreatedAt, r.AttemptID
				}
				s.count = len(rows)
				s.resolved = true
				return nil
			})
		} else if err == nil {
			err = ErrHTMLSendPackageInspectionV1
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(original), 5*time.Second)
		if session != nil {
			err = errors.Join(err, session.CloseV1(cleanup))
			if !session.RetiredV1() {
				err = errors.Join(err, ErrApplicationSessionUnknownV1)
			}
		}
		stop()
	}
	s.mu.Lock()
	s.active = false
	s.mu.Unlock()
	if err != nil {
		h.CloseConsumerV1()
		return h, errors.Join(ErrHTMLSendPackageInspectionV1, err)
	}
	return h, nil
}

func packageSendRecoveryOrderedV1(a pgtype.Timestamptz, aid uuid.UUID, b pgtype.Timestamptz, bid uuid.UUID) bool {
	if a.Valid && a.InfinityModifier == pgtype.NegativeInfinity {
		return applicationStampV1(b)
	}
	if !applicationStampV1(a) || !applicationStampV1(b) {
		return false
	}
	if a.Time.Before(b.Time) {
		return true
	}
	if !a.Time.Equal(b.Time) {
		return false
	}
	for i := range aid {
		if aid[i] != bid[i] {
			return aid[i] < bid[i]
		}
	}
	return false
}

func (s *applicationPackageSendRecoveryBatchStateV1) registeredV1() bool {
	if s == nil || s.factory == nil || s.factory.state == nil {
		return false
	}
	p := s.factory.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	for _, v := range p.packageRecoveryBatches {
		if v == s {
			return true
		}
	}
	return false
}

func (scope *applicationPackageSendRecoveryWorkScopeV1) validV1(w *ApplicationHTMLSendWorkV1) bool {
	if scope == nil || scope.batch == nil || scope.operation == nil || scope.operation.self != scope.operation || w == nil || w.stage == nil || w.stage.operation != scope.operation {
		return false
	}
	s := scope.batch
	s.mu.Lock()
	ok := s.active && !s.closed && !s.released && s.ctx != nil && s.ctx.Err() == nil && s.operation == scope.operation && s.next > 0 && s.next <= s.count && s.entries[s.next-1] == scope.entry && scope.operation.factory == s.factory && w.state != nil && w.state.ID == scope.entry.document && w.state.OrgID == scope.entry.org
	s.mu.Unlock()
	return ok && s.registeredV1()
}

// WithNextObservationV1 inspects one genuine private slot, not caller IDs. The
// bool records slot consumption even on refusal, allowing cursor progress past
// a broken job. No outcome authorizes replay or provider/mutation work.
// Physical SQL closes before callback delivery; Work/process grants remain paid
// through the callback, including concurrent Close through a copied handle.
func (h *ApplicationPackageSendRecoveryBatchV1) WithNextObservationV1(fn func(HTMLSendPackageAttemptObservationV1) error) (more bool, failure error) {
	if h == nil || h.state == nil || fn == nil {
		return false, ErrHTMLSendPackageInspectionV1
	}
	s := h.state
	if !s.registeredV1() {
		return false, ErrHTMLSendPackageInspectionV1
	}
	s.mu.Lock()
	if s.closed || s.released || s.active || !s.resolved || s.operation != nil || s.retention != nil || s.ctx == nil || s.ctx.Err() != nil || s.scan == nil || !s.scan.RetiredV1() {
		s.mu.Unlock()
		return false, ErrHTMLSendPackageInspectionV1
	}
	if s.next == s.count {
		s.mu.Unlock()
		return false, nil
	}
	entry := s.entries[s.next]
	s.next++
	s.cursor = PackageSendRecoveryCursorV1{CreatedAt: entry.createdAt.Time.UTC(), AttemptID: entry.attempt}
	s.active = true
	s.mu.Unlock()
	var op *ApplicationHTMLSendOperationV1
	defer func() {
		if op != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(s.ctx), 5*time.Second)
			err := op.CloseV1(cleanup)
			stop()
			failure = errors.Join(failure, err)
			s.mu.Lock()
			if err == nil && s.operation == op {
				s.operation = nil
			}
			s.mu.Unlock()
		}
		s.mu.Lock()
		s.active = false
		s.mu.Unlock()
		s.reconcileV1(nil)
	}()
	call, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	var err error
	op, err = s.factory.NewHTMLSendOperationV1(call, entry.org, entry.document)
	if err != nil {
		return true, err
	}
	s.mu.Lock()
	s.operation = op
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return true, ErrHTMLSendPackageInspectionV1
	}
	stage, err := op.OpenSQLV1(HTMLSendIntentReadV1)
	if err != nil {
		return true, err
	}
	session := stage.SessionV1()
	if session == nil {
		return true, ErrHTMLSendPackageInspectionV1
	}
	if _, err = session.NewAdmissionV1(stage.ContextV1()); err != nil {
		return true, err
	}
	var out HTMLSendPackageAttemptObservationV1
	scope := applicationPackageSendRecoveryWorkScopeV1{batch: s, operation: op, entry: entry}
	err = stage.WithTxV1(func(owned context.Context, _ generated.DBTX) error {
		work, e := session.NewHTMLSendWorkV1(owned, stage)
		if e != nil {
			return e
		}
		if _, e = work.StateV1(owned); e != nil {
			return e
		}
		out, e = work.inspectDurablePackageSendAttemptV1(owned, entry.attempt, &scope)
		return e
	})
	if err == nil {
		err = session.CommitV1(stage.ContextV1())
	}
	err = errors.Join(err, stage.CloseSQLV1())
	if !session.RetiredV1() {
		err = errors.Join(err, ErrApplicationSessionUnknownV1)
	}
	if err != nil {
		return true, err
	}
	s.mu.Lock()
	ok := !s.closed && s.ctx.Err() == nil
	s.mu.Unlock()
	if !ok {
		return true, ErrHTMLSendPackageInspectionV1
	}
	return true, fn(out)
}

func (h *ApplicationPackageSendRecoveryBatchV1) CursorV1() PackageSendRecoveryCursorV1 {
	if h == nil || h.state == nil {
		return PackageSendRecoveryCursorV1{}
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursor
}
func (h *ApplicationPackageSendRecoveryBatchV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	s.closed = true
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.reconcileV1(nil)
}

func (s *applicationPackageSendRecoveryBatchStateV1) reconcileV1(cleanup context.Context) bool {
	if s == nil || s.factory == nil || s.factory.state == nil {
		return false
	}
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return true
	}
	if !s.closed || s.active || s.reconciling {
		s.mu.Unlock()
		return false
	}
	s.reconciling = true
	op, session := s.operation, s.scan
	s.mu.Unlock()
	// Reconciliation may only close existing handles; it never opens/reads work.
	if cleanup != nil {
		if op != nil {
			if e := op.CloseV1(cleanup); e == nil {
				s.mu.Lock()
				if s.operation == op {
					s.operation = nil
				}
				s.mu.Unlock()
			}
		}
		if session != nil && !session.RetiredV1() {
			_ = session.CloseV1(cleanup)
		}
	}
	s.mu.Lock()
	if s.released {
		s.reconciling = false
		s.mu.Unlock()
		return true
	}
	if s.active || s.operation != nil || (s.scan != nil && !s.scan.RetiredV1()) {
		s.reconciling = false
		s.mu.Unlock()
		return false
	}
	if s.retention != nil && !s.retention.providerRetiredLockedV1() {
		s.reconciling = false
		s.mu.Unlock()
		return false
	}
	release := s.release
	retention := s.retention
	s.retention = nil
	s.release = nil
	s.entries = [50]applicationPackageSendRecoveryEntryV1{}
	s.count = 0
	s.scan = nil
	p := s.factory.state
	s.mu.Unlock()
	if retention != nil {
		retention.retireV1()
	}
	if release != nil {
		release()
	}
	p.mu.Lock()
	for i, v := range p.packageRecoveryBatches {
		if v == s {
			p.packageRecoveryBatches[i] = nil
			break
		}
	}
	p.mu.Unlock()
	// Publish retirement only after the actual retained owners and process
	// grant have closed. Concurrent cleanup must still observe the debt while
	// those calls run outside the batch mutex.
	s.mu.Lock()
	s.released = true
	s.reconciling = false
	s.mu.Unlock()
	return true
}

func (f *ApplicationSessionFactoryV1) reconcilePackageSendRecoveryBatchesV1(ctx context.Context) error {
	if f == nil || f.state == nil {
		return nil
	}
	p := f.state
	p.mu.Lock()
	list := p.packageRecoveryBatches
	p.mu.Unlock()
	pending := false
	for _, s := range list {
		if s == nil || s.reconcileV1(ctx) {
			continue
		}
		// An open batch is ordinary active work. A closed batch remains cleanup
		// debt until its real callback, SQL and provider owners have retired.
		s.mu.Lock()
		pending = pending || (s.closed && !s.released)
		s.mu.Unlock()
	}
	if pending {
		return ErrApplicationSessionUnknownV1
	}
	return nil
}
