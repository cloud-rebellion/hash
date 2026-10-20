// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

type HTMLSendSQLPurposeV1 uint8

const (
	HTMLSendPreparationV1 HTMLSendSQLPurposeV1 = iota + 1
	HTMLSendAdmissionV1
	HTMLSendSnapshotV1
	HTMLSendCompletionV1
	HTMLSendIntentReadV1
	HTMLSendIntentMarkV1
	HTMLSendAbortV1
	HTMLSendPinV1
	HTMLSendCompletedV1
	HTMLSendSourceV1
	HTMLSendQuotaV1
	HTMLSendEIDASV1
	HTMLSendSnapshotFieldsV1
	HTMLBlockSignPreparationV1
	HTMLBlockSignMutationV1
	HTMLHistoricalFinalizationClaimV1
	HTMLHistoricalFinalizationStageV1
	HTMLHistoricalFinalizationCheckpointV1
	HTMLHistoricalFinalizationResumeV1
	HTMLHistoricalFinalizationPublicationV1
)

// The fixed standalone call graph has at most16 SQL stages: preparation,
// admission, intent+reload, sealed snapshot+pin, one expiry abort+reload,
// retention-start+handoff, retention-complete+handoff, finalcompletion and the original quota check plus TWO original rule evaluations. A
// completed/failed branch replaces later stages rather than adding an endless
// retry loop. This is fixed program topology, not configurable spare capacity.
const htmlSendMaxSQLStagesV1 = 16

type ApplicationHTMLSendOperationV1 struct {
	reminderSubject                       uuid.UUID
	callerContext                         context.Context
	fieldListScope                        *applicationSignerScopeSnapshotV1
	packageReadScope                      *applicationSignerScopeSnapshotV1
	packageReadInput                      *ApplicationSignerPackageReadInputV1
	packageMemberRead                     *applicationSignerPackageMemberReadStateV1
	mu                                    sync.Mutex
	self                                  *ApplicationHTMLSendOperationV1
	factory                               *ApplicationSessionFactoryV1
	original                              context.Context
	cancel                                context.CancelFunc
	deadline                              time.Time
	org, document                         uuid.UUID
	stages                                []*ApplicationHTMLSendSQLStageV1
	resolverOwner                         *applicationHTMLSendResolverV1
	memberResolverOwners                  map[*applicationHTMLSendResolverV1]struct{}
	baseStages, sourceLimit, sourceOpened int
	closed                                bool
	packageSendAttemptID                  uuid.UUID
	packageSendReference                  *applicationHTMLSendPackageAttemptReferenceV1
	retentionReference                    *applicationHTMLSendRetentionReferenceV1
	completionReference                   *applicationHTMLSendCompletionReferenceV1
}
type ApplicationHTMLSendSQLStageV1 struct {
	self                                *ApplicationHTMLSendSQLStageV1
	operation                           *ApplicationHTMLSendOperationV1
	purpose                             HTMLSendSQLPurposeV1
	ctx                                 context.Context
	cancel                              context.CancelFunc
	session                             *ApplicationSessionV1
	work                                *ApplicationHTMLSendWorkV1
	opening, active, used, startingWork bool
}

func (f *ApplicationSessionFactoryV1) NewHTMLSendOperationV1(ctx context.Context, org, document uuid.UUID) (*ApplicationHTMLSendOperationV1, error) {
	if f == nil || f.state == nil || ctx == nil || ctx.Err() != nil || org == uuid.Nil || document == uuid.Nil {
		return nil, ErrHTMLSendWorkV1
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) {
		return nil, ErrHTMLSendWorkV1
	}
	f.state.mu.Lock()
	available := !f.state.closing && f.state.work != nil && f.state.work.coordinator != nil
	f.state.mu.Unlock()
	if !available {
		return nil, ErrHTMLSendWorkV1
	}
	original, cancel := context.WithCancel(ctx)
	o := &ApplicationHTMLSendOperationV1{factory: f, original: original, callerContext: ctx, cancel: cancel, deadline: deadline, org: org, document: document}
	o.self = o
	return o, nil
}
func (o *ApplicationHTMLSendOperationV1) OpenSQLV1(purpose HTMLSendSQLPurposeV1) (*ApplicationHTMLSendSQLStageV1, error) {
	if purpose == HTMLSendSourceV1 {
		return nil, ErrHTMLSendWorkV1
	}
	return o.openSQLV1(purpose, nil)
}
func (o *ApplicationHTMLSendOperationV1) bindResolverV1(p *applicationHTMLSendResolverV1) error {
	if o == nil || o.self != o || p == nil || p.self != p || p.work == nil || p.work.stage == nil || p.work.stage.operation != o || p.document == nil || p.document.OrgID != o.org {
		return ErrHTMLSendWorkV1
	}
	w := p.work
	w.mu.Lock()
	logical := w.logicalDocumentV1()
	member := w.familyRoot != nil
	w.mu.Unlock()
	if logical == uuid.Nil || p.document.ID != logical {
		return ErrHTMLSendWorkV1
	}
	n := 0
	for _, b := range p.bindings {
		if b == nil || b.DocumentID != logical {
			return ErrHTMLSendWorkV1
		}
		if b.SourceKind == "org.setting" {
			n++
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.original.Err() != nil {
		return ErrHTMLSendWorkV1
	}
	if !member {
		if logical != o.document || o.resolverOwner != nil {
			return ErrHTMLSendWorkV1
		}
		o.resolverOwner = p
		o.sourceLimit = n
		return nil
	}
	// Exactly one actual resolver belongs to each admitted member Work. Initial
	// org.setting calls reuse that member's same active preparation callback.
	if o.memberResolverOwners == nil {
		o.memberResolverOwners = make(map[*applicationHTMLSendResolverV1]struct{})
	}
	if _, exists := o.memberResolverOwners[p]; exists {
		return ErrHTMLSendWorkV1
	}
	o.memberResolverOwners[p] = struct{}{}
	return nil
}

// The outer fixed Send boundary has dropped all preparation views and joined
// every resolver before this method clears registry references. Member source
// loans/body consumers still close separately through their genuine root Work.
func (o *ApplicationHTMLSendOperationV1) RetirePreparationResolversV1() error {
	if o == nil || o.self != o {
		return ErrHTMLSendWorkV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return ErrHTMLSendWorkV1
	}
	o.resolverOwner = nil
	o.memberResolverOwners = nil
	o.sourceLimit = 0
	o.sourceOpened = 0
	return nil
}

func (o *ApplicationHTMLSendOperationV1) openSQLV1(purpose HTMLSendSQLPurposeV1, source *applicationHTMLSendResolverV1) (*ApplicationHTMLSendSQLStageV1, error) {
	if o == nil || o.self != o || purpose < HTMLSendPreparationV1 || purpose > HTMLReminderScheduledV1 {
		return nil, ErrHTMLSendWorkV1
	}
	o.mu.Lock()
	if o.closed || o.original.Err() != nil || !time.Now().Before(o.deadline) {
		o.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	if purpose == HTMLSendSourceV1 {
		if source == nil || source.self != source || o.resolverOwner != source || o.sourceOpened >= o.sourceLimit {
			o.mu.Unlock()
			return nil, ErrHTMLSendWorkV1
		}
		source.mu.Lock()
		live := source.liveV1() && source.active > 0 && source.work.stage.operation == o
		source.mu.Unlock()
		if !live {
			o.mu.Unlock()
			return nil, ErrHTMLSendWorkV1
		}
		o.sourceOpened++
	} else {
		if source != nil || o.baseStages >= htmlSendMaxSQLStagesV1 {
			o.mu.Unlock()
			return nil, ErrHTMLSendWorkV1
		}
		o.baseStages++
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if purpose == HTMLSendAdmissionV1 {
		ctx, cancel = context.WithTimeout(o.original, 10*time.Second)
	} else {
		ctx, cancel = context.WithCancel(o.original)
	}
	stage := &ApplicationHTMLSendSQLStageV1{operation: o, purpose: purpose, ctx: ctx, cancel: cancel, opening: true}
	stage.self = stage
	o.stages = append(o.stages, stage)
	o.mu.Unlock()
	// Registration precedes the genuine factory begin. Unknown starts/physical
	// sessions remain in that factory; no operation-close boolean retires them.
	session, err := o.factory.OpenV1(ctx, o.org, o.document)
	o.mu.Lock()
	stage.session = session
	stage.opening = false
	closed := o.closed
	o.mu.Unlock()
	if err != nil || closed {
		cancel()
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(o.original), 5*time.Second)
			_ = session.CloseV1(cleanup)
			stop()
		}
		if err != nil {
			return nil, err
		}
		return nil, ErrHTMLSendWorkV1
	}
	return stage, nil
}
func (s *ApplicationHTMLSendSQLStageV1) ContextV1() context.Context {
	if s == nil || s.self != s || s.operation == nil || s.operation.self != s.operation {
		return nil
	}
	return s.ctx
}
func (s *ApplicationHTMLSendSQLStageV1) SessionV1() *ApplicationSessionV1 {
	if s == nil || s.self != s || s.operation == nil || s.operation.self != s.operation {
		return nil
	}
	s.operation.mu.Lock()
	defer s.operation.mu.Unlock()
	return s.session
}
func (s *ApplicationHTMLSendSQLStageV1) WithTxV1(fn func(context.Context, generated.DBTX) error) error {
	if s == nil || s.self != s || s.operation == nil || s.operation.self != s.operation || fn == nil {
		return ErrHTMLSendWorkV1
	}
	o := s.operation
	o.mu.Lock()
	if o.closed || s.used || s.active || s.opening || s.session == nil || s.ctx.Err() != nil {
		o.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	s.used = true
	s.active = true
	session := s.session
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		s.active = false
		closed := o.closed
		work := s.work
		o.mu.Unlock()
		if closed && work != nil {
			work.CloseConsumerV1()
		}
	}()
	return session.WithTxV1(s.ctx, fn)
}
func (s *ApplicationHTMLSendSQLStageV1) CloseSQLV1() error {
	if s == nil || s.self != s || s.operation == nil || s.operation.self != s.operation {
		return ErrHTMLSendWorkV1
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(s.operation.original), 5*time.Second)
	defer cancel()
	return s.closeSQLV1(cleanup)
}

func (s *ApplicationHTMLSendSQLStageV1) closeSQLV1(cleanup context.Context) error {
	if s == nil || s.self != s || s.operation == nil || s.operation.self != s.operation || !applicationContextV1(cleanup) {
		return ErrHTMLSendWorkV1
	}
	o := s.operation
	o.mu.Lock()
	session := s.session
	opening, active := s.opening, s.active
	o.mu.Unlock()
	if session == nil {
		if opening || active {
			return ErrApplicationSessionUnknownV1
		}
		return ErrHTMLSendWorkV1
	}
	err := session.CloseV1(cleanup)
	s.cancel()
	// A physical close is not an operation/activity join. In-flight Open/CPU
	// retains this mapped stage until the ORIGINAL synchronous activity returns.
	o.mu.Lock()
	opening, active = s.opening, s.active
	o.mu.Unlock()
	if opening || active {
		return errors.Join(err, ErrApplicationSessionUnknownV1)
	}
	return err
}

// EndConsumerV1 synchronously ends only this genuine operation consumer.
// Bounded compositions call it before physical CloseV1 so an expired cleanup
// context cannot orphan logical ownership. It does no reconciliation or I/O;
// physical/backend uncertainty and independently retained outputs remain paid.
func (o *ApplicationHTMLSendOperationV1) EndConsumerV1() {
	o.closeConsumerOnlyV1()
}

func (o *ApplicationHTMLSendOperationV1) CloseConsumerV1() {
	if !o.closeConsumerOnlyV1() {
		return
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(o.original), 5*time.Second)
	defer cancel()
	_ = o.factory.ReconcileCleanupV1(cleanup)
}

func (o *ApplicationHTMLSendOperationV1) closeConsumerOnlyV1() bool {
	if o == nil || o.self != o {
		return false
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return false
	}
	o.closed = true
	retentionReference := o.retentionReference
	o.retentionReference = nil
	packageReference := o.packageSendReference
	o.packageSendReference = nil
	completionReference := o.completionReference
	o.completionReference = nil
	o.cancel()
	works := make([]*ApplicationHTMLSendWorkV1, 0, len(o.stages))
	for _, stage := range o.stages {
		stage.cancel()
		if !stage.active && stage.work != nil {
			works = append(works, stage.work)
		}
	}
	o.mu.Unlock()
	if retentionReference != nil {
		retentionReference.closeV1()
	}
	if packageReference != nil {
		packageReference.closeV1()
	}
	if completionReference != nil {
		completionReference.closeV1()
	}
	for _, work := range works {
		work.CloseConsumerV1()
	}
	return true
}

// CloseV1 ends this operation consumer and joins its actual SQL and physical
// admission observation. Known asynchronous payload consumers may outlive the
// HTTP response; their original admission and debt remain until real last use.
// Own SQL/fence/activity uncertainty still fails. Foreign cleanup cannot
// redefine this outcome. Every stage shares one cleanup budget and real handles.
func (o *ApplicationHTMLSendOperationV1) CloseV1(ctx context.Context) error {
	if o == nil {
		return nil
	}
	if o.self != o || o.factory == nil || o.factory.state == nil || !applicationContextV1(ctx) {
		return ErrHTMLSendWorkV1
	}
	cleanup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	o.closeConsumerOnlyV1()
	o.mu.Lock()
	// Closing forbids further stage registration under this same mutex. Keep
	// the actual now-immutable slice, without a new unowned snapshot allocation.
	stages := o.stages
	o.mu.Unlock()
	var result error
	for _, stage := range stages {
		if stage == nil || stage.self != stage || stage.operation != o {
			result = errors.Join(result, ErrHTMLSendWorkV1)
			continue
		}
		result = errors.Join(result, stage.closeSQLV1(cleanup))
		o.mu.Lock()
		session := stage.session
		busy := stage.opening || stage.active || stage.startingWork
		o.mu.Unlock()
		if busy {
			result = errors.Join(result, ErrApplicationSessionUnknownV1)
		}
		if session == nil || session.state == nil {
			continue
		}
		session.state.mu.Lock()
		admission := session.state.admission
		session.state.mu.Unlock()
		if admission == nil {
			continue
		}
		p := o.factory.state
		p.mu.Lock()
		registration := p.htmlAdmissions[admission]
		p.mu.Unlock()
		// A known post-commit hook may retain this exact payload consumer.
		// Pending debt remains in the identity-safe registry; it is not an
		// unknown physical SQL outcome or a reason to undo acknowledged success.
		_, err := o.factory.reconcileHTMLAdmissionRegistrationV1(cleanup, admission, registration)
		result = errors.Join(result, err)
	}
	// Preserve the existing global reconciliation side effect with only this
	// same remaining budget. Its foreign errors never release or forgive debt.
	_ = o.factory.ReconcileCleanupV1(cleanup)
	return result
}
