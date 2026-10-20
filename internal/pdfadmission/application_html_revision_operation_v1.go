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

var ErrHTMLRevisionOperationV1 = errors.New("pdfadmission: owned HTML revision operation unavailable")

const htmlRevisionSQLTimeoutV1 = 10 * time.Second

// These are the four actual original revision route SQL points, not a caller
// capacity maximum: initial, pre-render, pre-store and final append.
type HTMLRevisionSQLPurposeV1 uint8

const (
	HTMLRevisionInitialReadV1 HTMLRevisionSQLPurposeV1 = iota + 1
	HTMLRevisionBeforeRenderReadV1
	HTMLRevisionBeforeStoreReadV1
	HTMLRevisionMutationV1
)

// One actual route creates one operation BEFORE its first read. The operation
// captures that original bounded context, scope and saved factory; each short
// SQL callback is a child, not replacement request/credential authority.
// Native policy still validates the original actor/credential/CAS/evidence.
type ApplicationHTMLRevisionOperationV1 struct {
	state *applicationHTMLRevisionOperationV1
}
type applicationHTMLRevisionOperationV1 struct {
	mu            sync.Mutex
	factory       *ApplicationSessionFactoryV1
	ctx           context.Context
	cancel        context.CancelFunc
	deadline      time.Time
	org, document uuid.UUID
	actor         uuid.UUID
	workflow      HTMLCeremonyWorkflowPurposeV1
	participant   *applicationSignerScopeSnapshotV1
	stages        map[*applicationHTMLRevisionSQLV1]struct{}
	sources       map[*applicationHTMLRevisionSourceOwnerV1]struct{}
	attempted     [4]bool
	closed        bool
	declaration   htmlRevisionDeclarationV1
	releaseInput  func()
	sourceUses    int
}
type ApplicationHTMLRevisionSQLV1 struct{ state *applicationHTMLRevisionSQLV1 }
type applicationHTMLRevisionSQLV1 struct {
	mu             sync.Mutex
	operation      *applicationHTMLRevisionOperationV1
	purpose        HTMLRevisionSQLPurposeV1
	ctx            context.Context
	cancel         context.CancelFunc
	session        *ApplicationSessionV1
	admission      *ApplicationAdmissionV1
	reader         *ApplicationHTMLRevisionReaderV1
	writer         *ApplicationHTMLRevisionWriterV1
	consumerClosed bool
	opening        bool
}

func (f *ApplicationSessionFactoryV1) NewHTMLRevisionOperationV1(ctx context.Context, org, document, actor uuid.UUID, input *ApplicationHTMLAuthoringInputV1) (*ApplicationHTMLRevisionOperationV1, error) {
	if f == nil || f.state == nil || org == uuid.Nil || document == uuid.Nil || actor == uuid.Nil || !applicationContextV1(ctx) {
		return nil, ErrHTMLRevisionOperationV1
	}
	p := f.state
	p.mu.Lock()
	available := !p.closing && p.work != nil && p.work.coordinator != nil
	p.mu.Unlock()
	if !available {
		return nil, ErrHTMLRevisionOperationV1
	}
	declaration, releaseInput, err := f.revisionDeclarationV1(ctx, org, input)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	original, cancel := context.WithCancel(ctx)
	state := &applicationHTMLRevisionOperationV1{factory: f, ctx: original, cancel: cancel, deadline: deadline, org: org, document: document, actor: actor, declaration: declaration, releaseInput: releaseInput, stages: make(map[*applicationHTMLRevisionSQLV1]struct{})}
	return &ApplicationHTMLRevisionOperationV1{state: state}, nil
}
func (o *applicationHTMLRevisionOperationV1) usableV1() bool {
	return o != nil && !o.closed && o.factory != nil && o.factory.state != nil && o.org != uuid.Nil && o.document != uuid.Nil && applicationContextV1(o.ctx)
}

// No caller supplies a later/cleanup context to extend the SQL operation. Its
// actual10s child derives from the retained ORIGINAL bounded route context.
// Closing it has no effect on the original context used by source CPU stages.
func (h *ApplicationHTMLRevisionOperationV1) OpenSQLV1(purpose HTMLRevisionSQLPurposeV1) (*ApplicationHTMLRevisionSQLV1, error) {
	if h == nil || h.state == nil || purpose < HTMLRevisionInitialReadV1 || purpose > HTMLRevisionMutationV1 {
		return nil, ErrHTMLRevisionOperationV1
	}
	o := h.state
	o.mu.Lock()
	index := int(purpose - HTMLRevisionInitialReadV1)
	if !o.usableV1() || o.attempted[index] || (o.workflow != 0 && purpose != HTMLRevisionInitialReadV1) {
		o.mu.Unlock()
		return nil, ErrHTMLRevisionOperationV1
	}
	if index > 0 {
		previousRetired := false
		for previous := range o.stages {
			if previous.purpose == purpose-1 {
				previous.mu.Lock()
				original, opening := previous.session, previous.opening
				previous.mu.Unlock()
				previousRetired = !opening && original != nil && original.RetiredV1() && !original.CommitUnknownV1()
				break
			}
		}
		if !previousRetired {
			o.mu.Unlock()
			return nil, ErrHTMLRevisionOperationV1
		}
	}
	o.attempted[index] = true
	ctx, cancel := context.WithTimeout(o.ctx, htmlRevisionSQLTimeoutV1)
	if o.workflow == htmlCeremonyParticipantChangeV1 {
		cancel()
		ctx, cancel = context.WithCancel(o.ctx)
	}
	stage := &applicationHTMLRevisionSQLV1{operation: o, purpose: purpose, ctx: ctx, cancel: cancel, opening: true}
	o.stages[stage] = struct{}{}
	o.mu.Unlock()
	handle := &ApplicationHTMLRevisionSQLV1{state: stage}
	// Open is the genuine saved public factory/native physical owner. Stage
	// registration precedes dispatch so operation Close cannot miss a live open.
	session, err := o.factory.OpenV1(ctx, o.org, o.document)
	stage.mu.Lock()
	stage.session = session
	stage.mu.Unlock()
	if err == nil {
		var admission *ApplicationAdmissionV1
		admission, err = session.NewAdmissionV1(ctx)
		stage.mu.Lock()
		stage.admission = admission
		stage.mu.Unlock()
	}
	if err == nil {
		err = session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
			reader, err := session.NewHTMLRevisionReaderV1(call)
			stage.mu.Lock()
			stage.reader = reader
			closed := stage.consumerClosed
			stage.mu.Unlock()
			if closed && reader != nil {
				reader.CloseConsumerV1()
			}
			return err
		})
	}
	stage.mu.Lock()
	stage.opening = false
	stage.mu.Unlock()
	o.mu.Lock()
	closed := o.closed
	o.mu.Unlock()
	if err != nil || closed || ctx.Err() != nil {
		handle.CloseConsumerV1()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(o.ctx), 5*time.Second)
		defer stop()
		err = errors.Join(err, handle.CloseSQLV1(cleanup))
		return nil, errors.Join(ErrHTMLRevisionOperationV1, err)
	}
	return handle, nil
}

// This facade supplies the ACTUAL session's tracked DBTX and actual reader.
// Handler code must size/validate via that reader before any body query. No
// Pool transaction, raw pgx.Conn, nested transaction or retired hint is adopted.
func (h *ApplicationHTMLRevisionSQLV1) WithTxV1(consume func(context.Context, generated.DBTX, *ApplicationHTMLRevisionReaderV1) error) error {
	if h == nil || h.state == nil || consume == nil {
		return ErrHTMLRevisionOperationV1
	}
	s := h.state
	o := s.operation
	if o == nil {
		return ErrHTMLRevisionOperationV1
	}
	o.mu.Lock()
	usable := o.usableV1()
	o.mu.Unlock()
	s.mu.Lock()
	ctx, session, reader, closed := s.ctx, s.session, s.reader, s.consumerClosed
	s.mu.Unlock()
	if !usable || closed || session == nil || reader == nil || !applicationContextV1(ctx) {
		return ErrHTMLRevisionOperationV1
	}
	return session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error { return consume(call, db, reader) })
}
func (h *ApplicationHTMLRevisionSQLV1) CommitV1() error {
	if h == nil || h.state == nil {
		return ErrHTMLRevisionOperationV1
	}
	s := h.state
	o := s.operation
	if o == nil {
		return ErrHTMLRevisionOperationV1
	}
	o.mu.Lock()
	usable := o.usableV1()
	o.mu.Unlock()
	s.mu.Lock()
	ctx, session, closed := s.ctx, s.session, s.consumerClosed
	s.mu.Unlock()
	if !usable || closed || session == nil || (s.purpose != HTMLRevisionMutationV1 && o.workflow == 0) {
		return ErrHTMLRevisionOperationV1
	}
	return session.CommitV1(ctx) // actual serialized dispatch/unknown state
}

// Cleanup alone may use a fresh bounded context. It cannot call Open, recheck
// a credential, build source, admit new CPU or dispatch another mutation.
func (h *ApplicationHTMLRevisionSQLV1) CloseSQLV1(cleanup context.Context) error {
	if h == nil || h.state == nil {
		return nil
	}
	s := h.state
	s.mu.Lock()
	session, admission, cancel, opening := s.session, s.admission, s.cancel, s.opening
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if session == nil {
		if opening {
			return ErrApplicationSessionUnknownV1
		}
		return nil
	}
	err := session.CloseV1(cleanup)
	if admission != nil {
		_, reconcile := admission.ReconcileCleanupV1(cleanup)
		err = errors.Join(err, reconcile)
	}
	if opening {
		return errors.Join(err, ErrApplicationSessionUnknownV1)
	}
	return err
}
func (h *ApplicationHTMLRevisionSQLV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	s.consumerClosed = true
	reader, writer := s.reader, s.writer
	s.mu.Unlock()
	if writer != nil {
		writer.CloseConsumerV1()
	}
	if reader != nil {
		reader.CloseConsumerV1()
	}
}

// A source owner is born only from a registered stage's ACTUAL completed
// reader and borrows its original private snapshot. It retains o.ctx, not the
// auto-cancelled WithTx child, and may never renew that original deadline.
// This helper grants no parser/Compile work by itself.
func (o *applicationHTMLRevisionOperationV1) borrowSourceV1(reader *ApplicationHTMLRevisionReaderV1) (*applicationHTMLRevisionSourceSnapshotV1, func(), error) {
	if o == nil || reader == nil {
		return nil, nil, ErrHTMLRevisionOperationV1
	}
	o.mu.Lock()
	if !o.usableV1() {
		o.mu.Unlock()
		return nil, nil, ErrHTMLRevisionOperationV1
	}
	found := false
	for stage := range o.stages {
		stage.mu.Lock()
		same := stage.reader == reader && stage.session == reader.session && !stage.consumerClosed
		stage.mu.Unlock()
		if same {
			found = true
			break
		}
	}
	original := o.ctx
	o.mu.Unlock()
	if !found {
		return nil, nil, ErrHTMLRevisionOperationV1
	}
	snapshot, release, err := reader.borrowHTMLRevisionSourceV1(original)
	if err != nil {
		return nil, nil, err
	}
	if snapshot == nil || snapshot.document == nil || snapshot.document.ID != o.document || snapshot.document.OrgID != o.org || reader.session == nil || reader.session.state == nil || reader.session.state.factory != o.factory.state {
		release()
		return nil, nil, ErrHTMLRevisionOperationV1
	}
	return snapshot, release, nil
}
func (h *ApplicationHTMLRevisionOperationV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	o := h.state
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	o.closed = true
	o.cancel()
	stages := make([]*applicationHTMLRevisionSQLV1, 0, len(o.stages))
	for stage := range o.stages {
		stages = append(stages, stage)
	}
	o.mu.Unlock()
	for _, stage := range stages {
		(&ApplicationHTMLRevisionSQLV1{state: stage}).CloseConsumerV1()
	}
	o.mu.Lock()
	sources := make([]*applicationHTMLRevisionSourceOwnerV1, 0, len(o.sources))
	for source := range o.sources {
		sources = append(sources, source)
	}
	o.mu.Unlock()
	for _, source := range sources {
		(&ApplicationHTMLRevisionSourceV1{state: source}).CloseConsumerV1()
	}
	o.mu.Lock()
	releaseInput := o.releaseInputIfCompleteLockedV1()
	o.mu.Unlock()
	if releaseInput != nil {
		releaseInput()
	}
}

// Process/route cleanup can retry the SAME registered owners with a fresh
// cleanup context. It never opens replacement sessions or replays statements.
func (h *ApplicationHTMLRevisionOperationV1) CloseV1(cleanup context.Context) error {
	if h == nil || h.state == nil {
		return nil
	}
	h.CloseConsumerV1()
	o := h.state
	o.mu.Lock()
	stages := make([]*applicationHTMLRevisionSQLV1, 0, len(o.stages))
	for stage := range o.stages {
		stages = append(stages, stage)
	}
	o.mu.Unlock()
	var result error
	for _, stage := range stages {
		result = errors.Join(result, (&ApplicationHTMLRevisionSQLV1{state: stage}).CloseSQLV1(cleanup))
		// SQL retirement alone is intentionally sufficient for provider sequencing.
		// Whole-operation nil-close additionally requires this SAME admission to
		// settle its actual source/response/publication consumers. Keep all original
		// handles for cleanup-only retry while a real last user remains.
		stage.mu.Lock()
		admission := stage.admission
		stage.mu.Unlock()
		if admission != nil {
			pending, err := admission.ReconcileCleanupV1(cleanup)
			result = errors.Join(result, err)
			if pending != 0 {
				result = errors.Join(result, ErrApplicationSessionUnknownV1)
			}
		}
	}
	return result
}

// CommitDispatchedV1 observes only the actual serialized native session state.
// It is used to retain the stored PDF after an attempted/uncertain commit;
// caller intent, an error or zero rows cannot manufacture dispatch evidence.
func (h *ApplicationHTMLRevisionSQLV1) CommitDispatchedV1() bool {
	if h == nil || h.state == nil {
		return false
	}
	s := h.state
	s.mu.Lock()
	session := s.session
	s.mu.Unlock()
	if session == nil || session.state == nil {
		return false
	}
	session.state.mu.Lock()
	attempted := session.state.commitAttempted
	session.state.mu.Unlock()
	return attempted
}
