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

var ErrHTMLCeremonyWorkflowV1 = errors.New("pdfadmission: owned HTML ceremony workflow unavailable")

type HTMLCeremonyWorkflowPurposeV1 uint8

const (
	HTMLCeremonyReviewV1 HTMLCeremonyWorkflowPurposeV1 = iota + 1
	HTMLCeremonyChangeDecisionV1
	HTMLCeremonyRetireV1
	htmlCeremonyParticipantChangeV1
)

// This fixed single-transaction owner reuses the actual revision reader/source
// implementation. It has no revision declaration, candidate, writer, retry,
// replacement session or arbitrary supplied work-cost authority.
type ApplicationHTMLCeremonyWorkflowV1 struct {
	mu                                                                                                       sync.Mutex
	self                                                                                                     *ApplicationHTMLCeremonyWorkflowV1
	operation                                                                                                *ApplicationHTMLRevisionOperationV1
	stage                                                                                                    *ApplicationHTMLRevisionSQLV1
	reader                                                                                                   *ApplicationHTMLRevisionReaderV1
	snapshot                                                                                                 *applicationHTMLRevisionSourceSnapshotV1
	releaseBody                                                                                              func()
	closeConsumers                                                                                           []func()
	active                                                                                                   int
	opening, attempted, closed, resourcesClosed                                                              bool
	capturedRetired, reviewAttempted, reopenAttempted, changeAttempted, resolveAttempted, autoApplyAttempted bool
	changeInput                                                                                              HTMLParticipantChangeInputV1
	updated                                                                                                  *generated.Document
	change                                                                                                   *generated.ChangeRequest
	participant                                                                                              *generated.Recipient
	sender                                                                                                   *generated.User
	access                                                                                                   *generated.GetHTMLCeremonyWorkflowAccessV1Row
	policy                                                                                                   *HTMLCeremonyParticipantPolicyV1
	changeHeader                                                                                             *generated.GetHTMLChangeRequestReadHeaderV1Row
	notification                                                                                             *ApplicationHTMLChangeNotificationV1
}

func (f *ApplicationSessionFactoryV1) NewHTMLCeremonyWorkflowV1(ctx context.Context, org, document, actor uuid.UUID, purpose HTMLCeremonyWorkflowPurposeV1) (*ApplicationHTMLCeremonyWorkflowV1, error) {
	if purpose < HTMLCeremonyReviewV1 || purpose > HTMLCeremonyRetireV1 ||
		(purpose == HTMLCeremonyReviewV1 && actor == uuid.Nil) {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	return f.newHTMLCeremonyWorkflowV1(ctx, org, document, actor, purpose, nil, nil)
}

// The public participant has no caller-supplied tenant/document/recipient UUID.
// Its fixed scope is borrowed from the SAME genuine process probe observation.
// All original locked credential, role, notice and evidence checks remain at the
// mutation seam; the read observation itself grants no mutation permission.
func (f *ApplicationSessionFactoryV1) NewHTMLParticipantChangesV1(ctx context.Context, scope *ApplicationSignerScopeV1) (*ApplicationHTMLCeremonyWorkflowV1, error) {
	if !applicationContextV1(ctx) {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	snapshot, release, err := scope.borrowV1(f)
	if err != nil {
		return nil, errors.Join(ErrHTMLCeremonyWorkflowV1, err)
	}
	out, err := f.newHTMLCeremonyWorkflowV1(ctx, snapshot.org, snapshot.document, uuid.Nil, htmlCeremonyParticipantChangeV1, &snapshot, release)
	if err != nil {
		release()
	}
	return out, err
}
func (f *ApplicationSessionFactoryV1) newHTMLCeremonyWorkflowV1(ctx context.Context, org, document, actor uuid.UUID, purpose HTMLCeremonyWorkflowPurposeV1, participant *applicationSignerScopeSnapshotV1, release func()) (*ApplicationHTMLCeremonyWorkflowV1, error) {
	if f == nil || f.state == nil || org == uuid.Nil || document == uuid.Nil || !applicationContextV1(ctx) {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	f.state.mu.Lock()
	available := !f.state.closing && f.state.work != nil && f.state.work.coordinator != nil
	f.state.mu.Unlock()
	if !available {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	deadline, _ := ctx.Deadline()
	original, cancel := context.WithCancel(ctx)
	op := &applicationHTMLRevisionOperationV1{factory: f, ctx: original, cancel: cancel, deadline: deadline,
		org: org, document: document, actor: actor, workflow: purpose, participant: participant,
		releaseInput: release, stages: make(map[*applicationHTMLRevisionSQLV1]struct{})}
	w := &ApplicationHTMLCeremonyWorkflowV1{operation: &ApplicationHTMLRevisionOperationV1{state: op}}
	w.self = w
	return w, nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) OpenV1() error {
	if w == nil || w.self != w {
		return ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	if w.closed || w.attempted || w.operation == nil {
		w.mu.Unlock()
		return ErrHTMLCeremonyWorkflowV1
	}
	w.attempted, w.opening = true, true
	operation := w.operation
	w.mu.Unlock()
	stage, err := operation.OpenSQLV1(HTMLRevisionInitialReadV1)
	w.mu.Lock()
	w.stage = stage
	if stage != nil {
		w.reader = stage.state.reader
	}
	w.opening = false
	closed := w.closed
	closes, release, finish := w.retireLockedV1()
	w.mu.Unlock()
	w.finishResourcesV1(closes, release, finish)
	if err != nil || closed {
		return errors.Join(ErrHTMLCeremonyWorkflowV1, err)
	}
	return nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) WithTxV1(consume func(context.Context, generated.DBTX, *ApplicationHTMLRevisionReaderV1) error) error {
	if w == nil || w.self != w || consume == nil {
		return ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	if w.closed || w.resourcesClosed || w.opening || w.stage == nil || w.reader == nil {
		w.mu.Unlock()
		return ErrHTMLCeremonyWorkflowV1
	}
	w.active++
	stage := w.stage
	w.mu.Unlock()
	defer w.doneV1()
	return stage.WithTxV1(consume)
}
func (w *ApplicationHTMLCeremonyWorkflowV1) doneV1() {
	w.mu.Lock()
	w.active--
	closes, release, finish := w.retireLockedV1()
	w.mu.Unlock()
	w.finishResourcesV1(closes, release, finish)
}
func (w *ApplicationHTMLCeremonyWorkflowV1) retireLockedV1() ([]func(), func(), bool) {
	if !w.closed || w.resourcesClosed || w.active != 0 || w.opening {
		return nil, nil, false
	}
	w.resourcesClosed = true
	closes, release := w.closeConsumers, w.releaseBody
	if w.notification != nil {
		n := w.notification
		closes = append([]func(){n.clearV1}, closes...)
		w.notification = nil
	}
	w.closeConsumers, w.releaseBody = nil, nil
	w.snapshot, w.updated, w.change, w.participant, w.sender = nil, nil, nil, nil, nil
	w.changeInput = HTMLParticipantChangeInputV1{}
	w.access, w.policy, w.changeHeader = nil, nil, nil
	return closes, release, true
}
func (w *ApplicationHTMLCeremonyWorkflowV1) finishResourcesV1(closes []func(), release func(), finish bool) {
	for _, close := range closes {
		close()
	}
	if release != nil {
		release()
	}
	if finish {
		w.operation.CloseConsumerV1()
	}
}
func (w *ApplicationHTMLCeremonyWorkflowV1) CloseConsumerV1() {
	if w == nil || w.self != w {
		return
	}
	w.mu.Lock()
	w.closed = true
	operation := w.operation
	closes, release, finish := w.retireLockedV1()
	w.mu.Unlock()
	// Cancellation is immediate, while actual callbacks/results still retain all
	// original readers, models and work credit until their last explicit release.
	if operation != nil && operation.state != nil {
		operation.state.cancel()
	}
	w.finishResourcesV1(closes, release, finish)
}
func (w *ApplicationHTMLCeremonyWorkflowV1) CloseV1(cleanup context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLCeremonyWorkflowV1
	}
	w.CloseConsumerV1()
	w.mu.Lock()
	operation, joined := w.operation, w.resourcesClosed
	w.mu.Unlock()
	if operation == nil || operation.state == nil {
		return ErrHTMLCeremonyWorkflowV1
	}
	if joined {
		return operation.CloseV1(cleanup)
	}
	// The SAME attempted sessions can retire before a body consumer joins. Do not
	// call operation.CloseConsumer here: that would release the reader too early.
	operation.state.mu.Lock()
	stages := make([]*applicationHTMLRevisionSQLV1, 0, len(operation.state.stages))
	for stage := range operation.state.stages {
		stages = append(stages, stage)
	}
	operation.state.mu.Unlock()
	err := ErrApplicationSessionUnknownV1
	for _, stage := range stages {
		err = errors.Join(err, (&ApplicationHTMLRevisionSQLV1{state: stage}).CloseSQLV1(cleanup))
	}
	return err
}
func (w *ApplicationHTMLCeremonyWorkflowV1) CommitV1() error {
	if w == nil || w.self != w {
		return ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	stage, closed := w.stage, w.closed
	w.mu.Unlock()
	if closed || stage == nil {
		return ErrHTMLCeremonyWorkflowV1
	}
	return stage.CommitV1()
}
func (w *ApplicationHTMLCeremonyWorkflowV1) validCallV1(call context.Context) bool {
	if w == nil || w.self != w || !applicationContextV1(call) {
		return false
	}
	w.mu.Lock()
	stage, closed, active := w.stage, w.closed, w.active
	w.mu.Unlock()
	return !closed && active > 0 && stage != nil && stage.state != nil && htmlRevisionCollectionSessionV1(call, stage.state.session)
}
func (w *ApplicationHTMLCeremonyWorkflowV1) captureBodyV1(call context.Context) error {
	if !w.validCallV1(call) {
		return ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	if w.snapshot != nil {
		w.mu.Unlock()
		return nil
	}
	reader, original := w.reader, w.operation.state.ctx
	w.mu.Unlock()
	snapshot, release, err := reader.borrowHTMLRevisionSourceV1(original)
	if err != nil {
		return err
	}
	w.mu.Lock()
	if w.snapshot != nil {
		w.mu.Unlock()
		release()
		return ErrHTMLCeremonyWorkflowV1
	}
	w.snapshot, w.releaseBody = snapshot, release
	w.mu.Unlock()
	return nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) retainV1(call context.Context, raw, wire int64) error {
	if !w.validCallV1(call) || raw < 0 || wire < 0 {
		return ErrHTMLCeremonyWorkflowV1
	}
	if err := w.captureBodyV1(call); err != nil {
		return err
	}
	close, err := w.reader.authoring.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return errors.Join(ErrHTMLCeremonyWorkflowV1, err)
	}
	w.mu.Lock()
	w.closeConsumers = append(w.closeConsumers, close)
	closed := w.closed
	w.mu.Unlock()
	if closed || call.Err() != nil {
		return ErrHTMLCeremonyWorkflowV1
	}
	return nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) ReadActorDocumentV1(call context.Context, preflight func(HTMLRevisionReadAccessV1) error, gate func(HTMLRevisionReadAccessV1, *generated.User) error) (*HTMLRevisionReadModelsV1, error) {
	if !w.validCallV1(call) || preflight == nil {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	op := w.operation.state
	if op.workflow == htmlCeremonyParticipantChangeV1 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	var models *HTMLRevisionReadModelsV1
	var err error
	if op.actor == uuid.Nil && (op.workflow == HTMLCeremonyChangeDecisionV1 || op.workflow == HTMLCeremonyRetireV1) {
		// Original validated one-click decision has no organization User identity.
		models, err = w.reader.readDocumentBodyV1(call, uuid.Nil, preflight, nil, true)
	} else {
		if gate == nil {
			return nil, ErrHTMLCeremonyWorkflowV1
		}
		models, err = w.reader.ReadDocumentWithActorV1(call, op.actor, preflight, gate)
	}
	if err != nil {
		return nil, err
	}
	if err = w.captureBodyV1(call); err != nil {
		return nil, err
	}
	return models, nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) ReadParticipantDocumentV1(call context.Context, preflight func(HTMLRevisionReadAccessV1) error) (*HTMLRevisionReadModelsV1, error) {
	if !w.validCallV1(call) || preflight == nil || w.operation.state.workflow != htmlCeremonyParticipantChangeV1 || w.operation.state.participant == nil {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	models, err := w.reader.readDocumentBodyV1(call, uuid.Nil, preflight, nil, true)
	if err != nil {
		return nil, err
	}
	if err = w.captureBodyV1(call); err != nil {
		return nil, err
	}
	return models, nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) NewSourceV1(call context.Context) (*ApplicationHTMLRevisionSourceV1, error) {
	if !w.validCallV1(call) || (w.operation.state.workflow != HTMLCeremonyReviewV1 && w.operation.state.workflow != HTMLCeremonyRetireV1) {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	return w.stage.NewSourceV1(call)
}
func (w *ApplicationHTMLCeremonyWorkflowV1) AuditSessionV1(call context.Context) (*ApplicationSessionV1, error) {
	if !w.validCallV1(call) {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	return w.stage.AuditSessionV1(call)
}

// Only native completed result methods below may expose a model with a borrow.
// The HTTP/action adapter must keep release through its actual final response.
func (w *ApplicationHTMLCeremonyWorkflowV1) BorrowDocumentV1(call context.Context) (*generated.Document, func(), error) {
	if !w.validCallV1(call) {
		return nil, nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	if w.closed || w.resourcesClosed || w.updated == nil {
		w.mu.Unlock()
		return nil, nil, ErrHTMLCeremonyWorkflowV1
	}
	w.active++
	document := htmlRevisionCloneDocumentV1(w.updated)
	w.mu.Unlock()
	var once sync.Once
	return document, func() { once.Do(w.doneV1) }, nil
}

// The fixed review check is scalar work over the same already validated source.
func (h *ApplicationHTMLRevisionSourceV1) ValidateRetirementReviewV1() error {
	if h == nil || h.state == nil {
		return ErrHTMLRevisionSourceV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.purpose != htmlCeremonySourcePurposeV1 || s.operation == nil || s.operation.workflow != HTMLCeremonyRetireV1 || s.validation == nil || s.failure != nil || s.processing {
		return ErrHTMLRevisionSourceV1
	}
	return s.validation.ValidateV1(true)
}

// Kept local to avoid any later context being accepted as original authority.
func htmlCeremonyCleanupV1(original context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(original), 5*time.Second)
}
