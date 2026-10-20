// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"sync"
	"sync/atomic"
)

// A Send source is an opaque read-only purpose. It cannot materialize a new
// revision, accept a caller Document/cost, or invoke a caller CPU callback.
// Copies share the same immutable actual source and one validation state.
type ApplicationHTMLSendSourceV1 struct {
	state *applicationHTMLSendSourceStateV1
}
type applicationHTMLSendSourceStateV1 struct {
	policyMutex                                            sync.Mutex
	policyActivity                                         atomic.Uint64
	retirementClaim                                        atomic.Bool
	closeRequested                                         atomic.Bool
	retired                                                bool
	owner                                                  *applicationHTMLRevisionSourceOwnerV1
	work                                                   *ApplicationHTMLSendWorkV1
	candidate                                              bool
	blockTree                                              *blocks.Tree
	blockValues                                            map[string]string
	blockRoles                                             []string
	blockWorkBase, blockDecimalPeak                        int64
	blockAttempted, blockProcessing, blockRolesAttempted   bool
	blockTreeAttempted, blockEvidenceAttempted             bool
	blockTreeFailure, blockEvidenceFailure                 error
	blockFailure, blockRolesFailure, blockAdmissionFailure error
	quotaAttempted                                         bool
	eidasAttempted                                         bool
	partiesAttempted, rolesAttempted                       bool
	partiesFailure, rolesFailure                           error
	rolesPages                                             int
	validationAttempted                                    bool
	validationFailure                                      error
	attempted                                              bool
	failure                                                error
	currentAttempted                                       bool
	currentFailure                                         error
}

// NewSourceV1 is called only inside the registered actual Work callback after
// its document/current/collection reads. The source keeps that Work's real body
// borrower until source CPU plus original route-consumer last use have joined.
func (w *ApplicationHTMLSendWorkV1) NewSourceV1(call context.Context) (*ApplicationHTMLSendSourceV1, error) {
	if w == nil || w.self != w || !applicationContextV1(call) {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.sourceStarted || w.stage == nil || (w.stage.purpose == HTMLSendPinV1 && !w.pinsCompleted && w.familyRoot == nil) || w.stage.self != w.stage || w.stage.operation == nil || w.stage.operation.self != w.stage.operation || w.stage.session != w.session || w.models == nil || w.sourceDocument == nil {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	w.sourceStarted = true
	stage := w.stage
	op := stage.operation
	session := w.session
	w.mu.Unlock()
	document, current, release, err := w.borrowHTMLSendSourceV1()
	if err != nil {
		return nil, err
	}
	physical := session.state
	p := physical.factory
	p.mu.Lock()
	physical.mu.Lock()
	a := physical.admission
	registration := p.htmlAdmissions[a]
	if p.closing || physical.observer || physical.closed || physical.retired || physical.unknown || physical.ended ||
		!physical.callbackActive || physical.sqlActive || call.Value(applicationSessionCallbackKeyV1{}) != physical ||
		a == nil || !a.valid() || physical.fence == nil || a.fence != physical.fence || a.cleanupDone != physical.fence.clientDone || registration == nil ||
		op.factory == nil || op.factory.state != p || op.org != physical.org || op.document != physical.document || !applicationContextV1(op.original) {
		physical.mu.Unlock()
		p.mu.Unlock()
		release()
		return nil, ErrHTMLSendWorkV1
	}
	original, cancel := context.WithCancel(op.original)
	deadline, _ := original.Deadline()
	binding := &applicationHTMLRevisionSourceBindingV1{factory: p, session: session, admission: a, registration: registration, org: physical.org, document: w.logicalDocumentV1(), ctx: original, deadline: deadline}
	physical.mu.Unlock()
	p.mu.Unlock()
	owner := &applicationHTMLRevisionSourceOwnerV1{purpose: htmlSendSourcePurposeV1, binding: binding, snapshot: &applicationHTMLRevisionSourceSnapshotV1{document: document, current: current}, releaseBorrower: release, cancel: cancel}
	owner.self = owner
	handle := &ApplicationHTMLRevisionSourceV1{state: owner}
	// Register the immutable owner pointer on Work BEFORE initialComponents or
	// any real grant. Mutating the returned public shell cannot lose recovery.
	w.mu.Lock()
	if w.closed || w.resourcesClosed || w.sourceOwner != nil {
		w.mu.Unlock()
		handle.CloseConsumerV1()
		return nil, ErrHTMLSendWorkV1
	}
	w.sourceOwner = owner
	w.mu.Unlock()
	if err = owner.beginV1(); err != nil {
		handle.CloseConsumerV1()
		return nil, err
	}
	initial, err := owner.initialComponentsV1()
	if err == nil {
		err = owner.holdV1(htmlRevisionSourceInitialV1, 0, initial)
	}
	owner.finishV1()
	if err != nil {
		handle.CloseConsumerV1()
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	state := &applicationHTMLSendSourceStateV1{owner: owner, work: w}
	w.mu.Lock()
	if w.closed || w.sourceOwner != owner {
		w.mu.Unlock()
		state.closeV1()
		return nil, ErrHTMLSendWorkV1
	}
	w.sourceState = state
	w.mu.Unlock()
	return &ApplicationHTMLSendSourceV1{state: state}, nil
}

// ValidateReviewedV1 preserves the original htmlsource.Validate(doc,true)
// decision at its fixed Send policy point. It reuses only THIS actual immutable
// original tuple; distinct resolver-produced variables require their separately
// owned candidate scope and never replace the original locked-snapshot proof.
func (h *ApplicationHTMLSendSourceV1) ValidateReviewedV1() error {
	if h == nil || h.state == nil || h.state.owner == nil {
		return ErrHTMLSendWorkV1
	}
	state := h.state
	if !state.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer state.unlockV1()
	if state.closeRequested.Load() {
		return ErrHTMLSendWorkV1
	}
	owner := state.owner
	if owner.purpose != htmlSendSourcePurposeV1 {
		return ErrHTMLSendWorkV1
	}
	if err := owner.beginV1(); err != nil {
		return err
	}
	defer owner.finishV1()
	if state.attempted {
		return state.failure
	}
	state.attempted = true
	state.failure = ErrHTMLSendWorkV1
	validation, err := state.prepareValidationV1()
	if err != nil {
		state.failure = err
		return err
	}
	state.failure = validation.ValidateV1(true)
	if state.failure == nil {
		w := state.work
		if w == nil {
			state.failure = ErrHTMLSendWorkV1
		} else {
			w.mu.Lock()
			if w.closed {
				state.failure = ErrHTMLSendWorkV1
			} else if state.candidate && w.resolvedOwner == owner {
				w.reviewedCandidateValidated = true
			} else if !state.candidate && w.sourceOwner == owner {
				w.reviewedOriginalValidated = true
			} else {
				state.failure = ErrHTMLSendWorkV1
			}
			w.mu.Unlock()
		}
	}
	return state.failure
}

// ValidateCurrentV1 checks the genuine separately retained Current12 row. It
// neither accepts a caller row nor substitutes a resolved candidate for the
// original native document snapshot. Repeated use stays in this exact scope.
func (h *ApplicationHTMLSendSourceV1) ValidateCurrentV1() error {
	if h == nil || h.state == nil || h.state.owner == nil {
		return ErrHTMLSendWorkV1
	}
	state := h.state
	if !state.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer state.unlockV1()
	if state.closeRequested.Load() {
		return ErrHTMLSendWorkV1
	}
	owner := state.owner
	if owner.purpose != htmlSendSourcePurposeV1 {
		return ErrHTMLSendWorkV1
	}
	if err := owner.beginV1(); err != nil {
		return err
	}
	defer owner.finishV1()
	if !state.attempted || state.failure != nil {
		return ErrHTMLSendWorkV1
	}
	if state.currentAttempted {
		return state.currentFailure
	}
	state.currentAttempted = true
	state.currentFailure = ErrHTMLSendWorkV1
	current, err := state.work.readCurrentForSourceV1(owner)
	if err != nil {
		state.currentFailure = err
		return err
	}
	owner.mu.Lock()
	if owner.snapshot == nil {
		owner.mu.Unlock()
		return state.currentFailure
	}
	owner.snapshot.current = current
	owner.mu.Unlock()
	// The common Current adapter is intentionally HTML-only: it requires a
	// commitment even for Origin-only HTML. Original Send accepts genuine plain
	// PDF/block tuples without ANY HTML origin/current. Reviewed validation has
	// already checked this private tuple; the actual lazy read observed no row.
	if len(owner.snapshot.document.HtmlSourceJson) == 0 {
		d := owner.snapshot.document
		if current != nil || d.HtmlCurrentMaterializationID.Valid || len(d.HtmlCurrentSourceJson) != 0 || d.HtmlCurrentPageCount.Valid || d.HtmlCurrentMaterializationSequence.Valid || d.HtmlReviewedMaterializationID.Valid {
			state.currentFailure = htmlsource.ErrInvalid
			return state.currentFailure
		}
		owner.mu.Lock()
		if owner.processing || owner.currentAttempted || owner.validation == nil || !owner.validation.MatchesDocumentV1(d) {
			owner.mu.Unlock()
			return state.currentFailure
		}
		owner.currentAttempted = true
		owner.currentValidated = true
		owner.mu.Unlock()
		state.currentFailure = nil
		return nil
	}
	state.currentFailure = (&ApplicationHTMLRevisionSourceV1{state: owner}).ValidateCurrentV1()
	return state.currentFailure
}

// A registered policy frame exists BEFORE waiting on the serialization mutex.
// Close marks admission permanently closed; the last actual frame retires cached
// references and the original owner synchronously. TryLock failure is never a
// claim that a future holder exists. No background closer or provider wait.
func (s *applicationHTMLSendSourceStateV1) lockV1() bool {
	if s == nil {
		return false
	}
	for {
		before := s.policyActivity.Load()
		if before&1 != 0 || before > ^uint64(0)-2 {
			return false
		}
		if s.policyActivity.CompareAndSwap(before, before+2) {
			break
		}
	}
	s.policyMutex.Lock()
	return true
}

func (s *applicationHTMLSendSourceStateV1) closeV1() {
	if s == nil {
		return
	}
	s.closeRequested.Store(true)
	if s.owner != nil && s.owner.cancel != nil {
		s.owner.cancel()
	}
	before := s.policyActivity.Or(1)
	if before&^uint64(1) == 0 {
		s.retirePolicyOwnerV1()
	}
}

func (s *applicationHTMLSendSourceStateV1) unlockV1() {
	s.policyMutex.Unlock()
	if s.policyActivity.Add(^uint64(1)) == 1 {
		s.retirePolicyOwnerV1()
	}
}

// Only closed+zero registration may claim this cleanup. New frames are already
// refused and every previous mutex/CPU frame has returned, so clearing these
// references needs no producer mutex and cannot race a permitted cache reader.
func (s *applicationHTMLSendSourceStateV1) retirePolicyOwnerV1() {
	if s.policyActivity.Load() != 1 || !s.retirementClaim.CompareAndSwap(false, true) {
		return
	}
	s.retired = true
	s.failure = nil
	s.validationFailure = nil
	s.currentFailure = nil
	s.partiesFailure = nil
	s.rolesFailure = nil
	s.blockTree = nil
	s.blockValues = nil
	s.blockRoles = nil
	s.blockFailure = nil
	s.blockRolesFailure = nil
	s.blockAdmissionFailure = nil
	s.blockTreeFailure = nil
	s.blockEvidenceFailure = nil
	if s.owner != nil {
		(&ApplicationHTMLRevisionSourceV1{state: s.owner}).CloseConsumerV1()
	}
}

// This comparison only rejects a modified caller view after actual validation;
// it creates no work or snapshot authority and cannot adopt a different tuple.
func (h *ApplicationHTMLSendSourceV1) MatchesDocumentV1(doc *generated.Document) bool {
	if h == nil || h.state == nil || doc == nil {
		return false
	}
	s := h.state
	if !s.lockV1() {
		return false
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || !s.attempted || s.failure != nil || s.owner == nil {
		return false
	}
	owner := s.owner
	if err := owner.beginV1(); err != nil {
		return false
	}
	defer owner.finishV1()
	owner.mu.Lock()
	validation := owner.validation
	owner.mu.Unlock()
	return validation != nil && validation.MatchesDocumentV1(doc)
}

// prepareValidationV1 is private to the fixed Send policy paths. The state
// mutex and original active source borrower are held by the actual caller. The
// CRM continuation may reach current validation before the later explicit
// require-review gate; each still evaluates its original separate decision.
func (s *applicationHTMLSendSourceStateV1) prepareValidationV1() (*htmlsource.RevisionValidationV1, error) {
	if s == nil || s.owner == nil || s.closeRequested.Load() {
		return nil, ErrHTMLSendWorkV1
	}
	owner := s.owner
	if !s.validationAttempted {
		s.validationAttempted = true
		s.validationFailure = ErrHTMLSendWorkV1
		s.validationFailure = (&ApplicationHTMLRevisionSourceV1{state: owner}).ValidateV1()
	}
	if s.validationFailure != nil {
		return nil, s.validationFailure
	}
	owner.mu.Lock()
	v := owner.validation
	owner.mu.Unlock()
	if v == nil {
		return nil, ErrHTMLSendWorkV1
	}
	return v, nil
}
