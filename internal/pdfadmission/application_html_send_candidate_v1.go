// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
)

// NewResolvedSourceV1 accepts only THIS genuine completed resolver producer.
// The frozen bytes never arrive as a caller RawMessage/Document/size hint.
// Original document/source/PDF/review pins remain unchanged in the old owner;
// the resolved variable tuple has its own immutable validation scope.
func (h *ApplicationHTMLSendResolutionV1) NewResolvedSourceV1() (*ApplicationHTMLSendSourceV1, error) {
	if h == nil || h.state == nil {
		return nil, ErrHTMLSendWorkV1
	}
	p := h.state
	p.mu.Lock()
	w := p.work
	p.mu.Unlock()
	return w.NewResolvedSourceV1(h)
}

// A later fixed final stage may derive its own distinct candidate from the
// SAME operation's still-retained opaque resolution; it never adopts a public
// frozen byte view or reuses the preparation stage's source authority.
func (w *ApplicationHTMLSendWorkV1) NewResolvedSourceV1(h *ApplicationHTMLSendResolutionV1) (*ApplicationHTMLSendSourceV1, error) {
	if w == nil || w.self != w || h == nil || h.state == nil {
		return nil, ErrHTMLSendWorkV1
	}
	p := h.state
	p.mu.Lock()
	if !p.liveV1() || !p.attempted || p.failure != nil || p.active != 0 || p.frozen == nil || p.work.stage == nil || w.stage == nil || p.work.stage.operation != w.stage.operation || p.document == nil || p.document.ID != w.logicalDocumentV1() {
		p.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	p.active++
	frozen := p.frozen
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.active--; p.retireV1(); p.mu.Unlock() }()
	w.mu.Lock()
	original := w.sourceOwner
	w.mu.Unlock()
	if original == nil {
		return nil, ErrHTMLSendWorkV1
	}
	if err := original.beginV1(); err != nil {
		return nil, err
	}
	defer original.finishV1()
	document, current, release, err := w.borrowHTMLSendSourceV1()
	if err != nil {
		return nil, err
	}
	temporary := *document
	temporary.VariablesJson = frozen
	// The price walk sees the actual retained original39 fields plus the actual
	// opaque producer's frozen bytes. No deep clone or staged builder runs yet.
	binding := original.binding
	child, cancel := context.WithCancel(binding.ctx)
	fixedBinding := &applicationHTMLRevisionSourceBindingV1{factory: binding.factory, session: binding.session, admission: binding.admission, registration: binding.registration, org: binding.org, document: binding.document, ctx: child, deadline: binding.deadline}
	candidate := &applicationHTMLRevisionSourceOwnerV1{purpose: htmlSendSourcePurposeV1, binding: fixedBinding, snapshot: &applicationHTMLRevisionSourceSnapshotV1{document: &temporary, current: current}, releaseBorrower: release, cancel: cancel}
	candidate.self = candidate
	handle := &ApplicationHTMLRevisionSourceV1{state: candidate}
	w.mu.Lock()
	if w.closed || w.resourcesClosed || w.resolvedStarted || w.sourceOwner != original || (w.resolverOwner != p && w.stage.operation != p.work.stage.operation) {
		w.mu.Unlock()
		handle.CloseConsumerV1()
		return nil, ErrHTMLSendWorkV1
	}
	w.resolvedStarted = true
	w.resolvedOwner = candidate
	w.mu.Unlock()
	// Registration on the genuine Work precedes every candidate grant. Parent
	// credit and retained SQL-body borrower survive physical SQL retirement.
	if err = candidate.beginV1(); err != nil {
		handle.CloseConsumerV1()
		return nil, err
	}
	initial, e := candidate.initialDocumentComponentsV1(&temporary)
	if e == nil {
		e = candidate.holdV1(htmlRevisionSourceInitialV1, 0, initial)
	}
	if e == nil {
		// Clone after exact grant. No mutable output view is adopted or normalized.
		owned := htmlSendCloneDocumentV1(&temporary)
		candidate.mu.Lock()
		candidate.snapshot.document = owned
		candidate.mu.Unlock()
	}
	candidate.finishV1()
	if e != nil {
		handle.CloseConsumerV1()
		return nil, errors.Join(ErrHTMLSendWorkV1, e)
	}
	state := &applicationHTMLSendSourceStateV1{owner: candidate, work: w, candidate: true}
	w.mu.Lock()
	if w.closed || w.resolvedOwner != candidate {
		w.mu.Unlock()
		state.closeV1()
		return nil, ErrHTMLSendWorkV1
	}
	w.resolvedState = state
	w.mu.Unlock()
	return &ApplicationHTMLSendSourceV1{state: state}, nil
}
