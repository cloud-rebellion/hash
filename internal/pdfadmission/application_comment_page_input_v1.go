// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/commentwindow"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

var ErrCommentPageV1 = errors.New("pdfadmission: owned comment page unavailable")

const commentPageSignerInputProfileV1 HTMLAuthoringInputProfileV1 = 250
const commentPageStaffInputProfileV1 HTMLAuthoringInputProfileV1 = 251
const commentPageQueryBytesV1 = 172

const HTMLSignerCommentReadV1 HTMLSendSQLPurposeV1 = HTMLStaffCommentMutationV1 + 1
const HTMLStaffCommentReadV1 HTMLSendSQLPurposeV1 = HTMLSignerCommentReadV1 + 1

// A registered, fixed query producer captures the original HTTP deadline and
// parses only after its parent loan exists. No cursor can supply access scope.
type ApplicationCommentPageInputV1 struct {
	self      *ApplicationCommentPageInputV1
	state     *applicationHTMLAuthoringInputStateV1
	factory   *ApplicationSessionFactoryV1
	ctx       context.Context
	cancel    context.CancelFunc
	document  uuid.UUID
	selection commentwindow.Selection
	bound     bool
}

func (f *ApplicationSessionFactoryV1) NewSignerCommentPageInputV1(ctx context.Context, r *ApplicationSignerReaderV1, rawQuery string) (*ApplicationCommentPageInputV1, error) {
	if f == nil || f.state == nil || r == nil || r.self != r {
		return nil, ErrCommentPageV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factory != f || r.consumerClosed || r.released || r.creating || !r.read || (r.mode != SignerReadActiveV1 && r.mode != SignerReadActiveResponseV1) || r.finishScope == nil || r.session == nil || r.admission == nil || r.scope.recipient == uuid.Nil {
		return nil, ErrCommentPageV1
	}
	f.state.mu.Lock()
	_, registered := f.state.signerReaders[r]
	f.state.mu.Unlock()
	if !registered {
		return nil, ErrCommentPageV1
	}
	return f.newCommentPageInputV1(ctx, r.scope.org, r.scope.document, rawQuery, commentPageSignerInputProfileV1)
}

func (f *ApplicationSessionFactoryV1) NewStaffCommentPageInputV1(ctx context.Context, org, document uuid.UUID, rawQuery string) (*ApplicationCommentPageInputV1, error) {
	return f.newCommentPageInputV1(ctx, org, document, rawQuery, commentPageStaffInputProfileV1)
}

func (f *ApplicationSessionFactoryV1) newCommentPageInputV1(ctx context.Context, org, document uuid.UUID, rawQuery string, profile HTMLAuthoringInputProfileV1) (*ApplicationCommentPageInputV1, error) {
	if len(rawQuery) > commentPageQueryBytesV1 {
		return nil, commentwindow.ErrSelection
	}
	if f == nil || f.state == nil || org == uuid.Nil || document == uuid.Nil || !applicationContextV1(ctx) {
		return nil, ErrCommentPageV1
	}
	// Fixed query/map/base64 storage, typed request/result/operation controls and
	// context/once closures are funded before parsing or cloning any cursor.
	cost := int64(2*unsafe.Sizeof(ApplicationCommentPageInputV1{})+2*unsafe.Sizeof(applicationHTMLAuthoringInputStateV1{})+2*unsafe.Sizeof(ApplicationHTMLSendOperationV1{})+16*unsafe.Sizeof(sync.Once{})) + 16*commentPageQueryBytesV1 + 8192
	p := f.state
	p.mu.Lock()
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlInputProducers == nil || len(p.htmlInputProducers) >= applicationSessionMaxWorkV1 {
		p.mu.Unlock()
		return nil, ErrCommentPageV1
	}
	s := &applicationHTMLAuthoringInputStateV1{factory: p, org: org, profile: profile, limit: commentPageQueryBytesV1, active: 1}
	p.htmlInputProducers[s] = struct{}{}
	release, err := p.work.acquire(ctx, org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		delete(p.htmlInputProducers, s)
		p.mu.Unlock()
		return nil, errors.Join(ErrCommentPageV1, err)
	}
	s.releases = []func(){release}
	p.mu.Unlock()
	defer s.finishV1()
	var call context.Context
	var cancel context.CancelFunc
	if profile == commentPageStaffInputProfileV1 {
		call, cancel = context.WithTimeout(ctx, 10*time.Second)
	} else {
		call, cancel = context.WithCancel(ctx)
	}
	h := &ApplicationCommentPageInputV1{state: s, factory: f, ctx: call, cancel: cancel, document: document}
	h.self = h
	selection, err := commentwindow.Parse(rawQuery)
	if err == nil {
		_, _, _, err = selection.ForScope(org, document)
	}
	if err != nil {
		h.CloseConsumerV1()
		return nil, err
	}
	h.selection = selection
	return h, nil
}

func (h *ApplicationCommentPageInputV1) ContextV1() context.Context {
	if h == nil || h.self != h {
		return nil
	}
	return h.ctx
}

// One bind borrows the registered producer through response serialization.
// Native SQL stages cannot renew or replace this original request context.
func (f *ApplicationSessionFactoryV1) NewCommentPageOperationV1(h *ApplicationCommentPageInputV1) (*ApplicationHTMLSendOperationV1, commentwindow.Selection, func(), error) {
	if f == nil || f.state == nil || h == nil || h.self != h || h.factory != f || h.state == nil || !applicationContextV1(h.ctx) {
		return nil, commentwindow.Selection{}, nil, ErrCommentPageV1
	}
	p, s := f.state, h.state
	p.mu.Lock()
	s.mu.Lock()
	_, registered := p.htmlInputProducers[s]
	valid := registered && !p.closing && !s.consumerClosed && !s.retired && !h.bound && s.limit == commentPageQueryBytesV1 && (s.profile == commentPageSignerInputProfileV1 || s.profile == commentPageStaffInputProfileV1)
	if valid {
		h.bound = true
		s.active++
	}
	s.mu.Unlock()
	p.mu.Unlock()
	if !valid {
		return nil, commentwindow.Selection{}, nil, ErrCommentPageV1
	}
	finish := commentInputReleaseV1(s)
	op, err := f.NewHTMLSendOperationV1(h.ctx, s.org, h.document)
	if err != nil {
		finish()
		return nil, commentwindow.Selection{}, nil, err
	}
	return op, h.selection, finish, nil
}

func (h *ApplicationCommentPageInputV1) CloseConsumerV1() {
	if h != nil && h.self == h {
		h.cancel()
		(&ApplicationHTMLAuthoringInputV1{state: h.state}).CloseConsumerV1()
	}
}
