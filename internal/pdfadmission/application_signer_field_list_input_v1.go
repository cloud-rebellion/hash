// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

var ErrSignerFieldListV1 = errors.New("pdfadmission: owned signer field list unavailable")

const signerFieldListInputProfileV1 HTMLAuthoringInputProfileV1 = 247
const HTMLSignerFieldListReadV1 HTMLSendSQLPurposeV1 = HTMLStaffCommentReadV1 + 1

// A fixed, no-body producer derives all scope from the actual registered
// response reader. It accepts no document/recipient IDs, rows or size claims.
type ApplicationSignerFieldListInputV1 struct {
	self    *ApplicationSignerFieldListInputV1
	state   *applicationHTMLAuthoringInputStateV1
	factory *ApplicationSessionFactoryV1
	ctx     context.Context
	cancel  context.CancelFunc
	scope   applicationSignerScopeSnapshotV1
	bound   bool
}

func (f *ApplicationSessionFactoryV1) NewSignerFieldListInputV1(ctx context.Context, r *ApplicationSignerReaderV1) (*ApplicationSignerFieldListInputV1, error) {
	if f == nil || f.state == nil || r == nil || r.self != r || !applicationContextV1(ctx) {
		return nil, ErrSignerFieldListV1
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrSignerFieldListV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factory != f || r.consumerClosed || r.released || r.creating || !r.read || r.mode != SignerReadActiveResponseV1 || r.finishScope == nil || r.session == nil || r.admission == nil || r.scope.org == uuid.Nil || r.scope.document == uuid.Nil || r.scope.recipient == uuid.Nil {
		return nil, ErrSignerFieldListV1
	}
	p := f.state
	p.mu.Lock()
	_, registered := p.signerReaders[r]
	if !registered || p.closing || p.work == nil || p.work.coordinator == nil || p.htmlInputProducers == nil || len(p.htmlInputProducers) >= applicationSessionMaxWorkV1 {
		p.mu.Unlock()
		return nil, ErrSignerFieldListV1
	}
	cost := int64(2*unsafe.Sizeof(ApplicationSignerFieldListInputV1{}) + 2*unsafe.Sizeof(applicationHTMLAuthoringInputStateV1{}) + 2*unsafe.Sizeof(ApplicationHTMLSendOperationV1{}) + 16*unsafe.Sizeof(sync.Once{}) + 8192)
	s := &applicationHTMLAuthoringInputStateV1{factory: p, org: r.scope.org, profile: signerFieldListInputProfileV1, active: 1}
	p.htmlInputProducers[s] = struct{}{}
	release, err := p.work.acquire(ctx, r.scope.org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		delete(p.htmlInputProducers, s)
		p.mu.Unlock()
		return nil, errors.Join(ErrSignerFieldListV1, err)
	}
	s.releases = []func(){release}
	p.mu.Unlock()
	defer s.finishV1()
	call, cancel := context.WithCancel(ctx)
	h := &ApplicationSignerFieldListInputV1{state: s, factory: f, ctx: call, cancel: cancel, scope: r.scope}
	h.self = h
	return h, nil
}

func (h *ApplicationSignerFieldListInputV1) ContextV1() context.Context {
	if h == nil || h.self != h {
		return nil
	}
	return h.ctx
}

// The bound input remains active through actual response consumption. Closing
// SQL or cancelling the HTTP request cannot release its retained output loan.
func (f *ApplicationSessionFactoryV1) NewSignerFieldListOperationV1(h *ApplicationSignerFieldListInputV1) (*ApplicationHTMLSendOperationV1, func(), error) {
	if f == nil || f.state == nil || h == nil || h.self != h || h.factory != f || h.state == nil || !applicationContextV1(h.ctx) {
		return nil, nil, ErrSignerFieldListV1
	}
	p, s := f.state, h.state
	p.mu.Lock()
	s.mu.Lock()
	_, registered := p.htmlInputProducers[s]
	valid := registered && !p.closing && !s.consumerClosed && !s.retired && !h.bound && s.limit == 0 && s.profile == signerFieldListInputProfileV1
	if valid {
		h.bound = true
		s.active++
	}
	s.mu.Unlock()
	p.mu.Unlock()
	if !valid {
		return nil, nil, ErrSignerFieldListV1
	}
	finish := commentInputReleaseV1(s)
	op, err := f.NewHTMLSendOperationV1(h.ctx, h.scope.org, h.scope.document)
	if err != nil {
		finish()
		return nil, nil, err
	}
	op.fieldListScope = &h.scope
	return op, finish, nil
}

func (h *ApplicationSignerFieldListInputV1) CloseConsumerV1() {
	if h != nil && h.self == h {
		h.cancel()
		(&ApplicationHTMLAuthoringInputV1{state: h.state}).CloseConsumerV1()
	}
}
