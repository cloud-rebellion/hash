// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

var ErrSignerPackageReadV1 = errors.New("pdfadmission: owned signer package read unavailable")

const signerPackageReadInputProfileV1 HTMLAuthoringInputProfileV1 = 241
const HTMLSignerPackageReadV1 HTMLSendSQLPurposeV1 = htmlSendPackageRetentionPurposeV1 + 1

// A fixed, no-body producer derives all scope from the actual registered
// response reader. It accepts no document/recipient IDs, rows or size claims.
type ApplicationSignerPackageReadInputV1 struct {
	self        *ApplicationSignerPackageReadInputV1
	state       *applicationHTMLAuthoringInputStateV1
	factory     *ApplicationSessionFactoryV1
	ctx         context.Context
	cancel      context.CancelFunc
	scope       applicationSignerScopeSnapshotV1
	profile     applicationSignerPackageProfileV1
	completed   applicationCompletedPackagePinsV1
	bound       bool
	readStarted bool
}

func (f *ApplicationSessionFactoryV1) NewSignerPackageReadInputV1(ctx context.Context, r *ApplicationSignerReaderV1) (*ApplicationSignerPackageReadInputV1, error) {
	return f.newSignerPackageReadInputV1(ctx, r, signerPackageActiveProfileV1)
}
func (f *ApplicationSessionFactoryV1) NewCompletedSignerPackageReadInputV1(ctx context.Context, r *ApplicationSignerReaderV1) (*ApplicationSignerPackageReadInputV1, error) {
	return f.newSignerPackageReadInputV1(ctx, r, signerPackageCompletedProfileV1)
}
func (f *ApplicationSessionFactoryV1) newSignerPackageReadInputV1(ctx context.Context, r *ApplicationSignerReaderV1, profile applicationSignerPackageProfileV1) (*ApplicationSignerPackageReadInputV1, error) {
	if f == nil || f.state == nil || r == nil || r.self != r || !applicationContextV1(ctx) {
		return nil, ErrSignerPackageReadV1
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrSignerPackageReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factory != f || r.consumerClosed || r.released || r.creating || !r.read || r.mode != profile.readerModeV1() || profile.readerModeV1() == "" || r.finishScope == nil || r.session == nil || r.admission == nil || r.scope.org == uuid.Nil || r.scope.document == uuid.Nil || r.scope.recipient == uuid.Nil {
		return nil, ErrSignerPackageReadV1
	}
	var completed applicationCompletedPackagePinsV1
	if profile == signerPackageCompletedProfileV1 {
		if r.models == nil || r.models.Document == nil || r.models.Recipient == nil || !applicationStampV1(r.models.Recipient.MagicTokenExpiresAt) || !time.Now().Before(r.models.Recipient.MagicTokenExpiresAt.Time) {
			return nil, ErrSignerPackageReadV1
		}
		var err error
		completed, err = completedPackagePinsV1(r.models.Document)
		if err != nil {
			return nil, err
		}
	}
	p := f.state
	p.mu.Lock()
	_, registered := p.signerReaders[r]
	if !registered || p.closing || p.work == nil || p.work.coordinator == nil || p.htmlInputProducers == nil || len(p.htmlInputProducers) >= applicationSessionMaxWorkV1 {
		p.mu.Unlock()
		return nil, ErrSignerPackageReadV1
	}
	cost := int64(2*unsafe.Sizeof(ApplicationSignerPackageReadInputV1{}) + 2*unsafe.Sizeof(applicationHTMLAuthoringInputStateV1{}) + 2*unsafe.Sizeof(ApplicationHTMLSendOperationV1{}) + 16*unsafe.Sizeof(sync.Once{}) + 8192)
	if profile == signerPackageCompletedProfileV1 {
		cost += 32 * documentpackage.MaxObjectTextBytesV1
	}
	s := &applicationHTMLAuthoringInputStateV1{factory: p, org: r.scope.org, profile: signerPackageReadInputProfileV1, active: 1}
	p.htmlInputProducers[s] = struct{}{}
	release, err := p.work.acquire(ctx, r.scope.org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		delete(p.htmlInputProducers, s)
		p.mu.Unlock()
		return nil, errors.Join(ErrSignerPackageReadV1, err)
	}
	s.releases = []func(){release}
	p.mu.Unlock()
	defer s.finishV1()
	call, cancel := context.WithCancel(ctx)
	if profile == signerPackageCompletedProfileV1 {
		cancel()
		call, cancel = context.WithDeadline(ctx, r.models.Recipient.MagicTokenExpiresAt.Time)
	}
	h := &ApplicationSignerPackageReadInputV1{state: s, factory: f, ctx: call, cancel: cancel, scope: r.scope, profile: profile, completed: completed.cloneV1()}
	h.self = h
	return h, nil
}

func (h *ApplicationSignerPackageReadInputV1) ContextV1() context.Context {
	if h == nil || h.self != h {
		return nil
	}
	return h.ctx
}

// The bound input remains active through actual response consumption. Closing
// SQL or cancelling the HTTP request cannot release its retained output loan.
func (f *ApplicationSessionFactoryV1) NewSignerPackageReadOperationV1(h *ApplicationSignerPackageReadInputV1) (*ApplicationHTMLSendOperationV1, func(), error) {
	if f == nil || f.state == nil || h == nil || h.self != h || h.factory != f || h.state == nil || !applicationContextV1(h.ctx) {
		return nil, nil, ErrSignerPackageReadV1
	}
	p, s := f.state, h.state
	p.mu.Lock()
	s.mu.Lock()
	_, registered := p.htmlInputProducers[s]
	valid := registered && !p.closing && !s.consumerClosed && !s.retired && !h.bound && s.limit == 0 && s.profile == signerPackageReadInputProfileV1
	if valid {
		h.bound = true
		s.active++
	}
	s.mu.Unlock()
	p.mu.Unlock()
	if !valid {
		return nil, nil, ErrSignerPackageReadV1
	}
	finish := commentInputReleaseV1(s)
	op, err := f.NewHTMLSendOperationV1(h.ctx, h.scope.org, h.scope.document)
	if err != nil {
		finish()
		return nil, nil, err
	}
	op.packageReadScope = &h.scope
	op.packageReadInput = h
	return op, finish, nil
}

func (h *ApplicationSignerPackageReadInputV1) CloseConsumerV1() {
	if h != nil && h.self == h {
		h.cancel()
		(&ApplicationHTMLAuthoringInputV1{state: h.state}).CloseConsumerV1()
	}
}
