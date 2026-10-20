// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

var ErrSignerViewRequestV1 = errors.New("pdfadmission: owned signer view unavailable")

// This fixed request owns only the actual view request metadata and a borrow of the
// genuine original signer reader. Its UUIDs are private identity pins, never
// caller-provided credential or document authority. Policy runs at its original
// locked-document points, before any view mutation.
type ApplicationSignerViewRequestV1 struct {
	state *applicationSignerViewRequestV1
}
type applicationSignerViewRequestV1 struct {
	mu                            sync.Mutex
	self                          *applicationSignerViewRequestV1
	reader                        *ApplicationSignerReaderV1
	factory                       *ApplicationSessionFactoryV1
	org, document, recipient      uuid.UUID
	hash                          [32]byte
	ctx                           context.Context
	cancel                        context.CancelFunc
	grant                         *workguard.GrantV1
	ip, userAgent                 string
	active                        int
	bound, consumerClosed, closed bool
}

func (f *ApplicationSessionFactoryV1) NewSignerViewRequestV1(ctx context.Context, r *ApplicationSignerReaderV1, ip, userAgent string, notice article13.Evidence) (*ApplicationSignerViewRequestV1, error) {
	if f == nil || f.state == nil || r == nil || r.self != r || !applicationContextV1(ctx) {
		return nil, ErrSignerViewRequestV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, ErrSignerViewRequestV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factory != f || r.consumerClosed || r.released || r.creating || !r.read || r.mode != SignerReadActiveV1 || r.finishScope == nil || r.session == nil || r.admission == nil || r.scope.org == uuid.Nil || r.scope.document == uuid.Nil || r.scope.recipient == uuid.Nil {
		return nil, ErrSignerViewRequestV1
	}
	p := f.state
	p.mu.Lock()
	_, registered := p.signerReaders[r]
	available := registered && !p.closing && p.work != nil && p.work.coordinator != nil
	var coordinator *workguard.CoordinatorV1
	if available {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if !available {
		return nil, ErrSignerViewRequestV1
	}
	parent, err := signerViewRequestParentBytesV1(ctx, ip, userAgent, notice)
	if err != nil {
		return nil, err
	}
	grant, err := coordinator.TryAcquireV1(ctx, r.scope.org, workguard.VectorV1{ParentBytes: parent})
	if err != nil {
		return nil, errors.Join(ErrSignerViewRequestV1, err)
	}
	child, cancel := context.WithCancel(ctx)
	s := &applicationSignerViewRequestV1{reader: r, factory: f, org: r.scope.org, document: r.scope.document, recipient: r.scope.recipient, hash: r.scope.hash, ctx: child, cancel: cancel, grant: grant, ip: strings.Clone(ip), userAgent: strings.Clone(userAgent)}
	s.self = s
	// This is the existing original-reader consumer conjunction: physical SQL
	// close cannot retire original body consumers while this request uses them.
	r.blockSigningBorrowers++
	return &ApplicationSignerViewRequestV1{state: s}, nil
}

func signerViewRequestParentBytesV1(ctx context.Context, ip, userAgent string, notice article13.Evidence) (int64, error) {
	if !applicationContextV1(ctx) {
		return 0, ErrSignerViewRequestV1
	}
	parent := int64(2*unsafe.Sizeof(applicationSignerViewRequestV1{}) + 4*unsafe.Sizeof(uintptr(0)))
	for _, text := range [...]string{ip, userAgent} {
		if !htmlInputAddV1(&parent, int64(len(text)), 4) {
			return 0, ErrSignerViewRequestV1
		}
	}
	// Locked notice validation and BindAuditPayload preserve the original
	// canonical Article13 encoder. Price its actual concrete strings and escaped
	// wire bound before either later canonicalization; no flat request-size or
	// caller-supplied scalar can stand in for the producer.
	shape := htmlAuditShapeV1{}
	if err := shape.value(ctx, notice.Snapshot, 0); err != nil {
		return 0, err
	}
	for _, text := range [...]string{notice.Schema, notice.Digest} {
		if err := shape.text(text, false); err != nil {
			return 0, err
		}
	}
	resources, err := htmlAuditResourcesV1(shape.raw, shape.wire, shape.nodes)
	if err != nil || !htmlInputAddV1(&parent, resources.WorkingBytes, 1) {
		return 0, ErrSignerViewRequestV1
	}
	return parent, nil
}

func (h *ApplicationSignerViewRequestV1) MetadataV1() (string, string, error) {
	if h == nil || h.state == nil {
		return "", "", ErrSignerViewRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.consumerClosed || s.closed || s.reader == nil || s.grant == nil || s.ctx == nil || s.ctx.Err() != nil {
		return "", "", ErrSignerViewRequestV1
	}
	return s.ip, s.userAgent, nil
}

func (h *ApplicationSignerViewRequestV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.self != s || s.consumerClosed {
		s.mu.Unlock()
		return
	}
	s.consumerClosed = true
	s.cancel()
	r, grant := s.retireLockedV1()
	s.mu.Unlock()
	retireSignerViewRequestV1(r, grant)
}

func (s *applicationSignerViewRequestV1) retireLockedV1() (*ApplicationSignerReaderV1, *workguard.GrantV1) {
	if !s.consumerClosed || s.closed || s.active != 0 {
		return nil, nil
	}
	s.closed = true
	r, grant := s.reader, s.grant
	s.reader, s.factory, s.grant = nil, nil, nil
	s.ip, s.userAgent = "", ""
	return r, grant
}

func retireSignerViewRequestV1(r *ApplicationSignerReaderV1, grant *workguard.GrantV1) {
	if grant != nil {
		grant.Close()
	}
	if r != nil {
		r.mu.Lock()
		r.blockSigningBorrowers--
		consumers := r.retireBlockSigningReadConsumersV1()
		r.mu.Unlock()
		for _, close := range consumers {
			close()
		}
	}
}
