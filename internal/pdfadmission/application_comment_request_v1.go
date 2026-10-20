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

var ErrCommentRequestV1 = errors.New("pdfadmission: owned comment request unavailable")

// Closed comment stages add no capacity to the original16-stage operation.
const HTMLSignerCommentMutationV1 HTMLSendSQLPurposeV1 = HTMLSignerFieldsMutationV1 + 1
const HTMLStaffCommentMutationV1 HTMLSendSQLPurposeV1 = HTMLSignerCommentMutationV1 + 1

type ApplicationCommentRequestV1 struct{ state *applicationCommentRequestV1 }
type applicationCommentRequestV1 struct {
	mu                                                        sync.Mutex
	self                                                      *applicationCommentRequestV1
	factory                                                   *ApplicationSessionFactoryV1
	reader                                                    *ApplicationSignerReaderV1
	org, document, recipient, user                            uuid.UUID
	hash                                                      [32]byte
	ctx                                                       context.Context
	cancel                                                    context.CancelFunc
	grant                                                     *workguard.GrantV1
	inputRelease                                              func()
	operation                                                 *ApplicationHTMLSendOperationV1
	body, ip, userAgent                                       string
	notice                                                    article13.Evidence
	active                                                    int
	signer, operationAttempted, bound, consumerClosed, closed bool
}

// The original bounded HTTP context was captured BEFORE decoding. No caller
// can replace/renew it here. The real registered Active reader, not UUIDs or a
// scope probe, supplies the public credential lineage. Policy remains separate.
func (f *ApplicationSessionFactoryV1) NewSignerCommentRequestV1(r *ApplicationSignerReaderV1, input *ApplicationCommentInputV1, ip, ua string, notice article13.Evidence) (*ApplicationCommentRequestV1, error) {
	if f == nil || f.state == nil || input == nil || !applicationContextV1(input.original) || r == nil || r.self != r {
		return nil, ErrCommentRequestV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factory != f || r.consumerClosed || r.released || r.creating || !r.read || r.mode != SignerReadActiveV1 || r.finishScope == nil || r.session == nil || r.admission == nil || r.scope.org == uuid.Nil || r.scope.document == uuid.Nil || r.scope.recipient == uuid.Nil {
		return nil, ErrCommentRequestV1
	}
	f.state.mu.Lock()
	_, registered := f.state.signerReaders[r]
	available := registered && !f.state.closing
	f.state.mu.Unlock()
	if !available {
		return nil, ErrCommentRequestV1
	}
	h, err := f.newCommentRequestV1(input, r.scope.org, r.scope.document, uuid.Nil, true, ip, ua, notice)
	if err != nil {
		return nil, err
	}
	h.state.reader, h.state.recipient, h.state.hash = r, r.scope.recipient, r.scope.hash
	r.blockSigningBorrowers++
	return h, nil
}

// These IDs select the scoped native lock. Only the locked member and the
// original transport's final authorization can permit the staff mutation.
func (f *ApplicationSessionFactoryV1) NewStaffCommentRequestV1(input *ApplicationCommentInputV1, org, document, user uuid.UUID) (*ApplicationCommentRequestV1, error) {
	if user == uuid.Nil {
		return nil, ErrCommentRequestV1
	}
	return f.newCommentRequestV1(input, org, document, user, false, "", "", article13.Evidence{})
}
func (f *ApplicationSessionFactoryV1) newCommentRequestV1(input *ApplicationCommentInputV1, org, document, user uuid.UUID, signer bool, ip, ua string, notice article13.Evidence) (*ApplicationCommentRequestV1, error) {
	if f == nil || f.state == nil || input == nil || !applicationContextV1(input.original) || org == uuid.Nil || document == uuid.Nil {
		return nil, ErrCommentRequestV1
	}
	original := input.original
	parent := int64(2*unsafe.Sizeof(applicationCommentRequestV1{}) + 2*unsafe.Sizeof(ApplicationCommentRequestV1{}) + 8*unsafe.Sizeof(sync.Once{}))
	if signer {
		n, err := signerViewRequestParentBytesV1(original, ip, ua, notice)
		if err != nil || !htmlInputAddV1(&parent, n, 1) {
			return nil, ErrCommentRequestV1
		}
	}
	p := f.state
	p.mu.Lock()
	if p.closing || p.work == nil || p.work.coordinator == nil {
		p.mu.Unlock()
		return nil, ErrCommentRequestV1
	}
	grant, err := p.work.coordinator.TryAcquireV1(original, org, workguard.VectorV1{ParentBytes: parent})
	p.mu.Unlock()
	if err != nil {
		return nil, errors.Join(ErrCommentRequestV1, err)
	}
	profile := commentStaffInputProfileV1
	if signer {
		profile = commentSignerInputProfileV1
	}
	body, release, err := f.bindCommentBodyV1(original, org, input, profile)
	if err != nil {
		grant.Close()
		return nil, errors.Join(ErrCommentRequestV1, err)
	}
	// Staff's existing10s bound begins after decoding, once, and every native
	// stage derives from this captured child. Public retains the router deadline.
	var ctx context.Context
	var cancel context.CancelFunc
	if signer {
		ctx, cancel = context.WithCancel(original)
	} else {
		ctx, cancel = context.WithTimeout(original, 10*time.Second)
	}
	s := &applicationCommentRequestV1{factory: f, org: org, document: document, user: user, ctx: ctx, cancel: cancel, grant: grant, inputRelease: release, signer: signer, body: body, ip: strings.Clone(ip), userAgent: strings.Clone(ua), notice: notice}
	s.self = s
	return &ApplicationCommentRequestV1{state: s}, nil
}
func (h *ApplicationCommentRequestV1) MetadataV1() (string, string, string, article13.Evidence, error) {
	if h == nil || h.state == nil {
		return "", "", "", article13.Evidence{}, ErrCommentRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.consumerClosed || s.closed || s.ctx == nil || s.ctx.Err() != nil || s.inputRelease == nil {
		return "", "", "", article13.Evidence{}, ErrCommentRequestV1
	}
	return s.body, s.ip, s.userAgent, s.notice, nil
}
func (h *ApplicationCommentRequestV1) NewOperationV1() (*ApplicationHTMLSendOperationV1, error) {
	if h == nil || h.state == nil {
		return nil, ErrCommentRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.consumerClosed || s.closed || s.operationAttempted || s.ctx == nil || s.ctx.Err() != nil || s.factory == nil || s.inputRelease == nil {
		return nil, ErrCommentRequestV1
	}
	s.operationAttempted = true
	o, err := s.factory.NewHTMLSendOperationV1(s.ctx, s.org, s.document)
	if err != nil {
		return nil, err
	}
	s.operation = o
	return o, nil
}
func (h *ApplicationCommentRequestV1) CloseConsumerV1() {
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
	release := s.retireLockedV1()
	s.mu.Unlock()
	if release != nil {
		release()
	}
}
func (s *applicationCommentRequestV1) retireLockedV1() func() {
	if !s.consumerClosed || s.closed || s.active != 0 {
		return nil
	}
	s.closed = true
	reader, grant, input := s.reader, s.grant, s.inputRelease
	s.reader, s.grant, s.inputRelease, s.factory, s.operation = nil, nil, nil, nil, nil
	s.body, s.ip, s.userAgent = "", "", ""
	s.notice = article13.Evidence{}
	return func() {
		if input != nil {
			input()
		}
		retireSignerViewRequestV1(reader, grant)
	}
}
