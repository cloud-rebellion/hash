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

var ErrSignerFieldsRequestV1 = errors.New("pdfadmission: owned signer fields unavailable")

// This fixed request owns only the actual fields request metadata and a borrow of the
// genuine original signer reader. Its UUIDs are private identity pins, never
// caller-provided credential or document authority. Policy runs at its original
// locked-document points, before any fields mutation.
type ApplicationSignerFieldsRequestV1 struct {
	state *applicationSignerFieldsRequestV1
}
type applicationSignerFieldsRequestV1 struct {
	mu                            sync.Mutex
	self                          *applicationSignerFieldsRequestV1
	reader                        *ApplicationSignerReaderV1
	factory                       *ApplicationSessionFactoryV1
	org, document, recipient      uuid.UUID
	hash                          [32]byte
	ctx                           context.Context
	cancel                        context.CancelFunc
	grant                         *workguard.GrantV1
	capturedGrant                 *workguard.GrantV1
	noticeParent                  int64
	ip, userAgent                 string
	inputs                        []SignerFieldValueInputV1
	captured                      bool
	valuesRead                    bool
	active                        int
	bound, consumerClosed, closed bool
}

func (f *ApplicationSessionFactoryV1) NewSignerFieldsRequestV1(ctx context.Context, r *ApplicationSignerReaderV1, ip, userAgent string, notice article13.Evidence) (*ApplicationSignerFieldsRequestV1, error) {
	if f == nil || f.state == nil || r == nil || r.self != r || !applicationContextV1(ctx) {
		return nil, ErrSignerFieldsRequestV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, ErrSignerFieldsRequestV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factory != f || r.consumerClosed || r.released || r.creating || !r.read || r.mode != SignerReadActiveV1 || r.finishScope == nil || r.session == nil || r.admission == nil || r.scope.org == uuid.Nil || r.scope.document == uuid.Nil || r.scope.recipient == uuid.Nil {
		return nil, ErrSignerFieldsRequestV1
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
		return nil, ErrSignerFieldsRequestV1
	}
	parent, err := signerFieldsRequestParentBytesV1(ctx, ip, userAgent, notice)
	if err != nil {
		return nil, err
	}
	noticeParent, err := signerFieldsNoticeParentV1(ctx, notice)
	if err != nil {
		return nil, err
	}
	grant, err := coordinator.TryAcquireV1(ctx, r.scope.org, workguard.VectorV1{ParentBytes: parent})
	if err != nil {
		return nil, errors.Join(ErrSignerFieldsRequestV1, err)
	}
	child, cancel := context.WithCancel(ctx)
	s := &applicationSignerFieldsRequestV1{reader: r, factory: f, org: r.scope.org, document: r.scope.document, recipient: r.scope.recipient, hash: r.scope.hash, noticeParent: noticeParent, ctx: child, cancel: cancel, grant: grant, ip: strings.Clone(ip), userAgent: strings.Clone(userAgent)}
	s.self = s
	// This is the existing original-reader consumer conjunction: physical SQL
	// close cannot retire original body consumers while this request uses them.
	r.blockSigningBorrowers++
	return &ApplicationSignerFieldsRequestV1{state: s}, nil
}

func signerFieldsRequestParentBytesV1(ctx context.Context, ip, userAgent string, notice article13.Evidence) (int64, error) {
	if !applicationContextV1(ctx) {
		return 0, ErrSignerFieldsRequestV1
	}
	parent := int64(2*unsafe.Sizeof(applicationSignerFieldsRequestV1{}) + 4*unsafe.Sizeof(uintptr(0)))
	// The handler enforces this original body limit before encoding/json decode.
	// Price scanner/buffer/string copies and worst-case empty-object slice growth
	// before decode; UTF-8 replacement can triple raw string backing. Actual
	// captured values must fit these same structural bounds below.
	count := int64((SignerFieldsBodyLimitV1+2)/3 + 1)
	if !htmlInputAddV1(&parent, SignerFieldsBodyLimitV1, 8) || !htmlInputAddV1(&parent, count, 4*(int64(unsafe.Sizeof(SignerFieldValueInputV1{}))+16)) {
		return 0, ErrSignerFieldsRequestV1
	}
	for _, text := range [...]string{ip, userAgent} {
		if !htmlInputAddV1(&parent, int64(len(text)), 4) {
			return 0, ErrSignerFieldsRequestV1
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
		return 0, ErrSignerFieldsRequestV1
	}
	return parent, nil
}

func (h *ApplicationSignerFieldsRequestV1) MetadataV1() (string, string, error) {
	if h == nil || h.state == nil {
		return "", "", ErrSignerFieldsRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.consumerClosed || s.closed || s.reader == nil || s.grant == nil || s.ctx == nil || s.ctx.Err() != nil {
		return "", "", ErrSignerFieldsRequestV1
	}
	return s.ip, s.userAgent, nil
}

func (h *ApplicationSignerFieldsRequestV1) CloseConsumerV1() {
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
	r, grant, captured := s.retireLockedV1()
	s.mu.Unlock()
	retireSignerFieldsRequestV1(r, grant, captured)
}

func (s *applicationSignerFieldsRequestV1) retireLockedV1() (*ApplicationSignerReaderV1, *workguard.GrantV1, *workguard.GrantV1) {
	if !s.consumerClosed || s.closed || s.active != 0 {
		return nil, nil, nil
	}
	s.closed = true
	r, grant, captured := s.reader, s.grant, s.capturedGrant
	s.reader, s.factory, s.grant, s.capturedGrant = nil, nil, nil, nil
	s.ip, s.userAgent = "", ""
	s.inputs = nil
	return r, grant, captured
}

func retireSignerFieldsRequestV1(r *ApplicationSignerReaderV1, grant, captured *workguard.GrantV1) {
	if captured != nil {
		captured.Close()
	}
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

// CaptureValuesV1 detaches the actual decoded values under the original
// predecode capture owner. These are data, never recipient/document authority.
func (h *ApplicationSignerFieldsRequestV1) CaptureValuesV1(ctx context.Context, in []SignerFieldValueInputV1) error {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return ErrSignerFieldsRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.consumerClosed || s.closed || s.bound || s.captured || s.grant == nil || s.ctx.Err() != nil || len(in) == 0 || len(in) > (SignerFieldsBodyLimitV1+2)/3+1 {
		return ErrSignerFieldsRequestV1
	}
	raw := int64(0)
	for _, v := range in {
		if !htmlInputAddV1(&raw, int64(len(v.FieldID)), 1) || !htmlInputAddV1(&raw, int64(len(v.Value)), 1) {
			return ErrSignerFieldsRequestV1
		}
	}
	if raw > 3*SignerFieldsBodyLimitV1 {
		return ErrSignerFieldsRequestV1
	}
	parent, err := signerFieldsCapturedParentV1(ctx, in, s.noticeParent)
	if err != nil {
		return err
	}
	p := s.factory.state
	p.mu.Lock()
	available := !p.closing && p.work != nil && p.work.coordinator != nil
	var coordinator *workguard.CoordinatorV1
	if available {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if !available {
		return ErrSignerFieldsRequestV1
	}
	grant, err := coordinator.TryAcquireV1(ctx, s.org, workguard.VectorV1{ParentBytes: parent})
	if err != nil {
		return errors.Join(ErrSignerFieldsRequestV1, err)
	}
	s.capturedGrant = grant
	s.inputs = make([]SignerFieldValueInputV1, len(in))
	for i, v := range in {
		s.inputs[i] = SignerFieldValueInputV1{FieldID: strings.Clone(v.FieldID), Value: strings.Clone(v.Value)}
	}
	s.captured = true
	return nil
}
func (h *ApplicationSignerFieldsRequestV1) ValuesV1() ([]SignerFieldValueInputV1, error) {
	if h == nil || h.state == nil {
		return nil, ErrSignerFieldsRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.consumerClosed || s.closed || s.ctx.Err() != nil || !s.captured || s.grant == nil || s.valuesRead {
		return nil, ErrSignerFieldsRequestV1
	}
	s.valuesRead = true
	return append([]SignerFieldValueInputV1(nil), s.inputs...), nil
}

func signerFieldsNoticeParentV1(ctx context.Context, notice article13.Evidence) (int64, error) {
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
	if err != nil {
		return 0, err
	}
	return resources.WorkingBytes, nil
}
func signerFieldsCapturedParentV1(ctx context.Context, in []SignerFieldValueInputV1, noticeParent int64) (int64, error) {
	if !applicationContextV1(ctx) || noticeParent < 0 {
		return 0, ErrSignerFieldsRequestV1
	}
	parent := int64(0)
	binder, err := htmlStoredRetentionMapV1(8)
	if err != nil {
		return 0, err
	}
	if !htmlInputAddV1(&parent, int64(len(in)), noticeParent) || !htmlInputAddV1(&parent, int64(len(in)), 2*binder+4*int64(unsafe.Sizeof(SignerFieldValueInputV1{}))) {
		return 0, ErrSignerFieldsRequestV1
	}
	for _, v := range in {
		if !htmlInputAddV1(&parent, int64(len(v.FieldID)), 8) || !htmlInputAddV1(&parent, int64(len(v.Value)), 8) {
			return 0, ErrSignerFieldsRequestV1
		}
	}
	return parent, nil
}
func (h *ApplicationSignerFieldsRequestV1) ValueCountV1() (int, error) {
	if h == nil || h.state == nil {
		return 0, ErrSignerFieldsRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.consumerClosed || s.closed || !s.captured || s.grant == nil || s.capturedGrant == nil || s.ctx.Err() != nil {
		return 0, ErrSignerFieldsRequestV1
	}
	return len(s.inputs), nil
}
