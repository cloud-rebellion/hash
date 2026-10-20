// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

var ErrCommentInputV1 = errors.New("pdfadmission: owned comment input unavailable")

const commentHTTPBytesV1 int64 = 1 << 20
const commentSignerInputProfileV1 HTMLAuthoringInputProfileV1 = 252
const commentStaffInputProfileV1 HTMLAuthoringInputProfileV1 = 253

// Only the original comment declaration is accepted. This input grants no
// document access, role, mutation, audit, or SQL permission. The real route
// still applies its original decoder and the native mutation its locked policy.
type CommentDeclarationV1 struct {
	Body string `json:"body"`
}
type ApplicationCommentInputV1 struct {
	state    *applicationHTMLAuthoringInputStateV1
	original context.Context
}

func commentInputReadCostV1(profile HTMLAuthoringInputProfileV1) (int64, error) {
	// Exact handles, concrete typed declarations, once/release controls, decoder
	// and reader controls. Logical expression credit is separate from RSS limits.
	fixed := int64(unsafe.Sizeof(applicationHTMLAuthoringInputStateV1{})) + int64(unsafe.Sizeof(ApplicationCommentInputV1{})) + 2*int64(unsafe.Sizeof(CommentDeclarationV1{})) + 4*int64(unsafe.Sizeof(sync.Once{})) + int64(unsafe.Sizeof(json.Decoder{})) + 4096
	switch profile {
	case commentSignerInputProfileV1:
		// Whole-read buffer capacity before any strict token/field validation.
		return fixed + 2*(commentHTTPBytesV1+1), nil
	case commentStaffInputProfileV1:
		// Preserve one streaming Decode. Two growing input/decoder buffers plus
		// four retained/temporary strings at <=3 UTF-8 bytes per source byte cover
		// replacement decoding, the typed value, private capture and one bind copy.
		// Two full scanner-stack capacities cover the unchanged JSON depth ceiling.
		return fixed + 16*(commentHTTPBytesV1+1) + 2*10000*int64(unsafe.Sizeof(int(0))), nil
	default:
		return 0, ErrCommentInputV1
	}
}
func (f *ApplicationSessionFactoryV1) NewSignerCommentHTTPInputV1(ctx context.Context, org uuid.UUID) (*ApplicationCommentInputV1, error) {
	return f.newCommentHTTPInputV1(ctx, org, commentSignerInputProfileV1)
}
func (f *ApplicationSessionFactoryV1) NewStaffCommentHTTPInputV1(ctx context.Context, org uuid.UUID) (*ApplicationCommentInputV1, error) {
	return f.newCommentHTTPInputV1(ctx, org, commentStaffInputProfileV1)
}
func (f *ApplicationSessionFactoryV1) newCommentHTTPInputV1(ctx context.Context, org uuid.UUID, profile HTMLAuthoringInputProfileV1) (*ApplicationCommentInputV1, error) {
	cost, err := commentInputReadCostV1(profile)
	if err != nil || f == nil || f.state == nil || org == uuid.Nil || !applicationContextV1(ctx) {
		return nil, ErrCommentInputV1
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlInputProducers == nil || len(p.htmlInputProducers) >= applicationSessionMaxWorkV1 {
		return nil, ErrCommentInputV1
	}
	s := &applicationHTMLAuthoringInputStateV1{factory: p, org: org, profile: profile, limit: commentHTTPBytesV1}
	p.htmlInputProducers[s] = struct{}{}
	release, err := p.work.acquire(ctx, org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		delete(p.htmlInputProducers, s)
		return nil, errors.Join(ErrCommentInputV1, err)
	}
	s.releases = []func(){release}
	return &ApplicationCommentInputV1{state: s, original: ctx}, nil
}
func (h *ApplicationCommentInputV1) beginV1(ctx context.Context, profile HTMLAuthoringInputProfileV1, read bool) error {
	if h == nil || h.state == nil || h.state.factory == nil || !applicationContextV1(ctx) || !applicationContextV1(h.original) || ctx.Done() != h.original.Done() {
		return ErrCommentInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	if _, ok := p.htmlInputProducers[s]; !ok || p.closing || s.profile != profile || s.limit != commentHTTPBytesV1 || s.consumerClosed || s.retired || (read && s.readStarted) {
		return ErrCommentInputV1
	}
	if read {
		s.readStarted = true
	}
	s.active++
	return nil
}
func commentInputReleaseV1(s *applicationHTMLAuthoringInputStateV1) func() {
	var once sync.Once
	return func() { once.Do(s.finishV1) }
}

// The borrower spans the caller's ORIGINAL strict public validation on these
// exact private bytes. Its release must follow decoder/capture last use.
// No caller Content-Length or replacement raw buffer becomes input authority.
func (h *ApplicationCommentInputV1) ReadSignerJSONV1(ctx context.Context, body io.ReadCloser) ([]byte, func(), error) {
	if body == nil {
		return nil, nil, ErrCommentInputV1
	}
	if err := h.beginV1(ctx, commentSignerInputProfileV1, true); err != nil {
		return nil, nil, err
	}
	s := h.state
	release := commentInputReleaseV1(s)
	keep := false
	defer func() {
		if !keep {
			release()
		}
	}()
	raw, err := io.ReadAll(http.MaxBytesReader(nil, body, commentHTTPBytesV1))
	if err != nil {
		return nil, nil, err
	}
	// The strict public validators may retain maps/tokens for every actual source
	// member. 128 bytes per ACTUAL private source byte plus their finite scanner
	// stacks dominate these expressions, body replacement/clone/bind copies.
	cost := 128*int64(len(raw)+1) + 2*10000*int64(unsafe.Sizeof(int(0))) + 4096
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	if p.closing || s.consumerClosed || s.retired || ctx.Err() != nil {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, nil, ErrCommentInputV1
	}
	closeParse, err := p.work.acquire(ctx, s.org, workguard.VectorV1{ParentBytes: cost})
	if err == nil {
		s.releases = append(s.releases, closeParse)
		s.raw = raw
	}
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return nil, nil, errors.Join(ErrCommentInputV1, err)
	}
	keep = true
	return bytes.Clone(raw), release, nil
}

// This compares the caller's strict-decoder result with a typed parse of the
// SAME retained private bytes. It snapshots the body once; later replacement
// strings/maps or another public handle cannot change the native declaration.
func (h *ApplicationCommentInputV1) CaptureSignerBodyV1(ctx context.Context, expected string) error {
	if err := h.beginV1(ctx, commentSignerInputProfileV1, false); err != nil {
		return err
	}
	s := h.state
	defer s.finishV1()
	s.mu.Lock()
	if !s.readStarted || s.raw == nil || s.ready || s.canonicalStarted {
		s.mu.Unlock()
		return ErrCommentInputV1
	}
	s.canonicalStarted = true
	raw := s.raw
	s.mu.Unlock()
	var value CommentDeclarationV1
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if value.Body != expected {
		return ErrCommentInputV1
	}
	owned := []byte(value.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumerClosed || s.retired || ctx.Err() != nil {
		return ErrCommentInputV1
	}
	s.raw = owned
	s.ready = true
	s.canonicalStarted = false
	return nil
}

// Staff preserves the original DisallowUnknownFields + SINGLE streaming
// Decode: accepted trailing bytes are not whole-read or newly required to EOF.
// The caller's returned declaration is a view; the native body is private.
func (h *ApplicationCommentInputV1) DecodeStaffJSONV1(ctx context.Context, body io.ReadCloser) (CommentDeclarationV1, func(), error) {
	var value CommentDeclarationV1
	if body == nil {
		return value, nil, ErrCommentInputV1
	}
	if err := h.beginV1(ctx, commentStaffInputProfileV1, true); err != nil {
		return value, nil, err
	}
	s := h.state
	release := commentInputReleaseV1(s)
	keep := false
	defer func() {
		if !keep {
			release()
		}
	}()
	dec := json.NewDecoder(http.MaxBytesReader(nil, body, commentHTTPBytesV1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&value); err != nil {
		return value, nil, err
	}
	owned := []byte(value.Body)
	s.mu.Lock()
	if s.consumerClosed || s.retired || ctx.Err() != nil {
		s.mu.Unlock()
		return value, nil, ErrCommentInputV1
	}
	s.raw = owned
	s.ready = true
	s.mu.Unlock()
	keep = true
	return value, release, nil
}

// Only a genuine same-factory/org native comment request may bind this once.
// Its original input borrower must remain through response/body last use.
// This method is private; it provides no generic SQL, callback or cost API.
func (f *ApplicationSessionFactoryV1) bindCommentBodyV1(ctx context.Context, org uuid.UUID, h *ApplicationCommentInputV1, profile HTMLAuthoringInputProfileV1) (string, func(), error) {
	if f == nil || f.state == nil || h == nil || h.state == nil || h.state.factory == nil || !applicationContextV1(ctx) {
		return "", nil, ErrCommentInputV1
	}
	s := h.state
	p := f.state
	p.mu.Lock()
	s.mu.Lock()
	_, registered := p.htmlInputProducers[s]
	if !registered || p.closing || s.factory != p || s.org != org || s.consumerClosed || s.retired || !s.ready || s.canonicalStarted || s.profile != profile {
		s.mu.Unlock()
		p.mu.Unlock()
		return "", nil, ErrCommentInputV1
	}
	s.canonicalStarted = true
	s.active++
	raw := s.raw
	s.mu.Unlock()
	p.mu.Unlock()
	// One immutable copy; the pre-admitted decoder/capture ledger includes it.
	value := string(raw)
	return value, commentInputReleaseV1(s), nil
}
func (h *ApplicationCommentInputV1) CloseConsumerV1() {
	if h != nil && h.state != nil {
		(&ApplicationHTMLAuthoringInputV1{state: h.state}).CloseConsumerV1()
	}
}
