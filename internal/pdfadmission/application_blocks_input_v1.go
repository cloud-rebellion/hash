// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/blocks"
	"io"
	"math/big"
	"net/http"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

var ErrBlocksInputV1 = errors.New("pdfadmission: owned block authoring input unavailable")

const blocksAuthoringHTTPBytesV1 int64 = 1 << 20 // unchanged decodeSignerJSON limit
const blocksAuthoringHTTPProfileV1 HTMLAuthoringInputProfileV1 = 248
const blocksAuthoringMCPProfileV1 HTMLAuthoringInputProfileV1 = 249

type ApplicationBlocksInputV1 struct {
	state   *applicationHTMLAuthoringInputStateV1
	decimal *blocksInputDecimalStateV1
}
type blocksInputDecimalStateV1 struct {
	mu      sync.Mutex
	peak    int64
	failure error
}

// This concrete request owner only funds the existing authenticated document
// and block-command decoders. The original strict REST/MCP decoder determines
// accepted grammar, duplicate/null/case behavior and validation error order.
// Lexical counts price transient work, never final block topology or validity.
func (f *ApplicationSessionFactoryV1) NewBlocksHTTPInputV1(ctx context.Context, org uuid.UUID) (*ApplicationBlocksInputV1, error) {
	return f.newBlocksInputV1(ctx, org, blocksAuthoringHTTPProfileV1, nil)
}
func (f *ApplicationSessionFactoryV1) NewBlocksArgumentsV1(ctx context.Context, org uuid.UUID, args []byte) (*ApplicationBlocksInputV1, error) {
	return f.newBlocksInputV1(ctx, org, blocksAuthoringMCPProfileV1, args)
}
func (f *ApplicationSessionFactoryV1) newBlocksInputV1(ctx context.Context, org uuid.UUID, profile HTMLAuthoringInputProfileV1, args []byte) (*ApplicationBlocksInputV1, error) {
	if f == nil || f.state == nil || org == uuid.Nil || !applicationContextV1(ctx) || (profile != blocksAuthoringHTTPProfileV1 && profile != blocksAuthoringMCPProfileV1) {
		return nil, ErrBlocksInputV1
	}
	limit := blocksAuthoringHTTPBytesV1
	var cost int64
	var err error
	if profile == blocksAuthoringMCPProfileV1 {
		limit = int64(len(args))
		cost, err = plainSendBlockLexicalWorkV1(ctx, args)
	} else {
		cost, err = htmlAuthoringInputReadResourcesV1(limit)
	}
	if profile == blocksAuthoringHTTPProfileV1 {
		cost = max(cost, 8*limit+4*int64(unsafe.Sizeof(json.Decoder{})))
	}
	if err != nil || !htmlInputAddV1(&cost, 1, 2*int64(unsafe.Sizeof(ApplicationBlocksInputV1{}))+2*int64(unsafe.Sizeof(applicationHTMLAuthoringInputStateV1{}))+2*int64(unsafe.Sizeof(blocksInputDecimalStateV1{}))) {
		return nil, ErrBlocksInputV1
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlInputProducers == nil || len(p.htmlInputProducers) >= applicationSessionMaxWorkV1 {
		return nil, ErrBlocksInputV1
	}
	s := &applicationHTMLAuthoringInputStateV1{factory: p, org: org, profile: profile, limit: limit}
	p.htmlInputProducers[s] = struct{}{}
	release, err := p.work.acquire(ctx, org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		delete(p.htmlInputProducers, s)
		return nil, errors.Join(ErrBlocksInputV1, err)
	}
	s.releases = []func(){release}
	if profile == blocksAuthoringMCPProfileV1 {
		s.raw = bytes.Clone(args)
		s.ready = true
	}
	return &ApplicationBlocksInputV1{state: s, decimal: &blocksInputDecimalStateV1{}}, nil
}
func (h *ApplicationBlocksInputV1) beginV1(ctx context.Context, profile HTMLAuthoringInputProfileV1) error {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return ErrBlocksInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	if _, ok := p.htmlInputProducers[s]; !ok || p.closing || s.consumerClosed || s.retired || s.readStarted || s.profile != profile {
		return ErrBlocksInputV1
	}
	s.readStarted = true
	s.active++
	return nil
}

// The callback is the fixed route's original unchanged strict decoder. It is
// joined synchronously even when another copied shell closes or cancels; the
// raw and typed request remain retained until the actual response last use.
func (h *ApplicationBlocksInputV1) WithHTTPBodyV1(ctx context.Context, body io.ReadCloser, decode func([]byte) error) error {
	return h.withHTTPBodyV1(ctx, nil, body, decode)
}

// Automation preserves its original MaxBytesReader response-writer behavior
// and exact strict decoder/preparer. Three additional actual lexical passes
// fund duplicate/exact/type scans, canonical preparation and request hashing
// before any of those original allocations; the accepted grammar is unchanged.
func (h *ApplicationBlocksInputV1) WithAutomationHTTPBodyV1(ctx context.Context, w http.ResponseWriter, body io.ReadCloser, decodeAndPrepare func([]byte) error) error {
	if w == nil || decodeAndPrepare == nil {
		return ErrBlocksInputV1
	}
	return h.withHTTPBodyV1(ctx, w, body, func(raw []byte) error {
		cost, err := plainSendBlockLexicalWorkV1(ctx, raw)
		if err != nil {
			return err
		}
		extra := int64(0)
		if !htmlInputAddV1(&extra, cost, 3) {
			return ErrBlocksInputV1
		}
		if err = h.retainWorkV1(ctx, extra); err != nil {
			return err
		}
		return decodeAndPrepare(raw)
	})
}
func (h *ApplicationBlocksInputV1) withHTTPBodyV1(ctx context.Context, w http.ResponseWriter, body io.ReadCloser, decode func([]byte) error) error {
	if body == nil || decode == nil {
		return ErrBlocksInputV1
	}
	if err := h.beginV1(ctx, blocksAuthoringHTTPProfileV1); err != nil {
		return err
	}
	s := h.state
	defer s.finishV1()
	raw := make([]byte, int(blocksAuthoringHTTPBytesV1)+1)
	reader := http.MaxBytesReader(w, body, blocksAuthoringHTTPBytesV1)
	used := 0
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrBlocksInputV1, err)
		}
		n, err := reader.Read(raw[used:])
		used += n
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if used == len(raw) {
			return &http.MaxBytesError{Limit: blocksAuthoringHTTPBytesV1}
		}
	}
	raw = raw[:used]
	cost, err := plainSendBlockLexicalWorkV1(ctx, raw)
	if err != nil {
		return err
	}
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	if p.closing || s.consumerClosed || s.retired || ctx.Err() != nil {
		s.mu.Unlock()
		p.mu.Unlock()
		return ErrBlocksInputV1
	}
	release, err := p.work.acquire(ctx, s.org, workguard.VectorV1{ParentBytes: cost})
	if err == nil {
		s.releases = append(s.releases, release)
		s.raw = raw
		s.ready = true
	}
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return errors.Join(ErrBlocksInputV1, err)
	}
	return decode(raw)
}
func (h *ApplicationBlocksInputV1) WithArgumentsV1(ctx context.Context, decode func([]byte) error) error {
	if decode == nil {
		return ErrBlocksInputV1
	}
	if err := h.beginV1(ctx, blocksAuthoringMCPProfileV1); err != nil {
		return err
	}
	defer h.state.finishV1()
	return decode(h.state.raw)
}
func (h *ApplicationBlocksInputV1) CloseConsumerV1() {
	if h != nil && h.state != nil {
		(&ApplicationHTMLAuthoringInputV1{state: h.state}).CloseConsumerV1()
	}
}

// Existing block CRUD uses one streaming Decode, accepts trailing input, and
// may accept a completed first value even when unread trailing bytes exceed
// the original limit. Decode RawMessage first under the real maximum raw
// loan, then fund the unchanged typed Decode on exactly that first value.
// There is no new EOF, duplicate, null, case or member-count rule.
func (h *ApplicationBlocksInputV1) WithStreamingBodyV1(ctx context.Context, body io.ReadCloser, decode func([]byte) error) error {
	if body == nil || decode == nil {
		return ErrBlocksInputV1
	}
	if err := h.beginV1(ctx, blocksAuthoringHTTPProfileV1); err != nil {
		return err
	}
	s := h.state
	defer s.finishV1()
	var raw json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(nil, body, blocksAuthoringHTTPBytesV1)).Decode(&raw); err != nil {
		return err
	}
	cost, err := plainSendBlockLexicalWorkV1(ctx, raw)
	if err != nil {
		return err
	}
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	if p.closing || s.consumerClosed || s.retired || ctx.Err() != nil {
		s.mu.Unlock()
		p.mu.Unlock()
		return ErrBlocksInputV1
	}
	release, err := p.work.acquire(ctx, s.org, workguard.VectorV1{ParentBytes: cost})
	if err == nil {
		s.releases = append(s.releases, release)
		s.raw = raw
		s.ready = true
	}
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return errors.Join(ErrBlocksInputV1, err)
	}
	return decode(raw)
}

func (h *ApplicationBlocksInputV1) retainWorkV1(ctx context.Context, cost int64) error {
	if h == nil || h.state == nil || cost < 0 {
		return ErrBlocksInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	if _, ok := p.htmlInputProducers[s]; !ok || p.closing || s.consumerClosed || s.retired || s.active < 1 || ctx.Err() != nil {
		return ErrBlocksInputV1
	}
	release, err := p.work.acquire(ctx, s.org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		return errors.Join(ErrBlocksInputV1, err)
	}
	s.releases = append(s.releases, release)
	return nil
}

type blocksInputDecimalAdmissionV1 struct {
	input *ApplicationBlocksInputV1
	ctx   context.Context
}

func (a blocksInputDecimalAdmissionV1) BeforeDecimalV1(value string) (failure error) {
	h := a.input
	if h == nil || h.decimal == nil {
		return ErrBlocksInputV1
	}
	d := h.decimal
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		if failure != nil {
			d.failure = failure
		}
	}()
	if d.failure != nil {
		return d.failure
	}
	b, err := blocks.DecimalLogicalBoundForSendV1(value)
	if err != nil {
		return err
	}
	bits := int64(0)
	for _, v := range []int64{b.MantissaBits, b.PowerFiveBits, b.NumeratorBits, b.DenominatorBits} {
		if !htmlInputAddV1(&bits, v, 1) {
			return ErrBlocksInputV1
		}
	}
	words := bits / 64
	if bits%64 != 0 {
		words++
	}
	cost := int64(0)
	if !htmlInputAddV1(&cost, words, 64*8) || !htmlInputAddV1(&cost, b.SourceBytes, 8) || !htmlInputAddV1(&cost, 1, 32*int64(unsafe.Sizeof(big.Int{}))+8*int64(unsafe.Sizeof(big.Rat{}))) {
		return ErrBlocksInputV1
	}
	if cost > d.peak {
		if err = h.retainWorkV1(a.ctx, cost-d.peak); err != nil {
			return err
		}
		d.peak = cost
	}
	return nil
}

// set_document_blocks historically parses its actual replacement before the
// draft lock. Retain that exact original stage and grammar; the body owner
// funds lexical/decimal work before this original parser can allocate it.
func (h *ApplicationBlocksInputV1) ParseTreeV1(ctx context.Context, raw []byte) (*blocks.Tree, error) {
	if h == nil || h.state == nil || h.decimal == nil {
		return nil, ErrBlocksInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	if _, ok := p.htmlInputProducers[s]; !ok || p.closing || s.consumerClosed || s.retired || !s.ready {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrBlocksInputV1
	}
	s.active++
	s.mu.Unlock()
	p.mu.Unlock()
	defer s.finishV1()
	cost, err := plainSendBlockLexicalWorkV1(ctx, raw)
	if err != nil {
		return nil, err
	}
	if err = h.retainWorkV1(ctx, cost); err != nil {
		return nil, err
	}
	tree, err := blocks.ParseTreeForAuthoringV1(ctx, raw, blocksInputDecimalAdmissionV1{input: h, ctx: ctx})
	h.decimal.mu.Lock()
	failure := h.decimal.failure
	h.decimal.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	return tree, err
}

// Original template creation/update normalization stays before its member lock.
// The admitted request owns this additional parse and canonical output through
// the real response consumer, including copied-handle close races.
func (h *ApplicationBlocksInputV1) NormalizeTreeV1(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if h == nil || h.state == nil || h.decimal == nil {
		return nil, ErrBlocksInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	if _, ok := p.htmlInputProducers[s]; !ok || p.closing || s.consumerClosed || s.retired || !s.ready {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrBlocksInputV1
	}
	s.active++
	s.mu.Unlock()
	p.mu.Unlock()
	defer s.finishV1()
	cost, err := plainSendBlockLexicalWorkV1(ctx, raw)
	if err != nil {
		return nil, err
	}
	if err = h.retainWorkV1(ctx, cost); err != nil {
		return nil, err
	}
	normalized, err := blocks.NormalizeTreeForAuthoringV1(ctx, raw, blocksInputDecimalAdmissionV1{input: h, ctx: ctx}, func(tree *blocks.Tree) error {
		upper, e := blocksCanonicalOutputUpperV1(ctx, tree)
		if e != nil {
			return e
		}
		return h.retainWorkV1(ctx, upper)
	})
	h.decimal.mu.Lock()
	failure := h.decimal.failure
	h.decimal.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	return normalized, err
}
