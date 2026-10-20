// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"io"
	"sync"
	"unsafe"
)

const aiHTTPInputProfileV1 HTMLAuthoringInputProfileV1 = 238
const aiMCPArgumentsProfileV1 HTMLAuthoringInputProfileV1 = 239
const aiMCPEnvelopeProfileV1 HTMLAuthoringInputProfileV1 = 240

type ApplicationDocumentAIInputV1 struct {
	state  *applicationHTMLAuthoringInputStateV1
	growth *documentAIInputGrowthV1
}
type documentAIInputGrowthV1 struct {
	mu     sync.Mutex
	grant  *workguard.GrantV1
	target int64
}
type documentAIInputReaderV1 struct {
	owner  *ApplicationDocumentAIInputV1
	ctx    context.Context
	source io.Reader
	seen   int64
}

func (r *documentAIInputReaderV1) Read(p []byte) (int, error) {
	// Both unchanged fixed decoders initially allocate512 and grow by at most
	// 2*prior length+512. Before each prior Read returns, retain4*actual prefix
	// +2048 bytes of lookahead at the original typed-decoder allocation class.
	if r.seen < 0 || int64(len(p)) > 4*r.seen+2048 {
		return 0, ErrDocumentAIAuditV1
	}
	n, failure := r.source.Read(p)
	next, err := aiInputPrefixCostV1(r.seen + int64(n))
	if err != nil {
		return 0, err
	}
	g := r.owner.growth
	g.mu.Lock()
	if next > g.target {
		err = g.grant.TryGrowParentV1(r.ctx, next-g.target)
		if err == nil {
			g.target = next
		}
	}
	g.mu.Unlock()
	if err != nil {
		return 0, errors.Join(ErrDocumentAIAuditV1, err)
	}
	r.seen += int64(n)
	return n, failure
}
func aiInputPrefixCostV1(actual int64) (int64, error) {
	if actual < 0 || actual > ((1<<40)-2048)/4 {
		return 0, ErrDocumentAIAuditV1
	}
	return (4*actual + 2048) * 64, nil
}

func (f *ApplicationSessionFactoryV1) NewAIHTTPInputV1(ctx context.Context, org uuid.UUID, action string) (*ApplicationDocumentAIInputV1, error) {
	var limit int64
	switch action {
	case "suggest_counter_clause":
		limit = 32 * 1024
	case "check_bilingual_equivalence":
		limit = 64 * 1024
	case "run_risk_analysis":
		limit = 16 * 1024
	default:
		return nil, ErrDocumentAIAuditV1
	}
	return f.newAIInputV1(ctx, org, aiHTTPInputProfileV1, limit, nil)
}
func (f *ApplicationSessionFactoryV1) NewAIArgumentsV1(ctx context.Context, org uuid.UUID, args []byte) (*ApplicationDocumentAIInputV1, error) {
	return f.newAIInputV1(ctx, org, aiMCPArgumentsProfileV1, int64(len(args)), args)
}
func (f *ApplicationSessionFactoryV1) NewMCPEnvelopeInputV1(ctx context.Context, org uuid.UUID) (*ApplicationDocumentAIInputV1, error) {
	return f.newAIInputV1(ctx, org, aiMCPEnvelopeProfileV1, 1<<20, nil)
}
func (f *ApplicationSessionFactoryV1) newAIInputV1(ctx context.Context, org uuid.UUID, profile HTMLAuthoringInputProfileV1, limit int64, args []byte) (*ApplicationDocumentAIInputV1, error) {
	if f == nil || f.state == nil || org == uuid.Nil || !applicationContextV1(ctx) || limit < 0 {
		return nil, ErrDocumentAIAuditV1
	}
	// Original decoder controls/initial buffers are prepaid. Each actual prefix
	// grows this same retained grant before the next original decoder expansion.
	// MCP typed arguments use their already-owned actual raw argument length.
	// No body ceiling or single-Decode/trailing-value behavior is changed.
	cost := int64(8192) + 4*int64(unsafe.Sizeof(applicationHTMLAuthoringInputStateV1{}))
	var dynamic int64
	if profile == aiMCPArgumentsProfileV1 {
		if !htmlInputAddV1(&dynamic, limit, 64) {
			return nil, ErrDocumentAIAuditV1
		}
	} else {
		dynamic, _ = aiInputPrefixCostV1(0)
	}
	if !htmlInputAddV1(&cost, dynamic, 1) {
		return nil, ErrDocumentAIAuditV1
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.work == nil || p.htmlInputProducers == nil || len(p.htmlInputProducers) >= applicationSessionMaxWorkV1 {
		return nil, ErrDocumentAIAuditV1
	}
	grant, err := p.work.coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		return nil, errors.Join(ErrDocumentAIAuditV1, err)
	}
	s := &applicationHTMLAuthoringInputStateV1{factory: p, org: org, profile: profile, limit: limit, releases: []func(){grant.Close}}
	p.htmlInputProducers[s] = struct{}{}
	if profile == aiMCPArgumentsProfileV1 {
		s.raw = bytes.Clone(args)
		s.ready = true
	}
	return &ApplicationDocumentAIInputV1{state: s, growth: &documentAIInputGrowthV1{grant: grant, target: dynamic}}, nil
}
func (o *ApplicationDocumentAIInputV1) beginV1(ctx context.Context, args bool) error {
	if o == nil || o.state == nil || !applicationContextV1(ctx) {
		return ErrDocumentAIAuditV1
	}
	s := o.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	_, registered := p.htmlInputProducers[s]
	if !registered || p.closing || s.consumerClosed || s.retired || s.readStarted || (args != (s.profile == aiMCPArgumentsProfileV1)) {
		return ErrDocumentAIAuditV1
	}
	s.readStarted = true
	s.active++
	return nil
}
func (o *ApplicationDocumentAIInputV1) WithBodyV1(ctx context.Context, body io.Reader, decode func(io.Reader) error) error {
	if body == nil || decode == nil {
		return ErrDocumentAIAuditV1
	}
	if err := o.beginV1(ctx, false); err != nil {
		return err
	}
	defer o.state.finishV1()
	// Caller passes the original MaxBytesReader; the unchanged decoder executes
	// exactly once and a blocked Read remains an active borrower after cancel.
	return decode(&documentAIInputReaderV1{owner: o, ctx: ctx, source: body})
}
func (o *ApplicationDocumentAIInputV1) WithArgumentsV1(ctx context.Context, decode func([]byte) error) error {
	if decode == nil {
		return ErrDocumentAIAuditV1
	}
	if err := o.beginV1(ctx, true); err != nil {
		return err
	}
	defer o.state.finishV1()
	return decode(o.state.raw)
}
func (o *ApplicationDocumentAIInputV1) CloseConsumerV1() {
	if o != nil && o.state != nil {
		(&ApplicationHTMLAuthoringInputV1{state: o.state}).CloseConsumerV1()
	}
}
