// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/workguard"
	"sync"
)

var errHTMLCanonicalModelWorkV1 = fmt.Errorf("%w: stored HTML producer unavailable", ErrHTMLAuthoringReadV1)

// The unexported actual-model producer is created ONLY by a fixed native
// reader/writer after its scoped header/body checks. It owns no legal or SQL
// completion authority and exposes no caller budget/span/multiplicity API.
type applicationHTMLCanonicalModelConsumerV1 struct {
	self                    *applicationHTMLCanonicalModelConsumerV1
	mu                      sync.Mutex
	session                 *ApplicationSessionV1
	factory                 *applicationSessionFactoryStateV1
	parentCredit            *workguard.GrantV1
	active                  int
	scratch                 int64
	consumerClosed, retired bool
}

func (h *ApplicationSessionV1) newHTMLCanonicalModelConsumerV1(ctx context.Context) (result *applicationHTMLCanonicalModelConsumerV1, failure error) {
	phase := "owner_context"
	defer func() { failure = htmlCanonicalFailureV1(ctx, phase, failure) }()
	if !htmlAuthoringInputRuntimeOKV1 || h == nil || h.state == nil || !applicationContextV1(ctx) {
		return nil, errHTMLCanonicalModelWorkV1
	}
	s := h.state
	p := s.factory
	phase = "owner_factory"
	if p == nil {
		return nil, errHTMLCanonicalModelWorkV1
	}
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	phase = "owner_state"
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlCanonicalConsumers == nil || s.observer || s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || !s.dialed || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) || len(p.htmlCanonicalConsumers) >= applicationSessionMaxWorkV1 || s.admission == nil || !s.admission.valid() || s.admission.fence != s.fence || s.admission.cleanupDone != s.fence.clientDone || !s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s {
		return nil, errHTMLCanonicalModelWorkV1
	}
	owner := &applicationHTMLCanonicalModelConsumerV1{session: h, factory: p, active: 1}
	// The active producer pin exists before its first nonblocking work grant.
	// Factory close cannot discard a registered producer while it can install.
	owner.self = owner
	p.htmlCanonicalConsumers[owner] = struct{}{}
	return owner, nil
}
func (c *applicationHTMLCanonicalModelConsumerV1) holdV1(ctx context.Context, n int64) error {
	return c.holdAtV1(ctx, n, "model_hold")
}
func (c *applicationHTMLCanonicalModelConsumerV1) holdAtV1(ctx context.Context, n int64, phase string) (failure error) {
	defer func() { failure = htmlCanonicalFailureV1(ctx, phase, failure) }()
	if c == nil || c.self != c {
		return errHTMLCanonicalModelWorkV1
	}
	p := c.factory
	p.mu.Lock()
	c.mu.Lock()
	defer p.mu.Unlock()
	defer c.mu.Unlock()
	_, registered := p.htmlCanonicalConsumers[c]
	if !registered || p.closing || c.retired || c.consumerClosed || c.active != 1 || !applicationContextV1(ctx) {
		return errHTMLCanonicalModelWorkV1
	}
	// A genuine native session/callback created this fixed producer; each later
	// n is derived privately from its actual retained models, never a caller.
	// All parent bytes in this producer share the SAME retirement conjunction.
	// Grow its one private credit before allocation; never merge distinct owners.
	credit, err := htmlCanonicalChargeV1(ctx, p.work, c.session.state.org, c.parentCredit, n, phase)
	if err != nil {
		return errors.Join(errHTMLCanonicalModelWorkV1, err)
	}
	c.parentCredit = credit
	return nil
}

// The fixed producer invokes original canonical/Compile calls synchronously.
// Keep the largest complete scratch arena charged through LAST future use;
// all simultaneously retained typed/Compiled/canonical results add their full
// bytes to the same continuously retained credit. No GC/pool/RSS credit is
// released between calls; grant-count consolidation is not a byte discount.
func (c *applicationHTMLCanonicalModelConsumerV1) holdScratchV1(ctx context.Context, n int64) error {
	return c.holdScratchAtV1(ctx, n, "model_scratch")
}
func (c *applicationHTMLCanonicalModelConsumerV1) holdScratchAtV1(ctx context.Context, n int64, phase string) (failure error) {
	defer func() { failure = htmlCanonicalFailureV1(ctx, phase, failure) }()
	if c == nil || c.self != c || n < 0 {
		return errHTMLCanonicalModelWorkV1
	}
	p := c.factory
	p.mu.Lock()
	c.mu.Lock()
	defer p.mu.Unlock()
	defer c.mu.Unlock()
	_, registered := p.htmlCanonicalConsumers[c]
	if !registered || p.closing || c.retired || c.consumerClosed || c.active != 1 || !applicationContextV1(ctx) {
		return errHTMLCanonicalModelWorkV1
	}
	if n <= c.scratch {
		return nil
	}
	credit, err := htmlCanonicalChargeV1(ctx, p.work, c.session.state.org, c.parentCredit, n-c.scratch, phase)
	if err != nil {
		return errors.Join(errHTMLCanonicalModelWorkV1, err)
	}
	c.parentCredit = credit
	c.scratch = n
	return nil
}
func (c *applicationHTMLCanonicalModelConsumerV1) finishV1() {
	if c == nil || c.self != c {
		return
	}
	p := c.factory
	p.mu.Lock()
	c.mu.Lock()
	c.active--
	c.releaseIfCompleteV1()
	c.mu.Unlock()
	p.mu.Unlock()
}
func (c *applicationHTMLCanonicalModelConsumerV1) CloseConsumerV1() {
	if c == nil || c.self != c {
		return
	}
	p := c.factory
	p.mu.Lock()
	c.mu.Lock()
	c.consumerClosed = true
	c.releaseIfCompleteV1()
	c.mu.Unlock()
	p.mu.Unlock()
}
func (c *applicationHTMLCanonicalModelConsumerV1) releaseIfCompleteV1() {
	if c.retired || !c.consumerClosed || c.active != 0 {
		return
	}
	c.retired = true
	c.parentCredit.Close()
	c.parentCredit = nil
	delete(c.factory.htmlCanonicalConsumers, c)
}
