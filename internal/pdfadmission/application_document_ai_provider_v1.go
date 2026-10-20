// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"unsafe"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/workguard"
)

type ApplicationDocumentAIProviderV1 struct {
	work   *ApplicationDocumentAIWorkV1
	source ai.Provider
}

// This actual private dispatch snapshot, not a request ID, caller org or public
// coordinator, derives the stream/data owner. Original input/Shield/usage/result
// policy still belongs to the coordinator. Unknown provider types are not
// silently promoted into this deliberately supported native HTTP proof.
func (w *ApplicationDocumentAIWorkV1) NewProviderV1(ctx context.Context, source ai.Provider) (*ApplicationDocumentAIProviderV1, error) {
	if w == nil || w.state == nil || source == nil {
		return nil, ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.requested || s.snapshot == nil || s.policy == nil || s.closeAfterProvider {
		return nil, ErrDocumentAIAuditV1
	}
	switch source.(type) {
	case *ai.MistralProvider, *ai.AnthropicProvider:
	default:
		return nil, ErrDocumentAIAuditV1
	}
	if err := s.holdV1(ctx, 4*int64(unsafe.Sizeof(ApplicationDocumentAIProviderV1{})), 0); err != nil {
		return nil, err
	}
	return &ApplicationDocumentAIProviderV1{work: w, source: source}, nil
}
func (p *ApplicationDocumentAIProviderV1) Name() string     { return p.source.Name() }
func (p *ApplicationDocumentAIProviderV1) Model() string    { return p.source.Model() }
func (p *ApplicationDocumentAIProviderV1) Endpoint() string { return p.source.Endpoint() }
func (p *ApplicationDocumentAIProviderV1) Complete(ctx context.Context, req ai.Request) (value ai.Response, failure error) {
	if p == nil || p.work == nil || p.work.state == nil {
		return ai.Response{}, ErrDocumentAIAuditV1
	}
	s := p.work.state
	s.mu.Lock()
	if !s.validV1(ctx) || s.requested || s.snapshot == nil || s.closeAfterProvider {
		s.mu.Unlock()
		return ai.Response{}, ErrDocumentAIAuditV1
	}
	factory := s.session.state.factory
	org := s.session.state.org
	s.providerActive++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.providerActive--
		closing := s.closeAfterProvider
		s.mu.Unlock()
		if closing {
			value.Text = ""
			value.Model = ""
			value.Provider = ""
			failure = errors.Join(failure, ErrDocumentAIAuditV1)
			p.work.CloseConsumerV1()
		}
	}()
	factory.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !factory.closing && factory.work != nil {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if coordinator == nil {
		return ai.Response{}, ErrDocumentAIAuditV1
	}
	var owner *ai.NativeCompletionV1
	switch source := p.source.(type) {
	case *ai.MistralProvider:
		owner, failure = source.CompleteNativeV1(ctx, req, coordinator, org)
	case *ai.AnthropicProvider:
		owner, failure = source.CompleteNativeV1(ctx, req, coordinator, org)
	default:
		return ai.Response{}, ErrDocumentAIAuditV1
	}
	if owner != nil {
		s.mu.Lock()
		s.closes = append(s.closes, owner.CloseConsumerV1)
		s.mu.Unlock()
	}
	if failure != nil {
		if owner != nil {
			if observation, err := owner.UsageObservationV1(); err == nil {
				value.InputTokens = observation.InputTokens
				value.OutputTokens = observation.OutputTokens
			}
		}
		return value, failure
	}
	if owner == nil {
		return ai.Response{}, ErrDocumentAIAuditV1
	}
	failure = owner.WithResponseV1(func(actual ai.Response) error { value = actual; return nil })
	return value, failure
}

var _ ai.Provider = (*ApplicationDocumentAIProviderV1)(nil)
