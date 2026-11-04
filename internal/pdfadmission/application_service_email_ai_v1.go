// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/ai"
)

func (o *ApplicationServiceEmailControlV1) RetainAIBytesV1(ctx context.Context, n int64) error {
	if o == nil {
		return ErrServiceEmailControlV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.validLockedV1(ctx) || n < 0 || n > 64<<20 {
		return ErrServiceEmailControlV1
	}
	return o.grant.TryGrowParentV1(ctx, n)
}

// The original native HTTP provider supplies its real request/response/stream
// ownership. No caller client, fake retirement flag or detached vector is used.
func (o *ApplicationServiceEmailControlV1) WrapAIProviderV1(ctx context.Context, source ai.Provider) (ai.Provider, error) {
	if o == nil || !o.MatchesOrgV1(ctx, o.org) || source == nil {
		return nil, ErrServiceEmailControlV1
	}
	switch source.(type) {
	case *ai.MistralProvider, *ai.AnthropicProvider:
	default:
		return nil, ai.ErrNativeIOV1
	}
	return &serviceEmailAIProviderV1{o, source}, nil
}

type serviceEmailAIProviderV1 struct {
	owner  *ApplicationServiceEmailControlV1
	source ai.Provider
}

func (p *serviceEmailAIProviderV1) Name() string     { return p.source.Name() }
func (p *serviceEmailAIProviderV1) Model() string    { return p.source.Model() }
func (p *serviceEmailAIProviderV1) Endpoint() string { return p.source.Endpoint() }
func (p *serviceEmailAIProviderV1) Complete(ctx context.Context, request ai.Request) (response ai.Response, failure error) {
	if p == nil || p.owner == nil || !p.owner.MatchesOrgV1(ctx, p.owner.org) {
		return response, ErrServiceEmailControlV1
	}
	o := p.owner
	var native *ai.NativeCompletionV1
	switch provider := p.source.(type) {
	case *ai.MistralProvider:
		native, failure = provider.CompleteNativeV1(ctx, request, o.admission.coordinator, o.org)
	case *ai.AnthropicProvider:
		native, failure = provider.CompleteNativeV1(ctx, request, o.admission.coordinator, o.org)
	default:
		return response, ai.ErrNativeIOV1
	}
	if native != nil {
		o.mu.Lock()
		if o.closed {
			o.mu.Unlock()
			native.CloseConsumerV1()
			return response, errors.Join(failure, ErrServiceEmailControlV1)
		}
		o.closes = append(o.closes, native.CloseConsumerV1)
		o.mu.Unlock()
	}
	if failure != nil {
		return response, failure
	}
	if native == nil {
		return response, ai.ErrNativeIOV1
	}
	failure = native.WithResponseV1(func(value ai.Response) error { response = value; return nil })
	return
}
