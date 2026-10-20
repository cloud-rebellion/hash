// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ai

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/nethard"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// Only the actual native document source calls these fixed supported-provider
// entry points. Their coordinator/org are derived by that private source owner,
// not request JSON. Original Complete and custom HTTPDoer behavior are untouched.
// A manually constructed/custom-client provider is not silently attested here.
func (m *MistralProvider) CompleteNativeV1(ctx context.Context, req Request, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*NativeCompletionV1, error) {
	if m == nil {
		return nil, ErrNativeIOV1
	}
	client, ok := m.Client.(*http.Client)
	if !ok || client == nil || client != m.nativeClient {
		return nil, ErrNativeIOV1
	}
	frame, parent, err := nativeRequestResourcesV1(req, m.BaseURL, m.APIKey, m.ModelID)
	if err != nil {
		return nil, err
	}
	return completeNativeProviderV1(ctx, coordinator, org, frame, parent, m.nativeAllowPrivate, func(client *http.Client) (Response, error) {
		copy := *m
		copy.BaseURL = strings.Clone(m.BaseURL)
		copy.APIKey = strings.Clone(m.APIKey)
		copy.ModelID = strings.Clone(m.ModelID)
		copy.Client = client
		req.System = strings.Clone(req.System)
		req.User = strings.Clone(req.User)
		req.PromptName = strings.Clone(req.PromptName)
		return copy.Complete(ctx, req)
	})
}
func (a *AnthropicProvider) CompleteNativeV1(ctx context.Context, req Request, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*NativeCompletionV1, error) {
	if a == nil {
		return nil, ErrNativeIOV1
	}
	client, ok := a.Client.(*http.Client)
	if !ok || client == nil || client != a.nativeClient {
		return nil, ErrNativeIOV1
	}
	frame, parent, err := nativeRequestResourcesV1(req, a.BaseURL, a.APIKey, a.ModelID, a.Version)
	if err != nil {
		return nil, err
	}
	return completeNativeProviderV1(ctx, coordinator, org, frame, parent, a.nativeAllowPrivate, func(client *http.Client) (Response, error) {
		copy := *a
		copy.BaseURL = strings.Clone(a.BaseURL)
		copy.APIKey = strings.Clone(a.APIKey)
		copy.ModelID = strings.Clone(a.ModelID)
		copy.Version = strings.Clone(a.Version)
		copy.Client = client
		req.System = strings.Clone(req.System)
		req.User = strings.Clone(req.User)
		req.PromptName = strings.Clone(req.PromptName)
		return copy.Complete(ctx, req)
	})
}

// The privacy flag comes only from the original real provider constructor.
// Build a fresh fixed nethard transport: no arbitrary caller Transport/TLS/dial/
// proxy/redirect callback, cookie store, raw connection or fake retired flag is
// accepted as proof. This explicit native HTTP/1 profile preserves verified TLS,
// SSRF-at-dial, no proxy, no redirects,10s dial/TLS,25s header and30s client limits.
// HTTP/2 is not claimed by this decrypted raw-header accounting profile.
func completeNativeProviderV1(ctx context.Context, coordinator *workguard.CoordinatorV1, org uuid.UUID, frame, parent int64, allowPrivate bool, run func(*http.Client) (Response, error)) (*NativeCompletionV1, error) {
	if ctx == nil || ctx.Err() != nil || coordinator == nil || org == uuid.Nil || run == nil {
		return nil, ErrNativeIOV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, ErrNativeIOV1
	}
	grant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: parent})
	if err != nil {
		return nil, errors.Join(ErrNativeIOV1, err)
	}
	provider, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		grant.Close()
		return nil, errors.Join(ErrNativeIOV1, err)
	}
	base := nethard.Transport(func() bool { return allowPrivate })
	state := &aiNativeHTTPStateV1{ctx: ctx, grant: grant, provider: provider, connections: make(map[*aiNativeConnV1]struct{}), changed: make(chan struct{}), joined: make(chan struct{}), frameLimit: frame}
	state.self = state
	transport := base.Clone()
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	transport.TLSClientConfig = &tls.Config{NextProtos: []string{"http/1.1"}}
	transport.DialContext = state.dialV1(base)
	transport.DialTLSContext = state.dialTLSV1(base)
	state.transport = transport
	client := nethard.Client(30*time.Second, func() bool { return allowPrivate })
	client.Transport = &aiNativeRoundTripperV1{owner: state, transport: transport}
	response, callErr := run(client)
	state.mu.Lock()
	state.response = response
	state.closing = true
	state.signalV1()
	state.mu.Unlock()
	// Actual IO join continues independently after cancellation. A returned error
	// or CloseConsumer call cannot release local stream/retained response debt.
	go state.closeIOV1()
	handle := &NativeCompletionV1{state: state}
	select {
	case <-state.joined:
		if err := ctx.Err(); err != nil {
			state.finishDeliveryV1(false)
			return handle, errors.Join(callErr, ErrNativeIOV1, err)
		}
		state.finishDeliveryV1(callErr == nil)
		return handle, callErr
	case <-ctx.Done():
		state.finishDeliveryV1(false)
		return handle, errors.Join(callErr, ErrNativeIOV1, ctx.Err())
	}
}
