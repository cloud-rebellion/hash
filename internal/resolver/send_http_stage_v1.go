// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package resolver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

var ErrSendHTTPStageV1 = errors.New("resolver: owned send HTTP stage unavailable")

// SendHTTPReadV1 separates the existing fixed HTTP protocol from its generic
// JSON expansion. It grants no resources/tenant authority. The native Send
// owner must hold the read arena before Open/Read, then inspect the ACTUAL
// defensive body view and acquire parser/output work before DecodeValueV1.
// There is no callback, caller raw replacement, size hint or custom decoder.
type SendHTTPReadV1 struct{ state *sendHTTPReadStateV1 }
type sendHTTPReadStateV1 struct {
	mu                                               sync.Mutex
	kind                                             SourceKind
	path                                             string
	body                                             io.ReadCloser
	raw                                              []byte
	readStarted, readFinished, decodeStarted, closed bool
	failure                                          error
}

// SendHTTPResponseByteLimitV1 is the unchanged concrete source limit. It is a
// fact for the native fixed read profile, never a caller-controlled capacity.
func SendHTTPResponseByteLimitV1() int { return maxSourceResponseBytes }

func (h *HTTPSource) OpenSendReadV1(ctx context.Context, ref Ref) (*SendHTTPReadV1, error) {
	if h == nil {
		return nil, ErrNotConfigured
	}
	if h.BaseURL == "" || h.Token == "" {
		return nil, ErrNotConfigured
	}
	if err := validateHTTPSourceRef(ref.Source); err != nil {
		return nil, err
	}
	client := h.Client
	if client == nil {
		client = defaultIntegrationClient
	}
	url := strings.TrimRight(h.BaseURL, "/") + h.pathFor(ref)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s fetch: %w", h.kind, err)
	}
	if response.StatusCode == http.StatusNotFound {
		response.Body.Close()
		return nil, ErrNotFound
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		response.Body.Close()
		return nil, fmt.Errorf("%s fetch: HTTP %d", h.kind, response.StatusCode)
	}
	return &SendHTTPReadV1{state: &sendHTTPReadStateV1{kind: h.kind, path: ref.Path, body: response.Body}}, nil
}
func (h *SendHTTPReadV1) ReadBodyV1() (failure error) {
	if h == nil || h.state == nil {
		return ErrSendHTTPStageV1
	}
	s := h.state
	s.mu.Lock()
	if s.closed || s.readStarted || s.body == nil {
		s.mu.Unlock()
		return ErrSendHTTPStageV1
	}
	s.readStarted = true
	body := s.body
	s.mu.Unlock()
	// The original read and original Close both join before readFinished. The
	// native active producer remains charged through this whole synchronous call;
	// cancellation or an outer consumer closure is not proof this read retired.
	raw, err := io.ReadAll(io.LimitReader(body, maxSourceResponseBytes+1))
	_ = body.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = nil
	s.readFinished = true
	if err != nil {
		s.failure = err
		return err
	}
	if len(raw) > maxSourceResponseBytes {
		s.failure = fmt.Errorf("%s fetch: response exceeds byte limit", s.kind)
		return s.failure
	}
	if s.closed {
		s.failure = ErrSendHTTPStageV1
		return s.failure
	}
	s.raw = raw
	return nil
}

// BodyV1 never exposes mutable private response bytes. Its copy is covered by
// the native fixed bounded-read component before calling this projection.
func (h *SendHTTPReadV1) BodyV1() ([]byte, error) {
	if h == nil || h.state == nil {
		return nil, ErrSendHTTPStageV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.readFinished || s.failure != nil {
		return nil, ErrSendHTTPStageV1
	}
	return bytes.Clone(s.raw), nil
}
func (h *SendHTTPReadV1) DecodeValueV1() (string, error) {
	if h == nil || h.state == nil {
		return "", ErrSendHTTPStageV1
	}
	s := h.state
	s.mu.Lock()
	if s.closed || !s.readFinished || s.failure != nil || s.decodeStarted {
		s.mu.Unlock()
		return "", ErrSendHTTPStageV1
	}
	s.decodeStarted = true
	raw, kind, path := s.raw, s.kind, s.path
	s.mu.Unlock()
	// Preserve the original generic source grammar: UTF8+duplicate-aware root
	// object, depth64, UseNumber, successful2xx regardless of Content-Type, and
	// original decoded-key/path/stringify semantics. JSONB constraints do not
	// apply here (escaped NUL/unpaired UTF16 remain the legacy parser's decision).
	if err := validateSourceJSON(raw); err != nil {
		return "", fmt.Errorf("%s decode: %w", kind, err)
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return "", fmt.Errorf("%s decode: %w", kind, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", fmt.Errorf("%s decode: trailing JSON content", kind)
	}
	value, ok := jsonPathLookup(document, path)
	if !ok {
		return "", fmt.Errorf("%s: path %q not found in response", kind, path)
	}
	text, ok := stringify(value)
	if !ok {
		return "", fmt.Errorf("%s: path %q resolved to nil", kind, path)
	}
	return text, nil
}

// CloseV1 ends the response consumer, not a native work/physical completion
// receipt. If ReadBodyV1 is active, it retains the original body and closes it
// itself after the actual Read joins. No concurrent Close falsely refunds it.
func (h *SendHTTPReadV1) CloseV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	var body io.ReadCloser
	if !s.readStarted {
		body = s.body
		s.body = nil
	}
	s.raw = nil
	s.mu.Unlock()
	if body != nil {
		_ = body.Close()
	}
}
