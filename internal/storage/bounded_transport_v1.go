// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
)

const (
	boundedStorageErrorBytesV1         int64 = 64 << 10
	boundedStorageMetadataBytesV1      int64 = 8 << 20
	boundedStorageHeaderBytesV1        int64 = 64 << 10
	boundedStorageConnectionsPerHostV1       = 8
)

var (
	errBoundedStorageResponseV1       = errors.New("storage response exceeds admitted size")
	errBoundedStorageResponseClosedV1 = errors.New("storage response is closed")
	errBoundedStorageRequestV1        = errors.New("storage response admission is invalid")
)

type boundedStorageFailureV1 struct{ cause error }

func (e *boundedStorageFailureV1) Error() string { return "storage response read or cleanup failed" }
func (e *boundedStorageFailureV1) Unwrap() error { return e.cause }

type boundedStorageCancellationV1 struct{ canceled, cause error }

func (e *boundedStorageCancellationV1) Error() string   { return "storage response canceled" }
func (e *boundedStorageCancellationV1) Unwrap() []error { return []error{e.canceled, e.cause} }
func boundedStorageContextErrorV1(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &boundedStorageCancellationV1{canceled: err, cause: context.Cause(ctx)}
	}
	return nil
}

type objectResponseLimitKeyV1 struct{}
type objectResponseLimitV1 struct{ bytes int64 }

// withObjectResponseLimitV1 is private dispatch metadata, not permission or a
// physical retirement receipt. The exact read caller must first admit its own
// bytes/stream work. Only successful GET responses use limit+1; HEAD and all
// metadata responses retain the fixed profile. Invalid bounds refuse before I/O.
func withObjectResponseLimitV1(ctx context.Context, limit int64) context.Context {
	return context.WithValue(ctx, objectResponseLimitKeyV1{}, objectResponseLimitV1{bytes: limit})
}

type boundedStorageTransportV1 struct {
	base        http.RoundTripper
	connections *storageConnectionAdmissionV1
}

// This fixed process-local transport bounds response headers and active/idle
// connections per host. It preserves the pinned SDK TLS, proxy, timeout and
// no-decompression defaults. These limits are not deployment-wide permits or
// evidence that the transport, provider or remote work has physically retired.
func newBoundedStorageTransportV1(secure bool) (http.RoundTripper, error) {
	base := storageHTTPTransportBaseV1(secure)
	connections := newStorageConnectionAdmissionV1()
	base.DialContext = connections.dialV1(base.DialContext)
	connections.registerV1(base)
	return &boundedStorageTransportV1{base: base, connections: connections}, nil
}

func (t *boundedStorageTransportV1) CloseIdleConnections() {
	if t != nil {
		if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func boundedStorageSuccessV1(status int) bool {
	// These are precisely MinIO77 executeMethod's accepted statuses; an otherwise
	// 2xx status enters its error-body io.ReadAll and therefore needs the64KiB cap.
	return status == http.StatusOK || status == http.StatusNoContent || status == http.StatusPartialContent
}
func (t *boundedStorageTransportV1) RoundTrip(r *http.Request) (*http.Response, error) {
	if t == nil || t.base == nil || r == nil {
		return nil, errBoundedStorageRequestV1
	}
	ctx := r.Context()
	if err := boundedStorageContextErrorV1(ctx); err != nil {
		return nil, err
	}
	objectLimit, scoped := ctx.Value(objectResponseLimitKeyV1{}).(objectResponseLimitV1)
	if scoped && (objectLimit.bytes < 1 || objectLimit.bytes > maxStoredObjectBytes) {
		return nil, errBoundedStorageRequestV1
	}
	if t.connections != nil {
		trace := &httptrace.ClientTrace{PutIdleConn: func(err error) {
			if err == nil {
				t.connections.closeIdleForWaitersV1()
			}
		}}
		r = r.WithContext(httptrace.WithClientTrace(r.Context(), trace))
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		if response != nil && response.Body != nil {
			if closeErr := response.Body.Close(); closeErr != nil {
				err = errors.Join(err, &boundedStorageFailureV1{cause: closeErr})
			}
		}
		if canceled := boundedStorageContextErrorV1(ctx); canceled != nil {
			err = errors.Join(err, canceled)
		}
		return nil, &boundedStorageFailureV1{cause: err}
	}
	if response == nil || response.Body == nil {
		return nil, errBoundedStorageRequestV1
	}
	cap := boundedStorageMetadataBytesV1
	if !boundedStorageSuccessV1(response.StatusCode) {
		cap = boundedStorageErrorBytesV1
	} else if r.Method == http.MethodGet && scoped {
		cap = objectLimit.bytes + 1
	}
	// Unclassified successful GETs retain the8MiB metadata profile. A larger
	// object profile requires the private admitted exact-object context; no URL
	// heuristic can distinguish virtual-host object reads from bucket/list calls.
	response.Body = newBoundedStorageBodyV1(ctx, response.Body, cap)
	return response, nil
}

// Interface, pointer and concrete handle copies share one physical owner.
// They cannot duplicate Close or release the same in-flight Read accounting.
type boundedStorageBodyV1 struct{ state *boundedStorageBodyStateV1 }
type boundedStorageBodyStateV1 struct {
	ctx        context.Context
	underlying io.ReadCloser
	readMu     sync.Mutex
	mu         sync.Mutex
	joined     *sync.Cond
	remaining  int64
	active     int
	terminal   error
	closed     bool
	closeOnce  sync.Once
	closeErr   error
}

func newBoundedStorageBodyV1(ctx context.Context, body io.ReadCloser, limit int64) *boundedStorageBodyV1 {
	b := &boundedStorageBodyStateV1{ctx: ctx, underlying: body, remaining: limit}
	b.joined = sync.NewCond(&b.mu)
	return &boundedStorageBodyV1{state: b}
}
func (handle *boundedStorageBodyV1) Read(p []byte) (int, error) {
	if handle == nil || handle.state == nil {
		return 0, errBoundedStorageResponseClosedV1
	}
	b := handle.state
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return 0, errBoundedStorageResponseClosedV1
	}
	if b.terminal != nil {
		err := b.terminal
		b.mu.Unlock()
		return 0, err
	}
	if len(p) == 0 {
		b.mu.Unlock()
		return 0, nil
	}
	b.active++
	b.mu.Unlock()
	// Only one underlying Read runs at a time. Close never needs readMu before
	// closing that underlying response, so it can unblock a live Read safely.
	b.readMu.Lock()
	defer func() {
		b.readMu.Unlock()
		b.mu.Lock()
		b.active--
		if b.active == 0 {
			b.joined.Broadcast()
		}
		b.mu.Unlock()
	}()
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return 0, errBoundedStorageResponseClosedV1
	}
	if b.terminal != nil {
		err := b.terminal
		b.mu.Unlock()
		return 0, err
	}
	if err := boundedStorageContextErrorV1(b.ctx); err != nil {
		b.terminal = err
		b.mu.Unlock()
		return 0, err
	}
	remaining := b.remaining
	b.mu.Unlock()
	var n int
	var err error
	if remaining == 0 {
		// One private byte distinguishes exact EOF from overrun. It is never exposed
		// to the SDK, whose io.ReadAll therefore receives at most the admitted cap.
		var probe [1]byte
		n, err = b.underlying.Read(probe[:])
		clear(probe[:])
		if n > 0 {
			n = 0
			err = errBoundedStorageResponseV1
		} else if err == nil {
			err = io.ErrNoProgress
		}
	} else {
		readBytes := len(p)
		if int64(readBytes) > remaining {
			readBytes = int(remaining)
		}
		n, err = b.underlying.Read(p[:readBytes])
		if n < 0 || n > readBytes {
			n = 0
			err = io.ErrNoProgress
		}
		if n == 0 && err == nil {
			err = io.ErrNoProgress
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.remaining -= int64(n)
	if canceled := boundedStorageContextErrorV1(b.ctx); canceled != nil {
		err = canceled
	} else if b.closed {
		err = errBoundedStorageResponseClosedV1
	} else if err != nil && err != io.EOF && err != errBoundedStorageResponseV1 {
		err = &boundedStorageFailureV1{cause: err}
	}
	if err != nil {
		b.terminal = err
	}
	return n, err
}
func (handle *boundedStorageBodyV1) Close() error {
	if handle == nil || handle.state == nil {
		return nil
	}
	b := handle.state
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		// The actual response Body must support concurrent Read/Close, as required
		// by net/http. Close directly unblocks it; logical cancellation is no credit.
		closeErr := b.underlying.Close()
		b.mu.Lock()
		// Join every Read admitted before the terminal mark, including queued Reads,
		// before returning the once-only Close result. No detached cleanup actor.
		for b.active != 0 {
			b.joined.Wait()
		}
		if closeErr != nil {
			b.closeErr = &boundedStorageFailureV1{cause: closeErr}
		}
		if canceled := boundedStorageContextErrorV1(b.ctx); canceled != nil {
			b.closeErr = errors.Join(b.closeErr, canceled)
		}
		b.underlying = nil
		b.ctx = nil
		b.mu.Unlock()
	})
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closeErr
}
