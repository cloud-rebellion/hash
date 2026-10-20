// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// These controlled transports perform no network/provider work. They qualify
// the real SDK's allocation path and local response Read/Close ordering only;
// neither counts nor joined fixture actors prove remote/whole-transport retirement.
type boundedStorageRoundTripTestV1 func(*http.Request) (*http.Response, error)

func (f boundedStorageRoundTripTestV1) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type boundedStorageStreamTestV1 struct {
	mu        sync.Mutex
	left      int64
	readBytes int64
	closed    bool
	closes    atomic.Int32
}

func (s *boundedStorageStreamTestV1) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if s.left == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > s.left {
		n = int(s.left)
	}
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	s.left -= int64(n)
	s.readBytes += int64(n)
	return n, nil
}
func (s *boundedStorageStreamTestV1) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.closes.Add(1)
	return nil
}
func (s *boundedStorageStreamTestV1) observed() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readBytes
}
func boundedStorageResponseTestV1(r *http.Request, status int, size int64, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Content-Length": {strconv.FormatInt(size, 10)}, "Content-Type": {"application/pdf"}, "Last-Modified": {"Mon, 12 Oct 2026 00:00:00 GMT"}, "Etag": {"\"synthetic-etag\""}, "X-Amz-Version-Id": {"owned-response-version-1"}}, ContentLength: size, Body: body, Request: r}
}

func TestBoundedStorageTransportStopsSDKErrorAllocationAndDrainV1(t *testing.T) {
	//201 is deliberately included: MinIO77 treats it as an error even though it
	// is2xx. Both bodies would exceed the actual admitted SDK error profile.
	for _, status := range []int{http.StatusBadRequest, http.StatusCreated} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			stream := &boundedStorageStreamTestV1{left: 1 << 30}
			var calls atomic.Int32
			transport := &boundedStorageTransportV1{base: boundedStorageRoundTripTestV1(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				return boundedStorageResponseTestV1(r, status, stream.left, stream), nil
			})}
			mc, err := minio.New("bounded-sdk.invalid", &minio.Options{Region: "us-east-1", Creds: credentials.NewStaticV4("synthetic-access", "synthetic-secret", ""), Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			opts := minio.GetObjectOptions{}
			opts.VersionID = "owned-response-version-1"
			body, _, _, err := (minio.Core{Client: mc}).GetObject(ctx, "hash-bounded-test", "owned.pdf", opts)
			if body != nil || !errors.Is(err, errBoundedStorageResponseV1) {
				t.Fatal("real SDK consumed an unbounded error body", err)
			}
			if stream.observed() != boundedStorageErrorBytesV1+1 || stream.closes.Load() != 1 || calls.Load() != 1 {
				t.Fatal("SDK error/drain crossed the cap or response did not close exactly once")
			}
		})
	}
}

func TestBoundedStorageTransportSuccessfulProfilesAndPermanentRefusalV1(t *testing.T) {
	for _, mode := range []string{"admitted-get", "metadata-list-get", "metadata-put", "head-keeps-metadata-profile"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			method := http.MethodGet
			cap := boundedStorageMetadataBytesV1
			if mode == "admitted-get" {
				ctx = withObjectResponseLimitV1(ctx, 19)
				cap = 20
			}
			if mode == "metadata-put" {
				method = http.MethodPut
			}
			if mode == "head-keeps-metadata-profile" {
				method = http.MethodHead
				ctx = withObjectResponseLimitV1(ctx, 19)
			}
			stream := &boundedStorageStreamTestV1{left: cap + 100}
			transport := &boundedStorageTransportV1{base: boundedStorageRoundTripTestV1(func(r *http.Request) (*http.Response, error) {
				return boundedStorageResponseTestV1(r, http.StatusOK, cap+100, stream), nil
			})}
			request, err := http.NewRequestWithContext(ctx, method, "https://bounded-sdk.invalid/hash-bounded-test?list-type=2", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			if int64(len(raw)) != cap || !errors.Is(err, errBoundedStorageResponseV1) {
				t.Fatal("successful response escaped its admitted profile", err)
			}
			before := stream.observed()
			var scratch [32]byte
			for i := 0; i < 3; i++ {
				n, readErr := response.Body.Read(scratch[:])
				if n != 0 || !errors.Is(readErr, errBoundedStorageResponseV1) {
					t.Fatal("terminal refusal resumed reading")
				}
			}
			if before != cap+1 || stream.observed() != before {
				t.Fatal("SDK drain could read beyond permanent refusal")
			}
			if err := response.Body.Close(); err != nil || stream.closes.Load() != 1 {
				t.Fatal("bounded response failed direct Close", err)
			}
		})
	}
}

func TestBoundedStorageTransportExactEOFAndInvalidAdmissionV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// A body exactly at the admitted boundary is accepted only after actual EOF;
	// the private probe does not fabricate overflow or expose an extra SDK byte.
	stream := &boundedStorageStreamTestV1{left: 17}
	var calls atomic.Int32
	transport := &boundedStorageTransportV1{base: boundedStorageRoundTripTestV1(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return boundedStorageResponseTestV1(r, http.StatusOK, 17, stream), nil
	})}
	request, err := http.NewRequestWithContext(withObjectResponseLimitV1(ctx, 16), http.MethodGet, "https://bounded-sdk.invalid/owned.pdf", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(response.Body)
	if err != nil || len(raw) != 17 || stream.observed() != 17 {
		t.Fatal("exact admitted EOF was refused", err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{0, -1, maxStoredObjectBytes + 1} {
		request = request.Clone(withObjectResponseLimitV1(ctx, limit))
		response, err = transport.RoundTrip(request)
		if response != nil || !errors.Is(err, errBoundedStorageRequestV1) {
			t.Fatal("invalid response admission reached transport")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("invalid profile performed provider I/O")
	}
}

type boundedStorageJoinedBodyTestV1 struct {
	readEntered, releaseRead, finishRead, closeEntered, finishClose chan struct{}
	readOnce, closeOnce                                             sync.Once
	closes                                                          atomic.Int32
	closeErr                                                        error
}

func (b *boundedStorageJoinedBodyTestV1) Read([]byte) (int, error) {
	b.readOnce.Do(func() { close(b.readEntered) })
	<-b.releaseRead
	<-b.finishRead
	return 0, io.EOF
}
func (b *boundedStorageJoinedBodyTestV1) Close() error {
	b.closes.Add(1)
	b.closeOnce.Do(func() { close(b.closeEntered); close(b.releaseRead) })
	<-b.finishClose
	return b.closeErr
}
func TestBoundedStorageResponseCloseUnblocksThenJoinsAllReadsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	privateClose := errors.New("PRIVATE_BOUNDED_CLOSE_CAUSE")
	underlying := &boundedStorageJoinedBodyTestV1{readEntered: make(chan struct{}), releaseRead: make(chan struct{}), finishRead: make(chan struct{}), closeEntered: make(chan struct{}), finishClose: make(chan struct{}), closeErr: privateClose}
	body := newBoundedStorageBodyV1(ctx, underlying, 128)
	var finishRead, finishClose sync.Once
	readDone := make(chan struct{})
	closeDone := make(chan struct{})
	secondDone := make(chan struct{})
	closeResult := make(chan error, 1)
	secondResult := make(chan error, 1)
	go func() { defer close(readDone); var p [32]byte; _, _ = body.Read(p[:]) }()
	var secondStarted atomic.Bool
	t.Cleanup(func() {
		finishRead.Do(func() { close(underlying.finishRead) })
		finishClose.Do(func() { close(underlying.finishClose) })
		_ = body.Close()
		for _, done := range []<-chan struct{}{readDone, closeDone} {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("bounded response actor did not join")
			}
		}
		if secondStarted.Load() {
			select {
			case <-secondDone:
			case <-time.After(2 * time.Second):
				t.Error("second Close actor did not join")
			}
		}
	})
	select {
	case <-underlying.readEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("active response Read not witnessed")
	}
	go func() { defer close(closeDone); closeResult <- body.Close() }()
	select {
	case <-underlying.closeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("Close could not reach underlying response while Read blocked")
	}
	copied := *body // copied opaque handle must preserve the same physical owner
	secondStarted.Store(true)
	go func() { defer close(secondDone); secondResult <- copied.Close() }()
	finishClose.Do(func() { close(underlying.finishClose) })
	// Underlying Close has been released, but the active Read still owns its
	// critical section. Both public Close calls must remain joined to that Read.
	select {
	case <-closeDone:
		t.Fatal("Close credited active Read after underlying Close")
	default:
	}
	select {
	case <-secondDone:
		t.Fatal("concurrent Close bypassed joined result")
	default:
	}
	var after [1]byte
	if n, e := body.Read(after[:]); n != 0 || !errors.Is(e, errBoundedStorageResponseClosedV1) {
		t.Fatal("terminal Close admitted a new Read")
	}
	finishRead.Do(func() { close(underlying.finishRead) })
	for _, done := range []<-chan struct{}{readDone, closeDone, secondDone} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("response actor did not join")
		}
	}
	first, second := <-closeResult, <-secondResult
	if underlying.closes.Load() != 1 || !errors.Is(first, privateClose) || !errors.Is(second, privateClose) || first != second || strings.Contains(first.Error(), "PRIVATE") {
		t.Fatal("once-only joined Close result lost error identity or redaction")
	}
}

type boundedStorageCancellationBodyTestV1 struct {
	ctx     context.Context
	entered chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func (b *boundedStorageCancellationBodyTestV1) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (b *boundedStorageCancellationBodyTestV1) Close() error { b.closes.Add(1); return nil }
func TestBoundedStorageResponseCancellationPreservesCauseAndJoinsV1(t *testing.T) {
	deadline, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	ctx, cancel := context.WithCancelCause(deadline)
	underlying := &boundedStorageCancellationBodyTestV1{ctx: ctx, entered: make(chan struct{})}
	body := newBoundedStorageBodyV1(ctx, underlying, 128)
	privateCause := errors.New("PRIVATE_BOUNDED_CANCEL_CAUSE")
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() { defer close(done); _, err := io.ReadAll(body); result <- err }()
	t.Cleanup(func() {
		cancel(privateCause)
		_ = body.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("canceled response Read did not join")
		}
	})
	select {
	case <-underlying.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("response Read not witnessed")
	}
	cancel(privateCause)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled response Read did not join")
	}
	err := <-result
	if !errors.Is(err, context.Canceled) || !errors.Is(err, privateCause) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("response cancellation cause identity/redaction lost")
	}
	if err := body.Close(); !errors.Is(err, context.Canceled) || !errors.Is(err, privateCause) || strings.Contains(err.Error(), "PRIVATE") || underlying.closes.Load() != 1 {
		t.Fatal("canceled response did not directly close with preserved cause", err)
	}
}

func TestBoundedStorageTransportPreservesReadFailureWithoutPrivateTextV1(t *testing.T) {
	privateErr := errors.New("PRIVATE_RESPONSE_READ_CAUSE")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	underlying := &boundedStorageFailureBodyTestV1{err: privateErr}
	body := newBoundedStorageBodyV1(ctx, underlying, 128)
	raw, err := io.ReadAll(body)
	if len(raw) != 0 || !errors.Is(err, privateErr) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("read failure identity/redaction lost")
	}
	var p [16]byte
	_, _ = body.Read(p[:])
	if underlying.reads.Load() != 1 {
		t.Fatal("failure resumed underlying Read")
	}
	if err := body.Close(); err != nil || underlying.closes.Load() != 1 {
		t.Fatal("failed response cleanup lost", err)
	}
}

type boundedStorageFailureBodyTestV1 struct {
	err           error
	reads, closes atomic.Int32
}

func (b *boundedStorageFailureBodyTestV1) Read([]byte) (int, error) { b.reads.Add(1); return 0, b.err }
func (b *boundedStorageFailureBodyTestV1) Close() error             { b.closes.Add(1); return nil }

// Ensure the cap is delivered to consumers, rather than substituting empty data.
func TestBoundedStorageResponseKeepsExactSuccessfulBytesV1(t *testing.T) {
	raw := []byte("an owned exact response")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	body := newBoundedStorageBodyV1(ctx, io.NopCloser(bytes.NewReader(raw)), int64(len(raw))+1)
	got, err := io.ReadAll(body)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("bounded response changed exact bytes", err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
}
