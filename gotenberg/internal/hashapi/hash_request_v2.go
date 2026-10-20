// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type hashRequestKeyV2 struct{}
type hashWireBodyKeyV2 struct{}
type hashControlV2 struct {
	mu     sync.Mutex
	frozen bool
	raw    *http.ResponseController
}

func (c *hashControlV2) set(t time.Time, read bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		return http.ErrHandlerTimeout
	}
	if read {
		return c.raw.SetReadDeadline(t)
	}
	return c.raw.SetWriteDeadline(t)
}
func (c *hashControlV2) expireRead() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.raw.SetReadDeadline(time.Now())
}
func (c *hashControlV2) freeze(active bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frozen = true
	if active {
		_ = c.raw.SetReadDeadline(time.Now())
		_ = c.raw.SetWriteDeadline(time.Now())
	}
}

// The server registry is the retirement authority. Worker completion is a
// final close(done), never merely a result send; an external observer prunes
// completed records only after both worker and outer handler have retired.
type hashRequestV2 struct {
	server   *hashAPIServerV1
	done     chan struct{}
	wake     chan struct{}
	cancel   context.CancelFunc
	response *hashResponseV2
	body     *hashBodyV2
	control  *hashControlV2
	cleanups []func() error // sole worker owns registration/execution

	// Protected by server.mu.
	outerDone     bool
	lease         bool
	endErr        error
	outputErr     error
	inputDrainErr error
	quarantined   bool

	timerMu     sync.Mutex
	hardUntil   time.Time
	readUntil   time.Time
	hardExpired bool
	panicValue  any
}

func hashRequestFromV2(r *http.Request) *hashRequestV2 {
	owner, _ := r.Context().Value(hashRequestKeyV2{}).(*hashRequestV2)
	return owner
}
func (o *hashRequestV2) notify() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}
func (o *hashRequestV2) addCleanup(f func() error) { o.cleanups = append(o.cleanups, f) }
func (o *hashRequestV2) failOutput(err error) {
	o.server.mu.Lock()
	o.outputErr = errors.Join(o.outputErr, err)
	o.server.mu.Unlock()
}
func (o *hashRequestV2) armHard(d time.Duration) {
	o.timerMu.Lock()
	o.hardUntil = time.Now().Add(d)
	o.timerMu.Unlock()
	o.notify()
}
func (o *hashRequestV2) disarmHard() error {
	o.timerMu.Lock()
	defer o.timerMu.Unlock()
	if !o.hardUntil.IsZero() && !time.Now().Before(o.hardUntil) {
		o.hardExpired = true
	}
	o.hardUntil = time.Time{}
	o.notify()
	if o.hardExpired {
		o.response.mu.Lock()
		o.response.frozen = true
		o.response.mu.Unlock()
		return fmt.Errorf("hard timeout: %w", context.DeadlineExceeded)
	}
	return nil
}
func (o *hashRequestV2) stageDeadline(t time.Time) {
	o.timerMu.Lock()
	o.readUntil = t
	o.timerMu.Unlock()
	o.notify()
}
func (o *hashRequestV2) deadlines() (time.Time, bool, bool) {
	o.timerMu.Lock()
	defer o.timerMu.Unlock()
	now := time.Now()
	if !o.hardUntil.IsZero() && !now.Before(o.hardUntil) {
		o.hardExpired = true
	}
	readExpired := !o.readUntil.IsZero() && !now.Before(o.readUntil)
	if readExpired {
		o.readUntil = time.Time{}
	}
	next := o.hardUntil
	if o.hardExpired {
		next = time.Time{}
	}
	if !o.readUntil.IsZero() && (next.IsZero() || o.readUntil.Before(next)) {
		next = o.readUntil
	}
	return next, o.hardExpired, readExpired
}

func (s *hashAPIServerV1) pruneRequestsV2() {
	// Caller holds s.mu. No owner timer/writer lock is acquired here.
	for o := range s.owners {
		if !o.outerDone {
			continue
		}
		select {
		case <-o.done:
		default:
			continue
		}
		if o.endErr != nil {
			if !o.quarantined {
				o.quarantined = true
				s.cleanupErr = errors.Join(s.cleanupErr, o.endErr)
			}
			continue
		}
		delete(s.owners, o)
		s.requests--
		if o.lease {
			s.multipart--
		}
	}
}
func (o *hashRequestV2) reserveMultipart() bool {
	s := o.server
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneRequestsV2()
	if s.retiring || o.lease || s.multipart >= 2 {
		return false
	}
	s.multipart++
	o.lease = true
	return true
}
func (s *hashAPIServerV1) healthV2() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneRequestsV2()
	return s.cleanupErr
}
func (o *hashRequestV2) cleanup() error {
	var err error
	for i := len(o.cleanups) - 1; i >= 0; i-- {
		err = errors.Join(err, hashCleanupCallV2(o.cleanups[i]))
	}
	return err
}

func (s *hashAPIServerV1) serveOwnedV2(w http.ResponseWriter, r *http.Request, inner http.Handler) {
	ctx, cancel := context.WithCancel(r.Context())
	o := &hashRequestV2{server: s, done: make(chan struct{}), wake: make(chan struct{}, 1), cancel: cancel, control: &hashControlV2{raw: http.NewResponseController(w)}}
	o.response = newHashResponseV2(w)
	o.response.control = o.control
	wire, _ := r.Context().Value(hashWireBodyKeyV2{}).(bool)
	o.body = &hashBodyV2{raw: r.Body, wire: wire}
	// Clone both request metadata and parser caches away from net/http's final
	// request cleanup. The raw body is accessible only through its owned gate.
	request := r.Clone(context.WithValue(ctx, hashRequestKeyV2{}, o))
	request.Body = o.body
	s.mu.Lock()
	s.pruneRequestsV2()
	if s.retiring {
		s.mu.Unlock()
		cancel()
		panic(http.ErrAbortHandler)
	}
	if s.owners == nil {
		s.owners = make(map[*hashRequestV2]struct{})
	}
	s.owners[o] = struct{}{}
	s.requests++
	s.mu.Unlock()
	defer cancel()
	defer func() {
		s.mu.Lock()
		o.outerDone = true
		s.pruneRequestsV2()
		s.mu.Unlock()
		s.signal()
	}()
	go func() {
		defer close(o.done) // Last worker action, after all cleanup and telemetry.
		defer s.signal()
		defer func() {
			value := recover()
			err := o.cleanup()
			if value != nil {
				// A worker panic is recorded for the outer handler, with cleanup still
				// owned. Do not turn its response into an implicit successful200.
				o.timerMu.Lock()
				o.panicValue = value
				o.timerMu.Unlock()
			}
			s.mu.Lock()
			o.endErr = errors.Join(o.endErr, err)
			s.mu.Unlock()
		}()
		inner.ServeHTTP(o.response, request)
	}()

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		next, hard, readExpired := o.deadlines()
		if readExpired {
			// Interrupt a real stalled upload at the ORIGINAL processing deadline.
			// Never replace an earlier server deadline with a later one.
			_ = o.control.expireRead()
		}
		if hard {
			o.abandonV2(w, r, true)
			return
		}
		var timerC <-chan time.Time
		if !next.IsZero() {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(max(0, time.Until(next)))
			timerC = timer.C
		}
		select {
		case <-o.done:
			o.timerMu.Lock()
			value := o.panicValue
			o.timerMu.Unlock()
			if value != nil {
				o.response.freeze(o.control)
				o.finishBodyV2(r)
				panic(value)
			}
			// Completion never erases an already-expired armed hard deadline.
			_, expired, _ := o.deadlines()
			if expired {
				o.abandonV2(w, r, true)
				return
			}
			o.response.freeze(o.control)
			o.finishBodyV2(r)
			s.mu.Lock()
			cleanupErr := errors.Join(o.endErr, o.outputErr)
			s.mu.Unlock()
			if cleanupErr != nil {
				panic(http.ErrAbortHandler)
			}
			return
		case <-r.Context().Done():
			o.abandonV2(w, r, false)
			return
		case <-o.wake:
		case <-timerC:
		}
	}
}
func (o *hashRequestV2) finishBodyV2(r *http.Request) {
	// Aborting an unread body before Close prevents net/http's early-close
	// drain from retaining a network read. No raw body operation may survive
	// return from the outer handler.
	if !o.body.atEOF() {
		r.Close = true
		_ = o.control.expireRead()
	}
	err := o.body.finish()
	// Go1.26.9 net/http/transfer.go body.Close marks the HTTP1 body closed on
	// every normal return; its returned errors describe input-drain failure.
	// The read gate has joined and sockets stay independently tracked. Only
	// this exact server-owned HTTP1 body qualifies; arbitrary closers and
	// recovered panics remain cleanup uncertainty.
	o.body.mu.Lock()
	knownInputDrain := o.body.wire && r.ProtoMajor == 1 && o.body.closeReturned
	o.body.mu.Unlock()
	if err != nil && knownInputDrain {
		o.server.mu.Lock()
		o.inputDrainErr = errors.Join(o.inputDrainErr, err)
		o.server.mu.Unlock()
		return
	}
	if err != nil && !knownInputDrain {
		o.server.mu.Lock()
		o.endErr = errors.Join(o.endErr, fmt.Errorf("request body close: %w", err))
		o.server.mu.Unlock()
	}
}
func (o *hashRequestV2) abandonV2(w http.ResponseWriter, r *http.Request, timeout bool) {
	o.cancel()
	_ = o.control.expireRead()
	// Freeze does not hold the I/O mutex while expiring a blocked write. It
	// physically joins every admitted raw writer operation before returning.
	committed, wasActive := o.response.freeze(o.control)
	o.finishBodyV2(r)
	if timeout && !committed && !wasActive {
		// No worker header map or Echo response state is read by this goroutine.
		// No expired write deadline is reset to manufacture a fresh503.
		status, message := ParseError(context.DeadlineExceeded)
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
			r.Close = true
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, message)
		return
	}
	panic(http.ErrAbortHandler)
}

type hashResponseV2 struct {
	control   *hashControlV2
	header    http.Header
	raw       http.ResponseWriter
	ioMu      sync.Mutex
	mu        sync.Mutex
	frozen    bool
	active    bool
	idle      chan struct{}
	committed bool
}

func newHashResponseV2(w http.ResponseWriter) *hashResponseV2 {
	return &hashResponseV2{header: make(http.Header), raw: w, control: &hashControlV2{raw: http.NewResponseController(w)}}
}
func (w *hashResponseV2) Header() http.Header                { return w.header }
func (w *hashResponseV2) SetReadDeadline(t time.Time) error  { return w.control.set(t, true) }
func (w *hashResponseV2) SetWriteDeadline(t time.Time) error { return w.control.set(t, false) }
func (w *hashResponseV2) begin() (http.ResponseWriter, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.frozen {
		return nil, false
	}
	w.active = true
	w.idle = make(chan struct{})
	return w.raw, true
}
func (w *hashResponseV2) end() {
	w.mu.Lock()
	w.active = false
	close(w.idle)
	if w.frozen {
		w.raw = nil
	}
	w.mu.Unlock()
}
func (w *hashResponseV2) commit(raw http.ResponseWriter, status int) {
	w.mu.Lock()
	committed := w.committed
	if !committed {
		w.committed = true
	}
	w.mu.Unlock()
	if committed {
		return
	}
	raw.Header().Del("Content-Length")
	for k, v := range w.header {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		raw.Header()[k] = append([]string(nil), v...)
	}
	raw.WriteHeader(status)
}
func (w *hashResponseV2) WriteHeader(status int) {
	w.ioMu.Lock()
	defer w.ioMu.Unlock()
	raw, ok := w.begin()
	if !ok {
		return
	}
	defer w.end()
	w.commit(raw, status)
}
func (w *hashResponseV2) Write(p []byte) (int, error) {
	w.ioMu.Lock()
	defer w.ioMu.Unlock()
	raw, ok := w.begin()
	if !ok {
		return 0, http.ErrHandlerTimeout
	}
	defer w.end()
	w.commit(raw, http.StatusOK)
	return raw.Write(p)
}
func (w *hashResponseV2) FlushError() error {
	w.ioMu.Lock()
	defer w.ioMu.Unlock()
	raw, ok := w.begin()
	if !ok {
		return http.ErrHandlerTimeout
	}
	defer w.end()
	w.commit(raw, http.StatusOK)
	return http.NewResponseController(raw).Flush()
}
func (w *hashResponseV2) Flush() { _ = w.FlushError() }

// No Unwrap, Hijacker, ReaderFrom or Pusher. Deadline controls share the
// short ownership lock; no worker can extend a deadline after abandonment.
func (w *hashResponseV2) freeze(control *hashControlV2) (bool, bool) {
	w.mu.Lock()
	w.frozen = true
	committed, active, idle := w.committed, w.active, w.idle
	if !active {
		w.raw = nil
	}
	w.mu.Unlock()
	control.freeze(active)
	if active {
		<-idle
	}
	return committed, active
}

type hashBodyV2 struct {
	wire          bool
	closeReturned bool
	raw           io.ReadCloser
	ioMu          sync.Mutex
	mu            sync.Mutex
	frozen        bool
	eof           bool
	closed        bool
	closeErr      error
}

func (b *hashBodyV2) Read(p []byte) (int, error) {
	b.ioMu.Lock()
	defer b.ioMu.Unlock()
	b.mu.Lock()
	denied := b.frozen || b.closed
	b.mu.Unlock()
	if denied {
		return 0, http.ErrHandlerTimeout
	}
	n, err := b.raw.Read(p)
	if errors.Is(err, io.EOF) {
		b.mu.Lock()
		b.eof = true
		b.mu.Unlock()
	}
	return n, err
}
func (b *hashBodyV2) atEOF() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.eof || b.raw == http.NoBody
}
func (b *hashBodyV2) Close() error {
	b.ioMu.Lock()
	defer b.ioMu.Unlock()
	b.mu.Lock()
	if b.closed {
		err := b.closeErr
		b.mu.Unlock()
		return err
	}
	b.closed = true
	b.mu.Unlock()
	returned := false
	err := hashCleanupCallV2(func() error { err := b.raw.Close(); returned = true; return err })
	b.mu.Lock()
	b.closeReturned = returned
	b.closeErr = err
	b.mu.Unlock()
	return err
}
func (b *hashBodyV2) finish() error {
	b.mu.Lock()
	b.frozen = true
	b.mu.Unlock()
	// ReadDeadline was expired without holding either gate lock. Taking ioMu
	// joins a possibly blocked Read before closing the exact original body.
	return b.Close()
}
