// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ai

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
)

var ErrNativeIOV1 = errors.New("ai: owned provider IO unavailable")

type NativeCompletionV1 struct{ state *aiNativeHTTPStateV1 }
type aiNativeHTTPStateV1 struct {
	mu                                          sync.Mutex
	self                                        *aiNativeHTTPStateV1
	ctx                                         context.Context
	grant, provider                             *workguard.GrantV1
	transport                                   *http.Transport
	connections                                 map[*aiNativeConnV1]struct{}
	changed, joined                             chan struct{}
	dialing, active                             int
	frameLimit                                  int64
	replay                                      *aiNativeReplayFrameV1
	deliveryFinal, deliverySucceeded            bool
	response                                    Response
	closing, ioJoined, consumerClosed, released bool
}

func (s *aiNativeHTTPStateV1) signalV1() { close(s.changed); s.changed = make(chan struct{}) }

// The fixed concrete provider issues one HTTP request. This private owner is
// installed before Transport receives a body and retained through its real Close.
func (s *aiNativeHTTPStateV1) holdReplayV1(frame *aiNativeReplayFrameV1) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closing || s.released || s.grant == nil || s.replay != nil {
		return ErrNativeIOV1
	}
	s.replay = frame
	return nil
}

func (s *aiNativeHTTPStateV1) finishDeliveryV1(success bool) {
	s.mu.Lock()
	s.deliveryFinal, s.deliverySucceeded = true, success
	if !success {
		// The error-path handle retains numeric observations only. A later IO join
		// cannot restore result authority that cancellation/provider failure lost.
		s.response.Text, s.response.Model, s.response.Provider = "", "", ""
	}
	s.mu.Unlock()
}

func (s *aiNativeHTTPStateV1) beginDialV1(base *http.Transport, secure bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closing || s.released || s.grant == nil {
		return ErrNativeIOV1
	}
	// One actual dial's connection/control, private64KiB staging buffer and
	// standard transport/TLS record controls are prepaid before construction.
	cost, err := aiNativeConnectionControlsV1(base, secure)
	if err != nil {
		return err
	}
	if err := s.grant.TryGrowParentV1(s.ctx, cost); err != nil {
		return errors.Join(ErrNativeIOV1, err)
	}
	s.dialing++
	return nil
}

func (s *aiNativeHTTPStateV1) finishDialV1(inner net.Conn, err error) (net.Conn, error) {
	s.mu.Lock()
	var conn *aiNativeConnV1
	if inner != nil {
		conn = &aiNativeConnV1{owner: s, inner: inner, done: make(chan struct{}), scratch: make([]byte, 64<<10)}
		if secure, ok := inner.(*tls.Conn); ok {
			state := secure.ConnectionState()
			conn.secure = &state
		}
		s.connections[conn] = struct{}{}
	}
	closing := s.closing
	s.mu.Unlock()
	if conn != nil && (closing || err != nil) {
		_ = conn.Close()
	}
	s.mu.Lock()
	s.dialing--
	s.signalV1()
	s.mu.Unlock()
	if closing {
		return nil, ErrNativeIOV1
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, ErrNativeIOV1
	}
	return conn, nil
}

func (s *aiNativeHTTPStateV1) dialV1(base *http.Transport) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := s.beginDialV1(base, false); err != nil {
			return nil, err
		}
		dial := base.DialContext
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		conn, err := dial(ctx, network, address)
		return s.finishDialV1(conn, err)
	}
}

func (s *aiNativeHTTPStateV1) dialTLSV1(base *http.Transport) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := s.beginDialV1(base, true); err != nil {
			return nil, err
		}
		dial := base.DialContext
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		conn, err := dial(ctx, network, address)
		if err == nil {
			config := s.transport.TLSClientConfig.Clone()
			if config.ServerName == "" {
				config.ServerName, _, err = net.SplitHostPort(address)
			}
			if err == nil {
				secure := tls.Client(conn, config)
				handshake, stop := context.WithCancel(ctx)
				if base.TLSHandshakeTimeout > 0 {
					stop()
					handshake, stop = context.WithTimeout(ctx, base.TLSHandshakeTimeout)
				}
				err = secure.HandshakeContext(handshake)
				stop()
				if err == nil {
					conn = secure
				}
			}
		}
		return s.finishDialV1(conn, err)
	}
}

func (s *aiNativeHTTPStateV1) closeIOV1() {
	for {
		s.mu.Lock()
		connections := make([]*aiNativeConnV1, 0, len(s.connections))
		for conn := range s.connections {
			connections = append(connections, conn)
		}
		changed := s.changed
		s.mu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		s.transport.CloseIdleConnections()
		s.mu.Lock()
		if s.dialing == 0 {
			replay := s.replay
			s.mu.Unlock()
			// RoundTrip may return a response before its asynchronous request-body
			// writer ends. Connection closure unblocks IO; actual body Close plus
			// sealed replay/read joins are a separate mandatory retirement gate.
			replay.waitV1()
			s.mu.Lock()
			s.ioJoined = true
			// The physical local stream ends at this proven method/body/dial/Conn
			// IO join. Parent frame/output debt has a separate private lifetime and
			// remains charged through every real output/error consumer last use.
			provider := s.provider
			s.provider = nil
			if provider != nil {
				provider.Close()
			}
			close(s.joined)
			s.releaseLockedV1()
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		<-changed
	}
}

func (h *NativeCompletionV1) WithResponseV1(consume func(Response) error) error {
	if h == nil || h.state == nil || consume == nil {
		return ErrNativeIOV1
	}
	s := h.state
	s.mu.Lock()
	if s.self != s || s.consumerClosed || s.released || !s.ioJoined || !s.deliveryFinal || !s.deliverySucceeded || s.grant == nil {
		s.mu.Unlock()
		return ErrNativeIOV1
	}
	s.active++
	response := s.response
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active--; s.releaseLockedV1(); s.mu.Unlock() }()
	return consume(response)
}

func (h *NativeCompletionV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.self == s {
		s.consumerClosed = true
		s.releaseLockedV1()
	}
	s.mu.Unlock()
}
func (s *aiNativeHTTPStateV1) releaseLockedV1() {
	if !s.consumerClosed || !s.ioJoined || s.active != 0 || s.released {
		return
	}
	s.released = true
	s.response = Response{}
	s.connections = nil
	s.replay = nil
	grant := s.grant
	s.grant = nil
	if grant != nil {
		grant.Close()
	}
}

type aiNativeRoundTripperV1 struct {
	owner     *aiNativeHTTPStateV1
	transport *http.Transport
}

func (r *aiNativeRoundTripperV1) RoundTrip(original *http.Request) (*http.Response, error) {
	if original == nil {
		return nil, ErrNativeIOV1
	}
	// CONNECT/TLS through a configured proxy would hide the decrypted stream
	// behind Transport's internal TLS owner. Refuse that unsupported native
	// profile rather than claim an unobserved header/parser join.
	if original.URL.Scheme == "https" && r.transport.Proxy != nil {
		proxy, err := r.transport.Proxy(original)
		if err != nil {
			return nil, err
		}
		if proxy != nil {
			return nil, ErrNativeIOV1
		}
	}
	request := original.Clone(original.Context())
	if original.Body != nil {
		frame, err := io.ReadAll(io.LimitReader(original.Body, r.owner.frameLimit+1))
		_ = original.Body.Close()
		if err != nil {
			return nil, err
		}
		if int64(len(frame)) > r.owner.frameLimit {
			clear(frame)
			return nil, ErrNativeIOV1
		}
		replay := newAINativeReplayFrameV1(frame)
		defer replay.closeV1()
		if err := r.owner.holdReplayV1(replay); err != nil {
			return nil, err
		}
		body, err := replay.bodyV1()
		if err != nil {
			return nil, err
		}
		request.Body = body
		// Preserve standard Transport safe nothing-written/reused-connection
		// replay, and default client307/308 replay. This private replay callback
		// exposes opaque readers only. RoundTrip return seals future callbacks;
		// already issued readers stay live until Transport actually closes them.
		// The parent state separately joins this frame before local stream credit.
		request.GetBody = replay.bodyV1
	}
	var actualMu sync.Mutex
	var actual *aiNativeConnV1
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if conn, ok := info.Conn.(*aiNativeConnV1); ok {
			actualMu.Lock()
			actual = conn
			actualMu.Unlock()
			conn.headerMu.Lock()
			conn.header = aiNativeHeaderInventoryV1{}
			conn.headerMu.Unlock()
		}
	}}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	response, err := r.transport.RoundTrip(request)
	if response != nil {
		if err := r.owner.grant.TryGrowParentV1(r.owner.ctx, (128<<10)+4*int64(unsafe.Sizeof(aiNativeResponseBodyV1{}))); err != nil {
			_ = response.Body.Close()
			return nil, errors.Join(ErrNativeIOV1, err)
		}
		// Go net/http/transfer.go refuses trailers without a terminator within
		// the actual persistConn bufio.Reader size. Fund that concrete parser
		// maximum only for an actual chunked response, before the original caller
		// can perform the body read that invokes its original trailer parser.
		for _, encoding := range response.TransferEncoding {
			if encoding == "chunked" {
				size := r.transport.ReadBufferSize
				if size <= 0 {
					size = 4096
				}
				trailerCost, costErr := aiNativeHeaderResourcesV1(int64(size), int64(size))
				if costErr == nil {
					costErr = r.owner.grant.TryGrowParentV1(r.owner.ctx, trailerCost)
				}
				if costErr != nil {
					_ = response.Body.Close()
					return nil, errors.Join(ErrNativeIOV1, costErr)
				}
				break
			}
		}
		response.Body = &aiNativeResponseBodyV1{owner: r.owner, body: response.Body, scratch: make([]byte, 64<<10), done: make(chan struct{})}
		actualMu.Lock()
		conn := actual
		actualMu.Unlock()
		if response.TLS == nil && conn != nil && conn.secure != nil {
			state := *conn.secure
			response.TLS = &state
		}
	}
	return response, err
}

type aiNativeConnV1 struct {
	owner               *aiNativeHTTPStateV1
	inner               net.Conn
	mu                  sync.Mutex
	readMu              sync.Mutex
	headerMu            sync.Mutex
	active              int
	closed, innerClosed bool
	done                chan struct{}
	scratch             []byte
	header              aiNativeHeaderInventoryV1
	secure              *tls.ConnectionState
}

func (c *aiNativeConnV1) beginIOV1() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.active++
	return nil
}
func (c *aiNativeConnV1) retireStagingLockedV1() {
	if !c.closed || !c.innerClosed || c.active != 0 {
		return
	}
	// Transport receives copied bytes only. It never receives this private
	// staging slice; actual inner Close + joined Read/Write proves its last use.
	clear(c.scratch)
	c.scratch = nil
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}
func (c *aiNativeConnV1) endIOV1() {
	c.mu.Lock()
	c.active--
	c.retireStagingLockedV1()
	c.mu.Unlock()
}
func (c *aiNativeConnV1) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := c.beginIOV1(); err != nil {
		return 0, err
	}
	defer c.endIOV1()
	if len(p) == 0 {
		return 0, nil
	}
	scratch := c.scratch[:min(len(p), len(c.scratch))]
	n, err := c.inner.Read(scratch)
	if n > 0 {
		c.headerMu.Lock()
		wire, lines := c.header.observeV1(scratch[:n])
		c.headerMu.Unlock()
		cost, inventoryErr := aiNativeHeaderResourcesV1(wire, lines)
		if inventoryErr == nil && cost > 0 {
			inventoryErr = c.owner.grant.TryGrowParentV1(c.owner.ctx, cost)
		}
		if inventoryErr != nil {
			clear(scratch[:n])
			return 0, errors.Join(ErrNativeIOV1, inventoryErr)
		}
		copy(p, scratch[:n])
		clear(scratch[:n])
	}
	return n, err
}
func (c *aiNativeConnV1) Write(p []byte) (int, error) {
	if err := c.beginIOV1(); err != nil {
		return 0, err
	}
	defer c.endIOV1()
	return c.inner.Write(p)
}
func (c *aiNativeConnV1) Close() error {
	c.mu.Lock()
	first := !c.closed
	c.closed = true
	c.mu.Unlock()
	var err error
	if first {
		err = c.inner.Close()
		c.mu.Lock()
		c.innerClosed = true
		c.retireStagingLockedV1()
		c.mu.Unlock()
	}
	<-c.done
	return err
}
func (c *aiNativeConnV1) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *aiNativeConnV1) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *aiNativeConnV1) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *aiNativeConnV1) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *aiNativeConnV1) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// A size inventory only, not an acceptance parser. It recognizes a complete
// final status/header boundary; undecidable/malformed prefixes stay conservatively
// in header mode until the real net/http parser accepts or rejects them.
type aiNativeHeaderInventoryV1 struct {
	prefix                      [64]byte
	used, lineBytes             int
	previous                    byte
	statusLine, final, complete bool
}

func (h *aiNativeHeaderInventoryV1) observeV1(raw []byte) (wire, lines int64) {
	for _, b := range raw {
		if h.complete {
			break
		}
		wire++
		if !h.statusLine && h.used < len(h.prefix) {
			h.prefix[h.used] = b
			h.used++
		}
		if b == '\n' {
			lines++
			if !h.statusLine {
				h.statusLine = true
				text := string(h.prefix[:h.used])
				if strings.HasPrefix(text, "HTTP/") {
					if _, status, ok := strings.Cut(text, " "); ok {
						status = strings.TrimLeft(status, " ")
						if len(status) >= 3 && status[0] >= '1' && status[0] <= '9' && status[1] >= '0' && status[1] <= '9' && status[2] >= '0' && status[2] <= '9' {
							h.final = status[0] != '1' || status[:3] == "101"
						}
					}
				}
			}
			if h.lineBytes == 0 || h.lineBytes == 1 && h.previous == '\r' {
				if h.final {
					h.complete = true
				} else {
					*h = aiNativeHeaderInventoryV1{}
				}
			} else {
				h.lineBytes = 0
			}
		} else {
			h.lineBytes++
		}
		h.previous = b
	}
	return
}

var _ net.Conn = (*aiNativeConnV1)(nil)
var _ http.RoundTripper = (*aiNativeRoundTripperV1)(nil)

// Private decrypted response staging. A bounded read happens under prepaid
// scratch; actual prefix bytes are priced BEFORE the caller receives them and
// before original ReadAll growth, json.Unmarshal, text/error concatenation.
type aiNativeResponseBodyV1 struct {
	mu                  sync.Mutex
	readMu              sync.Mutex
	owner               *aiNativeHTTPStateV1
	body                io.ReadCloser
	scratch             []byte
	done                chan struct{}
	active              int
	closed, innerClosed bool
}

func (b *aiNativeResponseBodyV1) finishV1() { b.mu.Lock(); b.active--; b.retireV1(); b.mu.Unlock() }
func (b *aiNativeResponseBodyV1) retireV1() {
	if !b.closed || !b.innerClosed || b.active != 0 {
		return
	}
	clear(b.scratch)
	b.scratch = nil
	if b.done != nil {
		select {
		case <-b.done:
		default:
			close(b.done)
		}
	}
}
func (b *aiNativeResponseBodyV1) Read(p []byte) (int, error) {
	b.readMu.Lock()
	defer b.readMu.Unlock()
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return 0, io.EOF
	}
	if len(p) == 0 {
		b.mu.Unlock()
		return 0, nil
	}
	b.active++
	scratch := b.scratch[:min(len(p), len(b.scratch))]
	b.mu.Unlock()
	defer b.finishV1()
	n, err := b.body.Read(scratch)
	if n > 0 {
		cost := int64(0)
		if !aiNativeAddV1(&cost, int64(n), 512) {
			clear(scratch[:n])
			return 0, ErrNativeIOV1
		}
		if e := b.owner.grant.TryGrowParentV1(b.owner.ctx, cost); e != nil {
			clear(scratch[:n])
			return 0, errors.Join(ErrNativeIOV1, e)
		}
		copy(p, scratch[:n])
		clear(scratch[:n])
	}
	return n, err
}
func (b *aiNativeResponseBodyV1) Close() error {
	b.mu.Lock()
	first := !b.closed
	b.closed = true
	if b.done == nil {
		b.done = make(chan struct{})
	}
	done := b.done
	b.mu.Unlock()
	var err error
	if first {
		err = b.body.Close()
		b.mu.Lock()
		b.innerClosed = true
		b.retireV1()
		b.mu.Unlock()
	}
	<-done
	return err
}

// Fixed numeric provider observations can survive a cancelled delivery/IO join.
// No private text/model is borrowed before the actual local IO has joined.
type NativeUsageObservationV1 struct{ InputTokens, OutputTokens int }

func (h *NativeCompletionV1) UsageObservationV1() (NativeUsageObservationV1, error) {
	if h == nil || h.state == nil {
		return NativeUsageObservationV1{}, ErrNativeIOV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.consumerClosed || s.released || s.grant == nil {
		return NativeUsageObservationV1{}, ErrNativeIOV1
	}
	return NativeUsageObservationV1{InputTokens: s.response.InputTokens, OutputTokens: s.response.OutputTokens}, nil
}
