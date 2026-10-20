// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

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

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

var ErrEvidenceLocalIOV1 = errors.New("storage: owned local evidence IO unavailable")

// One private finite evidence PUT/reuse/readback operation. The existing SDK
// and standard HTTP parser perform their original protocol; the native local
// owner accounts actual request frames, header producers and response reads.
// Local IO/byte joins are not remote S3 termination, SDK goroutine, opaque
// Transport/TLS/x509 pool or physical-RSS retirement evidence.
type EvidenceLocalPutV1 struct{ state *evidenceLocalPutStateV1 }
type evidenceLocalPutStateV1 struct {
	mu                                          sync.Mutex
	self                                        *evidenceLocalPutStateV1
	ctx                                         context.Context
	grant                                       *workguard.GrantV1
	provider                                    *workguard.GrantV1
	coordinator                                 *workguard.CoordinatorV1
	org                                         uuid.UUID
	admission                                   *storageConnectionAdmissionV1
	transport                                   *http.Transport
	connections                                 map[*evidenceLocalConnV1]struct{}
	changed                                     chan struct{}
	joined                                      chan struct{}
	dialing, active                             int
	frameLimit                                  int64
	data                                        []byte
	hashScratch                                 []byte
	stored                                      StoredObject
	success                                     bool
	bodies                                      map[*evidenceLocalResponseBodyV1]struct{}
	closing, ioJoined, consumerClosed, released bool
}

func (s *evidenceLocalPutStateV1) signalV1() { close(s.changed); s.changed = make(chan struct{}) }

func (s *evidenceLocalPutStateV1) beginDialV1(base *http.Transport, secure bool, address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closing || s.released || s.grant == nil {
		return ErrEvidenceLocalIOV1
	}
	// One actual dial's connection/control, private64KiB staging buffer and
	// standard transport/TLS record controls are prepaid before construction.
	cost, err := evidenceLocalConnectionControlsV1(base, secure)
	if err != nil {
		return err
	}
	if !evidenceLocalAddV1(&cost, int64(len(address)), 32) {
		return ErrEvidenceLocalIOV1
	}
	if err := s.grant.TryGrowParentV1(s.ctx, cost); err != nil {
		return errors.Join(ErrEvidenceLocalIOV1, err)
	}
	s.dialing++
	return nil
}

func (s *evidenceLocalPutStateV1) finishDialV1(inner net.Conn, err error) (net.Conn, error) {
	s.mu.Lock()
	var conn *evidenceLocalConnV1
	if inner != nil {
		conn = &evidenceLocalConnV1{owner: s, inner: inner, done: make(chan struct{}), scratch: make([]byte, 64<<10)}
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
		return nil, ErrEvidenceLocalIOV1
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, ErrEvidenceLocalIOV1
	}
	return conn, nil
}

func (s *evidenceLocalPutStateV1) dialV1(base *http.Transport) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := s.beginDialV1(base, false, address); err != nil {
			return nil, err
		}
		dial := base.DialContext
		if dial == nil {
			return s.finishDialV1(nil, ErrEvidenceLocalIOV1)
		}
		conn, err := dial(ctx, network, address)
		return s.finishDialV1(conn, err)
	}
}

func (s *evidenceLocalPutStateV1) dialTLSV1(base *http.Transport) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := s.beginDialV1(base, true, address); err != nil {
			return nil, err
		}
		dial := base.DialContext
		if dial == nil {
			return s.finishDialV1(nil, ErrEvidenceLocalIOV1)
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

func (s *evidenceLocalPutStateV1) closeIOV1() {
	for {
		s.mu.Lock()
		connections := make([]*evidenceLocalConnV1, 0, len(s.connections))
		bodies := make([]*evidenceLocalResponseBodyV1, 0, len(s.bodies))
		for body := range s.bodies {
			bodies = append(bodies, body)
		}
		for conn := range s.connections {
			connections = append(connections, conn)
		}
		changed := s.changed
		s.mu.Unlock()
		for _, body := range bodies {
			_ = body.Close()
		}
		for _, conn := range connections {
			_ = conn.Close()
		}
		s.transport.CloseIdleConnections()
		s.mu.Lock()
		if s.dialing == 0 {
			if s.admission != nil {
				s.admission.unregisterV1(s.transport)
			}
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

// WithStoredV1 is a synchronous result borrower after proven local IO join.
// The callback must independently own any VersionID it keeps after returning.
func (h *EvidenceLocalPutV1) WithStoredV1(consume func(StoredObject) error) error {
	if consume == nil {
		return ErrEvidenceLocalIOV1
	}
	return h.withStoredObservationV1(true, func(stored StoredObject, _ bool) error { return consume(stored) })
}

// WithObservationV1 borrows a positive version after proven local IO join,
// including failed PUT/reuse/retention results. succeeded is the original
// operation's result, not publication authority. A pinned resume reports its
// supplied persisted identity. The callback must independently own retained
// strings, and keep this handle alive through its actual checkpoint/error use.
// Absence of a positive version is refused rather than invented as success.
func (h *EvidenceLocalPutV1) WithObservationV1(consume func(StoredObject, bool) error) error {
	return h.withStoredObservationV1(false, consume)
}

func (h *EvidenceLocalPutV1) withStoredObservationV1(requireSuccess bool, consume func(StoredObject, bool) error) error {
	if h == nil || h.state == nil || consume == nil {
		return ErrEvidenceLocalIOV1
	}
	s := h.state
	s.mu.Lock()
	if s.self != s || s.consumerClosed || s.released || !s.ioJoined || (requireSuccess && !s.success) || s.stored.VersionID == "" || s.grant == nil {
		s.mu.Unlock()
		return ErrEvidenceLocalIOV1
	}
	s.active++
	stored := s.stored
	succeeded := s.success
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active--; s.releaseLockedV1(); s.mu.Unlock() }()
	return consume(stored, succeeded)
}

func (h *EvidenceLocalPutV1) CloseConsumerV1() {
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
func (s *evidenceLocalPutStateV1) releaseLockedV1() {
	if !s.consumerClosed || !s.ioJoined || s.active != 0 || s.released {
		return
	}
	s.released = true
	clear(s.data)
	s.data = nil
	clear(s.hashScratch)
	s.hashScratch = nil
	s.stored = StoredObject{}
	s.connections = nil
	s.bodies = nil
	s.ctx = nil
	s.coordinator = nil
	s.transport = nil
	s.admission = nil
	grant := s.grant
	s.grant = nil
	if grant != nil {
		grant.Close()
	}
}

type evidenceLocalRoundTripperV1 struct {
	owner     *evidenceLocalPutStateV1
	transport *http.Transport
}

func (r *evidenceLocalRoundTripperV1) RoundTrip(original *http.Request) (*http.Response, error) {
	if original == nil || original.URL == nil {
		return nil, ErrEvidenceLocalIOV1
	}
	// A TLS proxy/CONNECT path hides its decrypted parser behind the standard
	// Transport. Keep the configured proxy policy and refuse that native proof;
	// never bypass it or silently send directly. Plain HTTP proxies remain on
	// the original Transport parser and the same observed plaintext stream.
	if r.transport.Proxy != nil {
		proxy, err := r.transport.Proxy(original)
		if err != nil {
			return nil, err
		}
		if proxy != nil && (original.URL.Scheme == "https" || proxy.Scheme == "https") {
			return nil, ErrEvidenceLocalIOV1
		}
		if proxy != nil {
			raw := int64(len(proxy.Host) + len(proxy.Path) + len(proxy.RawQuery))
			if proxy.User != nil {
				raw += int64(len(proxy.User.Username()))
				password, _ := proxy.User.Password()
				raw += int64(len(password))
			}
			cost, costErr := evidenceLocalScaledV1(raw, 16)
			if costErr == nil {
				costErr = r.owner.grant.TryGrowParentV1(r.owner.ctx, cost+1024)
			}
			if costErr != nil {
				return nil, errors.Join(ErrEvidenceLocalIOV1, costErr)
			}
		}
	}
	request := original.Clone(original.Context())
	if original.Body != nil {
		if original.ContentLength < 0 || original.ContentLength > r.owner.frameLimit {
			return nil, ErrEvidenceLocalIOV1
		}
		cost, err := evidenceLocalScaledV1(original.ContentLength+1, 2)
		if err != nil {
			return nil, err
		}
		frameGrant, err := r.owner.coordinator.TryAcquireV1(r.owner.ctx, r.owner.org, workguard.VectorV1{ParentBytes: cost + (64 << 10)})
		if err != nil {
			return nil, errors.Join(ErrEvidenceLocalIOV1, err)
		}
		frame := make([]byte, int(original.ContentLength))
		_, readErr := io.ReadFull(original.Body, frame)
		if readErr == nil {
			var probe [1]byte
			n, probeErr := original.Body.Read(probe[:])
			clear(probe[:])
			if n != 0 || probeErr != io.EOF {
				readErr = ErrEvidenceLocalIOV1
			}
		}
		closeErr := original.Body.Close()
		if err = errors.Join(readErr, closeErr); err != nil {
			clear(frame)
			frameGrant.Close()
			return nil, err
		}
		replay := newEvidenceLocalReplayFrameV1(frame, frameGrant, r.owner.ctx)
		defer func() { replay.closeV1(); frameGrant.Close() }()
		body, err := replay.bodyV1()
		if err != nil {
			return nil, err
		}
		request.Body = body
		request.GetBody = replay.bodyV1
		request.Trailer = original.Trailer.Clone()
	}
	var actualMu sync.Mutex
	var actual *evidenceLocalConnV1
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if conn, ok := info.Conn.(*evidenceLocalConnV1); ok {
			actualMu.Lock()
			actual = conn
			actualMu.Unlock()
			conn.headerMu.Lock()
			conn.header = evidenceLocalHeaderInventoryV1{}
			conn.headerMu.Unlock()
		}
	}}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	response, err := r.transport.RoundTrip(request)
	if response != nil {
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
				trailerCost, costErr := evidenceLocalHeaderResourcesV1(int64(size), int64(size))
				if costErr == nil {
					costErr = r.owner.grant.TryGrowParentV1(r.owner.ctx, trailerCost)
				}
				if costErr != nil {
					_ = response.Body.Close()
					return nil, errors.Join(ErrEvidenceLocalIOV1, costErr)
				}
				break
			}
		}
		if response.Body != nil {
			_, objectRead := original.Context().Value(objectResponseLimitKeyV1{}).(objectResponseLimitV1)
			fundXML := !boundedStorageSuccessV1(response.StatusCode) || original.Method != http.MethodGet || !objectRead
			body, bodyErr := r.owner.responseBodyV1(response.Body, fundXML)
			if bodyErr != nil {
				_ = response.Body.Close()
				return nil, bodyErr
			}
			response.Body = body
		}
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

type evidenceLocalConnV1 struct {
	owner               *evidenceLocalPutStateV1
	inner               net.Conn
	mu                  sync.Mutex
	readMu              sync.Mutex
	headerMu            sync.Mutex
	active              int
	closed, innerClosed bool
	done                chan struct{}
	scratch             []byte
	header              evidenceLocalHeaderInventoryV1
	secure              *tls.ConnectionState
}

func (c *evidenceLocalConnV1) beginIOV1() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.active++
	return nil
}
func (c *evidenceLocalConnV1) retireStagingLockedV1() {
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
func (c *evidenceLocalConnV1) endIOV1() {
	c.mu.Lock()
	c.active--
	c.retireStagingLockedV1()
	c.mu.Unlock()
}
func (c *evidenceLocalConnV1) Read(p []byte) (int, error) {
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
		cost, inventoryErr := evidenceLocalHeaderResourcesV1(wire, lines)
		if inventoryErr == nil && cost > 0 {
			inventoryErr = c.owner.grant.TryGrowParentV1(c.owner.ctx, cost)
		}
		if inventoryErr != nil {
			clear(scratch[:n])
			return 0, errors.Join(ErrEvidenceLocalIOV1, inventoryErr)
		}
		copy(p, scratch[:n])
		clear(scratch[:n])
	}
	return n, err
}
func (c *evidenceLocalConnV1) Write(p []byte) (int, error) {
	if err := c.beginIOV1(); err != nil {
		return 0, err
	}
	defer c.endIOV1()
	return c.inner.Write(p)
}
func (c *evidenceLocalConnV1) Close() error {
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
func (c *evidenceLocalConnV1) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *evidenceLocalConnV1) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *evidenceLocalConnV1) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *evidenceLocalConnV1) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *evidenceLocalConnV1) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// A size inventory only, not an acceptance parser. It recognizes a complete
// final status/header boundary; undecidable/malformed prefixes stay conservatively
// in header mode until the real net/http parser accepts or rejects them.
type evidenceLocalHeaderInventoryV1 struct {
	prefix                      [64]byte
	used, lineBytes             int
	previous                    byte
	statusLine, final, complete bool
}

func (h *evidenceLocalHeaderInventoryV1) observeV1(raw []byte) (wire, lines int64) {
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
					*h = evidenceLocalHeaderInventoryV1{}
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

var _ net.Conn = (*evidenceLocalConnV1)(nil)
var _ http.RoundTripper = (*evidenceLocalRoundTripperV1)(nil)
