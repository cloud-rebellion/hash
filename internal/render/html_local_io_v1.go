// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

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

var ErrHTMLLocalIOV1 = errors.New("render: owned local renderer IO unavailable")

// This is the existing Gotenberg route's local native owner. It does not
// implement an HTTP parser or remote Chromium job protocol: net/http.Transport
// still performs the real HTTP parsing, redirect policy and response framing.
// The private connection observes raw header bytes before copying them into
// that existing parser and funds those actual producers before they allocate.
// Its close joins the original request frame and actual local connection IO;
// remote renderer cancellation/process capacity requires separate evidence.
type HTMLLocalPDFV1 struct{ state *htmlLocalPDFStateV1 }
type htmlLocalPDFStateV1 struct {
	mu                                          sync.Mutex
	self                                        *htmlLocalPDFStateV1
	ctx                                         context.Context
	grant                                       *workguard.GrantV1
	provider                                    *workguard.GrantV1
	transport                                   *http.Transport
	connections                                 map[*htmlLocalConnV1]struct{}
	changed                                     chan struct{}
	joined                                      chan struct{}
	dialing, active                             int
	frameLimit                                  int64
	pdf                                         []byte
	closing, ioJoined, consumerClosed, released bool
}

// HTMLToPDFLocalOwnedV1 privately acquires its actual provider/Parent grant from
// the coordinator and organisation supplied by the calling native source owner.
// Parent and actual local-stream grants are private and have distinct proven
// last uses. No caller receives a closable grant alias. The original method runs unchanged
// on a private standard Transport, retaining all three original retries,
// options, default redirects and HTTP/HTTPS behavior. A returned error can
// still return an owned handle: callers must CloseConsumerV1 on every path.
func (g *Gotenberg) HTMLToPDFLocalOwnedV1(ctx context.Context, source string, options PDFOptions, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*HTMLLocalPDFV1, error) {
	if g == nil || g.HTTP == nil || ctx == nil || ctx.Err() != nil || coordinator == nil || org == uuid.Nil {
		return nil, ErrHTMLLocalIOV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, ErrHTMLLocalIOV1
	}
	frameLimit, parent, err := HTMLToPDFLocalResourcesV1(source, options)
	if err != nil {
		return nil, err
	}
	if err := htmlLocalValidateClientV1(g.HTTP); err != nil {
		return nil, err
	}
	if !htmlLocalAddV1(&parent, int64(len(g.BaseURL)), 16) {
		return nil, ErrHTMLLocalIOV1
	}
	parentGrant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: parent})
	if err != nil {
		return nil, errors.Join(ErrHTMLLocalIOV1, err)
	}
	provider, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		parentGrant.Close()
		return nil, errors.Join(ErrHTMLLocalIOV1, err)
	}
	base := htmlLocalTransportBaseV1()
	owner := &htmlLocalPDFStateV1{ctx: ctx, grant: parentGrant, provider: provider, connections: make(map[*htmlLocalConnV1]struct{}), changed: make(chan struct{}), joined: make(chan struct{}), frameLimit: frameLimit}
	owner.self = owner
	transport := base.Clone()
	// Decrypted header staging is a finite HTTP/1 transport profile. Both HTTP
	// and HTTPS remain supported with the original TLS verification/options;
	// ALPN selects HTTP/1.1 so no unobserved HPACK parser can precede the hook.
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	} else {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	transport.DialContext = owner.dialV1(base)
	transport.DialTLSContext = owner.dialTLSV1(base)
	owner.transport = transport
	client := *g.HTTP
	client.Transport = &htmlLocalRoundTripperV1{owner: owner, transport: transport}
	copy := *g
	copy.HTTP = &client
	pdf, renderErr := copy.HTMLToPDF(ctx, source, options)
	owner.mu.Lock()
	owner.pdf = pdf
	owner.closing = true
	owner.signalV1()
	owner.mu.Unlock()
	// Private Transport cleanup may finish after a cancelled caller. Its real
	// local-stream loan remains owned until this close/dial/IO continuation joins;
	// the Parent/output loan additionally awaits the actual result consumers.
	go owner.closeIOV1()
	handle := &HTMLLocalPDFV1{state: owner}
	select {
	case <-owner.joined:
		return handle, renderErr
	case <-ctx.Done():
		return handle, errors.Join(renderErr, ErrHTMLLocalIOV1, ctx.Err())
	}
}

func htmlLocalValidateClientV1(client *http.Client) error {
	// NewGotenberg installs exactly this callback-free client configuration.
	// A function code pointer cannot prove a closure/bound dialer's captured
	// state. Custom transports, redirects, cookie stores and TLS hooks are not
	// silently replaced by this native proof; those configurations are refused.
	if client == nil || client.Transport != nil || client.Jar != nil || client.CheckRedirect != nil {
		return ErrHTMLLocalIOV1
	}
	return nil
}
func htmlLocalTransportBaseV1() *http.Transport {
	// Constructor-owned standard defaults. Never clone mutable DefaultTransport
	// or accept a caller's net.Dialer method value/Proxy/TLS callback identity.
	return &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second}
}

func (s *htmlLocalPDFStateV1) signalV1() { close(s.changed); s.changed = make(chan struct{}) }

func (s *htmlLocalPDFStateV1) beginDialV1(base *http.Transport, secure bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closing || s.released || s.grant == nil {
		return ErrHTMLLocalIOV1
	}
	// One actual dial's connection/control, private64KiB staging buffer and
	// standard transport/TLS record controls are prepaid before construction.
	cost, err := htmlLocalConnectionControlsV1(base, secure)
	if err != nil {
		return err
	}
	if err := s.grant.TryGrowParentV1(s.ctx, cost); err != nil {
		return errors.Join(ErrHTMLLocalIOV1, err)
	}
	s.dialing++
	return nil
}

func (s *htmlLocalPDFStateV1) finishDialV1(inner net.Conn, err error) (net.Conn, error) {
	s.mu.Lock()
	var conn *htmlLocalConnV1
	if inner != nil {
		conn = &htmlLocalConnV1{owner: s, inner: inner, done: make(chan struct{}), scratch: make([]byte, 64<<10)}
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
		return nil, ErrHTMLLocalIOV1
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, ErrHTMLLocalIOV1
	}
	return conn, nil
}

func (s *htmlLocalPDFStateV1) dialV1(base *http.Transport) func(context.Context, string, string) (net.Conn, error) {
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

func (s *htmlLocalPDFStateV1) dialTLSV1(base *http.Transport) func(context.Context, string, string) (net.Conn, error) {
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

func (s *htmlLocalPDFStateV1) closeIOV1() {
	for {
		s.mu.Lock()
		connections := make([]*htmlLocalConnV1, 0, len(s.connections))
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

func (h *HTMLLocalPDFV1) WithPDFV1(consume func([]byte) error) error {
	if h == nil || h.state == nil || consume == nil {
		return ErrHTMLLocalIOV1
	}
	s := h.state
	s.mu.Lock()
	if s.self != s || s.consumerClosed || s.released || !s.ioJoined || s.pdf == nil || s.grant == nil {
		s.mu.Unlock()
		return ErrHTMLLocalIOV1
	}
	s.active++
	pdf := s.pdf
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active--; s.releaseLockedV1(); s.mu.Unlock() }()
	return consume(pdf)
}

func (h *HTMLLocalPDFV1) CloseConsumerV1() {
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
func (s *htmlLocalPDFStateV1) releaseLockedV1() {
	if !s.consumerClosed || !s.ioJoined || s.active != 0 || s.released {
		return
	}
	s.released = true
	clear(s.pdf)
	s.pdf = nil
	s.connections = nil
	grant := s.grant
	s.grant = nil
	if grant != nil {
		grant.Close()
	}
}

type htmlLocalRoundTripperV1 struct {
	owner     *htmlLocalPDFStateV1
	transport *http.Transport
}

func (r *htmlLocalRoundTripperV1) RoundTrip(original *http.Request) (*http.Response, error) {
	if original == nil {
		return nil, ErrHTMLLocalIOV1
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
			return nil, ErrHTMLLocalIOV1
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
			return nil, ErrHTMLLocalIOV1
		}
		replay := newHTMLLocalReplayFrameV1(frame)
		defer replay.closeV1()
		body, err := replay.bodyV1()
		if err != nil {
			return nil, err
		}
		request.Body = body
		// Preserve standard Transport safe nothing-written/reused-connection
		// replay, and default client307/308 replay. This private replay callback
		// exposes opaque readers only; after RoundTrip returns its frame closes,
		// joins actual Read copies and every later callback/read is refused.
		request.GetBody = replay.bodyV1
	}
	var actualMu sync.Mutex
	var actual *htmlLocalConnV1
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if conn, ok := info.Conn.(*htmlLocalConnV1); ok {
			actualMu.Lock()
			actual = conn
			actualMu.Unlock()
			conn.headerMu.Lock()
			conn.header = htmlLocalHeaderInventoryV1{}
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
				trailerCost, costErr := htmlLocalHeaderResourcesV1(int64(size), int64(size))
				if costErr == nil {
					costErr = r.owner.grant.TryGrowParentV1(r.owner.ctx, trailerCost)
				}
				if costErr != nil {
					_ = response.Body.Close()
					return nil, errors.Join(ErrHTMLLocalIOV1, costErr)
				}
				break
			}
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

type htmlLocalConnV1 struct {
	owner               *htmlLocalPDFStateV1
	inner               net.Conn
	mu                  sync.Mutex
	readMu              sync.Mutex
	headerMu            sync.Mutex
	active              int
	closed, innerClosed bool
	done                chan struct{}
	scratch             []byte
	header              htmlLocalHeaderInventoryV1
	secure              *tls.ConnectionState
}

func (c *htmlLocalConnV1) beginIOV1() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.active++
	return nil
}
func (c *htmlLocalConnV1) retireStagingLockedV1() {
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
func (c *htmlLocalConnV1) endIOV1() {
	c.mu.Lock()
	c.active--
	c.retireStagingLockedV1()
	c.mu.Unlock()
}
func (c *htmlLocalConnV1) Read(p []byte) (int, error) {
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
		cost, inventoryErr := htmlLocalHeaderResourcesV1(wire, lines)
		if inventoryErr == nil && cost > 0 {
			inventoryErr = c.owner.grant.TryGrowParentV1(c.owner.ctx, cost)
		}
		if inventoryErr != nil {
			clear(scratch[:n])
			return 0, errors.Join(ErrHTMLLocalIOV1, inventoryErr)
		}
		copy(p, scratch[:n])
		clear(scratch[:n])
	}
	return n, err
}
func (c *htmlLocalConnV1) Write(p []byte) (int, error) {
	if err := c.beginIOV1(); err != nil {
		return 0, err
	}
	defer c.endIOV1()
	return c.inner.Write(p)
}
func (c *htmlLocalConnV1) Close() error {
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
func (c *htmlLocalConnV1) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *htmlLocalConnV1) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *htmlLocalConnV1) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *htmlLocalConnV1) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *htmlLocalConnV1) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// A size inventory only, not an acceptance parser. It recognizes a complete
// final status/header boundary; undecidable/malformed prefixes stay conservatively
// in header mode until the real net/http parser accepts or rejects them.
type htmlLocalHeaderInventoryV1 struct {
	prefix                      [64]byte
	used, lineBytes             int
	previous                    byte
	statusLine, final, complete bool
}

func (h *htmlLocalHeaderInventoryV1) observeV1(raw []byte) (wire, lines int64) {
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
					*h = htmlLocalHeaderInventoryV1{}
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

var _ net.Conn = (*htmlLocalConnV1)(nil)
var _ http.RoundTripper = (*htmlLocalRoundTripperV1)(nil)
