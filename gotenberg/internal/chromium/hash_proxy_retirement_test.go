package chromium

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
)

// This fixture owns accepted sockets and joins acceptance and every handler.
// The older listener-only upstream helper is not retirement evidence.
type hashProxyPeer struct {
	listener     net.Listener
	mu           sync.Mutex
	connections  []net.Conn
	closing      bool
	acceptedDone chan struct{}
	handlers     sync.WaitGroup
	once         sync.Once
}

func hashNewProxyPeer(t *testing.T, handle func(net.Conn)) *hashProxyPeer {
	t.Helper()
	return hashNewProxyPeerWithDeadline(t, 15*time.Second, handle)
}

func hashNewProxyPeerWithDeadline(t *testing.T, lifetime time.Duration, handle func(net.Conn)) *hashProxyPeer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &hashProxyPeer{listener: l, acceptedDone: make(chan struct{})}
	t.Cleanup(func() { p.close(t) })
	go func() {
		defer close(p.acceptedDone)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			if p.closing {
				p.mu.Unlock()
				_ = conn.Close()
				return
			}
			p.connections = append(p.connections, conn)
			p.handlers.Add(1)
			p.mu.Unlock()
			_ = conn.SetDeadline(time.Now().Add(lifetime))
			go func() { defer p.handlers.Done(); defer conn.Close(); handle(conn) }()
		}
	}()
	return p
}

func (p *hashProxyPeer) close(t *testing.T) {
	t.Helper()
	p.once.Do(func() {
		p.mu.Lock()
		p.closing = true
		conns := append([]net.Conn(nil), p.connections...)
		p.mu.Unlock()
		_ = p.listener.Close()
		for _, conn := range conns {
			_ = conn.Close()
		}
		hashAwait(t, "fixture accept loop terminal", p.acceptedDone)
		done := make(chan struct{})
		go func() { p.handlers.Wait(); close(done) }()
		hashAwait(t, "all fixture accepted handlers terminal", done)
	})
}

func hashProxyForPeer(peer *hashProxyPeer) *pinningProxy {
	p := newPinningProxy(nil, nil, false, false, false)
	p.decide = func(context.Context, string, []*regexp2.Regexp, []*regexp2.Regexp, time.Time) (gotenberg.OutboundDecision, error) {
		return gotenberg.OutboundDecision{Bypass: true}, nil
	}
	p.dialBypass = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, peer.listener.Addr().String())
	}
	return p
}

func hashStartProxyFixture(t *testing.T, p *pinningProxy, unblock func()) {
	t.Helper()
	t.Cleanup(func() {
		if unblock != nil {
			unblock()
		}
		if err := p.Stop(testLogger()); err != nil {
			t.Error("fixture proxy retirement: ", err)
		}
	})
	if err := p.Start(testLogger()); err != nil {
		t.Fatal(err)
	}
}

func hashProxyGenerationForTest(p *pinningProxy) *hashProxyGeneration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation
}

func hashProxyWaitState(t *testing.T, p *pinningProxy, condition func(*hashProxyGeneration) bool) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		p.mu.Lock()
		ok := condition(p.generation)
		p.mu.Unlock()
		if ok {
			return
		}
		select {
		case <-timer.C:
			t.Fatal("proxy lifecycle state not reached")
		case <-tick.C:
		}
	}
}

func hashProxyClient(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	return c
}

func hashProxyReadACK(t *testing.T, br *bufio.Reader) {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil || line != "HTTP/1.1 200 OK\r\n" {
		t.Fatal("CONNECT ack: ", line, err)
	}
	line, err = br.ReadString('\n')
	if err != nil || line != "\r\n" {
		t.Fatal("CONNECT ack terminator: ", line, err)
	}
}

func hashProxyOpenTunnel(t *testing.T, p *pinningProxy) (net.Conn, *bufio.Reader) {
	t.Helper()
	u := mustParseURL(t, p.URL())
	c := hashProxyClient(t, u.Host)
	if _, err := io.WriteString(c, "CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	hashProxyReadACK(t, br)
	return c, br
}

type hashProxyHijacker struct {
	conn   net.Conn
	br     *bufio.Reader
	header http.Header
	before func()
}

func (w *hashProxyHijacker) Header() http.Header { return w.header }
func (w *hashProxyHijacker) WriteHeader(status int) {
	_, _ = fmt.Fprintf(w.conn, "HTTP/1.1 %d error\r\n\r\n", status)
}
func (w *hashProxyHijacker) Write(body []byte) (int, error) { return w.conn.Write(body) }
func (w *hashProxyHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.before != nil {
		w.before()
	}
	return w.conn, bufio.NewReadWriter(w.br, bufio.NewWriter(w.conn)), nil
}

func TestHashProxyCONNECTBufferedPayloadAndHalfClose(t *testing.T) {
	payload := []byte("\x00\xffHash coalesced CONNECT payload\x01")
	upstreamDone := make(chan struct{})
	upstream := hashNewProxyPeer(t, func(c net.Conn) {
		defer close(upstreamDone)
		raw, err := io.ReadAll(c)
		if err != nil || !bytes.Equal(raw, payload) {
			t.Error("half-close payload: ", err)
			return
		}
		_, _ = c.Write(append([]byte("echo:"), raw...))
	})
	p := hashProxyForPeer(upstream)
	hashStartProxyFixture(t, p, nil)
	g := hashProxyGenerationForTest(p)
	request := "CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n"
	readGate, handled, witness := make(chan struct{}), make(chan struct{}), make(chan int, 1)
	var gateOnce sync.Once
	release := func() { gateOnce.Do(func() { close(readGate) }) }
	front := hashNewProxyPeer(t, func(c net.Conn) {
		defer close(handled)
		<-readGate
		br := bufio.NewReader(c)
		if _, err := br.Peek(len(request) + len(payload)); err != nil {
			t.Error(err)
			return
		}
		req, err := http.ReadRequest(br)
		if err != nil {
			t.Error(err)
			return
		}
		witness <- br.Buffered()
		p.serveHTTP(g, &hashProxyHijacker{conn: c, br: br, header: make(http.Header)}, req)
	})
	t.Cleanup(release)
	c := hashProxyClient(t, front.listener.Addr().String())
	if _, err := c.Write(append([]byte(request), payload...)); err != nil {
		t.Fatal(err)
	}
	release()
	br := bufio.NewReader(c)
	hashProxyReadACK(t, br)
	if n := <-witness; n < len(payload) {
		t.Fatal("fixture did not witness buffered payload")
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(br)
	if err != nil || !bytes.Equal(raw, append([]byte("echo:"), payload...)) {
		t.Fatal("buffered/half-close relay: ", err)
	}
	hashAwait(t, "upstream half-close handler terminal", upstreamDone)
	hashAwait(t, "both splice copies and request terminal", handled)
}

func TestHashProxyActiveTunnelRetirementPreservesIndependentProxy(t *testing.T) {
	ownerDone, decoyDone := make(chan struct{}), make(chan struct{})
	ownerPeer := hashNewProxyPeer(t, func(c net.Conn) {
		defer close(ownerDone)
		if _, err := io.Copy(c, c); err != nil {
			t.Error("owner peer did not reach normal EOF: ", err)
		}
	})
	decoyPeer := hashNewProxyPeer(t, func(c net.Conn) {
		defer close(decoyDone)
		if _, err := io.Copy(c, c); err != nil {
			t.Error("independent peer did not reach normal EOF: ", err)
		}
	})
	owner, decoy := hashProxyForPeer(ownerPeer), hashProxyForPeer(decoyPeer)
	hashStartProxyFixture(t, owner, nil)
	hashStartProxyFixture(t, decoy, nil)
	old := hashProxyGenerationForTest(owner)
	c, br := hashProxyOpenTunnel(t, owner)
	dc, dbr := hashProxyOpenTunnel(t, decoy)
	exchange := func(c net.Conn, br *bufio.Reader, body string) {
		t.Helper()
		if _, err := io.WriteString(c, body); err != nil {
			t.Fatal(err)
		}
		out := make([]byte, len(body))
		if _, err := io.ReadFull(br, out); err != nil || string(out) != body {
			t.Fatal("tunnel exchange: ", err)
		}
	}
	exchange(c, br, "owner-live")
	exchange(dc, dbr, "independent-live")
	if err := owner.Stop(testLogger()); err != nil {
		t.Fatal(err)
	}
	hashAwait(t, "owner peer EOF and handler terminal", ownerDone)
	hashAwait(t, "owner serving terminal", old.serveDone)
	hashAwait(t, "owner retirement terminal", old.retirement.done)
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatal("owned client not closed: ", err)
	}
	if owner.URL() != "" || hashProxyGenerationForTest(owner) != nil {
		t.Fatal("retired generation still advertised")
	}
	exchange(dc, dbr, "independent-after-owner-stop")
	if err := owner.Start(testLogger()); err != nil {
		t.Fatal(err)
	}
	if hashProxyGenerationForTest(owner) == old || owner.URL() == "" {
		t.Fatal("confirmed retirement did not allow fresh generation")
	}
	if err := decoy.Stop(testLogger()); err != nil {
		t.Fatal(err)
	}
	hashAwait(t, "independent peer terminal", decoyDone)
}

func TestHashProxyCorporateHandshakeRetirement(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			entered, done := make(chan struct{}), make(chan struct{})
			peer := hashNewProxyPeer(t, func(c net.Conn) {
				defer close(done)
				br := bufio.NewReader(c)
				if scheme == "http" {
					req, err := http.ReadRequest(br)
					if err != nil || req.Method != http.MethodConnect || req.Host != "fixture.invalid:443" || req.Header.Get("Proxy-Authorization") == "" {
						t.Error("corporate CONNECT fixture not reached: ", err)
						return
					}
				} else {
					var prefix [6]byte // TLS record header followed by ClientHello type
					if _, err := io.ReadFull(br, prefix[:]); err != nil || prefix[0] != 0x16 || prefix[1] != 0x03 || int(prefix[3])<<8|int(prefix[4]) < 4 || prefix[5] != 0x01 {
						t.Error("corporate TLS ClientHello fixture not reached: ", err)
						return
					}
				}
				close(entered)
				if _, err := io.Copy(io.Discard, br); err != nil {
					t.Error("corporate peer did not reach normal EOF: ", err)
				}
			})
			p := hashProxyForPeer(peer)
			u := &url.URL{Scheme: scheme, Host: peer.listener.Addr().String(), User: url.UserPassword("fixture", "fixture")}
			p.upstreamProxy = func(*url.URL) (*url.URL, error) { return u, nil }
			hashStartProxyFixture(t, p, nil)
			c := hashProxyClient(t, mustParseURL(t, p.URL()).Host)
			_, err := io.WriteString(c, "CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			hashAwait(t, "real corporate handshake stalled", entered)
			old := hashProxyGenerationForTest(p)
			if err := p.Stop(testLogger()); err != nil {
				t.Fatal(err)
			}
			hashAwait(t, "corporate raw socket EOF/handler terminal", done)
			hashAwait(t, "corporate retirement joined", old.retirement.done)
			data, err := io.ReadAll(c)
			if err != nil || bytes.Contains(data, []byte("200 OK")) {
				t.Fatal("stalled handshake acknowledged: ", err)
			}
		})
	}
}

type hashProxyResponseReadWitness struct {
	net.Conn
	first   atomic.Bool
	bytes   int
	witness chan int
}

func (c *hashProxyResponseReadWitness) Read(body []byte) (int, error) {
	if c.first.CompareAndSwap(false, true) {
		if len(body) < c.bytes {
			return 0, errors.New("fixture CONNECT response buffer too small")
		}
		n, err := io.ReadFull(c.Conn, body[:c.bytes])
		c.witness <- n // prove response parser prefetched the exact greeting
		return n, err
	}
	return c.Conn.Read(body)
}

func (c *hashProxyResponseReadWitness) CloseWrite() error {
	return c.Conn.(*net.TCPConn).CloseWrite()
}

func TestHashProxyCorporateBufferedResponse(t *testing.T) {
	greeting := []byte("\x00\xffcorporate-buffered-greeting")
	entered, done := make(chan struct{}), make(chan struct{})
	peer := hashNewProxyPeer(t, func(c net.Conn) {
		defer close(done)
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			t.Error(err)
			return
		}
		_, err = c.Write(append([]byte("HTTP/1.1 200 OK\r\n\r\n"), greeting...))
		if err != nil {
			t.Error(err)
			return
		}
		close(entered)
		if _, err := io.Copy(io.Discard, br); err != nil {
			t.Error("corporate peer did not reach normal EOF: ", err)
		}
	})
	p := hashProxyForPeer(peer)
	witness := make(chan int, 1)
	rawDial := p.dialBypass
	wanted := len("HTTP/1.1 200 OK\r\n\r\n") + len(greeting)
	p.dialBypass = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := rawDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &hashProxyResponseReadWitness{Conn: conn, bytes: wanted, witness: witness}, nil
	}
	u := &url.URL{Scheme: "http", Host: peer.listener.Addr().String()}
	p.upstreamProxy = func(*url.URL) (*url.URL, error) { return u, nil }
	hashStartProxyFixture(t, p, nil)
	_, br := hashProxyOpenTunnel(t, p)
	if n := <-witness; n != wanted {
		t.Fatal("upstream buffered response not witnessed")
	}
	out := make([]byte, len(greeting))
	if _, err := io.ReadFull(br, out); err != nil || !bytes.Equal(out, greeting) {
		t.Fatal("corporate read-ahead lost: ", err)
	}
	hashAwait(t, "corporate response sent", entered)
	if err := p.Stop(testLogger()); err != nil {
		t.Fatal(err)
	}
	hashAwait(t, "corporate handler terminal", done)
}

func TestHashProxyLateDialAndTimeoutRetention(t *testing.T) {
	for _, method := range []string{"CONNECT", "forward"} {
		t.Run(method, func(t *testing.T) {
			entered, release, peerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			peer := hashNewProxyPeer(t, func(c net.Conn) {
				defer close(peerDone)
				var data [1]byte
				if n, err := c.Read(data[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Error("late dial was not closed without payload: ", n, err)
				}
			})
			p := hashProxyForPeer(peer)
			p.dialBypass = func(context.Context, string, string) (net.Conn, error) {
				close(entered)
				<-release
				return net.DialTimeout("tcp", peer.listener.Addr().String(), time.Second)
			}
			hashStartProxyFixture(t, p, unblock)
			c := hashProxyClient(t, mustParseURL(t, p.URL()).Host)
			request := "CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n"
			if method == "forward" {
				request = "GET http://fixture.invalid/ HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n"
			}
			if _, err := io.WriteString(c, request); err != nil {
				t.Fatal(err)
			}
			hashAwait(t, "dial admitted before shutdown", entered)
			old := hashProxyGenerationForTest(p)
			results := make(chan error, 2)
			firstDone, secondDone := make(chan struct{}), make(chan struct{})
			go func() { defer close(firstDone); results <- p.Stop(testLogger()) }()
			t.Cleanup(func() { unblock(); hashAwait(t, "first Stop caller cleanup joined", firstDone) })
			hashProxyWaitState(t, p, func(g *hashProxyGeneration) bool { return g == old && g.closing && g.retirement != nil })
			retirement := old.retirement
			go func() { defer close(secondDone); results <- p.Stop(testLogger()) }()
			t.Cleanup(func() { unblock(); hashAwait(t, "second Stop caller cleanup joined", secondDone) })
			if method == "forward" {
				hashProxyWaitState(t, p, func(g *hashProxyGeneration) bool { return g == old && len(g.requests) == 0 })
			} // detached dial still owns a counted worker
			if err := p.Start(testLogger()); !errors.Is(err, errHashProxyShutdown) || p.URL() != "" {
				t.Fatal("overlap admitted: ", err)
			}
			for range 2 {
				select {
				case err := <-results:
					if !errors.Is(err, errHashProxyShutdown) || !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("pending retirement accepted: ", err)
					}
				case <-time.After(hashProxyStopTimeout + time.Second):
					t.Fatal("Stop wait exceeded bound")
				}
			}
			hashAwait(t, "first Stop caller terminal", firstDone)
			hashAwait(t, "second Stop caller terminal", secondDone)
			if hashProxyGenerationForTest(p) != old || old.retirement != retirement {
				t.Fatal("retirement ownership replaced")
			}
			select {
			case <-retirement.done:
				t.Fatal("retirement completed before late dial joined")
			default:
			}
			unblock()
			hashAwait(t, "late returned peer closed", peerDone)
			hashAwait(t, "single retirement completed after late dial", retirement.done)
			if err := p.Start(testLogger()); err != nil || hashProxyGenerationForTest(p) == old {
				t.Fatal("confirmed lazy reconciliation failed: ", err)
			}
			data, err := io.ReadAll(c)
			if err != nil || bytes.Contains(data, []byte("200 OK")) {
				t.Fatal("late dial acknowledged: ", err)
			}
		})
	}
}

func TestHashProxyLateHijackRegistration(t *testing.T) {
	upstreamDone := make(chan struct{})
	peer := hashNewProxyPeer(t, func(c net.Conn) {
		defer close(upstreamDone)
		if _, err := io.Copy(io.Discard, c); err != nil {
			t.Error("late-hijack upstream did not reach normal EOF: ", err)
		}
	})
	entered, release, handled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	p := hashProxyForPeer(peer)
	hashStartProxyFixture(t, p, unblock)
	g := hashProxyGenerationForTest(p)
	front := hashNewProxyPeer(t, func(c net.Conn) {
		defer close(handled)
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			t.Error(err)
			return
		}
		p.serveHTTP(g, &hashProxyHijacker{conn: c, br: br, header: make(http.Header), before: func() { close(entered); <-release }}, req)
	})
	t.Cleanup(unblock)
	c := hashProxyClient(t, front.listener.Addr().String())
	if _, err := io.WriteString(c, "CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	hashAwait(t, "hijack entered before gate closes", entered)
	result, stopDone := make(chan error, 1), make(chan struct{})
	go func() { defer close(stopDone); result <- p.Stop(testLogger()) }()
	t.Cleanup(func() { unblock(); hashAwait(t, "late Hijack Stop caller cleanup joined", stopDone) })
	hashProxyWaitState(t, p, func(current *hashProxyGeneration) bool { return current == g && g.closing })
	if err := p.Start(testLogger()); !errors.Is(err, errHashProxyShutdown) {
		t.Fatal("restart admitted during hijack: ", err)
	}
	unblock()
	hashAwait(t, "late hijack handler joined", handled)
	hashAwait(t, "upstream socket closed", upstreamDone)
	hashAwait(t, "Stop caller terminal", stopDone)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(c)
	if err != nil || len(data) != 0 {
		t.Fatal("late hijack wrote ack/payload: ", err)
	}
}

func TestHashProxyDetachedForwardDialCancellation(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	p := newPinningProxy(nil, nil, false, false, false)
	p.decide = func(context.Context, string, []*regexp2.Regexp, []*regexp2.Regexp, time.Time) (gotenberg.OutboundDecision, error) {
		return gotenberg.OutboundDecision{Bypass: true}, nil
	}
	p.dialBypass = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}
	hashStartProxyFixture(t, p, nil)
	c := hashProxyClient(t, mustParseURL(t, p.URL()).Host)
	if _, err := io.WriteString(c, "GET http://fixture.invalid/ HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	hashAwait(t, "real forward Transport dial entered", entered)
	if err := p.Stop(testLogger()); err != nil {
		t.Fatal(err)
	}
	hashAwait(t, "detached Transport dial received request/generation cancellation", canceled)
}

type hashProxyCloseErrorConn struct {
	net.Conn
	calls atomic.Int64
	err   error
}

func (c *hashProxyCloseErrorConn) Close() error { c.calls.Add(1); _ = c.Conn.Close(); return c.err }

func TestHashProxyCloseFailureKeepsQuarantine(t *testing.T) {
	p := newPinningProxy(nil, nil, false, false, false)
	t.Cleanup(func() { _ = p.Stop(testLogger()) })
	if err := p.Start(testLogger()); err != nil {
		t.Fatal(err)
	}
	g := hashProxyGenerationForTest(p)
	r, err := p.hashAdmitProxyRequest(g, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var finishOnce sync.Once
	finish := func() { finishOnce.Do(r.finish) }
	t.Cleanup(finish)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	failure := errors.New("synthetic close uncertainty")
	raw := &hashProxyCloseErrorConn{Conn: a, err: failure}
	c, err := r.track(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	finish()
	for range 2 {
		if err := p.Stop(testLogger()); !errors.Is(err, errHashProxyShutdown) || !errors.Is(err, failure) {
			t.Fatal("prior closure uncertainty disappeared: ", err)
		}
	}
	if err := p.Start(testLogger()); !errors.Is(err, errHashProxyShutdown) || hashProxyGenerationForTest(p) != g || p.URL() != "" || raw.calls.Load() != 1 {
		t.Fatal("failed close admitted replacement or repeated close: ", err)
	}
}

func TestHashProxyPreHeaderClientRetirement(t *testing.T) {
	p := newPinningProxy(nil, nil, false, false, false)
	hashStartProxyFixture(t, p, nil)
	g := hashProxyGenerationForTest(p)
	c := hashProxyClient(t, mustParseURL(t, p.URL()).Host)
	hashProxyWaitState(t, p, func(current *hashProxyGeneration) bool { return current == g && len(g.connections) == 1 })
	if err := p.Stop(testLogger()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("accepted pre-header socket not retired: ", err)
	}
}
