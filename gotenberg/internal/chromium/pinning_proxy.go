package chromium

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
	"golang.org/x/net/http/httpproxy"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
)

// pinningProxy is a loopback-bound HTTP/1.1 forward and CONNECT proxy
// placed between Chromium and the outbound network. It runs the same
// allow/deny/IP-public validation as [gotenberg.FilterOutboundURL] on
// every request and dials the destination using the IPs resolved at that
// moment. Routing Chromium through this proxy eliminates the Chromium-side
// DNS lookup that otherwise opens a DNS rebinding window between
// Gotenberg's validation and Chromium's TCP connect.
//
// The proxy is transparent to the caller. HTTPS sub-resources tunnel
// through CONNECT with Chromium performing its own TLS handshake using
// the original hostname, preserving SNI and certificate validation.
type pinningProxy struct {
	allowList []*regexp2.Regexp
	denyList  []*regexp2.Regexp

	// decide resolves and validates a URL. Tests may override it.
	decide func(ctx context.Context, rawURL string, allowList, denyList []*regexp2.Regexp, deadline time.Time) (gotenberg.OutboundDecision, error)

	// dialPinned dials the pinned IPs for a decision. Tests may override
	// it to connect to a stub upstream regardless of decision.
	dialPinned func(ctx context.Context, network string, addrs []netip.Addr, port string) (net.Conn, error)

	// dialBypass dials the destination hostname directly (operator
	// allow-list opt-in). Tests may override it.
	dialBypass func(ctx context.Context, network, addr string) (net.Conn, error)

	// upstreamProxy resolves the upstream (corporate) proxy for a
	// destination URL from the standard proxy environment variables, or
	// returns a nil URL to connect directly. It is nil unless the operator
	// opted into proxy-environment honoring. When set, the pinning proxy
	// performs the authenticated proxy handshake that Chromium cannot. See
	// https://github.com/gotenberg/gotenberg/issues/1592.
	upstreamProxy func(*url.URL) (*url.URL, error)

	generation *hashProxyGeneration
	started    bool // cleared only after confirmed generation retirement
	mu         sync.Mutex
}

// newPinningProxy returns a pinning proxy configured with the given
// allow/deny lists and IP-class policy. The policy bools are applied via
// [gotenberg.DecideOutbound] on every request the proxy sees, so
// Chromium inherits whatever posture the operator selected. The
// returned proxy is not yet listening; call Start.
func newPinningProxy(allowList, denyList []*regexp2.Regexp, denyPrivateIPs, denyPublicIPs, enableEnvironmentProxy bool) *pinningProxy {
	p := &pinningProxy{
		allowList: allowList,
		denyList:  denyList,
		decide: func(ctx context.Context, rawURL string, allow, deny []*regexp2.Regexp, deadline time.Time) (gotenberg.OutboundDecision, error) {
			return gotenberg.DecideOutbound(ctx, rawURL, allow, deny, deadline,
				gotenberg.WithDenyPrivateIPs(denyPrivateIPs),
				gotenberg.WithDenyPublicIPs(denyPublicIPs),
			)
		},
		dialPinned: gotenberg.DialPinned,
		dialBypass: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	if enableEnvironmentProxy {
		// Honor the standard proxy environment variables, credentials
		// included. httpproxy reads the environment now and applies NO_PROXY.
		p.upstreamProxy = httpproxy.FromEnvironment().ProxyFunc()
	}

	return p
}

// Start binds the proxy to 127.0.0.1 on an ephemeral port and serves in a
// background goroutine. Bind failures return an error; the caller must
// not proceed to start Chromium with --proxy-server.
func (p *pinningProxy) Start(logger *slog.Logger) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.generation != nil {
		if p.generation.retirement == nil {
			return errors.New("pinning proxy already started")
		}
		if err := p.hashReconcileProxyLocked(p.generation); err != nil {
			return err
		}
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("bind pinning proxy: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	g := &hashProxyGeneration{
		listener: l, logger: logger.With(slog.String("logger", "pinning-proxy")),
		ctx: ctx, cancel: cancel, serveDone: make(chan struct{}),
		connections: make(map[*hashProxyConn]struct{}), requests: make(map[*hashProxyRequest]struct{}),
	}
	g.listener = &hashProxyListener{Listener: l, p: p, g: g}
	g.server = &http.Server{
		Handler:     http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { p.serveHTTP(g, w, req) }),
		BaseContext: func(net.Listener) context.Context { return g.ctx },
		// Guard against slow header attacks. Body reads are controlled
		// per-handler.
		ReadHeaderTimeout: 15 * time.Second,
		ErrorLog:          slog.NewLogLogger(g.logger.Handler(), slog.LevelWarn),
	}

	p.generation = g
	go func() {
		defer close(g.serveDone)
		serveErr := g.server.Serve(g.listener)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			g.logger.ErrorContext(context.Background(), fmt.Sprintf("pinning proxy serve: %s", serveErr))
		}
	}()

	p.started = true
	g.logger.DebugContext(context.Background(), fmt.Sprintf("pinning proxy listening on %s", l.Addr()))
	return nil
}

// Stop shuts the proxy down and waits for in-flight handlers to complete.
// Safe to call on a non-started proxy.
func (p *pinningProxy) Stop(logger *slog.Logger) error {
	p.mu.Lock()
	g := p.generation
	if g == nil {
		p.mu.Unlock()
		return nil
	}
	p.hashBeginProxyRetirementLocked(g)
	r := g.retirement
	p.mu.Unlock()
	timer := time.NewTimer(hashProxyStopTimeout)
	defer timer.Stop()
	select {
	case <-r.done:
		p.mu.Lock()
		err := p.hashReconcileProxyLocked(g)
		p.mu.Unlock()
		if err != nil {
			return err
		}
	case <-timer.C:
		return errors.Join(errHashProxyShutdown, context.DeadlineExceeded)
	}
	logger.DebugContext(context.Background(), "pinning proxy stopped")
	return nil
}

// URL returns the proxy URL suitable for Chromium's --proxy-server flag.
// Returns an empty string when the proxy is not listening.
func (p *pinningProxy) URL() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.generation == nil || p.generation.closing {
		return ""
	}
	return "http://" + p.generation.listener.Addr().String()
}

func (p *pinningProxy) serveHTTP(g *hashProxyGeneration, w http.ResponseWriter, req *http.Request) {
	r, err := p.hashAdmitProxyRequest(g, req.Context())
	if err != nil {
		http.Error(w, "proxy stopping", http.StatusServiceUnavailable)
		return
	}
	defer r.finish()
	req = req.Clone(r.ctx)
	if req.Method == http.MethodConnect {
		p.handleConnect(r, w, req)
		return
	}
	p.handleForward(r, w, req)
}

// handleConnect handles HTTPS (and any other CONNECT) tunnels. Chromium
// issues CONNECT host:port; the proxy validates the host, dials the
// pinned IP, and splices the client socket with the upstream socket.
// Chromium then negotiates TLS end-to-end with the original hostname in
// SNI.
func (p *pinningProxy) handleConnect(r *hashProxyRequest, w http.ResponseWriter, req *http.Request) {
	_, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}

	deadline, ok := req.Context().Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	// Bound policy/dial/corporate handshake only; a successful tunnel keeps
	// its request/generation lifetime instead of inheriting this deadline.
	handshakeCtx, cancelHandshake := context.WithDeadline(req.Context(), deadline)
	defer cancelHandshake()

	// The validation URL uses https:// so that http-like scheme checks
	// apply in [gotenberg.DecideOutbound]. The scheme does not influence
	// the CONNECT handling beyond filtering.
	decision, err := p.decide(handshakeCtx, "https://"+req.Host, p.allowList, p.denyList, deadline)
	if err != nil {
		if isClientCancellation(req.Context(), err) {
			r.g.logger.DebugContext(req.Context(), fmt.Sprintf("CONNECT abandoned by client for '%s': %s", req.Host, err))
		} else {
			r.g.logger.WarnContext(req.Context(), fmt.Sprintf("CONNECT blocked for '%s': %s", req.Host, err))
		}
		http.Error(w, "CONNECT blocked", http.StatusForbidden)
		return
	}

	// When the operator routes egress through an authenticated proxy,
	// Chromium cannot supply the credentials itself, so the pinning proxy
	// performs the CONNECT (and authentication) upstream. The decision above
	// still gated the destination through the allow/deny and IP-class rules.
	var proxyURL *url.URL
	if p.upstreamProxy != nil {
		proxyURL, err = p.upstreamProxy(&url.URL{Scheme: "https", Host: req.Host})
		if err != nil {
			r.g.logger.WarnContext(req.Context(), fmt.Sprintf("resolve upstream proxy for '%s': %s", req.Host, err))
			http.Error(w, "upstream proxy error", http.StatusBadGateway)
			return
		}
	}

	var upstream net.Conn
	switch {
	case proxyURL != nil:
		upstream, err = hashDialThroughProxy(handshakeCtx, proxyURL, req.Host, func(ctx context.Context, network, addr string) (net.Conn, error) {
			return r.dial(ctx, func(dialCtx context.Context) (net.Conn, error) { return p.dialBypass(dialCtx, network, addr) })
		})
	case decision.Bypass:
		upstream, err = r.dial(handshakeCtx, func(dialCtx context.Context) (net.Conn, error) { return p.dialBypass(dialCtx, "tcp", req.Host) })
	case len(decision.Pinned) > 0:
		upstream, err = r.dial(handshakeCtx, func(dialCtx context.Context) (net.Conn, error) {
			return p.dialPinned(dialCtx, "tcp", decision.Pinned, port)
		})
	default:
		err = errors.New("no pinned addresses and not bypassed")
	}
	if err == nil && (!time.Now().Before(deadline) || handshakeCtx.Err() != nil) {
		err = handshakeCtx.Err()
		if err == nil {
			err = context.DeadlineExceeded
		}
		_ = upstream.Close()
	}
	if err != nil {
		if isClientCancellation(req.Context(), err) {
			r.g.logger.DebugContext(req.Context(), fmt.Sprintf("CONNECT dial abandoned by client for '%s': %s", req.Host, err))
		} else {
			r.g.logger.WarnContext(req.Context(), fmt.Sprintf("CONNECT dial failed for '%s': %s", req.Host, err))
		}
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	cancelHandshake()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hj.Hijack()
	if err != nil {
		r.g.logger.ErrorContext(req.Context(), fmt.Sprintf("hijack CONNECT: %s", err))
		return
	}
	ownedClient, err := r.track(client)
	if err != nil {
		return // late hijack is closed before any acknowledgement or splice
	}
	defer ownedClient.Close()

	_, err = ownedClient.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		if isClientCancellation(req.Context(), err) {
			r.g.logger.DebugContext(req.Context(), fmt.Sprintf("write CONNECT ack abandoned by client: %s", err))
		} else {
			r.g.logger.WarnContext(req.Context(), fmt.Sprintf("write CONNECT ack: %s", err))
		}
		return
	}

	// Splice bytes in both directions until either side closes.
	var splice sync.WaitGroup
	splice.Add(2)
	go func() {
		defer splice.Done()
		_, _ = io.Copy(upstream, buffered.Reader)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer splice.Done()
		_, _ = io.Copy(ownedClient, upstream)
		_ = ownedClient.CloseWrite()
	}()
	splice.Wait()
}

// handleForward handles plain HTTP requests sent to the proxy as absolute
// URIs (GET http://host/path). The proxy revalidates the URL, then
// forwards the request via a transport that dials the pinned IP.
func (p *pinningProxy) handleForward(r *hashProxyRequest, w http.ResponseWriter, req *http.Request) {
	if req.URL == nil || req.URL.Scheme == "" || req.URL.Host == "" {
		http.Error(w, "absolute URL required", http.StatusBadRequest)
		return
	}

	deadline, ok := req.Context().Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}

	decision, err := p.decide(req.Context(), req.URL.String(), p.allowList, p.denyList, deadline)
	if err != nil {
		if isClientCancellation(req.Context(), err) {
			r.g.logger.DebugContext(req.Context(), fmt.Sprintf("forward abandoned by client for '%s': %s", req.URL, err))
		} else {
			r.g.logger.WarnContext(req.Context(), fmt.Sprintf("forward blocked for '%s': %s", req.URL, err))
		}
		http.Error(w, "request blocked", http.StatusForbidden)
		return
	}

	var proxyURL *url.URL
	if p.upstreamProxy != nil {
		proxyURL, err = p.upstreamProxy(req.URL)
		if err != nil {
			r.g.logger.WarnContext(req.Context(), fmt.Sprintf("resolve upstream proxy for '%s': %s", req.URL.Redacted(), err))
			http.Error(w, "upstream proxy error", http.StatusBadGateway)
			return
		}
	}

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	stripHopByHopHeaders(outReq.Header)

	// Build a fresh transport per request. The decision contains the pinned
	// IPs to dial; reusing a transport across requests would leak the
	// decision's closure across unrelated targets.
	transport := &http.Transport{
		DisableKeepAlives: true,
	}
	if proxyURL != nil {
		// The upstream proxy owns DNS and egress; Go adds Proxy-Authorization
		// from the URL's credentials. The decision above already gated the
		// destination, and dialBypass dials the proxy host directly.
		transport.Proxy = http.ProxyURL(proxyURL)
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return r.dial(ctx, func(dialCtx context.Context) (net.Conn, error) { return p.dialBypass(dialCtx, network, addr) })
		}
	} else {
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				return nil, fmt.Errorf("split forward addr %q: %w", addr, splitErr)
			}
			switch {
			case decision.Bypass:
				return r.dial(ctx, func(dialCtx context.Context) (net.Conn, error) { return p.dialBypass(dialCtx, network, addr) })
			case len(decision.Pinned) > 0:
				return r.dial(ctx, func(dialCtx context.Context) (net.Conn, error) {
					return p.dialPinned(dialCtx, network, decision.Pinned, port)
				})
			default:
				return nil, errors.New("no pinned addresses and not bypassed")
			}
		}
	}
	defer transport.CloseIdleConnections()

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		if isClientCancellation(req.Context(), err) {
			r.g.logger.DebugContext(req.Context(), fmt.Sprintf("forward RoundTrip abandoned by client for '%s': %s", req.URL, err))
		} else {
			r.g.logger.WarnContext(req.Context(), fmt.Sprintf("forward RoundTrip failed for '%s': %s", req.URL, err))
		}
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	stripHopByHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// Per RFC 7230 section 6.1.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func stripHopByHopHeaders(h http.Header) {
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// isClientCancellation reports whether err originates from the client (for
// example Chromium) closing the connection or letting the request deadline
// pass before the proxy could finish validating the destination. Such
// errors are not policy refusals: the proxy never reached an allow/deny
// rule decision. Callers downgrade these to debug to avoid alarming
// operators with noise from speculative or aborted browser requests. The
// canonical case is a Chromium DNS prefetch that the browser drops before
// the proxy's [outbound.resolveHost] call returns. The [net.DNSError]
// returned by [net.Resolver.LookupNetIP] unwraps to [context.Canceled] or
// [context.DeadlineExceeded] in that case, so an [errors.Is] walk catches
// it.
func isClientCancellation(ctx context.Context, err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return ctx.Err() != nil
}

// dialThroughUpstreamProxy tunnels to target through the upstream proxy,
// letting [gotenberg.DialThroughProxy] perform the authenticated CONNECT that
// Chromium cannot. dialBypass dials the proxy itself and is overridable in
// tests. See https://github.com/gotenberg/gotenberg/issues/1592.
func (p *pinningProxy) dialThroughUpstreamProxy(ctx context.Context, proxyURL *url.URL, target string) (net.Conn, error) {
	return gotenberg.DialThroughProxy(ctx, proxyURL, target, p.dialBypass)
}
