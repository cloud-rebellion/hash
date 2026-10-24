// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

const hashProxyStopTimeout = 5 * time.Second

var errHashProxyShutdown = errors.New("pinning proxy shutdown unconfirmed")

// One generation retains every resource until serving, admitted requests,
// late dial completions and both relay copies have joined. All admissions and
// registry changes use p.mu; no close or wait runs with that mutex held.
type hashProxyGeneration struct {
	listener    net.Listener
	server      *http.Server
	logger      *slog.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	serveDone   chan struct{}
	workers     sync.WaitGroup
	requests    map[*hashProxyRequest]struct{}
	connections map[*hashProxyConn]struct{}
	closeErr    error // p.mu; includes failures before retirement snapshots
	closing     bool
	retirement  *hashProxyRetirement
}

type hashProxyRetirement struct {
	done chan struct{}
	err  error // published by closing done
}

type hashProxyRequest struct {
	p         *pinningProxy
	g         *hashProxyGeneration
	ctx       context.Context
	cancel    context.CancelFunc
	owned     map[*hashProxyConn]struct{}
	finished  bool // p.mu
	stop      func() bool
	closeDone chan struct{}
}

type hashProxyConn struct {
	net.Conn
	p    *pinningProxy
	g    *hashProxyGeneration
	once sync.Once
	err  error
}

type hashProxyListener struct {
	net.Listener
	p *pinningProxy
	g *hashProxyGeneration
}

func (l *hashProxyListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.p.mu.Lock()
	if l.p.generation != l.g || l.g.closing {
		l.p.mu.Unlock()
		l.p.hashRecordProxyClose(l.g, conn.Close()) // Serve remains counted
		return nil, net.ErrClosed
	}
	c := &hashProxyConn{Conn: conn, p: l.p, g: l.g}
	l.g.connections[c] = struct{}{} // own client before HTTP headers or Hijack
	l.p.mu.Unlock()
	return c, nil
}

func (p *pinningProxy) hashRecordProxyClose(g *hashProxyGeneration, err error) {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return
	}
	p.mu.Lock()
	g.closeErr = errors.Join(g.closeErr, err)
	p.mu.Unlock()
}

func (c *hashProxyConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.p.mu.Lock()
		if c.err != nil && !errors.Is(c.err, net.ErrClosed) {
			c.g.closeErr = errors.Join(c.g.closeErr, c.err)
		}
		delete(c.g.connections, c)
		c.p.mu.Unlock()
	})
	return c.err
}

func (c *hashProxyConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil // preserve the underlying connection's lack of half-close support
}

func (p *pinningProxy) hashAdmitProxyRequest(g *hashProxyGeneration, parent context.Context) (*hashProxyRequest, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.generation != g || g.closing {
		return nil, errHashProxyShutdown
	}
	ctx, cancel := context.WithCancel(parent)
	r := &hashProxyRequest{p: p, g: g, ctx: ctx, cancel: cancel, owned: make(map[*hashProxyConn]struct{}), closeDone: make(chan struct{})}
	g.workers.Add(1)
	g.requests[r] = struct{}{}
	r.stop = context.AfterFunc(ctx, func() { defer close(r.closeDone); r.closeOwned() })
	return r, nil
}

func (r *hashProxyRequest) track(conn net.Conn) (*hashProxyConn, error) {
	r.p.mu.Lock()
	if r.p.generation != r.g || r.g.closing || r.finished || r.ctx.Err() != nil {
		r.p.mu.Unlock()
		r.p.hashRecordProxyClose(r.g, conn.Close()) // counted request/dial
		return nil, errHashProxyShutdown
	}
	if c, ok := conn.(*hashProxyConn); ok && c.p == r.p && c.g == r.g {
		r.owned[c] = struct{}{} // adopt the exact client tracked at Accept
		r.p.mu.Unlock()
		return c, nil
	}
	c := &hashProxyConn{Conn: conn, p: r.p, g: r.g}
	r.owned[c] = struct{}{}
	r.g.connections[c] = struct{}{}
	r.p.mu.Unlock()
	return c, nil
}

func (r *hashProxyRequest) dial(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	r.p.mu.Lock()
	if r.p.generation != r.g || r.g.closing || r.finished || ctx.Err() != nil {
		r.p.mu.Unlock()
		return nil, errHashProxyShutdown
	}
	r.g.workers.Add(1) // transports may let a canceled request's dial finish later
	r.p.mu.Unlock()
	defer r.g.workers.Done()
	// http.Transport detaches its DialContext from request cancellation.
	// Restore this request/generation's cancellation without changing policy.
	ctx, cancel := context.WithCancel(ctx)
	bridgeDone := make(chan struct{})
	stop := context.AfterFunc(r.ctx, func() { defer close(bridgeDone); cancel() })
	defer func() {
		cancel()
		if !stop() {
			<-bridgeDone
		}
	}()
	conn, err := dial(ctx)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if conn != nil {
			r.p.hashRecordProxyClose(r.g, conn.Close())
		}
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("proxy dial returned no connection")
	}
	return r.track(conn)
}

func (r *hashProxyRequest) closeOwned() {
	r.p.mu.Lock()
	connections := make([]*hashProxyConn, 0, len(r.owned))
	for c := range r.owned {
		connections = append(connections, c)
	}
	r.p.mu.Unlock()
	for _, c := range connections {
		_ = c.Close()
	}
}

func (r *hashProxyRequest) finish() {
	r.p.mu.Lock()
	r.finished = true // late transport dial results may no longer register
	r.p.mu.Unlock()
	r.cancel()
	r.closeOwned()
	if !r.stop() {
		<-r.closeDone // join cancellation-driven socket closes before Done
	}
	r.p.mu.Lock()
	delete(r.g.requests, r)
	r.p.mu.Unlock()
	r.g.workers.Done()
}

func (p *pinningProxy) hashBeginProxyRetirementLocked(g *hashProxyGeneration) {
	if g.retirement != nil {
		return
	}
	g.closing = true // no Add may race Wait after this gate closes
	r := &hashProxyRetirement{done: make(chan struct{})}
	g.retirement = r
	requests := make([]*hashProxyRequest, 0, len(g.requests))
	for req := range g.requests {
		requests = append(requests, req)
	}
	connections := make([]*hashProxyConn, 0, len(g.connections))
	for c := range g.connections {
		connections = append(connections, c)
	}
	go func() {
		defer close(r.done)
		g.cancel()
		for _, req := range requests {
			req.cancel()
		}
		closeErr := g.server.Close() // includes HTTP connections, not hijacked tunnels
		for _, c := range connections {
			if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		<-g.serveDone
		g.workers.Wait()
		p.mu.Lock()
		r.err = errors.Join(closeErr, g.closeErr)
		p.mu.Unlock()
	}()
}

func (p *pinningProxy) hashReconcileProxyLocked(g *hashProxyGeneration) error {
	select {
	case <-g.retirement.done:
	default:
		return errHashProxyShutdown
	}
	if g.retirement.err != nil {
		return errors.Join(errHashProxyShutdown, g.retirement.err)
	}
	if p.generation == g {
		p.generation, p.started = nil, false
	}
	return nil
}
