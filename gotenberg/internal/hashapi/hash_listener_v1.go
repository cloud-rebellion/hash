// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// hashRejectH2CUpgradeV1 is outside h2c.NewHandler: that library reads the
// complete HTTP/1 upgrade body before invoking its inner request handler.
// Ordinary HTTP/1 and HTTP/2 prior knowledge remain available. Admission for
// actual requests must live INSIDE h2c, never around a hijacked connection.
func hashRejectH2CUpgradeV1(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 1 {
			for _, line := range r.Header.Values("Upgrade") {
				for _, token := range strings.Split(line, ",") {
					if strings.EqualFold(strings.TrimSpace(token), "h2c") {
						w.Header().Set("Connection", "close")
						http.Error(w, "HTTP/1 h2c upgrade is not supported", http.StatusBadRequest)
						return
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// hashAPIServerV1 owns the actual serving goroutine and accepted connections.
// net/http does not wait for hijacked H2C connections in Shutdown.
// Request counts cover synchronous handler invocations, not the separately
// unresolved detached-handler behavior in the inherited timeout middleware.
type hashAPIServerV1 struct {
	server      *http.Server
	listener    *hashAPIListenerV1
	done        chan struct{}
	changed     chan struct{}
	mu          sync.Mutex
	connections map[*hashAPIConnV1]struct{}
	requests    int
	retiring    bool
	serveErr    error
	closeErr    error
	cleanupErr  error
	multipart   int
	owners      map[*hashRequestV2]struct{}
}

type hashAPIListenerV1 struct {
	net.Listener
	owner *hashAPIServerV1
}
type hashAPIConnV1 struct {
	net.Conn
	owner *hashAPIServerV1
	once  sync.Once
	err   error
}

func (s *hashAPIServerV1) signal() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}
func (l *hashAPIListenerV1) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tracked := &hashAPIConnV1{Conn: conn, owner: l.owner}
	l.owner.mu.Lock()
	l.owner.connections[tracked] = struct{}{}
	l.owner.mu.Unlock()
	l.owner.signal()
	// Match Echo's TCP keepalive policy while retaining the exact owned socket.
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err = tcp.SetKeepAlive(true); err == nil {
			err = tcp.SetKeepAlivePeriod(3 * time.Minute)
		}
		if err != nil {
			return nil, errors.Join(err, tracked.Close())
		}
	}
	return tracked, nil
}
func (c *hashAPIConnV1) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		if c.err == nil || errors.Is(c.err, net.ErrClosed) {
			delete(c.owner.connections, c)
		} else {
			c.owner.closeErr = errors.Join(c.owner.closeErr, fmt.Errorf("accepted connection close: %w", c.err))
		}
		c.owner.mu.Unlock()
		c.owner.signal()
	})
	return c.err
}

func startHashAPIServerV1(server *http.Server, handler http.Handler, certFile, keyFile string) (*hashAPIServerV1, error) {
	if server == nil || handler == nil {
		return nil, errors.New("HTTP server and handler are required")
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("both TLS certificate and key files are required")
	}
	secure := certFile != ""
	if secure {
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load API TLS identity: %w", err)
		}
		if server.TLSConfig == nil {
			server.TLSConfig = &tls.Config{}
		} else {
			server.TLSConfig = server.TLSConfig.Clone()
		}
		server.TLSConfig.Certificates = []tls.Certificate{certificate}
	}
	priorConnContext := server.ConnContext
	server.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		if priorConnContext != nil {
			ctx = priorConnContext(ctx, conn)
		}
		return context.WithValue(ctx, hashWireBodyKeyV2{}, true)
	}
	h2server := &http2.Server{}
	if err := http2.ConfigureServer(server, h2server); err != nil {
		return nil, fmt.Errorf("configure API HTTP/2: %w", err)
	}
	owned := &hashAPIServerV1{server: server, done: make(chan struct{}), changed: make(chan struct{}, 1), connections: make(map[*hashAPIConnV1]struct{})}
	// Track each real HTTP2 stream inside h2c, never its hijacked connection.
	trackedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { owned.serveOwnedV2(w, r, handler) })
	server.Handler = hashRejectH2CUpgradeV1(h2c.NewHandler(trackedHandler, h2server))
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen API: %w", err)
	}
	owned.listener = &hashAPIListenerV1{Listener: listener, owner: owned}
	go func() {
		defer close(owned.done)
		var err error
		if secure {
			err = server.ServeTLS(owned.listener, "", "")
		} else {
			err = server.Serve(owned.listener)
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		if err != nil && server.ErrorLog != nil {
			server.ErrorLog.Printf("API serving failed: %v", err)
		}
		owned.mu.Lock()
		owned.serveErr = err
		owned.mu.Unlock()
		owned.signal()
	}()
	return owned, nil
}

func (s *hashAPIServerV1) stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	// The fence and admission count share a mutex: every inner handler has
	// either entered before retirement or is refused, even if HTTP/2 delayed
	// scheduling it until after socket retirement.
	s.mu.Lock()
	s.retiring = true
	s.mu.Unlock()
	s.signal()
	shutdownErr := s.server.Shutdown(ctx)
	done := s.done
	joined := false
	for {
		if !joined {
			select {
			case <-done:
				joined = true
				done = nil
			default:
			}
		}
		s.mu.Lock()
		s.pruneRequestsV2()
		count, requests, serveErr, closeErr := len(s.connections), s.requests, s.serveErr, errors.Join(s.closeErr, s.cleanupErr)
		s.mu.Unlock()
		if joined && count == 0 && requests == 0 {
			return errors.Join(shutdownErr, serveErr, closeErr)
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(shutdownErr, err, serveErr, closeErr, fmt.Errorf("API retirement unconfirmed: serve_joined=%t connections=%d requests=%d", joined, count, requests))
		}
		select {
		case <-done:
			joined = true
			done = nil
		case <-s.changed:
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
		}
	}
}
