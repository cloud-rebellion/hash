// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// One original Client's actual ordinary and native transports share the same
// existing eight physical connection positions per dial host. A reservation
// spans Dial, failed-Dial cleanup and actual Conn.Close plus joined local IO.
// It is not a provider/work permit, a new capacity axis or remote retirement.
type storageConnectionHostV1 struct{ network, address string }
type storageConnectionCountV1 struct{ active, waiters int }
type storageConnectionAdmissionV1 struct {
	mu         sync.Mutex
	self       *storageConnectionAdmissionV1
	hosts      map[storageConnectionHostV1]*storageConnectionCountV1
	transports map[*http.Transport]struct{}
	changed    chan struct{}
	waiters    int
}

func newStorageConnectionAdmissionV1() *storageConnectionAdmissionV1 {
	s := &storageConnectionAdmissionV1{changed: make(chan struct{}), transports: make(map[*http.Transport]struct{})}
	s.self = s
	return s
}
func (s *storageConnectionAdmissionV1) registerV1(t *http.Transport) {
	s.mu.Lock()
	s.transports[t] = struct{}{}
	s.mu.Unlock()
}
func (s *storageConnectionAdmissionV1) unregisterV1(t *http.Transport) {
	s.mu.Lock()
	delete(s.transports, t)
	s.mu.Unlock()
}
func (s *storageConnectionAdmissionV1) signalV1() { close(s.changed); s.changed = make(chan struct{}) }
func (s *storageConnectionAdmissionV1) closeIdleForWaitersV1() {
	s.mu.Lock()
	if s.waiters == 0 {
		s.mu.Unlock()
		return
	}
	transports := make([]*http.Transport, 0, len(s.transports))
	for t := range s.transports {
		transports = append(transports, t)
	}
	s.mu.Unlock()
	// Only genuine standard Transport idle connections close. Active requests
	// remain intact. PutIdleConn runs after actual idle insertion, so an active
	// ordinary connection becoming idle cannot strand a native waiter until the
	// old60-second idle timeout. No detached polling/cleanup goroutine is needed.
	for _, t := range transports {
		t.CloseIdleConnections()
	}
}
func (s *storageConnectionAdmissionV1) acquireV1(ctx context.Context, network, address string) (storageConnectionHostV1, error) {
	key := storageConnectionHostV1{network: network, address: address}
	waiting := false
	for {
		if err := ctx.Err(); err != nil {
			if waiting {
				s.mu.Lock()
				entry := s.hosts[key]
				entry.waiters--
				s.waiters--
				if entry.active == 0 && entry.waiters == 0 {
					delete(s.hosts, key)
					if len(s.hosts) == 0 {
						s.hosts = nil
					}
				}
				s.signalV1()
				s.mu.Unlock()
			}
			return key, err
		}
		s.mu.Lock()
		if s.hosts == nil {
			s.hosts = make(map[storageConnectionHostV1]*storageConnectionCountV1)
		}
		entry := s.hosts[key]
		if entry == nil {
			key = storageConnectionHostV1{network: strings.Clone(network), address: strings.Clone(address)}
			entry = &storageConnectionCountV1{}
			s.hosts[key] = entry
		}
		if entry.active < boundedStorageConnectionsPerHostV1 {
			if waiting {
				entry.waiters--
				s.waiters--
			}
			entry.active++
			s.mu.Unlock()
			return key, nil
		}
		if !waiting {
			entry.waiters++
			s.waiters++
			waiting = true
		}
		changed := s.changed
		s.mu.Unlock()
		s.closeIdleForWaitersV1()
		select {
		case <-changed:
		case <-ctx.Done():
		}
	}
}
func (s *storageConnectionAdmissionV1) releaseV1(key storageConnectionHostV1) {
	s.mu.Lock()
	entry := s.hosts[key]
	entry.active--
	if entry.active == 0 && entry.waiters == 0 {
		delete(s.hosts, key)
		if len(s.hosts) == 0 {
			s.hosts = nil
		}
	}
	s.signalV1()
	s.mu.Unlock()
}
func (s *storageConnectionAdmissionV1) dialV1(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		key, err := s.acquireV1(ctx, network, address)
		if err != nil {
			return nil, err
		}
		inner, err := dial(ctx, network, address)
		if inner == nil {
			s.releaseV1(key)
			return nil, err
		}
		conn := &storageAdmittedConnV1{inner: inner, owner: s, key: key}
		conn.joined = sync.NewCond(&conn.mu)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

type storageAdmittedConnV1 struct {
	inner    net.Conn
	owner    *storageConnectionAdmissionV1
	key      storageConnectionHostV1
	mu       sync.Mutex
	joined   *sync.Cond
	active   int
	closed   bool
	once     sync.Once
	closeErr error
}

func (c *storageAdmittedConnV1) beginV1() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.active++
	return nil
}
func (c *storageAdmittedConnV1) endV1() {
	c.mu.Lock()
	c.active--
	if c.active == 0 {
		c.joined.Broadcast()
	}
	c.mu.Unlock()
}
func (c *storageAdmittedConnV1) Read(p []byte) (int, error) {
	if err := c.beginV1(); err != nil {
		return 0, err
	}
	defer c.endV1()
	return c.inner.Read(p)
}
func (c *storageAdmittedConnV1) Write(p []byte) (int, error) {
	if err := c.beginV1(); err != nil {
		return 0, err
	}
	defer c.endV1()
	return c.inner.Write(p)
}
func (c *storageAdmittedConnV1) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		err := c.inner.Close()
		c.mu.Lock()
		for c.active != 0 {
			c.joined.Wait()
		}
		c.closeErr = err
		c.mu.Unlock()
		c.owner.releaseV1(c.key)
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeErr
}
func (c *storageAdmittedConnV1) LocalAddr() net.Addr               { return c.inner.LocalAddr() }
func (c *storageAdmittedConnV1) RemoteAddr() net.Addr              { return c.inner.RemoteAddr() }
func (c *storageAdmittedConnV1) SetDeadline(t time.Time) error     { return c.inner.SetDeadline(t) }
func (c *storageAdmittedConnV1) SetReadDeadline(t time.Time) error { return c.inner.SetReadDeadline(t) }
func (c *storageAdmittedConnV1) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}
