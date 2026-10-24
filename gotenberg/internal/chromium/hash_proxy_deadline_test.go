// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestHashProxyLateDialDeadlineClosesExactConnection(t *testing.T) {
	done := make(chan struct{})
	peer := hashNewProxyPeer(t, func(c net.Conn) {
		defer close(done)
		var body [1]byte
		if n, err := c.Read(body[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Error("late deadline socket received payload or remained open: ", n, err)
		}
	})
	p := hashProxyForPeer(peer)
	hashStartProxyFixture(t, p, nil)
	r, err := p.hashAdmitProxyRequest(hashProxyGenerationForTest(p), context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var finishOnce sync.Once
	finish := func() { finishOnce.Do(r.finish) }
	t.Cleanup(finish)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	conn, err := r.dial(ctx, func(actual context.Context) (net.Conn, error) {
		<-actual.Done() // explicitly ignore cancellation and return a late real socket
		return net.DialTimeout("tcp", peer.listener.Addr().String(), time.Second)
	})
	if conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("late nil-error dial accepted: ", err)
	}
	hashAwait(t, "exact late socket closed before peer sees payload", done)
	finish()
	if err := p.Stop(testLogger()); err != nil {
		t.Fatal(err)
	}
}
