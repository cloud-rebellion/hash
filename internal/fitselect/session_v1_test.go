// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitselect

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
)

type testCloserV1 struct {
	closed       bool
	err          error
	closeCalls   int
	setClosed    bool
	done         chan struct{}
	deferCleanup bool
}

func (c *testCloserV1) Close(ctx context.Context) error {
	c.closeCalls++
	if c.done == nil {
		c.done = make(chan struct{})
	}
	if c.setClosed {
		c.closed = true
		if !c.deferCleanup {
			select {
			case <-c.done:
			default:
				close(c.done)
			}
		}
	}
	return c.err
}
func (c *testCloserV1) IsClosed() bool               { return c.closed }
func (c *testCloserV1) CleanupDone() <-chan struct{} { return c.done }
func TestFreshSessionCapacityV1CancellationAndVerifiedClose(t *testing.T) {
	slots := make(chan struct{}, 1)
	permit, err := acquireSessionV1(context.Background(), slots)
	if err != nil {
		t.Fatal(err)
	}
	waiting, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() { close(started); _, e := acquireSessionV1(waiting, slots); result <- e }()
	<-started
	cancel()
	select {
	case e := <-result:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("capacity wait lost cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("capacity wait did not cancel")
	}
	if len(slots) != 1 {
		t.Fatal("canceled wait consumed or freed active session")
	}
	c := &testCloserV1{err: errors.New("close transport failed")}
	closeErr, closed := closeConnection(c)
	permit.releaseAfterClose(closed)
	if closeErr == nil || closed || len(slots) != 1 {
		t.Fatal("unverified close prematurely admitted another SQL session")
	}
	// A close response error can still follow an actually closed connection.
	// Later verified closure releases one permit, even if cleanup is repeated.
	c.setClosed = true
	closeErr, closed = closeConnection(c)
	permit.releaseAfterClose(closed)
	permit.releaseAfterClose(closed)
	if closeErr == nil || !closed || len(slots) != 0 || c.closeCalls != 2 {
		t.Fatal("verified close error leaked or double-released session")
	}
	next, e := acquireSessionV1(context.Background(), slots)
	if e != nil {
		t.Fatal("capacity not recovered after verified close")
	}
	next.releaseAfterClose(true)
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, e = acquireSessionV1(canceled, slots); !errors.Is(e, context.Canceled) || len(slots) != 0 {
		t.Fatal("pre-canceled caller reached available capacity")
	}
}

func TestPhysicalCleanupV1LogicalCloseCannotRelease(t *testing.T) {
	slots := make(chan struct{}, 1)
	permit, e := acquireSessionV1(context.Background(), slots)
	if e != nil {
		t.Fatal(e)
	}
	closer := &testCloserV1{closed: true, setClosed: true, deferCleanup: true, done: make(chan struct{})}
	err, done := closeConnection(closer)
	permit.releaseAfterClose(done)
	if !errors.Is(err, ErrOutcomeUnknownV1) || done || len(slots) != 1 {
		t.Fatal("logical close bypassed actual cleanup fence")
	}
	close(closer.done)
	err, done = closeConnection(closer)
	permit.releaseAfterClose(done)
	if err != nil || !done || len(slots) != 0 {
		t.Fatal("physical cleanup completion did not reclaim permit")
	}
}
func TestSQLAdapterV1BoundedShutdownOwnsActivePermit(t *testing.T) {
	adapter := &PostgreSQLV1{slots: make(chan struct{}, 1), pending: make(map[*pgx.Conn]*sessionPermitV1), changed: make(chan struct{})}
	permit, e := adapter.acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e = adapter.CloseV1(ctx); !errors.Is(e, ErrOutcomeUnknownV1) || len(adapter.slots) != 1 {
		t.Fatal("timed shutdown claimed active session cleanup")
	}
	if _, e = adapter.acquire(context.Background()); !errors.Is(e, ErrOutcomeUnknownV1) {
		t.Fatal("closed adapter admitted another SQL session")
	}
	permit.releaseAfterClose(true)
	if e = adapter.CloseV1(context.Background()); e != nil || len(adapter.slots) != 0 {
		t.Fatal("shutdown did not join verified completion")
	}
}
