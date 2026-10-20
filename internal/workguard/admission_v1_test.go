// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package workguard

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func guardContextV1(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func guardLimitsV1() LimitsV1 {
	v := VectorV1{ParentBytes: 8, DBStagingBytes: 8, ChildAddressBytes: 8, PDFWorkers: 8, SQLSessions: 8, ProviderStreams: 8, RendererRequests: 8}
	return LimitsV1{Global: v, Organisation: v, MaxGrants: 32, MaxOrganisationGrants: 32}
}
func guardNewV1(t *testing.T, l LimitsV1) *CoordinatorV1 {
	t.Helper()
	c, err := NewV1(l)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAdmissionV1AtomicVectorRefusal(t *testing.T) {
	for axis := 0; axis < 7; axis++ {
		t.Run(string(rune('a'+axis)), func(t *testing.T) {
			c := guardNewV1(t, guardLimitsV1())
			org := uuid.New()
			other := uuid.New()
			ctx := guardContextV1(t)
			var full [7]int64
			full[axis] = 8
			g, err := c.TryAcquireV1(ctx, org, vectorV1(full))
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			before := c.SnapshotV1(org)
			mixed := VectorV1{ParentBytes: 1, DBStagingBytes: 1, ChildAddressBytes: 1, PDFWorkers: 1, SQLSessions: 1, ProviderStreams: 1, RendererRequests: 1}
			if rejected, err := c.TryAcquireV1(ctx, other, mixed); rejected != nil || !errors.Is(err, ErrUnavailableV1) {
				t.Fatal("partial vector admitted")
			}
			if after := c.SnapshotV1(org); after != before || c.SnapshotV1(other).OrganisationGrants != 0 {
				t.Fatal("refusal mutated accounting")
			}
		})
	}
}

func TestAdmissionV1GlobalAndOrganisationLimits(t *testing.T) {
	l := guardLimitsV1()
	l.Global.ParentBytes = 8
	l.Organisation.ParentBytes = 4
	c := guardNewV1(t, l)
	ctx := guardContextV1(t)
	a, b := uuid.New(), uuid.New()
	first, err := c.TryAcquireV1(ctx, a, VectorV1{ParentBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if g, err := c.TryAcquireV1(ctx, a, VectorV1{ParentBytes: 1}); g != nil || err == nil {
		t.Fatal("tenant overspend")
	}
	second, err := c.TryAcquireV1(ctx, b, VectorV1{ParentBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if g, err := c.TryAcquireV1(ctx, uuid.New(), VectorV1{ParentBytes: 1}); g != nil || err == nil {
		t.Fatal("global overspend")
	}
	if got := c.SnapshotV1(a); got.Global.ParentBytes != 8 || got.Organisation.ParentBytes != 4 || got.ActiveOrganisations != 2 {
		t.Fatal(got)
	}
}

func TestAdmissionV1ConcurrentLastVectorAndCopyClose(t *testing.T) {
	l := guardLimitsV1()
	l.Global.ParentBytes = 4
	l.Organisation.ParentBytes = 4
	l.Global.PDFWorkers = 1
	l.Organisation.PDFWorkers = 1
	c := guardNewV1(t, l)
	ctx := guardContextV1(t)
	orgs := []uuid.UUID{uuid.New(), uuid.New()}
	start := make(chan struct{})
	results := make(chan *GrantV1, 32)
	var actors sync.WaitGroup
	for i := 0; i < 32; i++ {
		actors.Add(1)
		go func(org uuid.UUID) {
			defer actors.Done()
			<-start
			g, _ := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 4, PDFWorkers: 1})
			results <- g
		}(orgs[i%2])
	}
	close(start)
	actors.Wait()
	close(results)
	var winner *GrantV1
	count := 0
	for g := range results {
		if g != nil {
			count++
			winner = g
		}
	}
	if winner != nil {
		defer winner.Close()
	}
	if count != 1 || c.SnapshotV1(uuid.Nil).GlobalGrants != 1 {
		t.Fatal("last vector was not exclusive", count)
	}
	// Copying the exported opaque handle still shares its private once owner.
	alias := *winner
	var closers sync.WaitGroup
	for i := 0; i < 32; i++ {
		closers.Add(1)
		go func() { defer closers.Done(); alias.Close(); winner.Close() }()
	}
	closers.Wait()
	if got := c.SnapshotV1(orgs[0]); got != (SnapshotV1{}) {
		t.Fatal("duplicate release", got)
	}
}

func TestAdmissionV1CancellationAndUnknownRetain(t *testing.T) {
	l := guardLimitsV1()
	l.MaxGrants = 1
	l.MaxOrganisationGrants = 1
	c := guardNewV1(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	g, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 1, SQLSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	cancel()
	if c.SnapshotV1(org).GlobalGrants != 1 {
		t.Fatal("cancellation credited unresolved work")
	}
	if next, err := c.TryAcquireV1(guardContextV1(t), org, VectorV1{ParentBytes: 1}); next != nil || err == nil {
		t.Fatal("grant count ignored")
	}
	g.Close()
	next, err := c.TryAcquireV1(guardContextV1(t), org, VectorV1{ParentBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
	if got := c.SnapshotV1(org); got != (SnapshotV1{}) {
		t.Fatal(got)
	}
}

func TestAdmissionV1InvalidAndOverflowInputs(t *testing.T) {
	c := guardNewV1(t, guardLimitsV1())
	org := uuid.New()
	for _, cost := range []VectorV1{{}, {ParentBytes: -1}, {ParentBytes: math.MaxInt64}, {PDFWorkers: 1 << 17}, {ParentBytes: 1, DBStagingBytes: -1}} {
		if g, err := c.TryAcquireV1(guardContextV1(t), org, cost); g != nil || !errors.Is(err, ErrUnavailableV1) {
			t.Fatal("invalid vector admitted")
		}
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if g, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 1}); g != nil || err == nil {
			t.Fatal("unbounded context admitted")
		}
	}
	if g, err := c.TryAcquireV1(guardContextV1(t), uuid.Nil, VectorV1{ParentBytes: 1}); g != nil || err == nil {
		t.Fatal("unknown tenant admitted")
	}
	ctx, cancel := context.WithCancel(guardContextV1(t))
	cancel()
	if g, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 1}); g != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if c.SnapshotV1(org) != (SnapshotV1{}) {
		t.Fatal("invalid calls allocated state")
	}
	for _, mutate := range []func(*LimitsV1){func(l *LimitsV1) { l.MaxGrants = 0 }, func(l *LimitsV1) { l.MaxOrganisationGrants = 33 }, func(l *LimitsV1) { l.Organisation.ParentBytes = 9 }, func(l *LimitsV1) { l.Global.ChildAddressBytes = -1 }} {
		l := guardLimitsV1()
		mutate(&l)
		if guard, err := NewV1(l); guard != nil || err == nil {
			t.Fatal("invalid limits admitted")
		}
	}
}
