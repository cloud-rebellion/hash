// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package workguard

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func parentGrowthCoordinatorV1(t *testing.T, global, org int64) *CoordinatorV1 {
	t.Helper()
	c, err := NewV1(LimitsV1{Global: VectorV1{ParentBytes: global, DBStagingBytes: 4}, Organisation: VectorV1{ParentBytes: org, DBStagingBytes: 4}, MaxGrants: 4, MaxOrganisationGrants: 2})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGrantParentGrowthRetainsOneGrantAndEveryByteV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	org := uuid.New()
	c := parentGrowthCoordinatorV1(t, 32, 16)
	g, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 2, DBStagingBytes: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	copy := *g
	for _, bytes := range []int64{3, 4, 7} {
		if err := copy.TryGrowParentV1(ctx, bytes); err != nil {
			t.Fatal(err)
		}
	}
	want := SnapshotV1{Global: VectorV1{ParentBytes: 16, DBStagingBytes: 3}, Organisation: VectorV1{ParentBytes: 16, DBStagingBytes: 3}, GlobalGrants: 1, OrganisationGrants: 1, ActiveOrganisations: 1}
	if got := c.SnapshotV1(org); got != want {
		t.Fatalf("grown work/count mismatch: %+v", got)
	}
	if err := g.TryGrowParentV1(ctx, 1); !errors.Is(err, ErrUnavailableV1) || c.SnapshotV1(org) != want {
		t.Fatal("organisation limit refused without preserving original work", err)
	}
	copy.Close()
	g.Close()
	if got := c.SnapshotV1(org); got != (SnapshotV1{}) {
		t.Fatalf("final grown work survived close: %+v", got)
	}
	if err := copy.TryGrowParentV1(ctx, 1); !errors.Is(err, ErrUnavailableV1) {
		t.Fatal("copied closed grant grew", err)
	}
}

func TestGrantParentGrowthGlobalLimitIsAtomicV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := parentGrowthCoordinatorV1(t, 16, 16)
	org, other := uuid.New(), uuid.New()
	g, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h, err := c.TryAcquireV1(ctx, other, VectorV1{ParentBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	before := c.SnapshotV1(org)
	if err := g.TryGrowParentV1(ctx, 3); !errors.Is(err, ErrUnavailableV1) || c.SnapshotV1(org) != before {
		t.Fatal("global refusal mutated accounting", err)
	}
	if err := g.TryGrowParentV1(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if got := c.SnapshotV1(org); got.Global.ParentBytes != 16 || got.Organisation.ParentBytes != 6 || got.GlobalGrants != 2 || got.OrganisationGrants != 1 {
		t.Fatalf("growth stole or changed another grant: %+v", got)
	}
}

func TestGrantParentGrowthRefusesInvalidAndUnboundedContextsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := parentGrowthCoordinatorV1(t, 64, 64)
	org := uuid.New()
	g, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	before := c.SnapshotV1(org)
	for _, n := range []int64{-1, 0, math.MaxInt64, (1 << 40) + 1, 1 << 40} {
		if err := g.TryGrowParentV1(ctx, n); !errors.Is(err, ErrUnavailableV1) || c.SnapshotV1(org) != before {
			t.Fatal("invalid/unfunded growth changed accounting", n, err)
		}
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	expired, stopExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stopExpired()
	for _, call := range []context.Context{nil, context.Background(), cancelled, expired} {
		if err := g.TryGrowParentV1(call, 1); !errors.Is(err, ErrUnavailableV1) || c.SnapshotV1(org) != before {
			t.Fatal("invalid/dead/unbounded context grew", err)
		}
	}
	if err := g.TryGrowParentV1(cancelled, 1); !errors.Is(err, context.Canceled) {
		t.Fatal("original cancellation missing", err)
	}
	if err := g.TryGrowParentV1(expired, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("original deadline missing", err)
	}
	var nilGrant *GrantV1
	if nilGrant.TryGrowParentV1(ctx, 1) == nil || (&GrantV1{}).TryGrowParentV1(ctx, 1) == nil {
		t.Fatal("nil/unowned grant grew")
	}
}

func TestGrantParentGrowthCannotGrowProcessOnlyV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := parentGrowthCoordinatorV1(t, 16, 16)
	g, err := c.TryAcquireProcessV1(ctx, VectorV1{ParentBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	before := c.SnapshotV1(uuid.Nil)
	if err := g.TryGrowParentV1(ctx, 1); !errors.Is(err, ErrUnavailableV1) || c.SnapshotV1(uuid.Nil) != before {
		t.Fatal("process-only work acquired organisation growth", err)
	}
}

func TestGrantParentGrowthCheckedUpperBoundaryV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := parentGrowthCoordinatorV1(t, 1<<40, 1<<40)
	org := uuid.New()
	g, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if err := g.TryGrowParentV1(ctx, (1<<40)-1); err != nil {
		t.Fatal(err)
	}
	before := c.SnapshotV1(org)
	if before.Global.ParentBytes != 1<<40 {
		t.Fatal("boundary work omitted", before)
	}
	if err := g.TryGrowParentV1(ctx, 1); !errors.Is(err, ErrUnavailableV1) || c.SnapshotV1(org) != before {
		t.Fatal("large counter wrapped or mutated on refusal", err)
	}
}

func TestGrantParentGrowthCompetesAtomicallyAndJoinsCloseV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	for iteration := 0; iteration < 64; iteration++ {
		c := parentGrowthCoordinatorV1(t, 8, 8)
		g, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var admitted atomic.Int64
		for i := 0; i < 16; i++ {
			wg.Go(func() {
				<-start
				if g.TryGrowParentV1(ctx, 1) == nil {
					admitted.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()
		if admitted.Load() != 7 || c.SnapshotV1(org).GlobalGrants != 1 || c.SnapshotV1(org).Global.ParentBytes != 8 {
			t.Fatal("concurrent growth exceeded or lost capacity", admitted.Load(), c.SnapshotV1(org))
		}
		g.Close()
		g, err = c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		copy := *g
		start = make(chan struct{})
		wg.Go(func() { <-start; _ = copy.TryGrowParentV1(ctx, 1) })
		wg.Go(func() { <-start; g.Close() })
		close(start)
		wg.Wait()
		if got := c.SnapshotV1(org); got != (SnapshotV1{}) {
			t.Fatalf("close raced final grown work: %+v", got)
		}
		if copy.TryGrowParentV1(ctx, 1) == nil {
			t.Fatal("growth resurrected a closed grant")
		}
		full, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 8})
		if err != nil {
			t.Fatal("grown work leaked after joined close", err)
		}
		full.Close()
	}
}
