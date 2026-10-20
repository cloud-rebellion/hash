// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package workguard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestParentGrowthDenialExactDecisionV1(t *testing.T) {
	for _, orgLimit := range []bool{false, true} {
		t.Run(map[bool]string{false: "global", true: "organisation"}[orgLimit], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			limits := LimitsV1{Global: VectorV1{ParentBytes: 10}, Organisation: VectorV1{ParentBytes: 10}, MaxGrants: 4, MaxOrganisationGrants: 4}
			if orgLimit {
				limits.Global.ParentBytes = 20
			}
			c, err := NewV1(limits)
			if err != nil {
				t.Fatal(err)
			}
			org := uuid.New()
			g, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 8})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			before := c.SnapshotV1(org)
			denial, err := g.TryGrowParentWithDenialV1(ctx, 3)
			got := denial.SnapshotV1()
			want := AdmissionGlobalResourceV1
			if orgLimit {
				want = AdmissionOrganisationResourceV1
			}
			if !errors.Is(err, ErrUnavailableV1) || !denial.CapacityV1() || got.Reason != want || got.Dimension != AdmissionParentBytesV1 || got.Before != before || got.Requested != (VectorV1{ParentBytes: 3}) || got.GlobalLimit != limits.Global || got.OrganisationLimit != limits.Organisation || c.SnapshotV1(org) != before {
				t.Fatal("growth denial changed accounting or lost exact decision", got, err)
			}
			copy := got
			if d, err := g.TryGrowParentWithDenialV1(ctx, 2); err != nil || d != (AdmissionDenialV1{}) {
				t.Fatal("exact boundary growth failed", d, err)
			}
			if denial.SnapshotV1() != copy {
				t.Fatal("denial aliased live coordinator")
			}
			g.Close()
			if d, err := g.TryGrowParentWithDenialV1(ctx, 1); !errors.Is(err, ErrUnavailableV1) || d.CapacityV1() || d.SnapshotV1().Reason != AdmissionCoordinatorUnavailableV1 {
				t.Fatal("closed grant misclassified", d, err)
			}
		})
	}
}
func TestParentGrowthDenialValidationAndConcurrentLastCapacityV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := NewV1(LimitsV1{Global: VectorV1{ParentBytes: 3}, Organisation: VectorV1{ParentBytes: 3}, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	org := uuid.New()
	g, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	before := c.SnapshotV1(org)
	for _, n := range []int64{0, -1, 1<<40 + 1} {
		d, err := g.TryGrowParentWithDenialV1(ctx, n)
		if !errors.Is(err, ErrUnavailableV1) || d.CapacityV1() || d.SnapshotV1().Reason != AdmissionInvalidV1 || c.SnapshotV1(org) != before {
			t.Fatal("invalid growth changed accounting", n, d, err)
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	d, err := g.TryGrowParentWithDenialV1(canceled, 1)
	if !errors.Is(err, context.Canceled) || d.CapacityV1() || d.SnapshotV1().Reason != AdmissionContextV1 || c.SnapshotV1(org) != before {
		t.Fatal("cancellation misclassified", d, err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan struct {
		d   AdmissionDenialV1
		err error
	}, 2)
	for range 2 {
		wg.Go(func() {
			<-start
			d, err := g.TryGrowParentWithDenialV1(ctx, 2)
			results <- struct {
				d   AdmissionDenialV1
				err error
			}{d, err}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	wins, denials := 0, 0
	for r := range results {
		if r.err == nil {
			wins++
			if r.d != (AdmissionDenialV1{}) {
				t.Fatal("successful growth reported denial")
			}
		} else {
			denials++
			s := r.d.SnapshotV1()
			if !r.d.CapacityV1() || s.Before.Global.ParentBytes != 3 || s.Requested.ParentBytes != 2 {
				t.Fatal("concurrent refusal lost exact decision", s, r.err)
			}
		}
	}
	if wins != 1 || denials != 1 || c.SnapshotV1(org).Global.ParentBytes != 3 || c.SnapshotV1(org).GlobalGrants != before.GlobalGrants {
		t.Fatal("last capacity not atomic", wins, denials)
	}
}
