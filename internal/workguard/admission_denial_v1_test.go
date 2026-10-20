// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package workguard

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"reflect"
	"sync"
	"testing"
)

func TestAdmissionDenialExactFirstAxisAndScopeV1(t *testing.T) {
	for axis := 0; axis < 7; axis++ {
		for _, organisationOnly := range []bool{false, true} {
			l := guardLimitsV1()
			if organisationOnly {
				v := l.Organisation.dimensions()
				v[axis] = 4
				l.Organisation = vectorV1(v)
			}
			c := guardNewV1(t, l)
			org := uuid.New()
			ctx := guardContextV1(t)
			var full [7]int64
			if organisationOnly {
				full[axis] = 4
			} else {
				full[axis] = 8
			}
			held, err := c.TryAcquireV1(ctx, org, vectorV1(full))
			if err != nil {
				t.Fatal(err)
			}
			before := c.SnapshotV1(org)
			requested := VectorV1{ParentBytes: 1, DBStagingBytes: 1, ChildAddressBytes: 1, PDFWorkers: 1, SQLSessions: 1, ProviderStreams: 1, RendererRequests: 1}
			g, denial, err := c.TryAcquireWithDenialV1(ctx, org, requested)
			want := AdmissionGlobalResourceV1
			if organisationOnly {
				want = AdmissionOrganisationResourceV1
			}
			got := denial.SnapshotV1()
			if g != nil || err != ErrUnavailableV1 || !denial.CapacityV1() || got.Reason != want || got.Dimension != AdmissionDimensionV1(axis+1) || got.Before != before || got.Requested != requested || got.GlobalLimit != l.Global || got.OrganisationLimit != l.Organisation || got.GlobalGrantLimit != l.MaxGrants || got.OrganisationGrantLimit != l.MaxOrganisationGrants {
				t.Fatalf("axis%d organisation%t: %+v %v", axis, organisationOnly, got, err)
			}
			if c.SnapshotV1(org) != before {
				t.Fatal("denial mutated accounting")
			}
			copied := got
			got.Before.Global.ParentBytes = 999
			held.Close()
			if denial.SnapshotV1() != copied {
				t.Fatal("observation retained mutable live state")
			}
		}
	}
}
func TestAdmissionDenialCountAndValidationOrderV1(t *testing.T) {
	ctx := guardContextV1(t)
	org := uuid.New()
	for _, organisationOnly := range []bool{false, true} {
		l := guardLimitsV1()
		l.MaxGrants = 1
		l.MaxOrganisationGrants = 1
		if organisationOnly {
			l.MaxGrants = 2
		}
		c := guardNewV1(t, l)
		held, err := c.TryAcquireV1(ctx, org, VectorV1{ParentBytes: 1})
		if err != nil {
			t.Fatal(err)
		}
		g, d, err := c.TryAcquireWithDenialV1(ctx, org, VectorV1{ParentBytes: 8})
		want := AdmissionGlobalGrantCountV1
		if organisationOnly {
			want = AdmissionOrganisationGrantCountV1
		}
		if g != nil || err != ErrUnavailableV1 || d.SnapshotV1().Reason != want || d.SnapshotV1().Dimension != AdmissionNoDimensionV1 {
			t.Fatal(d, err)
		}
		held.Close()
	}
	c := guardNewV1(t, guardLimitsV1())
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, d, err := c.TryAcquireWithDenialV1(cancelled, org, VectorV1{ParentBytes: 1})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnavailableV1) || d.CapacityV1() || d.SnapshotV1().Reason != AdmissionContextV1 {
		t.Fatal(d, err)
	}
	if g, d, err := c.TryAcquireWithDenialV1(ctx, org, VectorV1{ParentBytes: 1}); g == nil || err != nil || d != (AdmissionDenialV1{}) {
		t.Fatal("success changed", d, err)
	} else {
		g.Close()
	}
	if g, d, err := c.TryAcquireWithDenialV1(nil, org, VectorV1{ParentBytes: 1}); g != nil || err != ErrUnavailableV1 || d.SnapshotV1().Reason != AdmissionInvalidV1 {
		t.Fatal(d, err)
	}
	c.orgs = nil
	if g, d, err := c.TryAcquireWithDenialV1(ctx, org, VectorV1{ParentBytes: 1}); g != nil || err != ErrUnavailableV1 || d.CapacityV1() || d.SnapshotV1().Reason != AdmissionCoordinatorUnavailableV1 {
		t.Fatal(d, err)
	}
}
func TestAdmissionDenialAtomicConcurrentLastCapacityV1(t *testing.T) {
	l := guardLimitsV1()
	l.Global.ParentBytes = 1
	l.Organisation.ParentBytes = 1
	c := guardNewV1(t, l)
	org := uuid.New()
	ctx := guardContextV1(t)
	type result struct {
		g   *GrantV1
		d   AdmissionDenialV1
		err error
	}
	results := make(chan result, 32)
	start := make(chan struct{})
	var actors sync.WaitGroup
	for i := 0; i < 32; i++ {
		actors.Add(1)
		go func() {
			defer actors.Done()
			<-start
			g, d, err := c.TryAcquireWithDenialV1(ctx, org, VectorV1{ParentBytes: 1})
			results <- result{g, d, err}
		}()
	}
	close(start)
	actors.Wait()
	close(results)
	var winner *GrantV1
	denied := 0
	for result := range results {
		if result.err == nil {
			if winner != nil || result.g == nil || result.d != (AdmissionDenialV1{}) {
				t.Fatal("multiple winners")
			}
			winner = result.g
			continue
		}
		denied++
		d := result.d.SnapshotV1()
		if result.g != nil || result.err != ErrUnavailableV1 || d.Reason != AdmissionGlobalResourceV1 || d.Dimension != AdmissionParentBytesV1 || d.Before.Global.ParentBytes != 1 || d.Before.Organisation.ParentBytes != 1 || d.Before.GlobalGrants != 1 || d.Before.OrganisationGrants != 1 {
			t.Fatal("refusal not from exact locked decision", d, result.err)
		}
	}
	if winner == nil || denied != 31 {
		t.Fatal("incorrect atomic winners", denied)
	}
	winner.Close()
	if c.SnapshotV1(org) != (SnapshotV1{}) {
		t.Fatal("actual winner did not drain")
	}
}
func TestAdmissionDenialContainsOnlyFixedNumericValuesV1(t *testing.T) {
	var walk func(reflect.Type)
	walk = func(kind reflect.Type) {
		switch kind.Kind() {
		case reflect.Struct:
			for i := 0; i < kind.NumField(); i++ {
				walk(kind.Field(i).Type)
			}
		case reflect.Int64, reflect.Uint8:
		default:
			t.Fatalf("denial contains alias/allocation-capable field %s", kind)
		}
	}
	walk(reflect.TypeOf(AdmissionDenialV1{}))
}
