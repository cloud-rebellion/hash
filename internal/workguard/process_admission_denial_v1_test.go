// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package workguard

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestProcessAdmissionDenialExactDecisionWithoutTenantV1(t *testing.T) {
	ctx := guardContextV1(t)
	for axis := 0; axis < 7; axis++ {
		c := guardNewV1(t, guardLimitsV1())
		var full [7]int64
		full[axis] = 8
		held, err := c.TryAcquireProcessV1(ctx, vectorV1(full))
		if err != nil {
			t.Fatal(err)
		}
		before := c.SnapshotV1(uuid.Nil)
		var requested [7]int64
		requested[axis] = 1
		grant, denial, err := c.TryAcquireProcessWithDenialV1(ctx, vectorV1(requested))
		d := denial.SnapshotV1()
		if grant != nil || err != ErrUnavailableV1 || !denial.CapacityV1() ||
			d.Reason != AdmissionGlobalResourceV1 || d.Dimension != AdmissionDimensionV1(axis+1) ||
			d.Requested != vectorV1(requested) || d.Before != before || d.GlobalLimit != guardLimitsV1().Global ||
			d.OrganisationLimit != (VectorV1{}) || d.OrganisationGrantLimit != 0 || d.Before.ActiveOrganisations != 0 {
			t.Fatalf("axis%d: invalid original process decision: %+v %v", axis, d, err)
		}
		if c.SnapshotV1(uuid.Nil) != before {
			t.Fatal("denial changed accounting")
		}
		held.Close()
		if denial.SnapshotV1() != d {
			t.Fatal("denial retained live accounting")
		}
		grant, success, err := c.TryAcquireProcessWithDenialV1(ctx, vectorV1(requested))
		if grant == nil || err != nil || success != (AdmissionDenialV1{}) {
			t.Fatal("success semantics changed")
		}
		grant.Close()
		if got := c.SnapshotV1(uuid.Nil); got.GlobalGrants != 0 || got.ActiveOrganisations != 0 {
			t.Fatal("retained process or invented tenant")
		}
	}
}

func TestProcessAdmissionDenialValidationAndCountV1(t *testing.T) {
	ctx := guardContextV1(t)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for _, tc := range []struct {
		ctx    context.Context
		cost   VectorV1
		reason AdmissionDenialReasonV1
	}{
		{nil, VectorV1{SQLSessions: 1}, AdmissionInvalidV1},
		{context.Background(), VectorV1{SQLSessions: 1}, AdmissionInvalidV1},
		{canceled, VectorV1{SQLSessions: 1}, AdmissionContextV1},
		{ctx, VectorV1{}, AdmissionInvalidV1},
		{ctx, VectorV1{SQLSessions: -1}, AdmissionInvalidV1},
	} {
		c := guardNewV1(t, guardLimitsV1())
		g, d, err := c.TryAcquireProcessWithDenialV1(tc.ctx, tc.cost)
		if g != nil || !errors.Is(err, ErrUnavailableV1) || d.CapacityV1() || d.SnapshotV1().Reason != tc.reason {
			t.Fatal("validation semantics changed", d, err)
		}
		if c.SnapshotV1(uuid.Nil).GlobalGrants != 0 {
			t.Fatal("invalid request granted capacity")
		}
	}
	l := guardLimitsV1()
	l.MaxGrants = 1
	l.MaxOrganisationGrants = 1
	c := guardNewV1(t, l)
	held, err := c.TryAcquireProcessV1(ctx, VectorV1{ParentBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	g, d, err := c.TryAcquireProcessWithDenialV1(ctx, VectorV1{SQLSessions: 9})
	if g != nil || err != ErrUnavailableV1 || d.SnapshotV1().Reason != AdmissionGlobalGrantCountV1 || d.SnapshotV1().Dimension != AdmissionNoDimensionV1 {
		t.Fatal("count precedence changed", d, err)
	}
	held.Close()
	c.orgs = nil
	g, d, err = c.TryAcquireProcessWithDenialV1(ctx, VectorV1{SQLSessions: 1})
	if g != nil || err != ErrUnavailableV1 || d.CapacityV1() || d.SnapshotV1().Reason != AdmissionCoordinatorUnavailableV1 {
		t.Fatal("closed coordinator changed", d, err)
	}
}

func TestProcessAdmissionDenialConcurrentLastSlotV1(t *testing.T) {
	l := guardLimitsV1()
	l.Global.SQLSessions = 1
	l.Organisation.SQLSessions = 1
	c := guardNewV1(t, l)
	ctx := guardContextV1(t)
	type result struct {
		g   *GrantV1
		d   AdmissionDenialV1
		err error
	}
	start := make(chan struct{})
	results := make(chan result, 16)
	var actors sync.WaitGroup
	for i := 0; i < 16; i++ {
		actors.Add(1)
		go func() {
			defer actors.Done()
			<-start
			g, d, e := c.TryAcquireProcessWithDenialV1(ctx, VectorV1{SQLSessions: 1})
			results <- result{g, d, e}
		}()
	}
	close(start)
	actors.Wait()
	close(results)
	var winner *GrantV1
	denied := 0
	for r := range results {
		if r.err == nil {
			if winner != nil || r.g == nil || r.d != (AdmissionDenialV1{}) {
				t.Fatal("multiple winners")
			}
			winner = r.g
			continue
		}
		denied++
		d := r.d.SnapshotV1()
		if r.g != nil || r.err != ErrUnavailableV1 || d.Reason != AdmissionGlobalResourceV1 || d.Dimension != AdmissionSQLSessionsV1 || d.Before.Global.SQLSessions != 1 || d.Before.GlobalGrants != 1 || d.Before.Organisation != (VectorV1{}) || d.Before.ActiveOrganisations != 0 {
			t.Fatal("not the original locked decision", d, r.err)
		}
	}
	if winner == nil || denied != 15 {
		t.Fatal("invalid winner count", denied)
	}
	winner.Close()
}
