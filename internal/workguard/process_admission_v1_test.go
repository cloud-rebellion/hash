// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package workguard

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestProcessWorkCompetesWithSameGlobalTenantBudgetV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := NewV1(LimitsV1{Global: VectorV1{SQLSessions: 2, ParentBytes: 16}, Organisation: VectorV1{SQLSessions: 1, ParentBytes: 16}, MaxGrants: 3, MaxOrganisationGrants: 1})
	if err != nil {
		t.Fatal(err)
	}
	process, err := c.TryAcquireProcessV1(ctx, VectorV1{SQLSessions: 1})
	if err != nil {
		t.Fatal("process control refused fixed shared capacity")
	}
	defer process.Close()
	org := uuid.New()
	snap := c.SnapshotV1(org)
	if snap.Global.SQLSessions != 1 || snap.GlobalGrants != 1 || snap.ActiveOrganisations != 0 || snap.OrganisationGrants != 0 {
		t.Fatal("unscoped work invented or charged a tenant")
	}
	tenant, err := c.TryAcquireV1(ctx, org, VectorV1{SQLSessions: 1})
	if err != nil {
		t.Fatal("process control incorrectly spent tenant-local allocation")
	}
	defer tenant.Close()
	if extra, err := c.TryAcquireProcessV1(ctx, VectorV1{SQLSessions: 1}); err == nil || extra != nil {
		if extra != nil {
			extra.Close()
		}
		t.Fatal("process work bypassed the shared global SQL ceiling")
	}
	if extra, err := c.TryAcquireV1(ctx, uuid.New(), VectorV1{SQLSessions: 1}); err == nil || extra != nil {
		if extra != nil {
			extra.Close()
		}
		t.Fatal("other tenant bypassed held process control")
	}
	process.Close()
	process.Close()
	snap = c.SnapshotV1(org)
	if snap.Global.SQLSessions != 1 || snap.GlobalGrants != 1 || snap.Organisation.SQLSessions != 1 || snap.OrganisationGrants != 1 || snap.ActiveOrganisations != 1 {
		t.Fatal("process-only closure removed tenant accounting or refunded twice")
	}
	replacement, err := c.TryAcquireProcessV1(ctx, VectorV1{SQLSessions: 1})
	if err != nil {
		t.Fatal("actual local process owner could not reuse released fixture capacity")
	}
	replacement.Close()
	tenant.Close()
	if final := c.SnapshotV1(org); final.Global != (VectorV1{}) || final.GlobalGrants != 0 || final.ActiveOrganisations != 0 {
		t.Fatal("local-only accounting fixture retained an owner")
	}
}
func TestProcessWorkCannotBypassGlobalGrantLimitV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := NewV1(LimitsV1{Global: VectorV1{ParentBytes: 100}, Organisation: VectorV1{ParentBytes: 100}, MaxGrants: 1, MaxOrganisationGrants: 1})
	if err != nil {
		t.Fatal(err)
	}
	held, err := c.TryAcquireProcessV1(ctx, VectorV1{ParentBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if next, err := c.TryAcquireV1(ctx, uuid.New(), VectorV1{ParentBytes: 1}); err == nil || next != nil {
		if next != nil {
			next.Close()
		}
		t.Fatal("tenant work bypassed process grant cap")
	}
	if next, err := c.TryAcquireProcessV1(ctx, VectorV1{ParentBytes: 1}); err == nil || next != nil {
		if next != nil {
			next.Close()
		}
		t.Fatal("process work bypassed process grant cap")
	}
}
func TestProcessWorkRefusesUnboundedCancelledOrInvalidV1(t *testing.T) {
	c, err := NewV1(LimitsV1{Global: VectorV1{SQLSessions: 1}, Organisation: VectorV1{SQLSessions: 1}, MaxGrants: 1, MaxOrganisationGrants: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	cancelled, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	for _, tc := range []struct {
		ctx  context.Context
		cost VectorV1
	}{{nil, VectorV1{SQLSessions: 1}}, {context.Background(), VectorV1{SQLSessions: 1}}, {cancelled, VectorV1{SQLSessions: 1}}, {ctx, VectorV1{}}, {ctx, VectorV1{SQLSessions: -1}}, {ctx, VectorV1{SQLSessions: 1<<16 + 1}}} {
		if owner, err := c.TryAcquireProcessV1(tc.ctx, tc.cost); owner != nil || !errors.Is(err, ErrUnavailableV1) {
			if owner != nil {
				owner.Close()
			}
			t.Fatal("invalid unscoped fixture created a process owner")
		}
	}
	if snap := c.SnapshotV1(uuid.Nil); snap.GlobalGrants != 0 || snap.ActiveOrganisations != 0 {
		t.Fatal("rejected process acquisition mutated accounting")
	}
}
