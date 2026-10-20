// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package workguard

import (
	"context"
	"errors"
)

// TryAcquireProcessV1 admits trusted process-wide control/probe work before an
// authenticated tenant is known. It charges the SAME global vector/grant limits
// as ordinary tenant work, but never invents a tenant UUID, charges a claimed
// tenant or creates an organisation account. It grants no tenant/data authority.
// Fixed native adapters, not request bodies, must derive the actual cost.
func (c *CoordinatorV1) TryAcquireProcessV1(ctx context.Context, cost VectorV1) (*GrantV1, error) {
	return c.tryAcquireProcessV1(ctx, cost, nil)
}

// TryAcquireProcessWithDenialV1 observes the same single process acquisition.
// Its fixed numeric companion grants no tenant or resource authority. The
// caller must already own storage for the observation independently.
func (c *CoordinatorV1) TryAcquireProcessWithDenialV1(ctx context.Context, cost VectorV1) (*GrantV1, AdmissionDenialV1, error) {
	var denial AdmissionDenialV1
	grant, err := c.tryAcquireProcessV1(ctx, cost, &denial)
	return grant, denial, err
}

func (c *CoordinatorV1) tryAcquireProcessV1(ctx context.Context, cost VectorV1, denial *AdmissionDenialV1) (*GrantV1, error) {
	if c == nil || ctx == nil || !validVectorV1(cost) || cost == (VectorV1{}) {
		recordAdmissionDenialReasonV1(denial, AdmissionInvalidV1)
		return nil, ErrUnavailableV1
	}
	if err := ctx.Err(); err != nil {
		recordAdmissionDenialReasonV1(denial, AdmissionContextV1)
		return nil, errors.Join(ErrUnavailableV1, err)
	}
	if _, bounded := ctx.Deadline(); !bounded {
		recordAdmissionDenialReasonV1(denial, AdmissionInvalidV1)
		return nil, ErrUnavailableV1
	}
	n := cost.dimensions()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		recordAdmissionDenialReasonV1(denial, AdmissionContextV1)
		return nil, errors.Join(ErrUnavailableV1, err)
	}
	if c.orgs == nil {
		recordAdmissionDenialReasonV1(denial, AdmissionCoordinatorUnavailableV1)
		return nil, ErrUnavailableV1
	}
	if c.global.grants >= c.limits.MaxGrants {
		c.recordProcessCapacityDenialLockedV1(denial, cost, AdmissionGlobalGrantCountV1, AdmissionNoDimensionV1)
		return nil, ErrUnavailableV1
	}
	global := c.limits.Global.dimensions()
	for i := range n {
		if n[i] > global[i]-c.global.used[i] {
			c.recordProcessCapacityDenialLockedV1(denial, cost, AdmissionGlobalResourceV1, AdmissionDimensionV1(i+1))
			return nil, ErrUnavailableV1
		}
	}
	for i := range n {
		c.global.used[i] += n[i]
	}
	c.global.grants++
	return &GrantV1{state: &grantStateV1{owner: c, cost: n, processOnly: true}}, nil
}

// Caller holds the original decision lock. Process work has no organisation;
// no invented UUID, tenant lookup or later snapshot contributes these facts.
func (c *CoordinatorV1) recordProcessCapacityDenialLockedV1(d *AdmissionDenialV1, cost VectorV1, reason AdmissionDenialReasonV1, dimension AdmissionDimensionV1) {
	if d != nil {
		*d = AdmissionDenialV1{reason: reason, dimension: dimension, requested: cost,
			globalLimit: c.limits.Global, globalGrantLimit: c.limits.MaxGrants,
			before: SnapshotV1{Global: vectorV1(c.global.used), GlobalGrants: c.global.grants, ActiveOrganisations: int64(len(c.orgs))}}
	}
}
