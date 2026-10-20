// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package workguard accounts for live work in one application process.
package workguard

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
)

var ErrUnavailableV1 = errors.New("workguard: capacity unavailable")

// VectorV1 separates conservative parent working memory, transient logical DB
// staging, child virtual address capacity and actual physical operations. It is
// neither a measured RSS bound nor a durable storage or deployment-wide quota.
// Trusted versioned adapters derive these costs from bounded input metadata;
// request bodies must never supply arbitrary cost vectors as permission.
type VectorV1 struct {
	ParentBytes, DBStagingBytes, ChildAddressBytes             int64
	PDFWorkers, SQLSessions, ProviderStreams, RendererRequests int64
}

func (v VectorV1) dimensions() [7]int64 {
	return [7]int64{v.ParentBytes, v.DBStagingBytes, v.ChildAddressBytes, v.PDFWorkers, v.SQLSessions, v.ProviderStreams, v.RendererRequests}
}
func vectorV1(v [7]int64) VectorV1 {
	return VectorV1{v[0], v[1], v[2], v[3], v[4], v[5], v[6]}
}
func validVectorV1(v VectorV1) bool {
	for i, n := range v.dimensions() {
		max := int64(1 << 40)
		if i >= 3 {
			max = 1 << 16
		}
		if n < 0 || n > max {
			return false
		}
	}
	return true
}

// Zero resource limits disable that resource. Both grant-count limits must be
// positive; they also bound the organisation map and outstanding grant objects.
// Each server/worker instance needs one shared coordinator and operator-approved
// limits whose aggregate fits the deployment's measured headroom.
type LimitsV1 struct {
	Global, Organisation             VectorV1
	MaxGrants, MaxOrganisationGrants int64
}
type accountV1 struct {
	used   [7]int64
	grants int64
}
type CoordinatorV1 struct {
	mu     sync.Mutex
	limits LimitsV1
	global accountV1
	orgs   map[uuid.UUID]*accountV1
}

func NewV1(l LimitsV1) (*CoordinatorV1, error) {
	if !validVectorV1(l.Global) || !validVectorV1(l.Organisation) || l.MaxGrants < 1 || l.MaxGrants > 1<<16 || l.MaxOrganisationGrants < 1 || l.MaxOrganisationGrants > l.MaxGrants {
		return nil, ErrUnavailableV1
	}
	g, o := l.Global.dimensions(), l.Organisation.dimensions()
	for i := range g {
		if o[i] > g[i] {
			return nil, ErrUnavailableV1
		}
	}
	return &CoordinatorV1{limits: l, orgs: make(map[uuid.UUID]*accountV1)}, nil
}

// GrantV1 owns one indivisible vector. Cancellation, expiry, logical SQL commit
// and process-local lease changes do not release it. Its owner calls Close only
// after all charged buffers, borrowers and physical work have retired. Unknown
// retirement remains charged. This class does not manufacture retirement proof.
type GrantV1 struct {
	state *grantStateV1
}
type grantStateV1 struct {
	once        sync.Once
	owner       *CoordinatorV1
	org         uuid.UUID
	cost        [7]int64
	processOnly bool
	closed      bool // Protected with cost by owner.mu, shared by copied handles.
}

// TryAcquireV1 never queues or waits for capacity, runs no I/O or user callback,
// and grants all dimensions/global/organisation counters atomically. The short
// mutex protects only bounded arithmetic and accounting. Callers holding entity
// locks must roll back on refusal before waiting or retrying outside the locks.
func (c *CoordinatorV1) TryAcquireV1(ctx context.Context, org uuid.UUID, cost VectorV1) (*GrantV1, error) {
	return c.tryAcquireV1(ctx, org, cost, nil)
}

// One core preserves the original validation, refusal and mutation order.
// An optional fixed numeric output records only this exact locked decision.
func (c *CoordinatorV1) tryAcquireV1(ctx context.Context, org uuid.UUID, cost VectorV1, denial *AdmissionDenialV1) (*GrantV1, error) {
	if c == nil || ctx == nil || org == uuid.Nil || !validVectorV1(cost) || cost == (VectorV1{}) {
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
	if c.orgs == nil || c.global.grants >= c.limits.MaxGrants {
		if c.orgs == nil {
			recordAdmissionDenialReasonV1(denial, AdmissionCoordinatorUnavailableV1)
		} else {
			c.recordAdmissionCapacityDenialLockedV1(denial, org, cost, AdmissionGlobalGrantCountV1, 0)
		}
		return nil, ErrUnavailableV1
	}
	a := c.orgs[org]
	if a == nil {
		a = &accountV1{}
	}
	if a.grants >= c.limits.MaxOrganisationGrants {
		c.recordAdmissionCapacityDenialLockedV1(denial, org, cost, AdmissionOrganisationGrantCountV1, 0)
		return nil, ErrUnavailableV1
	}
	g, o := c.limits.Global.dimensions(), c.limits.Organisation.dimensions()
	for i := range n {
		// Subtraction precedes addition: even rejected large input cannot wrap.
		if n[i] > g[i]-c.global.used[i] || n[i] > o[i]-a.used[i] {
			reason := AdmissionGlobalResourceV1
			if n[i] <= g[i]-c.global.used[i] {
				reason = AdmissionOrganisationResourceV1
			}
			c.recordAdmissionCapacityDenialLockedV1(denial, org, cost, reason, AdmissionDimensionV1(i+1))
			return nil, ErrUnavailableV1
		}
	}
	for i := range n {
		c.global.used[i] += n[i]
		a.used[i] += n[i]
	}
	c.global.grants++
	a.grants++
	c.orgs[org] = a
	return &GrantV1{state: &grantStateV1{owner: c, org: org, cost: n}}, nil
}

// TryGrowParentV1 adds positive parent work to this same continuously retained
// organisation grant. The original global/organisation limits still apply;
// grant counts and every other resource dimension remain unchanged. It neither
// refunds earlier work nor creates SQL, provider or process-only authority.
// A caller must retain the original grant until all of its grown work retires.
func (g *GrantV1) TryGrowParentV1(ctx context.Context, additionalBytes int64) error {
	return g.tryGrowParentV1(ctx, additionalBytes, nil)
}

// TryGrowParentWithDenialV1 reports the same atomic growth decision. Its copied
// numeric observation grants no resource or retry authority.
func (g *GrantV1) TryGrowParentWithDenialV1(ctx context.Context, additionalBytes int64) (AdmissionDenialV1, error) {
	var denial AdmissionDenialV1
	err := g.tryGrowParentV1(ctx, additionalBytes, &denial)
	return denial, err
}

func (g *GrantV1) tryGrowParentV1(ctx context.Context, additionalBytes int64, denial *AdmissionDenialV1) error {
	if g == nil || g.state == nil || g.state.owner == nil || ctx == nil || additionalBytes <= 0 || additionalBytes > 1<<40 {
		recordAdmissionDenialReasonV1(denial, AdmissionInvalidV1)
		return ErrUnavailableV1
	}
	if err := ctx.Err(); err != nil {
		recordAdmissionDenialReasonV1(denial, AdmissionContextV1)
		return errors.Join(ErrUnavailableV1, err)
	}
	if _, bounded := ctx.Deadline(); !bounded {
		recordAdmissionDenialReasonV1(denial, AdmissionInvalidV1)
		return ErrUnavailableV1
	}
	s := g.state
	c := s.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		recordAdmissionDenialReasonV1(denial, AdmissionContextV1)
		return errors.Join(ErrUnavailableV1, err)
	}
	if s.closed || s.processOnly || s.org == uuid.Nil || c.orgs == nil {
		recordAdmissionDenialReasonV1(denial, AdmissionCoordinatorUnavailableV1)
		return ErrUnavailableV1
	}
	a := c.orgs[s.org]
	if a == nil || additionalBytes > (1<<40)-s.cost[0] {
		recordAdmissionDenialReasonV1(denial, AdmissionInvalidV1)
		return ErrUnavailableV1
	}
	if additionalBytes > c.limits.Global.ParentBytes-c.global.used[0] {
		c.recordAdmissionCapacityDenialLockedV1(denial, s.org, VectorV1{ParentBytes: additionalBytes}, AdmissionGlobalResourceV1, AdmissionParentBytesV1)
		return ErrUnavailableV1
	}
	if additionalBytes > c.limits.Organisation.ParentBytes-a.used[0] {
		c.recordAdmissionCapacityDenialLockedV1(denial, s.org, VectorV1{ParentBytes: additionalBytes}, AdmissionOrganisationResourceV1, AdmissionParentBytesV1)
		return ErrUnavailableV1
	}
	c.global.used[0] += additionalBytes
	a.used[0] += additionalBytes
	s.cost[0] += additionalBytes
	return nil
}

// Close is synchronous, idempotent, bounded accounting with no I/O/callbacks.
// Keep a grant private to its actual lifetime owner rather than sharing Close
// with request consumers who cannot prove physical retirement.
func (g *GrantV1) Close() {
	if g == nil || g.state == nil || g.state.owner == nil {
		return
	}
	s := g.state
	s.once.Do(func() {
		c := s.owner
		c.mu.Lock()
		defer c.mu.Unlock()
		s.closed = true
		for i, n := range s.cost {
			c.global.used[i] -= n
		}
		c.global.grants--
		if !s.processOnly {
			a := c.orgs[s.org]
			for i, n := range s.cost {
				a.used[i] -= n
			}
			a.grants--
			if a.grants == 0 {
				delete(c.orgs, s.org)
			}
		}
	})
}

type SnapshotV1 struct {
	Global, Organisation                                  VectorV1
	GlobalGrants, OrganisationGrants, ActiveOrganisations int64
}

// SnapshotV1 is a consistent bounded numeric observation, not spare durable
// storage proof or a permit. No organisation inventory or document data leaves.
func (c *CoordinatorV1) SnapshotV1(org uuid.UUID) SnapshotV1 {
	if c == nil {
		return SnapshotV1{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := SnapshotV1{Global: vectorV1(c.global.used), GlobalGrants: c.global.grants, ActiveOrganisations: int64(len(c.orgs))}
	if a := c.orgs[org]; a != nil {
		s.Organisation = vectorV1(a.used)
		s.OrganisationGrants = a.grants
	}
	return s
}
