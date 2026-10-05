// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package importguard bounds expensive authoring work shared by HTTP and MCP.
package importguard

import (
	"errors"
	"github.com/google/uuid"
	"sync"
)

var ErrBusy = errors.New("import capacity busy; retry later")

// Admission rejects excess work immediately instead of retaining queued bodies.
// Limits are process-local; the HTTP singleton lease must remain enforced.
type Admission struct {
	mu        sync.Mutex
	active    int
	anonymous bool
	orgs      map[uuid.UUID]bool
	limit     int
}

func New(limit int) *Admission {
	if limit < 1 {
		panic("import capacity must be positive")
	}
	return &Admission{limit: limit, orgs: make(map[uuid.UUID]bool)}
}

// Shared permits two imports globally and one per organisation. Acquire before
// body decoding/rendering; retain the lease through cleaning and persistence.
var Shared = New(2)

func (a *Admission) Acquire(org uuid.UUID) (func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if org == uuid.Nil || a.active >= a.limit || a.orgs[org] {
		return nil, ErrBusy
	}
	a.active++
	a.orgs[org] = true
	var once sync.Once
	return func() { once.Do(func() { a.mu.Lock(); defer a.mu.Unlock(); a.active--; delete(a.orgs, org) }) }, nil
}

// AcquireAnonymous shares the global budget but permits at most one public
// verification at a time, leaving capacity for authenticated authoring.
func (a *Admission) AcquireAnonymous() (func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active >= a.limit || a.anonymous {
		return nil, ErrBusy
	}
	a.active++
	a.anonymous = true
	var once sync.Once
	return func() { once.Do(func() { a.mu.Lock(); defer a.mu.Unlock(); a.active--; a.anonymous = false }) }, nil
}
