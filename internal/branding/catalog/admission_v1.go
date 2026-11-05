// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package catalog

import (
	"context"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/google/uuid"
	"sync"
	"sync/atomic"
)

type inputKeyV1 struct{}
type inputPermitV1 struct {
	org    uuid.UUID
	closed atomic.Bool
}

// AcquireInputV1 admits the actual bounded import BEFORE JSON/base64 decoding.
// A nested service borrows this exact live permit, rather than taking a second
// organization slot. The original adapter keeps it through response delivery.
func AcquireInputV1(ctx context.Context, org uuid.UUID) (context.Context, func(), error) {
	if p, ok := ctx.Value(inputKeyV1{}).(*inputPermitV1); ok && p.org == org && !p.closed.Load() {
		return ctx, func() {}, nil
	}
	if org == uuid.Nil {
		return ctx, nil, ErrInputV1
	}
	release, e := importguard.Shared.Acquire(org)
	if e != nil {
		return ctx, nil, e
	}
	p := &inputPermitV1{org: org}
	var once sync.Once
	return context.WithValue(ctx, inputKeyV1{}, p), func() { once.Do(func() { p.closed.Store(true); release() }) }, nil
}
