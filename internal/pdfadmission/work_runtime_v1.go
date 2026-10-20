// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrWorkRuntimeV1 = errors.New("pdfadmission: configured process work runtime unavailable")

// WorkRuntimeV1 binds one process-owned coordinator, cost adapter and fixed
// native session factory to the SAME real application pool. It stores no READY,
// spare-memory, spare-connection, controller, generation or retirement claim.
// Construct once during startup and share this opaque object, never per request.
type WorkRuntimeV1 struct {
	pool        *pgxpool.Pool
	coordinator *workguard.CoordinatorV1
	work        *WorkAdmissionV1
	sessions    *ApplicationSessionFactoryV1
}

// NewWorkRuntimeV1 consumes explicit operator-assigned caps. The total DB cap
// includes this process's existing pool maximum plus its direct owned sessions
// (including observers). This arithmetic is an admission ceiling, NOT a claim
// that PostgreSQL has spare connections or that other processes are retired.
// Call only with the application's successfully initialized actual pool.
func NewWorkRuntimeV1(pool *pgxpool.Pool, limits workguard.LimitsV1, totalDBConnections int64) (*WorkRuntimeV1, error) {
	if pool == nil || totalDBConnections < 1 {
		return nil, ErrWorkRuntimeV1
	}
	config := pool.Config()
	if config == nil || config.ConnConfig == nil || config.MaxConns < 1 || limits.Global.SQLSessions < 1 || totalDBConnections < int64(config.MaxConns) || limits.Global.SQLSessions > totalDBConnections-int64(config.MaxConns) {
		return nil, ErrWorkRuntimeV1
	}
	coordinator, err := workguard.NewV1(limits)
	if err != nil {
		return nil, ErrWorkRuntimeV1
	}
	work, err := NewWorkAdmissionV1(coordinator)
	if err != nil {
		return nil, ErrWorkRuntimeV1
	}
	sessions, err := NewApplicationSessionFactoryV1(config.ConnConfig, work, ApplicationSessionDirectProfileV1)
	if err != nil {
		return nil, ErrWorkRuntimeV1
	}
	return &WorkRuntimeV1{pool: pool, coordinator: coordinator, work: work, sessions: sessions}, nil
}
func (r *WorkRuntimeV1) MatchesPoolV1(pool *pgxpool.Pool) bool {
	return r != nil && pool != nil && r.pool == pool && r.coordinator != nil && r.work != nil && r.sessions != nil
}
func (r *WorkRuntimeV1) WorkV1() *WorkAdmissionV1 {
	if r == nil || !r.MatchesPoolV1(r.pool) {
		return nil
	}
	return r.work
}
func (r *WorkRuntimeV1) SessionsV1() *ApplicationSessionFactoryV1 {
	if r == nil || !r.MatchesPoolV1(r.pool) {
		return nil
	}
	return r.sessions
}
func (r *WorkRuntimeV1) CloseV1(ctx context.Context) error {
	if r == nil || r.SessionsV1() == nil {
		return ErrWorkRuntimeV1
	}
	return r.sessions.CloseV1(ctx)
}
func (r *WorkRuntimeV1) ReconcileCleanupV1(ctx context.Context) error {
	if r == nil || r.SessionsV1() == nil {
		return ErrWorkRuntimeV1
	}
	return r.sessions.ReconcileCleanupV1(ctx)
}
