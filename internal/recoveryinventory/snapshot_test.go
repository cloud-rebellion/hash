// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package recoveryinventory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type inventoryBeginnerStub struct {
	tx      *inventoryTxStub
	calls   int
	options pgx.TxOptions
}

func (s *inventoryBeginnerStub) BeginTx(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	s.calls++
	s.options = options
	return s.tx, nil
}

type inventoryTxStub struct {
	pgx.Tx
	execErr        error
	cancel         context.CancelFunc
	statements     []string
	rollbackErr    error
	rollbackCalls  int
	cleanupLive    bool
	cleanupBounded bool
}

func (s *inventoryTxStub) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	s.statements = append(s.statements, sql)
	if s.cancel != nil {
		s.cancel()
	}
	return pgconn.CommandTag{}, s.execErr
}

func (s *inventoryTxStub) Rollback(ctx context.Context) error {
	s.rollbackCalls++
	s.cleanupLive = ctx.Err() == nil
	deadline, ok := ctx.Deadline()
	s.cleanupBounded = ok && time.Until(deadline) > 0 && time.Until(deadline) <= 5*time.Second
	return s.rollbackErr
}

func TestBeginInventorySnapshotPolicyV1(t *testing.T) {
	tx := &inventoryTxStub{}
	db := &inventoryBeginnerStub{tx: tx}
	got, err := Begin(context.Background(), db)
	if err != nil || got != tx || db.calls != 1 ||
		db.options != (pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}) ||
		len(tx.statements) != 1 || tx.statements[0] != "SET LOCAL jit=off" || tx.rollbackCalls != 0 {
		t.Fatal("inventory snapshot lost its local read-only execution boundary")
	}
	if err := Rollback(got); err != nil || tx.rollbackCalls != 1 || !tx.cleanupLive || !tx.cleanupBounded {
		t.Fatal("inventory snapshot cleanup is not independently bounded")
	}
}

func TestBeginInventoryPolicyFailureCleansCanceledCallerV1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	refused := errors.New("policy refused")
	cleanupRefused := errors.New("cleanup refused")
	tx := &inventoryTxStub{execErr: refused, cancel: cancel, rollbackErr: cleanupRefused}
	got, err := Begin(ctx, &inventoryBeginnerStub{tx: tx})
	if got != nil || !errors.Is(err, refused) || !errors.Is(err, cleanupRefused) ||
		tx.rollbackCalls != 1 || !tx.cleanupLive || !tx.cleanupBounded || ctx.Err() == nil {
		t.Fatal("failed policy returned usable authority or lost bounded cleanup failure")
	}
}

func TestBeginInventoryCanceledCallerDoesNotAcquireV1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	db := &inventoryBeginnerStub{tx: &inventoryTxStub{}}
	got, err := Begin(ctx, db)
	if got != nil || !errors.Is(err, context.Canceled) || db.calls != 0 {
		t.Fatal("already canceled inventory caller acquired a transaction")
	}
}

func TestInventoryRollbackClosedAndFailureV1(t *testing.T) {
	closed := &inventoryTxStub{rollbackErr: pgx.ErrTxClosed}
	if err := Rollback(closed); err != nil || closed.rollbackCalls != 1 || !closed.cleanupBounded {
		t.Fatal("closed transaction cleanup failed")
	}
	refused := errors.New("rollback refused")
	failed := &inventoryTxStub{rollbackErr: refused}
	if err := Rollback(failed); !errors.Is(err, refused) || failed.rollbackCalls != 1 || !failed.cleanupBounded {
		t.Fatal("rollback failure was hidden")
	}
}
