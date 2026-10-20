// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package recoveryinventory owns the execution policy for the canonical object
// inventory. The inventory remains a pure SELECT, including when embedded by a
// reader; its recursive estimates can otherwise trigger expensive LLVM work for
// small recovered databases.
package recoveryinventory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Beginner is implemented by pgx connections and pools. The returned transaction
// must stay owned until its rows are drained and it is committed or rolled back.
type Beginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// Begin opens one read-only repeatable-read snapshot and installs JIT policy
// before any inventory or related validation is planned on that transaction.
// It preserves the caller's context, protocol, timeouts and connection settings.
func Begin(ctx context.Context, db Beginner) (pgx.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("begin recovery inventory snapshot: %w", err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL jit=off"); err != nil {
		return nil, errors.Join(fmt.Errorf("set recovery inventory execution policy: %w", err), Rollback(tx))
	}
	return tx, nil
}

// Rollback bounds transaction cleanup independently of a canceled query context.
// ErrTxClosed only means there is no further transaction cleanup to request; it
// is not an acknowledgement that a disconnected PostgreSQL backend has retired.
func Rollback(tx pgx.Tx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}
