// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package authoring

import (
	"context"
	"errors"
	"fmt"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LockOwner serializes organization settings before retaining the live owner's
// identity and admitted credential. NO KEY UPDATE permits another authorized
// mutation's audit FK KEY SHARE while it finishes ahead of a role change.
// LockAuthor intentionally remains suitable only for sender-capable authoring.
func LockOwner(ctx context.Context, tx pgx.Tx, actor Actor) (*MemberGuard, error) {
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if tx == nil {
		return nil, errors.New("owner mutation transaction unavailable")
	}
	q := generated.New(tx)
	if _, err := q.GetOrgForOwnerMutation(ctx, actor.OrgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrMutationPermissionRevoked
		}
		return nil, fmt.Errorf("lock owner organization: %w", err)
	}
	user, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return nil, fmt.Errorf("lock organization owner: %w", err)
	}
	if user.Role != string(auth.RoleOwner) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	guard := &MemberGuard{user: *user, tx: tx, authorize: actor.Authorize}
	if err := guard.Recheck(ctx); err != nil {
		return nil, err
	}
	return guard, nil
}

// CommitOwnerMutation discloses results only after the original credential,
// live owner, mutation and audit append have passed the same bounded transaction.
// The callback must use its supplied context and queries, not an admission-time
// snapshot. External object writes need explicit exact-version compensation.
func CommitOwnerMutation[T any](ctx context.Context, pool *pgxpool.Pool, logger *audit.Logger, actor Actor,
	mutate func(context.Context, *generated.Queries) (T, error), event func(T) audit.Entry,
) (T, error) {
	var zero T
	if pool == nil || logger == nil || mutate == nil || event == nil {
		return zero, errors.New("owner mutation dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, MutationTimeout)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return zero, err
	}
	defer func() { _ = Rollback(ctx, tx) }()
	guard, err := LockOwner(ctx, tx, actor)
	if err != nil {
		return zero, err
	}
	value, err := mutate(ctx, generated.New(tx))
	if err != nil {
		return zero, err
	}
	entry := event(value)
	if entry.OrgID != actor.OrgID || entry.ActorUserID == nil || *entry.ActorUserID != actor.UserID {
		return zero, errors.New("owner mutation audit identity mismatch")
	}
	pending, err := logger.LogTx(ctx, tx, entry)
	if err != nil {
		return zero, err
	}
	if err := guard.Recheck(ctx); err != nil {
		return zero, err
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, err
	}
	logger.Publish(pending)
	return value, nil
}
