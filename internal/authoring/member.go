// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package authoring

import (
	"context"
	"errors"
	"fmt"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MemberGuard protects authoring that creates a new parent (document/template),
// where LockDraft cannot be used yet. It retains the live member and original
// credential locks through commit. Call Recheck after the transactional audit.
type MemberGuard struct {
	user      generated.User
	tx        pgx.Tx
	authorize auth.TransactionAuthorization
}

func LockAuthor(ctx context.Context, tx pgx.Tx, actor Actor) (*MemberGuard, error) {
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if tx == nil {
		return nil, errors.New("authoring transaction unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	user, err := generated.New(tx).GetUserForShare(ctx, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return nil, fmt.Errorf("lock authoring member: %w", err)
	}
	if user.Role != string(auth.RoleSender) && user.Role != string(auth.RoleOwner) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	guard := &MemberGuard{user: *user, tx: tx, authorize: actor.Authorize}
	if err := guard.Recheck(ctx); err != nil {
		return nil, err
	}
	return guard, nil
}

func (g *MemberGuard) Recheck(ctx context.Context) error {
	if g == nil || g.tx == nil || g.authorize == nil || g.user.ID == uuid.Nil || g.user.OrgID == uuid.Nil {
		return auth.ErrMutationPermissionRevoked
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	user := g.user // A callback cannot rewrite the retained identity.
	if err := g.authorize(ctx, g.tx, &user); err != nil {
		return err
	}
	return ctx.Err()
}
