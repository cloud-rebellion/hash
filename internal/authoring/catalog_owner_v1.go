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

// LockCatalogOwnerV1 retains the original blocking NO KEY UPDATE -> full
// scoped User SHARE -> actual role -> original credential ordering. The
// original owner mutation discarded every Org field; this fixed identity
// query avoids expanding that unused model. The caller's native reader must
// acquire actual User body work before this function reads it. The same real
// full User, original MemberGuard, and credential locks survive through commit.
func LockCatalogOwnerV1(ctx context.Context, tx pgx.Tx, actor Actor) (*MemberGuard, error) {
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if tx == nil {
		return nil, errors.New("owner mutation transaction unavailable")
	}
	q := generated.New(tx)
	if _, err := q.GetCatalogRuleOrgExistenceV1(ctx, actor.OrgID); err != nil {
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
	if err = guard.Recheck(ctx); err != nil {
		return nil, err
	}
	return guard, nil
}
