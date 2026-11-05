// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package auth

import (
	"context"

	"github.com/google/uuid"
)

// DesignCredentialIdentityV1 returns only the identity of the credential already
// verified by RequireAPIKey. It does not authorize a read or mutation; callers
// retain APIKeyTransactionAuthorization across every native transaction.
func DesignCredentialIdentityV1(ctx context.Context) (key, user, org uuid.UUID, err error) {
	if ctx == nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, ErrMutationPermissionRevoked
	}
	r, ok := ctx.Value(apiCredentialContextKey{}).(apiCredentialReceipt)
	u, admitted := FromContext(ctx)
	if !ok || !admitted || r.ID == uuid.Nil || r.UserID == uuid.Nil || r.OrgID == uuid.Nil || len(r.Hash) != 32 || r.UserID != u.UserID || r.OrgID != u.OrgID {
		return uuid.Nil, uuid.Nil, uuid.Nil, ErrMutationPermissionRevoked
	}
	return r.ID, r.UserID, r.OrgID, nil
}
