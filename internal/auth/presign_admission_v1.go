// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This constructor reads only the private middleware receipt installed after
// actual API secret verification/use admission. A document agent token cannot
// become a workflow executor. Neither client UUIDs nor an exported DTO can
// construct this original credential capability.
type PreSignAPIAdmissionV1 struct {
	org, user, credential uuid.UUID
	binding               string
	authorize             TransactionAuthorization
}

func NewPreSignAPIAdmissionV1(ctx context.Context, document uuid.UUID) (PreSignAPIAdmissionV1, error) {
	var out PreSignAPIAdmissionV1
	if ctx == nil || ctx.Err() != nil {
		return out, ErrMutationPermissionRevoked
	}
	r, ok := ctx.Value(apiCredentialContextKey{}).(apiCredentialReceipt)
	if !ok || r.DocumentID != uuid.Nil || r.ID == uuid.Nil || r.OrgID == uuid.Nil || r.UserID == uuid.Nil || len(r.Hash) != sha256.Size {
		return out, ErrMutationPermissionRevoked
	}
	a, err := APIKeyTransactionAuthorization(ctx, document, "write:authoring", "write:workflow")
	if err != nil {
		return out, err
	}
	raw, err := json.Marshal(struct {
		Org, User, Credential uuid.UUID
		Hash                  []byte
	}{r.OrgID, r.UserID, r.ID, r.Hash})
	if err != nil {
		return out, ErrMutationPermissionRevoked
	}
	h := sha256.New()
	_, _ = h.Write([]byte("hash:presign-original-api-key:v1\x00"))
	_, _ = h.Write(raw)
	return PreSignAPIAdmissionV1{org: r.OrgID, user: r.UserID, credential: r.ID, binding: hex.EncodeToString(h.Sum(nil)), authorize: a}, nil
}

func (a PreSignAPIAdmissionV1) OrgID() uuid.UUID        { return a.org }
func (a PreSignAPIAdmissionV1) UserID() uuid.UUID       { return a.user }
func (a PreSignAPIAdmissionV1) CredentialID() uuid.UUID { return a.credential }
func (a PreSignAPIAdmissionV1) Commitment() string      { return a.binding }
func (a PreSignAPIAdmissionV1) AuthorizeV1(ctx context.Context, tx pgx.Tx, user *generated.User) error {
	if a.authorize == nil || a.org == uuid.Nil || a.user == uuid.Nil || a.credential == uuid.Nil || len(a.binding) != 64 {
		return ErrMutationPermissionRevoked
	}
	return a.authorize(ctx, tx, user)
}
