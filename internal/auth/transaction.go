// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrMutationPermissionRevoked = errors.New("permission or credential revoked")
	ErrMutationCredentialExpired = errors.New("credential expired before transaction committed")
)

// TransactionAuthorization checks the admitted credential after parent/member
// lock waits and again before commit. Engines retain the live member lock and
// supply that row; API authorization also retains a credential SHARE lock.
// A callback performs no response writes, use claims or external side effects.
type TransactionAuthorization func(context.Context, pgx.Tx, *generated.User) error

func SessionTransactionAuthorization(cookies *SignedCookie, cookie string, session SessionPayload, orgID uuid.UUID) TransactionAuthorization {
	return func(ctx context.Context, _ pgx.Tx, user *generated.User) error {
		if cookies == nil || cookie == "" {
			return ErrMutationCredentialExpired
		}
		if user == nil || session.UserID == uuid.Nil || user.ID != session.UserID || user.OrgID != orgID || user.SessionGeneration != session.Generation {
			return ErrMutationPermissionRevoked
		}
		payload, err := cookies.Verify(cookie)
		if err != nil {
			return ErrMutationCredentialExpired
		}
		var signed SessionPayload
		if json.Unmarshal(payload, &signed) != nil || signed.UserID != session.UserID || signed.Generation != session.Generation {
			return ErrMutationPermissionRevoked
		}
		return ctx.Err()
	}
}

type apiCredentialContextKey struct{}

// This receipt is private and installed only after secret verification and the
// middleware's successful use claim. It contains no plaintext credential.
type apiCredentialReceipt struct {
	ID, UserID, OrgID, DocumentID uuid.UUID
	Hash                          []byte
	Scopes                        []string
}

func APIKeyTransactionAuthorization(ctx context.Context, documentID uuid.UUID, requiredScopes ...string) (TransactionAuthorization, error) {
	requiredScopes = append([]string(nil), requiredScopes...)
	receipt, ok := ctx.Value(apiCredentialContextKey{}).(apiCredentialReceipt)
	if !ok || receipt.ID == uuid.Nil || receipt.UserID == uuid.Nil || receipt.OrgID == uuid.Nil || len(receipt.Hash) != 32 {
		return nil, ErrMutationPermissionRevoked
	}
	if receipt.DocumentID != uuid.Nil && receipt.DocumentID != documentID {
		return nil, ErrMutationPermissionRevoked
	}
	for _, scope := range requiredScopes {
		if !credentialHasScope(receipt.Scopes, scope) {
			return nil, ErrMutationPermissionRevoked
		}
	}
	return func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
		if tx == nil || user == nil || user.ID != receipt.UserID || user.OrgID != receipt.OrgID {
			return ErrMutationPermissionRevoked
		}
		var hash []byte
		var scopes []string
		var expiresAt pgtype.Timestamptz
		var err error
		if receipt.DocumentID == uuid.Nil {
			err = tx.QueryRow(ctx, `SELECT key_hash,scopes,expires_at
				FROM api_keys WHERE id=$1 AND org_id=$2 AND user_id=$3 FOR SHARE`, receipt.ID, receipt.OrgID, receipt.UserID).Scan(&hash, &scopes, &expiresAt)
		} else {
			var revoked bool
			err = tx.QueryRow(ctx, `SELECT key_hash,scopes,expires_at,revoked_at IS NOT NULL
				FROM document_agent_tokens WHERE id=$1 AND org_id=$2 AND document_id=$3 AND created_by=$4
				FOR SHARE`, receipt.ID, receipt.OrgID, documentID, receipt.UserID).Scan(&hash, &scopes, &expiresAt, &revoked)
			if err == nil && revoked {
				return ErrMutationPermissionRevoked
			}
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMutationPermissionRevoked
		}
		if err != nil {
			return fmt.Errorf("load transaction credential authorization: %w", err)
		}
		if subtle.ConstantTimeCompare(hash, receipt.Hash) != 1 {
			return ErrMutationPermissionRevoked
		}
		if receipt.DocumentID != uuid.Nil && !expiresAt.Valid {
			return ErrMutationCredentialExpired
		}
		if expiresAt.Valid {
			// A SELECT expression can be evaluated before its SHARE lock wait.
			// Sample the database clock only after the credential row is locked,
			// so even the first check refuses natural expiry during that wait.
			var now time.Time
			if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				return fmt.Errorf("sample transaction credential expiry: %w", err)
			}
			if !expiresAt.Time.After(now) {
				return ErrMutationCredentialExpired
			}
		}
		for _, scope := range requiredScopes {
			if !credentialHasScope(scopes, scope) {
				return ErrMutationPermissionRevoked
			}
		}
		return ctx.Err()
	}, nil
}

func credentialHasScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required || scope == "admin" {
			return true
		}
	}
	return false
}
