// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const PreviewTimeout = 15 * time.Second

var ErrPreviewChanged = errors.New("document or binding changed during preview; refresh and retry")

// CheckPreview validates the original read credential and the exact snapshot
// after external source/branding waits. It never writes observations, consumes
// another token use, or requires sender privileges. Draft and frozen reads use
// the same member/credential checks. Locks are short and remain bounded by the
// caller's preview deadline; external requests never hold document locks.
func CheckPreview(ctx context.Context, pool *pgxpool.Pool, doc *generated.Document, report []ResolveReport, userID uuid.UUID, authorize auth.TransactionAuthorization) error {
	if pool == nil || doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || userID == uuid.Nil || authorize == nil {
		return auth.ErrMutationPermissionRevoked
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin preview verification: %w", err)
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	q := generated.New(tx)
	current, err := q.GetResolverDocumentRevisionForShare(ctx, generated.GetResolverDocumentRevisionForShareParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return authoring.ErrDocumentNotFound
	}
	if err != nil {
		return fmt.Errorf("verify preview document: %w", err)
	}
	if current.Status != doc.Status || !sameTimestamp(current.UpdatedAt, doc.UpdatedAt) {
		return ErrPreviewChanged
	}
	user, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: userID, OrgID: doc.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return fmt.Errorf("verify preview member: %w", err)
	}
	switch auth.Role(user.Role) {
	case auth.RoleViewer, auth.RoleSender, auth.RoleOwner:
	default:
		return auth.ErrMutationPermissionRevoked
	}
	if err := authorize(ctx, tx, user); err != nil {
		return err
	}
	if report != nil {
		bindings, err := q.ListVariableBindingsForShare(ctx, doc.ID)
		if err != nil {
			return fmt.Errorf("verify preview binding revision: %w", err)
		}
		if len(bindings) != len(report) {
			return ErrPreviewChanged
		}
		for i, binding := range bindings {
			before := report[i].bindingSnapshot
			if before == nil || binding == nil || before.DocumentID != binding.DocumentID || before.VariableName != binding.VariableName || before.SourceKind != binding.SourceKind || before.SourceRef != binding.SourceRef || before.SourcePath != binding.SourcePath || before.Fallback != binding.Fallback || !sameTimestamp(before.CreatedAt, binding.CreatedAt) || !sameTimestamp(before.UpdatedAt, binding.UpdatedAt) {
				return ErrPreviewChanged
			}
		}
	}
	// Natural credential expiry can occur while waiting for the binding locks.
	if err := authorize(ctx, tx, user); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("finish preview verification: %w", err)
	}
	return nil
}

func sameTimestamp(a, b pgtype.Timestamptz) bool {
	return a.Valid == b.Valid && a.InfinityModifier == b.InfinityModifier && (!a.Valid || a.Time.Equal(b.Time))
}
