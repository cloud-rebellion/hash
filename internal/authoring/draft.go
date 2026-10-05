// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package authoring admits draft mutations under the caller's transaction.
package authoring

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrDocumentNotFound      = errors.New("document not found")
	ErrDocumentNotDraft      = errors.New("document not editable (must be draft)")
	ErrDocumentHasEvidence   = errors.New("document contains retained signing evidence or sealing state")
	ErrPrivacyReviewChanging = errors.New("privacy review is changing; retry after it completes")
	ErrPendingPrivacyReview  = errors.New("document changes await the open privacy request review")
)

const MutationTimeout = 10 * time.Second

// Actor retains the original admitted credential, regardless of transport.
// Callers must not replace Authorize with a freshly issued credential.
type Actor struct {
	OrgID, UserID uuid.UUID
	Authorize     auth.TransactionAuthorization
}

// DraftGuard retains the parent, live member and credential locks until the
// caller commits or rolls back. Document is the fresh draft authoring snapshot;
// changing it cannot change the private authorization identity.
type DraftGuard struct {
	Document  *generated.Document
	user      generated.User
	tx        pgx.Tx
	authorize auth.TransactionAuthorization
}

// LockDraft requires a bounded READ COMMITTED transaction owned by the caller.
// It serializes with deletion, signing, member changes and privacy review.
// Callers must Recheck after their mutations and transactional audit append,
// immediately before committing, and publish events only after commit.
func LockDraft(ctx context.Context, tx pgx.Tx, actor Actor, docID uuid.UUID) (*DraftGuard, error) {
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if tx == nil {
		return nil, errors.New("draft mutation transaction unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	q := generated.New(tx)
	doc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDocumentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock draft parent: %w", err)
	}
	if doc.Status != "draft" {
		return nil, ErrDocumentNotDraft
	}
	user, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return nil, fmt.Errorf("lock draft member: %w", err)
	}
	if user.Role != string(auth.RoleSender) && user.Role != string(auth.RoleOwner) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	guard := &DraftGuard{Document: doc, user: *user, tx: tx, authorize: actor.Authorize}
	if err := guard.Recheck(ctx); err != nil {
		return nil, err
	}
	retained, err := q.HasRetainedDraftEvidenceForPurge(ctx, generated.HasRetainedDraftEvidenceForPurgeParams{DocumentID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return nil, fmt.Errorf("inspect draft evidence: %w", err)
	}
	if retained {
		return nil, ErrDocumentHasEvidence
	}
	// Global DSR writers take the exclusive organization fence. Linked review
	// writers serialize through this parent. Do not wait on an inverse fence
	// while holding the parent: report contention so the caller can retry.
	fence, err := q.TryCollabArchivePrivacyFence(ctx, actor.OrgID)
	if err != nil {
		return nil, fmt.Errorf("fence draft privacy review: %w", err)
	}
	if !fence {
		return nil, ErrPrivacyReviewChanging
	}
	pending, err := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return nil, fmt.Errorf("inspect draft privacy review: %w", err)
	}
	if pending {
		return nil, ErrPendingPrivacyReview
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return guard, nil
}

func (g *DraftGuard) UserID() uuid.UUID {
	if g == nil {
		return uuid.Nil
	}
	return g.user.ID
}

// Recheck validates the original credential after any mutation or audit wait.
// Each invocation gets a copy so callbacks cannot alter the retained identity.
func (g *DraftGuard) Recheck(ctx context.Context) error {
	if g == nil || g.tx == nil || g.authorize == nil || g.user.ID == uuid.Nil || g.user.OrgID == uuid.Nil {
		return auth.ErrMutationPermissionRevoked
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	user := g.user
	if err := g.authorize(ctx, g.tx, &user); err != nil {
		return err
	}
	return ctx.Err()
}

// Rollback detaches cleanup from the failed request while keeping it bounded.
func Rollback(ctx context.Context, tx pgx.Tx) error {
	if tx == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return tx.Rollback(ctx)
}
