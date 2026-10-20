// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This guard preserves LockDraft's live member/credential/evidence/privacy
// sequence, but its parent and User are the actual native bounded projections.
// It never substitutes a partial Document for the retained full body.
type htmlRevisionPolicyGuardV1 struct {
	user      generated.User
	tx        pgx.Tx
	authorize auth.TransactionAuthorization
}

func (g *htmlRevisionPolicyGuardV1) Recheck(ctx context.Context) error {
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
func htmlRevisionPolicyReadV1(ctx context.Context, db generated.DBTX, reader *pdfadmission.ApplicationHTMLRevisionReaderV1, actor authoring.Actor, id uuid.UUID, expected time.Time) (*pdfadmission.HTMLRevisionReadModelsV1, *htmlRevisionPolicyGuardV1, error) {
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, nil, auth.ErrMutationPermissionRevoked
	}
	if db == nil || reader == nil {
		return nil, nil, errors.New("draft mutation transaction unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// This is the actual tracked DBTX supplied by the native callback. Its
	// existing compatibility facade refuses transaction/connection control.
	tx := &htmlCreationPolicyTxV1{DBTX: db}
	q := generated.New(db)
	var guard *htmlRevisionPolicyGuardV1
	parentSeen := false
	models, err := reader.ReadDocumentWithActorV1(ctx, actor.UserID, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
		parentSeen = true
		if a.DocumentID != id || a.OrgID != actor.OrgID {
			return authoring.ErrDocumentNotFound
		}
		if !a.Draft {
			return authoring.ErrDocumentNotDraft
		}
		return nil
	}, func(a pdfadmission.HTMLRevisionReadAccessV1, user *generated.User) error {
		if user == nil {
			return auth.ErrMutationPermissionRevoked
		}
		if user.Role != string(auth.RoleSender) && user.Role != string(auth.RoleOwner) {
			return auth.ErrMutationPermissionRevoked
		}
		guard = &htmlRevisionPolicyGuardV1{user: *user, tx: tx, authorize: actor.Authorize}
		if err := guard.Recheck(ctx); err != nil {
			return err
		}
		retained, err := q.HasRetainedDraftSigningEvidence(ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: id, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect draft evidence: %w", err)
		}
		if retained {
			return authoring.ErrDocumentHasEvidence
		}
		fence, err := q.TryCollabArchivePrivacyFence(ctx, actor.OrgID)
		if err != nil {
			return fmt.Errorf("fence draft privacy review: %w", err)
		}
		if !fence {
			return authoring.ErrPrivacyReviewChanging
		}
		pending, err := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: id, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect draft privacy review: %w", err)
		}
		if pending {
			return authoring.ErrPendingPrivacyReview
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Preserve lockHTMLDocumentRevision's second fresh User query and its
		// sender-or-owner check after the original evidence/privacy checks.
		current, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
		if err != nil {
			return err
		}
		if current.Role != string(auth.RoleOwner) && a.SenderID != actor.UserID {
			return auth.ErrMutationPermissionRevoked
		}
		// After original actor/privacy policy, stale actual scalar CAS can refuse
		// before a missing body cache changes the original conflict to unavailable.
		if !a.UpdatedAt.Valid || !a.UpdatedAt.Time.Equal(expected) {
			return errHTMLDocumentRevisionConflict
		}
		return nil
	})
	if !parentSeen && errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, authoring.ErrDocumentNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if guard == nil {
		return nil, nil, auth.ErrMutationPermissionRevoked
	}
	return models, guard, nil
}
