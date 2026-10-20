// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package packageauthoring

import (
	"context"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type GuardV1 struct {
	user      generated.User
	tx        pgx.Tx
	authorize auth.TransactionAuthorization
}

func (g *GuardV1) Recheck(ctx context.Context) error {
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

var ErrChangedV1 = errors.New("document package source changed; reload and review the exact documents")

// This fixed policy binds BOTH actual document subjects to the original staff
// credential. It is not a public endpoint or a Send/signing permission. The
// eventual selection writer retains the same transaction, these guards and
// native consumers through audit and the final pre-COMMIT credential recheck.
func ReadSelectionV1(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1, actor authoring.Actor, ids [2]uuid.UUID, expected [2]time.Time) ([2]*generated.Document, [2]*GuardV1, error) {
	var docs [2]*generated.Document
	var guards [2]*GuardV1
	if owner == nil || db == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || ids[0] == uuid.Nil || ids[1] == uuid.Nil || ids[0] == ids[1] {
		return docs, guards, auth.ErrMutationPermissionRevoked
	}
	tx := &nativePolicyTxV1{DBTX: db}
	q := generated.New(db)
	slotFor := func(id uuid.UUID) int {
		if id == ids[0] {
			return 0
		}
		if id == ids[1] {
			return 1
		}
		return -1
	}
	models, err := owner.ReadDocumentsV1(call, actor.UserID, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
		if a.OrgID != actor.OrgID || slotFor(a.DocumentID) < 0 {
			return authoring.ErrDocumentNotFound
		}
		if !a.Draft {
			return authoring.ErrDocumentNotDraft
		}
		return nil
	}, func(a pdfadmission.HTMLRevisionReadAccessV1, user *generated.User) error {
		slot := slotFor(a.DocumentID)
		if slot < 0 || user == nil || user.ID != actor.UserID || user.OrgID != actor.OrgID || (user.Role != string(auth.RoleOwner) && user.Role != string(auth.RoleSender)) {
			return auth.ErrMutationPermissionRevoked
		}
		guard := &GuardV1{user: *user, tx: tx, authorize: actor.Authorize}
		if err := guard.Recheck(call); err != nil {
			return err
		}
		retained, err := q.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: a.DocumentID, OrgID: actor.OrgID})
		if err != nil {
			return err
		}
		if retained {
			return authoring.ErrDocumentHasEvidence
		}
		fence, err := q.TryCollabArchivePrivacyFence(call, actor.OrgID)
		if err != nil {
			return err
		}
		if !fence {
			return authoring.ErrPrivacyReviewChanging
		}
		pending, err := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: a.DocumentID, OrgID: actor.OrgID})
		if err != nil {
			return err
		}
		if pending {
			return authoring.ErrPendingPrivacyReview
		}
		if user.Role != string(auth.RoleOwner) && a.SenderID != actor.UserID {
			return auth.ErrMutationPermissionRevoked
		}
		if !a.UpdatedAt.Valid || !a.UpdatedAt.Time.Equal(expected[slot]) {
			return ErrChangedV1
		}
		guards[slot] = guard
		return call.Err()
	})
	if err != nil {
		return docs, guards, err
	}
	for i, m := range models {
		if m == nil || m.Document == nil || m.Document.ID != ids[i] || m.Document.OrgID != actor.OrgID {
			return docs, guards, authoring.ErrDocumentNotFound
		}
		doc := m.Document
		if doc.SourceKind != "pdf" || doc.IsEnvelope || doc.ParentEnvelopeID.Valid || doc.DeletedAt.Valid {
			return docs, guards, authoring.ErrDocumentNotDraft
		}
		docs[i] = doc
	}
	if err = owner.ValidateSourcesV1(call); err != nil {
		return docs, guards, err
	}
	for _, guard := range guards {
		if guard == nil {
			return docs, guards, auth.ErrMutationPermissionRevoked
		}
		if err = guard.Recheck(call); err != nil {
			return docs, guards, err
		}
	}
	return docs, guards, call.Err()
}

// Package-aware source policy retains the original paired checks and their
// original credential. Native ReadDraftV1 independently funds/reads the actual
// ordered rows and fences privacy for every immutable old member in both SQL
// stages. A caller DTO, current old source row or claimed size cannot replace it.
func ReadDraftSelectionV1(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1, actor authoring.Actor, ids [2]uuid.UUID, expected [2]time.Time, draft pdfadmission.DocumentPackageDraftExpectedV1) ([2]*generated.Document, [2]*GuardV1, error) {
	docs, guards, err := ReadSelectionV1(call, db, owner, actor, ids, expected)
	if err != nil {
		return docs, guards, err
	}
	err = owner.ReadDraftV1(call, draft)
	if errors.Is(err, pdfadmission.ErrDocumentPackagePendingPrivacyV1) {
		err = authoring.ErrPendingPrivacyReview
	}
	if errors.Is(err, pdfadmission.ErrDocumentPackagePrivacyChangingV1) {
		err = authoring.ErrPrivacyReviewChanging
	}
	if err != nil {
		return docs, guards, err
	}
	for _, guard := range guards {
		if guard == nil {
			return docs, guards, auth.ErrMutationPermissionRevoked
		}
		if err = guard.Recheck(call); err != nil {
			return docs, guards, err
		}
	}
	return docs, guards, call.Err()
}
