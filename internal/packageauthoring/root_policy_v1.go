// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package packageauthoring

import (
	"context"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

// The actual current native callback owns this policy; returned DTOs cannot
// authorize another transaction. Evidence/privacy refusal precedes root body.
func readStaffDraftRootV1(call context.Context, db generated.DBTX, reader *pdfadmission.ApplicationHTMLRevisionReaderV1, actor authoring.Actor, root uuid.UUID) (*GuardV1, error) {
	tx := &nativePolicyTxV1{DBTX: db}
	var guard *GuardV1
	models, e := reader.ReadDocumentWithActorV1(call, actor.UserID, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
		if a.OrgID != actor.OrgID || a.DocumentID != root {
			return authoring.ErrDocumentNotFound
		}
		if !a.Draft {
			return authoring.ErrDocumentNotDraft
		}
		return nil
	}, func(a pdfadmission.HTMLRevisionReadAccessV1, user *generated.User) error {
		if user == nil || user.ID != actor.UserID || user.OrgID != actor.OrgID || (user.Role != "owner" && user.Role != "sender") {
			return auth.ErrMutationPermissionRevoked
		}
		if user.Role != "owner" && a.SenderID != actor.UserID {
			return auth.ErrMutationPermissionRevoked
		}
		guard = &GuardV1{user: *user, tx: tx, authorize: actor.Authorize}
		if e := guard.Recheck(call); e != nil {
			return e
		}
		q := generated.New(db)
		retained, e := q.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: root, OrgID: actor.OrgID})
		if e != nil {
			return e
		}
		if retained {
			return authoring.ErrDocumentHasEvidence
		}
		fence, e := q.TryCollabArchivePrivacyFence(call, actor.OrgID)
		if e != nil {
			return e
		}
		if !fence {
			return authoring.ErrPrivacyReviewChanging
		}
		fence, e = q.TryDocumentPackageMemberPrivacyFenceV1(call, generated.TryDocumentPackageMemberPrivacyFenceV1Params{DocumentID: root, OrgID: actor.OrgID})
		if e != nil {
			return e
		}
		if !fence {
			return authoring.ErrPrivacyReviewChanging
		}
		pending, e := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: root, OrgID: actor.OrgID})
		if e != nil {
			return e
		}
		if pending {
			return authoring.ErrPendingPrivacyReview
		}
		return guard.Recheck(call)
	})
	if e != nil {
		return nil, e
	}
	if models == nil || models.Document == nil || models.Document.SourceKind != "pdf" || models.Document.IsEnvelope || models.Document.ParentEnvelopeID.Valid || models.Document.DeletedAt.Valid {
		return nil, authoring.ErrDocumentNotDraft
	}
	return guard, nil
}
