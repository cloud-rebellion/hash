// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blockauthoring

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

// Purpose-only draft editing accepts every existing source representation.
// It never rewrites source bytes, version snapshots or signing evidence.
// Parent/CAS/member/evidence/privacy and final original credential checks keep
// their original order, and each successful event uses actual ownedaudit hooks.
func MutateDocumentPurposeV1(ctx context.Context, d DependenciesV1, actor ActorV1, document uuid.UUID, via versions.Via, expected string, checkObservation func(*generated.Document, string) error, purpose documentpurpose.Purpose) (result *ResultV1, failure error) {
	return mutateDocumentMetadataV1(ctx, d, actor, document, expected, checkObservation, &purpose, "", "")
}

// Metadata merging is serialized under the same original draft/credential gates.
// It does not claim a caller observation or repair an unreadable old draft.
func AttachDocumentMetadataV1(ctx context.Context, d DependenciesV1, actor ActorV1, document uuid.UUID, key, value string) (*ResultV1, error) {
	if key == "" || documentpurpose.IsReservedKey(key) {
		return nil, errors.New("metadata key is unavailable")
	}
	return mutateDocumentMetadataV1(ctx, d, actor, document, "", func(*generated.Document, string) error { return nil }, nil, key, value)
}

func mutateDocumentMetadataV1(ctx context.Context, d DependenciesV1, actor ActorV1, document uuid.UUID, expected string, checkObservation func(*generated.Document, string) error, purpose *documentpurpose.Purpose, key, value string) (result *ResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || document == uuid.Nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || checkObservation == nil {
		return nil, errors.New("native draft mutation dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	session, err := d.Sessions.OpenV1(ctx, actor.OrgID, document)
	if err != nil {
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			_ = session.CloseV1(cleanup)
		}
		return nil, err
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = session.CloseV1(cleanup)
		return nil, err
	}
	state := &resultStateV1{factory: d.Sessions}
	result = &ResultV1{state: state}
	committed := false
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		closeErr := session.CloseV1(cleanup)
		_, reconcileErr := admission.ReconcileCleanupV1(cleanup)
		if !committed {
			failure = errors.Join(failure, closeErr, reconcileErr)
		}
	}()
	var doc *generated.Document
	var pending audit.PendingEvent
	var eventOwner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.revisionReader, err = session.NewHTMLRevisionReaderV1(call)
		if err != nil {
			return err
		}
		tx := &nativeBlocksPolicyTxV1{DBTX: db}
		q := generated.New(tx)
		var user *generated.User
		models, err := state.revisionReader.ReadDocumentWithActorV1(call, actor.UserID, func(access pdfadmission.HTMLRevisionReadAccessV1) error {
			if !access.Draft {
				return authoring.ErrDocumentNotDraft
			}
			return nil
		}, func(_ pdfadmission.HTMLRevisionReadAccessV1, member *generated.User) error {
			if member == nil || member.ID != actor.UserID || member.OrgID != actor.OrgID || (member.Role != string(auth.RoleSender) && member.Role != string(auth.RoleOwner)) {
				return auth.ErrMutationPermissionRevoked
			}
			if err := actor.Authorize(call, tx, member); err != nil {
				return err
			}
			user = member
			return nil
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return authoring.ErrDocumentNotFound
		}
		if err != nil {
			return fmt.Errorf("lock draft parent: %w", err)
		}
		old := models.Document
		retained, err := q.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: old.ID, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect draft evidence: %w", err)
		}
		if retained {
			return authoring.ErrDocumentHasEvidence
		}
		fence, err := q.TryCollabArchivePrivacyFence(call, actor.OrgID)
		if err != nil {
			return fmt.Errorf("fence draft privacy review: %w", err)
		}
		if !fence {
			return authoring.ErrPrivacyReviewChanging
		}
		privacy, err := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: old.ID, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect draft privacy review: %w", err)
		}
		if privacy {
			return authoring.ErrPendingPrivacyReview
		}
		if err = call.Err(); err != nil {
			return err
		}
		if err = checkObservation(old, expected); err != nil {
			return err
		}
		payload := map[string]any{"via": actor.Via, "tool": actor.Tool}
		auditPurpose := pdfadmission.HTMLAuditDocumentPurposeUpdatedV1
		if purpose != nil {
			state.purposeWriter, err = session.NewDocumentPurposeWriterV1(call, state.revisionReader)
			if err == nil {
				doc, err = state.purposeWriter.ChangeV1(call, *purpose)
			}
			payload["purpose"] = string(*purpose)
		} else {
			state.metadataWriter, err = session.NewDocumentMetadataWriterV1(call, state.revisionReader)
			if err == nil {
				doc, err = state.metadataWriter.AttachV1(call, key, value)
			}
			auditPurpose = pdfadmission.HTMLAuditDocumentMetadataAttachedV1
			payload["key"], payload["value"] = key, value
		}
		if err != nil {
			return err
		}
		id, uid := doc.ID, actor.UserID
		pending, eventOwner, err = ownedaudit.LogV1(d.Audit, call, session, auditPurpose, audit.Entry{OrgID: actor.OrgID, ActorUserID: &uid, DocumentID: &id, Kind: audit.KindDocumentUpdated, Payload: payload})
		if eventOwner != nil {
			state.events = append(state.events, eventOwner)
		}
		if err != nil {
			return err
		}
		pending = detachEventIDsV1(pending)
		finalUser := *user
		if err = actor.Authorize(call, tx, &finalUser); err != nil {
			return err
		}
		return call.Err()
	})
	if err != nil {
		return result, err
	}
	if err = session.CommitV1(ctx); err != nil {
		return result, err
	}
	committed = true
	result.Document = doc
	if err = ownedaudit.PublishV1(d.Audit, pending, eventOwner); err != nil {
		return result, err
	}
	return result, nil
}
