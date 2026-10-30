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
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

var ErrRestoreDocumentKindV1 = errors.New("restore only supported on block-source documents")

// MutateTreeV1 is the existing fixed REST/MCP block-edit transaction. The
// transport supplies its original observation checker and edit callback; the
// callback receives the existing validator's decimal admission hook. Neither
// callback supplies a native source, transaction, measured size or authority.
func MutateTreeV1(ctx context.Context, d DependenciesV1, actor ActorV1, document uuid.UUID, via versions.Via, expected string, checkObservation func(*generated.Document, string) error, edit pdfadmission.BlocksEditV1) (result *ResultV1, failure error) {
	return mutateTreeV1(ctx, d, actor, document, via, expected, checkObservation, edit, 0)
}

// RestoreVersionV1 uses the same native draft/actor/CAS transaction and writer
// as ordinary block edits, including its fresh output measurements and audit.
func RestoreVersionV1(ctx context.Context, d DependenciesV1, actor ActorV1, document uuid.UUID, version int32, expected string, checkObservation func(*generated.Document, string) error) (*ResultV1, error) {
	if version < 1 || !d.SnapshotMutation {
		return nil, errors.New("document version history unavailable")
	}
	return mutateTreeV1(ctx, d, actor, document, versions.ViaRestore, expected, checkObservation, nil, version)
}

func mutateTreeV1(ctx context.Context, d DependenciesV1, actor ActorV1, document uuid.UUID, via versions.Via, expected string, checkObservation func(*generated.Document, string) error, edit pdfadmission.BlocksEditV1, restoreVersion int32) (result *ResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || document == uuid.Nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || checkObservation == nil || (edit == nil && restoreVersion < 1) {
		return nil, errors.New("owned block mutation dependencies unavailable")
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
		// Original LockDraft's evidence and privacy gates remain before source kind,
		// caller observation, tree parsing or mutation. No generic policy shortcut.
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
		if old.SourceKind != "blocks" {
			if restoreVersion > 0 {
				return ErrRestoreDocumentKindV1
			}
			return authoring.ErrDocumentNotDraft
		}
		if err = checkObservation(old, expected); err != nil {
			return err
		}
		state.mutationWriter, err = session.NewBlocksMutationWriterV1(call, state.revisionReader)
		if err != nil {
			return err
		}
		var topCount int
		snapshotName, snapshotSummary := old.Name, actor.Tool
		if restoreVersion > 0 {
			doc, snapshotName, err = state.mutationWriter.RestoreVersionV1(call, restoreVersion)
			snapshotSummary = fmt.Sprintf("restored from v%d", restoreVersion)
		} else {
			doc, topCount, err = state.mutationWriter.EditTreeV1(call, edit)
		}
		if err != nil {
			return err
		}
		if restoreVersion > 0 && actor.Via == "rest" {
			topCount, err = blocks.CountTopLevelTreeBlocksContext(call, doc.BlocksJson)
			if err != nil {
				return err
			}
		}
		if d.SnapshotMutation {
			if _, err = versions.New(q).SnapshotWithParentIdentityV1(call, versions.SnapshotInput{DocumentID: doc.ID, OrgID: doc.OrgID, Name: snapshotName, SourceKind: doc.SourceKind, BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, CreatedBy: &actor.UserID, Via: via, Summary: snapshotSummary}); err != nil {
				return err
			}
		}
		if err = state.mutationWriter.MeasureFreshPolicyV1(call); err != nil {
			return err
		}
		id, uid := doc.ID, actor.UserID
		purpose := pdfadmission.HTMLAuditBlocksUpdatedV1
		payload := map[string]any{"via": actor.Via, "tool": actor.Tool, "blocks": topCount}
		if restoreVersion > 0 {
			purpose = pdfadmission.HTMLAuditBlocksRestoredV1
			payload = map[string]any{"via": actor.Via, "tool": actor.Tool, "restored_from_v": restoreVersion}
			if actor.Via == "rest" {
				payload["restored_blocks"] = topCount
			}
		}
		pending, eventOwner, err = ownedaudit.LogV1(d.Audit, call, session, purpose, audit.Entry{OrgID: actor.OrgID, ActorUserID: &uid, DocumentID: &id, Kind: audit.KindDocumentUpdated, IP: actor.IP, UserAgent: actor.UserAgent, Payload: payload})
		if eventOwner != nil {
			state.events = append(state.events, eventOwner)
		}
		if err != nil {
			return err
		}
		pending = detachEventIDsV1(pending)
		// Original admitted credential, same locked user and actual native DBTX.
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
