// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blockauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

var ErrDraftSignatureRequiredV1 = errors.New("this reviewed contract requires both intended parties to sign")

type PlainDraftMutationInputV1 struct {
	VariablesOnly bool
	Variables     json.RawMessage
	Patch         pdfadmission.PlainDraftPatchV1
}

// Only actual ordinary PDF/blocks sources enter this native route. An HTML
// selection race refuses before mutation and never reopens a Pool transaction.
// Parent/CAS/member/evidence/privacy and final original credential checks keep
// their original order, and each successful event uses actual ownedaudit hooks.
func MutatePlainDraftV1(ctx context.Context, d DependenciesV1, actor ActorV1, document uuid.UUID, via versions.Via, expected string, checkObservation func(*generated.Document, string) error, in PlainDraftMutationInputV1) (result *ResultV1, failure error) {
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
			if access.HasHTMLSource {
				return pdfadmission.ErrPlainDraftSourceKindV1
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
		if in.VariablesOnly && old.SourceKind != "blocks" {
			return authoring.ErrDocumentNotDraft
		}
		if !in.VariablesOnly && in.Patch.RequiresSignature != nil && !*in.Patch.RequiresSignature {
			parties, e := htmlsource.ContractParties(old)
			if e != nil || len(parties) != 0 {
				return ErrDraftSignatureRequiredV1
			}
		}
		if err = checkObservation(old, expected); err != nil {
			return err
		}
		state.plainDraftWriter, err = session.NewPlainDraftMutationWriterV1(call, state.revisionReader)
		if err != nil {
			return err
		}
		if in.VariablesOnly {
			doc, err = state.plainDraftWriter.SetVariablesV1(call, in.Variables)
		} else {
			doc, err = state.plainDraftWriter.PatchV1(call, in.Patch)
		}
		if err != nil {
			return err
		}
		if d.SnapshotMutation {
			if _, err = versions.New(q).SnapshotWithParentIdentityV1(call, versions.SnapshotInput{DocumentID: doc.ID, OrgID: doc.OrgID, Name: doc.Name, SourceKind: doc.SourceKind, BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, CreatedBy: &actor.UserID, Via: via, Summary: actor.Tool}); err != nil {
				return err
			}
		}
		if err = state.plainDraftWriter.MeasureFreshPolicyV1(call); err != nil {
			return err
		}
		var payload map[string]any
		if in.VariablesOnly {
			payload = map[string]any{"via": "mcp", "tool": "set_variables"}
		}
		id, uid := doc.ID, actor.UserID
		pending, eventOwner, err = ownedaudit.LogV1(d.Audit, call, session, pdfadmission.HTMLAuditPlainDraftUpdatedV1, audit.Entry{OrgID: actor.OrgID, ActorUserID: &uid, DocumentID: &id, Kind: audit.KindDocumentUpdated, Payload: payload})
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
