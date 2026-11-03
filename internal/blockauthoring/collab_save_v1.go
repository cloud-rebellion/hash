// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package blockauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CanonicalCollabInputV1 struct {
	PeerID     string
	Checkpoint [32]byte
	Generation int64
	BlocksJSON json.RawMessage
}

// SaveCanonicalCollabV1 retains the original real room checkpoint and M70
// canonical/generation/replay SQL. Its source mutation, all output measurements
// and owned audit now share the SAME native transaction and actor/CAS guards.
// The hub selects the genuine peer/document/org before any parent SQL lock.
func SaveCanonicalCollabV1(ctx context.Context, d DependenciesV1, actor ActorV1, hub *collab.Hub, document uuid.UUID, expected string, checkObservation func(*generated.Document, string) error, in CanonicalCollabInputV1) (result *ResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || hub == nil || document == uuid.Nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || checkObservation == nil || in.Generation < 1 {
		return nil, errors.New("native canonical collaboration dependencies unavailable")
	}
	room, err := hub.RoomForSave(document, actor.OrgID, actor.UserID, in.PeerID)
	if err != nil {
		return nil, err
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
	var user *generated.User
	var observedDocument *generated.Document
	// Acquire the actual parent/member/evidence/privacy before room mutex.
	// WithTx callbacks expose no raw transaction/commit, and subsequent callbacks
	// use this retained native session's same still-open physical transaction.
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.revisionReader, err = session.NewHTMLRevisionReaderV1(call)
		if err != nil {
			return err
		}
		tx := &nativeBlocksPolicyTxV1{DBTX: db}
		q := generated.New(tx)
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
			return fmt.Errorf("lock canonical collaboration parent: %w", err)
		}
		old := models.Document
		if old.SourceKind != "blocks" {
			return authoring.ErrDocumentNotDraft
		}
		retained, err := q.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: old.ID, OrgID: actor.OrgID})
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
		privacy, err := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: old.ID, OrgID: actor.OrgID})
		if err != nil {
			return err
		}
		if privacy {
			return authoring.ErrPendingPrivacyReview
		}
		observedDocument = old
		return nil
	})
	if err != nil {
		return result, err
	}
	var replay *pdfadmission.ApplicationCanonicalCollabReplayLoanV1
	var doc *generated.Document
	var pending audit.PendingEvent
	var eventOwner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	err = room.CommitSaveCheckpointWithStateAdmissionV1(in.PeerID, in.Checkpoint, func(bytes int) error {
		return session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
			// The consumed checkpoint keeps its original conflict response even
			// when its document timestamp is also old. A genuine fresh token must
			// still pass CAS before writer/replay admission or any detached copy.
			if err := checkObservation(observedDocument, expected); err != nil {
				return err
			}
			var err error
			state.plainDraftWriter, err = session.NewPlainDraftMutationWriterV1(call, state.revisionReader)
			if err != nil {
				return err
			}
			replay, err = state.plainDraftWriter.AdmitCanonicalCollabReplayV1(call, bytes)
			return err
		})
	}, func(cp collab.SaveCheckpoint) error {
		if cp.Generation != in.Generation {
			return collab.ErrSaveCheckpoint
		}
		err := session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
			tx := &nativeBlocksPolicyTxV1{DBTX: db}
			member := *user
			if err := actor.Authorize(call, tx, &member); err != nil {
				return err
			}
			var err error
			doc, err = state.plainDraftWriter.SaveCanonicalCollabV1(call, replay, cp.Generation, cp.State, cp.PendingUpdates, actor.UserID, in.BlocksJSON)
			if err != nil {
				return err
			}
			if err = state.plainDraftWriter.MeasureFreshPolicyV1(call); err != nil {
				return err
			}
			id, uid := doc.ID, actor.UserID
			pending, eventOwner, err = ownedaudit.LogV1(d.Audit, call, session, pdfadmission.HTMLAuditPlainDraftUpdatedV1, audit.Entry{OrgID: actor.OrgID, ActorUserID: &uid, DocumentID: &id, Kind: audit.KindDocumentUpdated})
			if eventOwner != nil {
				state.events = append(state.events, eventOwner)
			}
			if err != nil {
				return err
			}
			pending = detachEventIDsV1(pending)
			member = *user
			if err = actor.Authorize(call, tx, &member); err != nil {
				return err
			}
			return call.Err()
		})
		if err != nil {
			return err
		}
		if err = session.CommitV1(ctx); err != nil {
			return err
		}
		committed = true
		return nil
	})
	if err != nil {
		return result, err
	}
	result.Document = doc
	if err = ownedaudit.PublishV1(d.Audit, pending, eventOwner); err != nil {
		return result, err
	}
	return result, nil
}
