// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdftemplateauthoring

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"sync"
	"time"
)

type CaptureDependenciesV1 struct {
	Sessions *pdfadmission.ApplicationSessionFactoryV1
	Audit    *audit.Logger
	Storage  *storage.Client
}
type CaptureActorV1 struct {
	OrgID, UserID uuid.UUID
	Authorize     auth.TransactionAuthorization
}
type CaptureResultV1 struct {
	Template *generated.Template
	state    *captureResultStateV1
}
type captureResultStateV1 struct {
	once       sync.Once
	factory    *pdfadmission.ApplicationSessionFactoryV1
	inspection *pdfadmission.ApplicationPDFLayoutInspectionV1
	reader     *pdfadmission.ApplicationHTMLRevisionReaderV1
	writer     *pdfadmission.ApplicationPDFLayoutCaptureV1
}

func (r *CaptureResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		if s.writer != nil {
			s.writer.CloseConsumerV1()
		} else if s.inspection != nil {
			s.inspection.CloseConsumerV1()
		}
		if s.reader != nil {
			s.reader.CloseConsumerV1()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if s.factory != nil {
			_ = s.factory.ReconcileCleanupV1(cleanup)
		}
	})
}

// Original inspection (30s, unlocked) finishes before the original fresh10s
// draft transaction. Role/credential/evidence/privacy precede source/CAS and
// complete collections; exact export/INSERT/audit/credential/commit follows.
func CaptureV1(parent context.Context, d CaptureDependenciesV1, actor CaptureActorV1, document uuid.UUID, expected time.Time, input pdflayout.ExportInputV1) (result *CaptureResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || d.Storage == nil {
		return nil, pdfadmission.ErrPDFLayoutCaptureV1
	}
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || document == uuid.Nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	state := &captureResultStateV1{factory: d.Sessions}
	result = &CaptureResultV1{state: state}
	inspectionCtx, inspectionCancel := context.WithTimeout(parent, 30*time.Second)
	defer inspectionCancel()
	var err error
	state.inspection, err = d.Sessions.InspectPDFLayoutSourceV1(inspectionCtx, actor.OrgID, document, expected, d.Storage)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, authoring.ErrDocumentNotFound
	}
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(parent, authoring.MutationTimeout)
	defer cancel()
	session, err := d.Sessions.OpenV1(ctx, actor.OrgID, document)
	if err != nil {
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			_ = session.CloseV1(cleanup)
		}
		return result, err
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = session.CloseV1(cleanup)
		return result, err
	}
	committed := false
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		closed := session.CloseV1(cleanup)
		_, reconciled := admission.ReconcileCleanupV1(cleanup)
		if !committed {
			failure = errors.Join(failure, closed, reconciled)
		}
	}()
	var pending audit.PendingEvent
	var eventOwner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLRevisionReaderV1(call)
		if err != nil {
			return err
		}
		tx := &nativePDFTemplateReadTxV1{DBTX: db}
		queries := generated.New(tx)
		var originalUser generated.User
		_, err = state.reader.ReadPDFLayoutDocumentWithActorV1(call, actor.UserID, func(access pdfadmission.HTMLRevisionReadAccessV1) error {
			if !access.Draft {
				return authoring.ErrDocumentNotDraft
			}
			return nil
		}, func(_ pdfadmission.HTMLRevisionReadAccessV1, member *generated.User) error {
			if member == nil || member.ID != actor.UserID || member.OrgID != actor.OrgID || (member.Role != string(auth.RoleSender) && member.Role != string(auth.RoleOwner)) {
				return auth.ErrMutationPermissionRevoked
			}
			originalUser = *member
			copy := originalUser
			return actor.Authorize(call, tx, &copy)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return authoring.ErrDocumentNotFound
		}
		if err != nil {
			return err
		}
		retained, err := queries.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: document, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect draft evidence: %w", err)
		}
		if retained {
			return authoring.ErrDocumentHasEvidence
		}
		fence, err := queries.TryCollabArchivePrivacyFence(call, actor.OrgID)
		if err != nil {
			return fmt.Errorf("fence draft privacy review: %w", err)
		}
		if !fence {
			return authoring.ErrPrivacyReviewChanging
		}
		privacy, err := queries.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: document, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect draft privacy review: %w", err)
		}
		if privacy {
			return authoring.ErrPendingPrivacyReview
		}
		if err = call.Err(); err != nil {
			return err
		}
		state.writer, err = session.NewPDFLayoutCaptureV1(call, state.reader, state.inspection, actor.UserID, input)
		if err != nil {
			return err
		}
		result.Template, err = state.writer.CreateTemplateV1(call)
		if err != nil {
			return err
		}
		pending, eventOwner, err = ownedaudit.LogPDFLayoutTemplateCreatedV1(d.Audit, call, state.writer, audit.Entry{OrgID: actor.OrgID, DocumentID: &document})
		if err != nil {
			return err
		}
		copy := originalUser
		if err = actor.Authorize(call, tx, &copy); err != nil {
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
	if err = ownedaudit.PublishV1(d.Audit, pending, eventOwner); err != nil {
		return result, err
	}
	return result, nil
}
