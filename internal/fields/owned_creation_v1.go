// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package fields

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type OwnedFieldResultV1 struct {
	Field *generated.DocumentField
	state *ownedFieldResultStateV1
}
type ownedFieldResultStateV1 struct {
	once       sync.Once
	reader     *pdfadmission.ApplicationHTMLRevisionReaderV1
	auditOwner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	batch      *pdfadmission.ApplicationPlainPDFFieldBatchV1
	factory    *pdfadmission.ApplicationSessionFactoryV1
}

func (r *OwnedFieldResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		if s.auditOwner != nil {
			s.auditOwner.CloseConsumerV1()
		}
		if s.batch != nil {
			s.batch.CloseConsumerV1()
		}
		if s.reader != nil {
			s.reader.CloseConsumerV1()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.factory != nil {
			_ = s.factory.ReconcileCleanupV1(ctx)
		}
	})
}

// Actual REST and MCP creation use this native path. Role/credential/source/
// retained-evidence/privacy/validation/recipient/quota/audit ordering remains
// the shared authoring policy, while only the exact fresh native field can be
// measured. Missing old document caches are never repaired by an author.
func (e *MutationEngine) CreateOwnedV1(parent context.Context, factory *pdfadmission.ApplicationSessionFactoryV1, actor Actor, docID uuid.UUID, input CreateInput) (result *OwnedFieldResultV1, failure error) {
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if e == nil || nilDependency(e.Audit) || factory == nil {
		return nil, errors.New("field mutation dependencies unavailable")
	}
	logger, ok := e.Audit.(*audit.Logger)
	if !ok || logger == nil {
		return nil, errors.New("native field audit unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	session, err := factory.OpenV1(ctx, actor.OrgID, docID)
	if err != nil {
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			_ = session.CloseV1(cleanup)
		}
		return nil, fmt.Errorf("begin field mutation: %w", err)
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = session.CloseV1(cleanup)
		return nil, err
	}
	state := &ownedFieldResultStateV1{factory: factory}
	result = &OwnedFieldResultV1{state: state}
	var pending audit.PendingEvent
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
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLRevisionReaderV1(call)
		if err != nil {
			return err
		}
		tx := &nativeFieldPolicyTxV1{DBTX: db}
		q := generated.New(tx)
		var user *generated.User
		models, err := state.reader.ReadFieldDocumentWithActorV1(call, actor.UserID, func(access pdfadmission.HTMLRevisionReadAccessV1) error {
			if !access.Draft {
				return ErrDocumentNotDraft
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
			return ErrDocumentNotFound
		}
		if err != nil {
			return fmt.Errorf("lock field parent: %w", err)
		}
		doc := models.Document
		if len(doc.HtmlSourceJson) != 0 {
			_, signingArtifact, err := htmlsource.SigningPage(doc)
			if err != nil || signingArtifact != nil {
				return ErrHTMLArtifactChanged
			}
			current, err := state.reader.ReadFieldCurrentV1(call)
			if err != nil {
				return ErrHTMLArtifactChanged
			}
			if err = htmlmaterialization.ValidateCurrentReadProjectionV1(doc, current); err != nil {
				return ErrHTMLArtifactChanged
			}
			commitment, err := htmlsource.Commitment(doc)
			if err != nil || actor.ExpectedHTMLSourceCommitment == "" || actor.ExpectedHTMLSourceCommitment != commitment || actor.ExpectedPDFSHA256 == "" || actor.ExpectedPDFSHA256 != hex.EncodeToString(doc.PdfSha256) {
				return ErrHTMLArtifactChanged
			}
		}
		if err := call.Err(); err != nil {
			return err
		}
		retained, err := q.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: doc.ID, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect field evidence: %w", err)
		}
		if retained {
			return ErrDocumentHasEvidence
		}
		fence, err := q.TryCollabArchivePrivacyFence(call, actor.OrgID)
		if err != nil {
			return fmt.Errorf("fence field privacy review: %w", err)
		}
		if !fence {
			return ErrPrivacyReviewChanging
		}
		privacy, err := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: doc.ID, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect field privacy review: %w", err)
		}
		if privacy {
			return ErrPendingPrivacyReview
		}
		if err = state.reader.RetainPlainFieldInputV1(call, input.Options, input.Type, input.Label); err != nil {
			return err
		}
		input.Options = append(json.RawMessage(nil), input.Options...)
		if input.RecipientID != nil {
			id := *input.RecipientID
			input.RecipientID = &id
		}
		values, err := normalizeCreateInput(input, doc)
		if err != nil {
			return err
		}
		count, err := q.CountDocumentFieldsForAuthoring(call, doc.ID)
		if err != nil {
			return fmt.Errorf("count draft fields: %w", err)
		}
		if count >= MaxFieldsPerDocument {
			return ErrFieldLimitReached
		}
		recipientID := pgtype.UUID{}
		if values.RecipientID != nil {
			recipient, err := state.reader.ReadPlainFieldRecipientV1(call, *values.RecipientID)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && recipient.DocumentID != doc.ID) {
				return ErrRecipientNotFound
			}
			if err != nil {
				return fmt.Errorf("load field recipient: %w", err)
			}
			recipientID = pgtype.UUID{Bytes: recipient.ID, Valid: true}
		}
		state.batch, err = state.reader.NewPlainPDFFieldBatchV1(call, []generated.CreateDraftFieldParams{{DocumentID: doc.ID, OrgID: actor.OrgID, RecipientID: recipientID, Type: values.Type, Page: int32(values.Page), XPct: percentNumeric(values.XPct), YPct: percentNumeric(values.YPct), WPct: percentNumeric(values.WPct), HPct: percentNumeric(values.HPct), Required: values.Required, Label: pgtype.Text{String: values.Label, Valid: values.Label != ""}, OptionsJson: values.Options}})
		if err != nil {
			return err
		}
		field, err := state.batch.CreateNextV1(call)
		if err != nil {
			return fmt.Errorf("create draft field: %w", err)
		}
		result.Field = field
		payload := map[string]any{"field_id": field.ID.String(), "type": field.Type, "page": field.Page, "required": field.Required}
		if actor.Via != "" {
			payload["via"] = actor.Via
		}
		if actor.Tool != "" {
			payload["tool"] = actor.Tool
		}
		userID, documentID := user.ID, doc.ID
		pending, state.auditOwner, err = ownedaudit.LogV1(logger, call, session, pdfadmission.HTMLAuditPlainFieldAddedV1, audit.Entry{OrgID: actor.OrgID, ActorUserID: &userID, DocumentID: &documentID, Kind: "document.field_added", IP: actor.IP, UserAgent: actor.UserAgent, Payload: payload})
		if err != nil {
			return fmt.Errorf("audit field mutation: %w", err)
		}
		if err = actor.Authorize(call, tx, user); err != nil {
			return err
		}
		return call.Err()
	})
	if err != nil {
		return result, err
	}
	if err = session.CommitV1(ctx); err != nil {
		return result, fmt.Errorf("commit field mutation: %w", err)
	}
	committed = true
	if err = ownedaudit.PublishV1(logger, pending, state.auditOwner); err != nil {
		return result, err
	}
	return result, nil
}
