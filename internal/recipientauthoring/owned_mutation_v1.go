// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package recipientauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This leaf adapter sits above canonical recipients and the native source owner.
// Canonical validation/legacy engine stay free of any pdfadmission dependency.
type MutationEngine recipients.MutationEngine
type MutationActor = recipients.MutationActor
type Values = recipients.Values
type Patch = recipients.Patch

type OwnedRecipientResultV1 struct {
	Recipient *generated.Recipient
	state     *ownedRecipientResultStateV1
}
type ownedRecipientResultStateV1 struct {
	once    sync.Once
	session *pdfadmission.ApplicationSessionV1
	factory *pdfadmission.ApplicationSessionFactoryV1
	reader  *pdfadmission.ApplicationHTMLRevisionReaderV1
	writer  *pdfadmission.ApplicationPlainRecipientMutationV1
	event   *pdfadmission.ApplicationHTMLAuditEventConsumerV1
}

func (r *OwnedRecipientResultV1) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return json.Marshal(r.Recipient)
}
func (r *OwnedRecipientResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		if s.event != nil {
			s.event.CloseConsumerV1()
		}
		if s.writer != nil {
			s.writer.CloseConsumerV1()
		}
		if s.reader != nil {
			s.reader.CloseConsumerV1()
		}
		if s.factory != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.factory.ReconcileCleanupV1(ctx)
		}
	})
}

type ownedRecipientOperationV1 uint8

const (
	ownedRecipientCreateV1 ownedRecipientOperationV1 = iota + 1
	ownedRecipientUpdateV1
	ownedRecipientDeleteV1
)

func (e *MutationEngine) CreateOwnedV1(ctx context.Context, factory *pdfadmission.ApplicationSessionFactoryV1, source *generated.Queries, actor MutationActor, document uuid.UUID, input Values) (*OwnedRecipientResultV1, error) {
	return e.mutateOwnedV1(ctx, factory, source, actor, document, uuid.Nil, ownedRecipientCreateV1, input, Patch{})
}
func (e *MutationEngine) UpdateOwnedV1(ctx context.Context, factory *pdfadmission.ApplicationSessionFactoryV1, source *generated.Queries, actor MutationActor, document, recipient uuid.UUID, patch Patch) (*OwnedRecipientResultV1, error) {
	return e.mutateOwnedV1(ctx, factory, source, actor, document, recipient, ownedRecipientUpdateV1, Values{}, patch)
}
func (e *MutationEngine) DeleteOwnedV1(ctx context.Context, factory *pdfadmission.ApplicationSessionFactoryV1, source *generated.Queries, actor MutationActor, document, recipient uuid.UUID) (*OwnedRecipientResultV1, error) {
	return e.mutateOwnedV1(ctx, factory, source, actor, document, recipient, ownedRecipientDeleteV1, Values{}, Patch{})
}

// Actual scalar source data alone selects the ordinary path; it grants no
// authorization/body/transaction authority. Existing HTML origins are immutable
// once present. HTML/current/ambiguous sources keep the complete original
// contract-recipient engine, which re-locks/rechecks every original policy.
// Ordinary selection is independently rechecked under the actual native parent
// UPDATE lock, so an origin attached during the wait cannot enter this writer.
func (e *MutationEngine) mutateOwnedV1(parent context.Context, factory *pdfadmission.ApplicationSessionFactoryV1, source *generated.Queries, actor MutationActor, document, recipient uuid.UUID, operation ownedRecipientOperationV1, input Values, patch Patch) (*OwnedRecipientResultV1, error) {
	if actor.UserID == uuid.Nil || actor.OrgID == uuid.Nil || actor.Authorize == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if !recipients.MutationDependenciesAvailableV1((*recipients.MutationEngine)(e)) {
		return nil, errors.New("recipient mutation dependencies unavailable")
	}
	legacyEngine := (*recipients.MutationEngine)(e)
	legacy := func() (*OwnedRecipientResultV1, error) {
		var row *generated.Recipient
		var err error
		switch operation {
		case ownedRecipientCreateV1:
			row, err = legacyEngine.Create(parent, actor, document, input)
		case ownedRecipientUpdateV1:
			row, err = legacyEngine.Update(parent, actor, document, recipient, patch)
		case ownedRecipientDeleteV1:
			row, err = legacyEngine.Delete(parent, actor, document, recipient)
		default:
			err = errors.New("recipient mutation operation unavailable")
		}
		return &OwnedRecipientResultV1{Recipient: row}, err
	}
	if source == nil {
		return nil, errors.New("recipient source discriminator unavailable")
	}
	peek, err := source.GetRecipientMutationSourceDiscriminatorV1(parent, generated.GetRecipientMutationSourceDiscriminatorV1Params{DocumentID: document, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return legacy()
	}
	if err != nil {
		return nil, fmt.Errorf("inspect recipient source: %w", err)
	}
	if peek == nil || peek.ID != document || peek.OrgID != actor.OrgID {
		return nil, pdfadmission.ErrPlainRecipientWriterV1
	}
	if (peek.SourceKind != "pdf" && peek.SourceKind != "blocks") || peek.HasHtmlOrigin || peek.HasHtmlCurrent || peek.HasHtmlMaterialization {
		return legacy()
	}
	result, err := e.mutateOrdinaryNativeV1(parent, factory, actor, document, recipient, operation, input, patch)
	// Native source-selection races refuse with this actual owner. A fresh
	// request can reclassify current HTML; this operation never opens a pooled
	// legacy transaction after native work has started, even after retirement.
	return result, err
}
func (e *MutationEngine) mutateOrdinaryNativeV1(parent context.Context, factory *pdfadmission.ApplicationSessionFactoryV1, actor MutationActor, document, recipient uuid.UUID, operation ownedRecipientOperationV1, input Values, patch Patch) (result *OwnedRecipientResultV1, failure error) {
	logger, ok := e.Audit.(*audit.Logger)
	if !ok || logger == nil || factory == nil {
		return nil, errors.New("native recipient mutation dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	session, err := factory.OpenV1(ctx, actor.OrgID, document)
	if err != nil {
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			_ = session.CloseV1(cleanup)
		}
		return nil, fmt.Errorf("begin recipient mutation: %w", err)
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = session.CloseV1(cleanup)
		return nil, err
	}
	state := &ownedRecipientResultStateV1{session: session, factory: factory}
	result = &OwnedRecipientResultV1{state: state}
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
	var pending audit.PendingEvent
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLRevisionReaderV1(call)
		if err != nil {
			return err
		}
		state.writer, err = session.NewPlainRecipientMutationV1(call, state.reader)
		if err != nil {
			return err
		}
		tx := &nativeRecipientPolicyTxV1{DBTX: db}
		q := generated.New(tx)
		if operation == ownedRecipientCreateV1 {
			if err = e.Billing.LockDocumentQuotaMutation(call, q, actor.OrgID); err != nil {
				return err
			}
		}
		draft, err := state.writer.LockOrdinaryParentV1(call)
		if errors.Is(err, pgx.ErrNoRows) {
			return recipients.ErrDocumentNotFound
		}
		if err != nil {
			return err
		}
		if !draft {
			return recipients.ErrDocumentNotDraft
		}
		var user *generated.User
		models, err := state.reader.ReadFieldDocumentWithActorV1(call, actor.UserID, func(access pdfadmission.HTMLRevisionReadAccessV1) error {
			if !access.Draft {
				return recipients.ErrDocumentNotDraft
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
			return recipients.ErrDocumentNotFound
		}
		if errors.Is(err, auth.ErrMutationPermissionRevoked) {
			return auth.ErrMutationPermissionRevoked
		}
		if errors.Is(err, auth.ErrMutationCredentialExpired) {
			return auth.ErrMutationCredentialExpired
		}
		if err != nil {
			return fmt.Errorf("lock recipient parent: %w", err)
		}
		if err = state.writer.AcceptActualDocumentV1(call); err != nil {
			return err
		}
		doc := models.Document
		if err = call.Err(); err != nil {
			return err
		}
		retained, err := q.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: doc.ID, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect recipient authoring evidence: %w", err)
		}
		if retained {
			return recipients.ErrDocumentHasEvidence
		}
		parties, err := htmlsource.ContractParties(doc)
		if err != nil {
			return invalid("contract_party", "contract source is invalid; review the document before editing recipients")
		}
		fence, err := q.TryCollabArchivePrivacyFence(call, actor.OrgID)
		if err != nil {
			return fmt.Errorf("fence recipient privacy review: %w", err)
		}
		if !fence {
			return recipients.ErrPrivacyReviewChanging
		}
		privacy, err := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: doc.ID, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect recipient privacy review: %w", err)
		}
		if privacy {
			return recipients.ErrPendingPrivacyReview
		}
		var row *generated.Recipient
		purpose := pdfadmission.HTMLAuditPlainRecipientCreatedV1
		kind := audit.KindRecipientCreated
		switch operation {
		case ownedRecipientCreateV1:
			if len(parties) != 0 {
				return invalid("contract_party", "reviewed contract recipients are created from the printed party information; use a contract revision")
			}
			if input.Role == "" {
				input.Role = "signer"
			}
			if input.Locale == "" {
				input.Locale = doc.DefaultLocale
			}
			if input.Locale == "" {
				input.Locale = "en"
			}
			if err = state.writer.RetainRecipientInputV1(call, input.Email, input.Name, input.Role, input.Locale); err != nil {
				return err
			}
			values, err := recipients.Normalize(input)
			if err != nil {
				return err
			}
			if err = recipients.ValidateResponseRole(values.Role); err != nil {
				return err
			}
			_, hash, err := auth.MintMagicToken()
			if err != nil {
				return fmt.Errorf("mint recipient token: %w", err)
			}
			row, err = state.writer.CreateRecipientV1(call, generated.CreateRecipientParams{DocumentID: doc.ID, Role: values.Role, Email: values.Email, Name: values.Name, OrderIndex: values.OrderIndex, Locale: values.Locale, MagicTokenHash: hash, MagicTokenExpiresAt: magictoken.Expiry(doc.ExpiresAt, time.Now())})
			if err != nil {
				return fmt.Errorf("create recipient: %w", err)
			}
			if err = state.writer.EnforceDocumentQuotaV1(call, e.Billing); err != nil {
				return err
			}
		case ownedRecipientUpdateV1:
			purpose = pdfadmission.HTMLAuditPlainRecipientUpdatedV1
			kind = audit.KindRecipientUpdated
			existing, err := state.writer.ReadRecipientV1(call, recipient)
			if errors.Is(err, pgx.ErrNoRows) {
				return recipients.ErrRecipientNotFound
			}
			if err != nil {
				return fmt.Errorf("load recipient: %w", err)
			}
			if err = state.writer.RetainRecipientInputV1(call, recipientPatchTextV1(patch.Email), recipientPatchTextV1(patch.Name), recipientPatchTextV1(patch.Role), recipientPatchTextV1(patch.Locale)); err != nil {
				return err
			}
			values, err := recipients.NormalizePatch(existing, patch)
			if err != nil {
				return err
			}
			if err = recipients.ValidateContractRecipientUpdateV1(parties, existing, values); err != nil {
				return err
			}
			row, err = state.writer.UpdateRecipientV1(call, generated.UpdateRecipientParams{ID: existing.ID, DocumentID: doc.ID, Email: values.Email, Name: values.Name, Role: values.Role, OrderIndex: values.OrderIndex, Locale: values.Locale})
			if err != nil {
				return fmt.Errorf("update recipient: %w", err)
			}
		case ownedRecipientDeleteV1:
			purpose = pdfadmission.HTMLAuditPlainRecipientDeletedV1
			kind = audit.KindRecipientDeleted
			existing, err := state.writer.ReadRecipientV1(call, recipient)
			if errors.Is(err, pgx.ErrNoRows) {
				return recipients.ErrRecipientNotFound
			}
			if err != nil {
				return fmt.Errorf("load recipient: %w", err)
			}
			if len(parties) != 0 {
				return invalid("contract_party", "required contract recipients cannot be deleted; use a contract revision")
			}
			row, err = state.writer.DeleteRecipientV1(call, existing.ID)
			if err != nil {
				return fmt.Errorf("delete recipient: %w", err)
			}
		default:
			return errors.New("recipient mutation operation unavailable")
		}
		if row == nil {
			return errors.New("recipient mutation returned no recipient")
		}
		result.Recipient = row
		payload := map[string]any{"email": row.Email, "name": row.Name, "role": row.Role}
		if actor.Via != "" {
			payload["via"] = actor.Via
		}
		if actor.Tool != "" {
			payload["tool"] = actor.Tool
		}
		userID, documentID, recipientID := user.ID, doc.ID, row.ID
		pending, state.event, err = ownedaudit.LogV1(logger, call, session, purpose, audit.Entry{OrgID: actor.OrgID, ActorUserID: &userID, DocumentID: &documentID, RecipientID: &recipientID, Kind: kind, IP: actor.IP, UserAgent: actor.UserAgent, Payload: payload})
		if err != nil {
			return fmt.Errorf("audit recipient mutation: %w", err)
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
		return result, fmt.Errorf("commit recipient mutation: %w", err)
	}
	committed = true
	if err = ownedaudit.PublishV1(logger, pending, state.event); err != nil {
		return result, err
	}
	return result, nil
}
func recipientPatchTextV1(text *string) string {
	if text == nil {
		return ""
	}
	return *text
}

func invalid(field, reason string) error {
	return &recipients.ValidationError{Field: field, Reason: reason}
}
