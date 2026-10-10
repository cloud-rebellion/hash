// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package recipients

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrDocumentNotFound      = errors.New("document not found")
	ErrRecipientNotFound     = errors.New("recipient not found")
	ErrDocumentNotDraft      = errors.New("document not editable (must be draft)")
	ErrDocumentHasEvidence   = errors.New("document contains retained signing evidence or sealing state")
	ErrPrivacyReviewChanging = errors.New("privacy review is changing; retry after it completes")
	ErrPendingPrivacyReview  = errors.New("recipient changes await the open privacy request review")
)

type mutationPool interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// MutationEngine is the shared REST/MCP boundary for fresh recipient authoring.
// Automated materialization has its own authorized transaction and uses the
// guarded database queries directly rather than nesting another transaction.
type MutationEngine struct {
	Pool    mutationPool
	Audit   audit.TxAppender
	Billing *billing.Engine
}

type MutationActor struct {
	OrgID, UserID            uuid.UUID
	Authorize                auth.TransactionAuthorization
	Via, Tool, IP, UserAgent string
}

// Patch preserves omitted fields. Explicit empty values still undergo the
// canonical validation; they cannot silently become an omitted edit.
type Patch struct {
	Email      *string `json:"email,omitempty"`
	Name       *string `json:"name,omitempty"`
	Role       *string `json:"role,omitempty"`
	OrderIndex *int32  `json:"order_index,omitempty"`
	Locale     *string `json:"locale,omitempty"`
}

func (e *MutationEngine) Create(ctx context.Context, actor MutationActor, docID uuid.UUID, input Values) (*generated.Recipient, error) {
	return e.mutate(ctx, actor, docID, true, audit.KindRecipientCreated,
		func(ctx context.Context, q *generated.Queries, doc *generated.Document, parties []htmlsource.ContractParty) (*generated.Recipient, error) {
			if len(parties) != 0 {
				return nil, invalid("contract_party", "reviewed contract recipients are created from the printed party information; use a contract revision")
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
			values, err := Normalize(input)
			if err != nil {
				return nil, err
			}
			if err := ValidateResponseRole(values.Role); err != nil {
				return nil, err
			}
			_, hash, err := auth.MintMagicToken()
			if err != nil {
				return nil, fmt.Errorf("mint recipient token: %w", err)
			}
			rec, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
				DocumentID: doc.ID, Role: values.Role, Email: values.Email, Name: values.Name,
				OrderIndex: values.OrderIndex, Locale: values.Locale, MagicTokenHash: hash,
				MagicTokenExpiresAt: magictoken.Expiry(doc.ExpiresAt, time.Now()),
			})
			if err != nil {
				return nil, fmt.Errorf("create recipient: %w", err)
			}
			if err := e.Billing.EnforceDocumentQuotaMutation(ctx, q, actor.OrgID); err != nil {
				return nil, err
			}
			return rec, nil
		})
}

func (e *MutationEngine) Update(ctx context.Context, actor MutationActor, docID, recipientID uuid.UUID, patch Patch) (*generated.Recipient, error) {
	return e.mutate(ctx, actor, docID, false, audit.KindRecipientUpdated,
		func(ctx context.Context, q *generated.Queries, doc *generated.Document, parties []htmlsource.ContractParty) (*generated.Recipient, error) {
			existing, err := mutationRecipient(ctx, q, actor.OrgID, doc.ID, recipientID)
			if err != nil {
				return nil, err
			}
			values, err := NormalizePatch(existing, patch)
			if err != nil {
				return nil, err
			}
			if err := validateContractRecipientUpdate(parties, existing, values); err != nil {
				return nil, err
			}
			updated, err := q.UpdateRecipient(ctx, generated.UpdateRecipientParams{
				ID: existing.ID, DocumentID: doc.ID, Email: values.Email, Name: values.Name,
				Role: values.Role, OrderIndex: values.OrderIndex, Locale: values.Locale,
			})
			if err != nil {
				return nil, fmt.Errorf("update recipient: %w", err)
			}
			return updated, nil
		})
}

func (e *MutationEngine) Delete(ctx context.Context, actor MutationActor, docID, recipientID uuid.UUID) (*generated.Recipient, error) {
	return e.mutate(ctx, actor, docID, false, audit.KindRecipientDeleted,
		func(ctx context.Context, q *generated.Queries, doc *generated.Document, parties []htmlsource.ContractParty) (*generated.Recipient, error) {
			existing, err := mutationRecipient(ctx, q, actor.OrgID, doc.ID, recipientID)
			if err != nil {
				return nil, err
			}
			if len(parties) != 0 {
				return nil, invalid("contract_party", "required contract recipients cannot be deleted; use a contract revision")
			}
			if _, err := q.DeleteRecipient(ctx, generated.DeleteRecipientParams{ID: existing.ID, DocumentID: doc.ID}); err != nil {
				return nil, fmt.Errorf("delete recipient: %w", err)
			}
			return existing, nil
		})
}

// Generic recipient editing cannot silently change who the printed contract
// names. The contract revision path owns changes to printed identities and the
// matching bound recipients; ordinary routing edits can keep their UUIDs.
func validateContractRecipientUpdate(parties []htmlsource.ContractParty, existing *generated.Recipient, values Values) error {
	if len(parties) == 0 {
		return nil
	}
	for _, party := range parties {
		if existing != nil && existing.ID == party.RecipientID {
			if existing.Role == party.Role && existing.Name == party.Name && existing.Email == party.Email &&
				values.Role == existing.Role && values.Name == existing.Name && values.Email == existing.Email {
				return nil
			}
			return invalid("contract_party", "recipient identity must match the printed contract; use a contract revision")
		}
	}
	return invalid("contract_party", "recipient is not bound to an intended contract party")
}

func NormalizePatch(existing *generated.Recipient, patch Patch) (Values, error) {
	if existing == nil {
		return Values{}, ErrRecipientNotFound
	}
	values := Values{Email: existing.Email, Name: existing.Name, Role: existing.Role, OrderIndex: existing.OrderIndex, Locale: existing.Locale}
	if patch.Email != nil {
		values.Email = *patch.Email
	}
	if patch.Name != nil {
		values.Name = *patch.Name
	}
	if patch.Role != nil {
		values.Role = *patch.Role
	}
	if patch.OrderIndex != nil {
		values.OrderIndex = *patch.OrderIndex
	}
	if patch.Locale != nil {
		values.Locale = *patch.Locale
	}
	normalized, err := Normalize(values)
	if err != nil {
		return Values{}, err
	}
	if err := ValidateResponseRole(normalized.Role); err != nil {
		return Values{}, err
	}
	return normalized, nil
}

func mutationRecipient(ctx context.Context, q *generated.Queries, orgID, docID, recipientID uuid.UUID) (*generated.Recipient, error) {
	rec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipientID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && rec.DocumentID != docID) {
		return nil, ErrRecipientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load recipient: %w", err)
	}
	return rec, nil
}

func (e *MutationEngine) mutate(ctx context.Context, actor MutationActor, docID uuid.UUID, quota bool, kind string,
	mutation func(context.Context, *generated.Queries, *generated.Document, []htmlsource.ContractParty) (*generated.Recipient, error),
) (*generated.Recipient, error) {
	if actor.UserID == uuid.Nil || actor.OrgID == uuid.Nil || actor.Authorize == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if e == nil || nilMutationDependency(e.Pool) || nilMutationDependency(e.Audit) {
		return nil, errors.New("recipient mutation dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := e.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin recipient mutation: %w", err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer rollbackCancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	q := generated.New(tx)
	// Quota writers use one ordering: quota, undeleted parent, live member and
	// credential, mutation, audit. The early HTTP/tool lookup is advisory only.
	if quota {
		if err := e.Billing.LockDocumentQuotaMutation(ctx, q, actor.OrgID); err != nil {
			return nil, err
		}
	}
	doc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDocumentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock recipient parent: %w", err)
	}
	if doc.Status != "draft" {
		return nil, ErrDocumentNotDraft
	}
	user, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return nil, fmt.Errorf("lock recipient member: %w", err)
	}
	if user.Role != string(auth.RoleSender) && user.Role != string(auth.RoleOwner) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err := actor.Authorize(ctx, tx, user); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	retained, err := q.HasRetainedDraftSigningEvidence(ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return nil, fmt.Errorf("inspect recipient authoring evidence: %w", err)
	}
	if retained {
		return nil, ErrDocumentHasEvidence
	}
	parties, err := htmlsource.ContractParties(doc)
	if err != nil {
		return nil, invalid("contract_party", "contract source is invalid; review the document before editing recipients")
	}
	// Recipient deletion cascades assigned fields and clears privacy-request
	// recipient links; edits also replace the subject's current identifying data.
	// Keep that state stable during both linked and organization-wide review.
	// Global request writers hold the exclusive fence. Never wait on it while
	// holding the parent/member locks: a writer can subsequently need those rows.
	privacyFence, err := q.TryCollabArchivePrivacyFence(ctx, actor.OrgID)
	if err != nil {
		return nil, fmt.Errorf("fence recipient privacy review: %w", err)
	}
	if !privacyFence {
		return nil, ErrPrivacyReviewChanging
	}
	pendingPrivacy, err := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return nil, fmt.Errorf("inspect recipient privacy review: %w", err)
	}
	if pendingPrivacy {
		return nil, ErrPendingPrivacyReview
	}
	rec, err := mutation(ctx, q, doc, parties)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, errors.New("recipient mutation returned no recipient")
	}
	payload := map[string]any{"email": rec.Email, "name": rec.Name, "role": rec.Role}
	if actor.Via != "" {
		payload["via"] = actor.Via
	}
	if actor.Tool != "" {
		payload["tool"] = actor.Tool
	}
	// Migration43 keeps immutable audit subject UUIDs after recipient deletion.
	// The deleted subject stays in the hash input and audit history.
	pending, err := e.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: actor.OrgID, ActorUserID: &user.ID, DocumentID: &doc.ID, RecipientID: &rec.ID,
		Kind: kind, IP: actor.IP, UserAgent: actor.UserAgent, Payload: payload,
	})
	if err != nil {
		return nil, fmt.Errorf("audit recipient mutation: %w", err)
	}
	if err := actor.Authorize(ctx, tx, user); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit recipient mutation: %w", err)
	}
	e.Audit.Publish(pending)
	return rec, nil
}

func nilMutationDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
