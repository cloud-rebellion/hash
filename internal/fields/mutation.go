// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package fields owns draft field authoring, separate from signing's internal
// post-send field materialization and recipient value submission.
package fields

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrDocumentNotFound      = errors.New("document not found")
	ErrFieldNotFound         = errors.New("field not found")
	ErrRecipientNotFound     = errors.New("recipient does not belong to document")
	ErrDocumentNotDraft      = errors.New("document not editable (must be draft)")
	ErrDocumentHasEvidence   = errors.New("document contains retained signing evidence or sealing state")
	ErrPrivacyReviewChanging = errors.New("privacy review is changing; retry after it completes")
	ErrPendingPrivacyReview  = errors.New("field changes await the open privacy request review")
	ErrFieldLimitReached     = errors.New("document field limit reached (maximum 1000)")
	ErrHTMLArtifactChanged   = errors.New("HTML document source or PDF changed; reload before changing fields")
)

const MaxFieldsPerDocument = 1000

type mutationPool interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type MutationEngine struct {
	Pool  mutationPool
	Audit audit.TxAppender
}

type Actor struct {
	OrgID, UserID                uuid.UUID
	Authorize                    auth.TransactionAuthorization
	Via, Tool, IP, UserAgent     string
	ExpectedPDFSHA256            string
	ExpectedHTMLSourceCommitment string
}

// CreateInput uses percentages for geometry. MCP converts basis points at its
// wire boundary; both transports then validate and persist the same units.
type CreateInput struct {
	RecipientID            *uuid.UUID
	Type                   string
	Page                   int
	XPct, YPct, WPct, HPct float64
	Required               bool
	Label                  string
	Options                json.RawMessage
}

type ValidationError struct{ Field, Reason string }

func (e *ValidationError) Error() string { return "invalid field " + e.Field + ": " + e.Reason }

func (e *MutationEngine) Create(ctx context.Context, actor Actor, docID uuid.UUID, input CreateInput) (*generated.DocumentField, error) {
	input.Options = append(json.RawMessage(nil), input.Options...)
	if input.RecipientID != nil {
		id := *input.RecipientID
		input.RecipientID = &id
	}
	return e.mutate(ctx, actor, docID, "document.field_added", func(ctx context.Context, q *generated.Queries, doc *generated.Document) (*generated.DocumentField, error) {
		values, err := normalizeCreateInput(input, doc)
		if err != nil {
			return nil, err
		}
		count, err := q.CountDocumentFieldsForAuthoring(ctx, doc.ID)
		if err != nil {
			return nil, fmt.Errorf("count draft fields: %w", err)
		}
		if count >= MaxFieldsPerDocument {
			return nil, ErrFieldLimitReached
		}
		recipientID := pgtype.UUID{}
		if values.RecipientID != nil {
			recipient, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: *values.RecipientID, OrgID: actor.OrgID})
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && recipient.DocumentID != doc.ID) {
				return nil, ErrRecipientNotFound
			}
			if err != nil {
				return nil, fmt.Errorf("load field recipient: %w", err)
			}
			recipientID = pgtype.UUID{Bytes: recipient.ID, Valid: true}
		}
		row, err := q.CreateDraftField(ctx, generated.CreateDraftFieldParams{
			DocumentID: doc.ID, OrgID: actor.OrgID, RecipientID: recipientID, Type: values.Type, Page: int32(values.Page),
			XPct: percentNumeric(values.XPct), YPct: percentNumeric(values.YPct),
			WPct: percentNumeric(values.WPct), HPct: percentNumeric(values.HPct), Required: values.Required,
			Label: pgtype.Text{String: values.Label, Valid: values.Label != ""}, OptionsJson: values.Options,
		})
		if err != nil {
			return nil, fmt.Errorf("create draft field: %w", err)
		}
		return row, nil
	})
}

func (e *MutationEngine) Delete(ctx context.Context, actor Actor, docID, fieldID uuid.UUID) (*generated.DocumentField, error) {
	return e.mutate(ctx, actor, docID, "document.field_deleted", func(ctx context.Context, q *generated.Queries, doc *generated.Document) (*generated.DocumentField, error) {
		field, err := q.GetFieldForAuthoring(ctx, generated.GetFieldForAuthoringParams{ID: fieldID, DocumentID: doc.ID, OrgID: actor.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFieldNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("load draft field: %w", err)
		}
		if _, err := q.DeleteFieldByID(ctx, generated.DeleteFieldByIDParams{ID: field.ID, OrgID: actor.OrgID}); err != nil {
			return nil, fmt.Errorf("delete draft field: %w", err)
		}
		return field, nil
	})
}

func (e *MutationEngine) mutate(ctx context.Context, actor Actor, docID uuid.UUID, kind string,
	mutation func(context.Context, *generated.Queries, *generated.Document) (*generated.DocumentField, error),
) (*generated.DocumentField, error) {
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if e == nil || nilDependency(e.Pool) || nilDependency(e.Audit) {
		return nil, errors.New("field mutation dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := e.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin field mutation: %w", err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer rollbackCancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	q := generated.New(tx)
	doc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDocumentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock field parent: %w", err)
	}
	if doc.Status != "draft" {
		return nil, ErrDocumentNotDraft
	}
	user, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return nil, fmt.Errorf("lock field member: %w", err)
	}
	if user.Role != string(auth.RoleSender) && user.Role != string(auth.RoleOwner) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err := actor.Authorize(ctx, tx, user); err != nil {
		return nil, err
	}
	if len(doc.HtmlSourceJson) != 0 {
		if _, err := htmlmaterialization.Current(ctx, q, doc); err != nil {
			return nil, ErrHTMLArtifactChanged
		}
		commitment, err := htmlsource.Commitment(doc)
		if err != nil || actor.ExpectedHTMLSourceCommitment == "" || actor.ExpectedHTMLSourceCommitment != commitment ||
			actor.ExpectedPDFSHA256 == "" || actor.ExpectedPDFSHA256 != hex.EncodeToString(doc.PdfSha256) {
			return nil, ErrHTMLArtifactChanged
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	retained, err := q.HasRetainedDraftSigningEvidence(ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return nil, fmt.Errorf("inspect field evidence: %w", err)
	}
	if retained {
		return nil, ErrDocumentHasEvidence
	}
	// Shared fencing stabilizes global review. Linked DSR writers use this
	// parent; never wait on an inverse organization fence while holding it.
	fence, err := q.TryCollabArchivePrivacyFence(ctx, actor.OrgID)
	if err != nil {
		return nil, fmt.Errorf("fence field privacy review: %w", err)
	}
	if !fence {
		return nil, ErrPrivacyReviewChanging
	}
	pendingPrivacy, err := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return nil, fmt.Errorf("inspect field privacy review: %w", err)
	}
	if pendingPrivacy {
		return nil, ErrPendingPrivacyReview
	}
	field, err := mutation(ctx, q, doc)
	if err != nil {
		return nil, err
	}
	if field == nil {
		return nil, errors.New("field mutation returned no field")
	}
	payload := map[string]any{"field_id": field.ID.String(), "type": field.Type, "page": field.Page, "required": field.Required}
	if actor.Via != "" {
		payload["via"] = actor.Via
	}
	if actor.Tool != "" {
		payload["tool"] = actor.Tool
	}
	pending, err := e.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: actor.OrgID, ActorUserID: &user.ID, DocumentID: &doc.ID, Kind: kind,
		IP: actor.IP, UserAgent: actor.UserAgent, Payload: payload,
	})
	if err != nil {
		return nil, fmt.Errorf("audit field mutation: %w", err)
	}
	if err := actor.Authorize(ctx, tx, user); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit field mutation: %w", err)
	}
	e.Audit.Publish(pending)
	return field, nil
}

func normalizeCreateInput(input CreateInput, doc *generated.Document) (CreateInput, error) {
	invalid := func(field, reason string) (CreateInput, error) {
		return CreateInput{}, &ValidationError{Field: field, Reason: reason}
	}
	switch input.Type {
	case "text", "date", "checkbox", "dropdown", "initial":
	case "signature":
		if doc == nil || doc.SourceKind != "pdf" {
			return invalid("type", "signature fields come from the block tree for block-source documents")
		}
		if input.RecipientID == nil || *input.RecipientID == uuid.Nil {
			return invalid("recipient_id", "signature fields must be assigned to a recipient")
		}
	default:
		return invalid("type", "must be text|date|checkbox|dropdown|initial|signature")
	}
	if input.RecipientID != nil && *input.RecipientID == uuid.Nil {
		return invalid("recipient_id", "must be a nonzero uuid")
	}
	if input.Page <= 0 {
		input.Page = 1
	}
	if input.Page > 1000 {
		return invalid("page", "must be between 1 and 1000")
	}
	if doc != nil && len(doc.HtmlSourceJson) != 0 && doc.HtmlCurrentPageCount.Valid && int32(input.Page) > doc.HtmlCurrentPageCount.Int32 {
		return invalid("page", "must exist in the current HTML materialization PDF")
	}
	for _, item := range []struct {
		name  string
		value *float64
	}{
		{"x_pct", &input.XPct}, {"y_pct", &input.YPct}, {"w_pct", &input.WPct}, {"h_pct", &input.HPct},
	} {
		if math.IsNaN(*item.value) || math.IsInf(*item.value, 0) || *item.value < 0 || *item.value > 100 {
			return invalid(item.name, "must be finite and between 0 and 100 percent")
		}
		*item.value = math.Round(*item.value*10000) / 10000
	}
	if input.WPct <= 0 || input.HPct <= 0 || input.XPct+input.WPct > 100 || input.YPct+input.HPct > 100 {
		return invalid("geometry", "width and height must be positive and the rectangle must fit within the page")
	}
	if !utf8.ValidString(input.Label) || len(input.Label) > 800 || utf8.RuneCountInString(input.Label) > 200 {
		return invalid("label", "must be valid UTF-8, at most 200 characters and 800 bytes")
	}
	for _, r := range input.Label {
		if unicode.IsControl(r) {
			return invalid("label", "must not contain control characters")
		}
	}
	if len(input.Options) == 0 {
		input.Options = json.RawMessage(`{}`)
	}
	if len(input.Options) > 16*1024 || !utf8.Valid(input.Options) {
		return invalid("options", "must be valid UTF-8 JSON and at most 16 KiB")
	}
	var options map[string]json.RawMessage
	if json.Unmarshal(input.Options, &options) != nil || options == nil {
		return invalid("options", "must be a JSON object")
	}
	if err := validateOptionsJSON(input.Options); err != nil {
		return CreateInput{}, err
	}
	if input.Type == "dropdown" {
		var choices []string
		if json.Unmarshal(options["choices"], &choices) != nil || len(choices) == 0 || len(choices) > 100 {
			return invalid("options", "dropdown requires 1 to 100 choices")
		}
		seen := make(map[string]bool, len(choices))
		for _, choice := range choices {
			if strings.TrimSpace(choice) == "" || len(choice) > 512 || !utf8.ValidString(choice) || seen[choice] {
				return invalid("options", "dropdown choices must be unique, nonempty UTF-8 strings of at most 512 bytes")
			}
			for _, r := range choice {
				if unicode.IsControl(r) {
					return invalid("options", "dropdown choices must not contain control characters")
				}
			}
			seen[choice] = true
		}
	}
	return input, nil
}

func percentNumeric(percent float64) pgtype.Numeric {
	return pgtype.Numeric{Int: big.NewInt(int64(math.Round(percent * 10000))), Exp: -4, Valid: true}
}

func nilDependency(value any) bool {
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
