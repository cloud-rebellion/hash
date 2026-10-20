// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdflayout

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Prepare checks the current SHARE-locked template and complete identity map
// before any document is inserted. Version pins are mandatory for typed layouts.
func Prepare(template *generated.Template, expectedVersion *int32, bindings []Binding) (*Layout, []recipients.Values, error) {
	if template == nil || template.SourceKind != "pdf" {
		if len(bindings) > 0 || expectedVersion != nil {
			return nil, nil, invalid("party bindings require a PDF template")
		}
		return nil, nil, nil
	}
	layout, err := Parse(template.FieldsJson, template.PageCount.Int32)
	if err != nil {
		return nil, nil, err
	}
	if expectedVersion != nil && *expectedVersion != template.Version {
		return nil, nil, ErrPrecondition
	}
	if layout != nil && expectedVersion == nil {
		return nil, nil, invalid("expected_template_version is required for a named-party layout")
	}
	if layout != nil && (!template.PdfStorageKey.Valid || template.PdfStorageKey.String == "" || len(template.PdfSha256) != sha256.Size || (template.EvidenceVersionPinRequired && (!template.PdfStorageVersionID.Valid || template.PdfStorageVersionID.String == ""))) {
		return nil, nil, invalid("named-party layout requires the exact committed PDF source")
	}
	values, err := layout.Bind(bindings, "en")
	return layout, values, err
}

// Materialize runs only inside creation's bounded transaction, whose quota,
// template and author locks remain held. No magic-link credential is returned.
// Caller must append its document event, recheck original credentials, commit,
// then publish every returned event.
func Materialize(ctx context.Context, tx pgx.Tx, q *generated.Queries, engine *billing.Engine, logger audit.TxAppender,
	doc *generated.Document, userID uuid.UUID, layout *Layout, values []recipients.Values, via string,
) ([]audit.PendingEvent, error) {
	if layout == nil {
		return nil, nil
	}
	if doc == nil || doc.SourceKind != "pdf" || doc.Status != "draft" || len(values) != len(layout.Parties) {
		return nil, invalid("materialization requires a fresh PDF draft")
	}
	owners := make(map[string]uuid.UUID, len(values))
	var events []audit.PendingEvent
	for _, value := range values {
		if err := engine.LockDocumentQuotaMutation(ctx, q, doc.OrgID); err != nil {
			return nil, err
		}
		_, hash, err := auth.MintMagicToken()
		if err != nil {
			return nil, fmt.Errorf("mint layout recipient: %w", err)
		}
		rec, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
			DocumentID: doc.ID, Role: value.Role, Name: value.Name, Email: value.Email, Locale: value.Locale, OrderIndex: value.OrderIndex,
			MagicTokenHash: hash, MagicTokenExpiresAt: magictoken.Expiry(doc.ExpiresAt, time.Now()),
		})
		if err != nil {
			return nil, fmt.Errorf("create layout recipient: %w", err)
		}
		if err := engine.EnforceDocumentQuotaMutation(ctx, q, doc.OrgID); err != nil {
			return nil, err
		}
		owners[value.Role] = rec.ID
		event, err := logger.LogTx(ctx, tx, audit.Entry{OrgID: doc.OrgID, ActorUserID: &userID, DocumentID: &doc.ID, RecipientID: &rec.ID, Kind: audit.KindRecipientCreated,
			Payload: map[string]any{"role": value.Role, "name": value.Name, "email": value.Email, "via": via, "template_layout_version": layout.Version}})
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	for _, field := range layout.Fields {
		owner, exists := owners[field.PartyRole]
		if !exists {
			return nil, invalid("field has no fresh recipient")
		}
		row, err := q.CreateDraftField(ctx, MaterializationFieldParamsV1(doc.ID, doc.OrgID, owner, field))
		if err != nil {
			return nil, fmt.Errorf("create layout field: %w", err)
		}
		event, err := logger.LogTx(ctx, tx, audit.Entry{OrgID: doc.OrgID, ActorUserID: &userID, DocumentID: &doc.ID, Kind: "document.field_added",
			Payload: map[string]any{"field_id": row.ID, "recipient_id": owner, "party_role": field.PartyRole, "type": "signature", "page": field.Page, "required": true, "via": via}})
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func percent(value float64) pgtype.Numeric {
	return pgtype.Numeric{Int: big.NewInt(int64(math.Round(value * 10000))), Exp: -4, Valid: true}
}
