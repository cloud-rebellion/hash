// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdflayout

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// MaterializationFieldParamsV1 is the original pure canonical field projection
// shared by legacy/native template materializers. It supplies no Tx, source,
// actor, fresh result or measurement authority; both producers validate those
// independently and use the same original percentage rounding implementation.
func MaterializationFieldParamsV1(document, organisation, recipient uuid.UUID, field Field) generated.CreateDraftFieldParams {
	return generated.CreateDraftFieldParams{DocumentID: document, OrgID: organisation, RecipientID: pgtype.UUID{Bytes: recipient, Valid: true}, Type: "signature", Page: field.Page,
		XPct: percent(field.XPct), YPct: percent(field.YPct), WPct: percent(field.WPct), HPct: percent(field.HPct), Required: true, Label: pgtype.Text{String: field.Label, Valid: field.Label != ""}, OptionsJson: []byte("{}")}
}
