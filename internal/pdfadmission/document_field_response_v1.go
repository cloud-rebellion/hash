// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"encoding/json"
	"math/big"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// DocumentFieldDTOV1 is the original complete public/staff field projection.
// Its caller owns all row, map and encoder allocations. Keeping one serializer
// preserves NULL/empty values, optional keys and signature fields across routes.
func DocumentFieldDTOV1(f *generated.DocumentField) map[string]any {
	out := map[string]any{
		"id": f.ID.String(), "document_id": f.DocumentID.String(),
		"type": f.Type, "page": f.Page,
		"x_pct": fieldCoordinateV1(f.XPct), "y_pct": fieldCoordinateV1(f.YPct),
		"w_pct": fieldCoordinateV1(f.WPct), "h_pct": fieldCoordinateV1(f.HPct),
		"required": f.Required,
	}
	if f.RecipientID.Valid {
		out["recipient_id"] = uuid.UUID(f.RecipientID.Bytes).String()
	}
	if f.Label.Valid {
		out["label"] = f.Label.String
	}
	if f.Value.Valid {
		out["value"] = f.Value.String
	}
	if f.CompletedAt.Valid {
		out["completed_at"] = f.CompletedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if len(f.OptionsJson) > 0 {
		out["options"] = json.RawMessage(f.OptionsJson)
	}
	return out
}

// Keep the existing numericToFloat algorithm, including invalid-as-zero and
// the original multiplication/division order, rather than changing geometry.
func fieldCoordinateV1(n pgtype.Numeric) float64 {
	if !n.Valid || n.Int == nil {
		return 0
	}
	f, _ := new(big.Float).SetInt(n.Int).Float64()
	p := 1.0
	if n.Exp >= 0 {
		for i := 0; i < int(n.Exp); i++ {
			p *= 10
		}
	} else {
		for i := 0; i < -int(n.Exp); i++ {
			p /= 10
		}
	}
	return f * p
}
