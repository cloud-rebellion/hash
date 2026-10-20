// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// ErrSignaturePreparationChanged requires a fresh signing attempt. Preparation
// must never be consumed against a different source or set of signing targets.
var ErrSignaturePreparationChanged = errors.New("signature source or placement changed; reload the document before signing")

// manualSignatureTargets binds preflight to the retained PDF and every placed
// signature field for this recipient, rather than the first matching row. It
// copies scalar values: later mutation of a query result cannot change a receipt.
// This is a state binding, not a claim that the signature's ink fits its fields.
type manualSignatureTargets struct {
	documentID, orgID, recipientID uuid.UUID
	sourceKey, sourceVersion       pgtype.Text
	sourceSHA                      [sha256.Size]byte
	versionPinsRequired            bool
	fields                         []manualSignatureTarget
}

type manualSignatureTarget struct {
	id         uuid.UUID
	page       int32
	required   bool
	x, y, w, h string
}

func captureManualSignatureTargets(doc *generated.Document, recipientID uuid.UUID, rows []*generated.DocumentField) (*manualSignatureTargets, error) {
	if doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || recipientID == uuid.Nil || doc.SourceKind != "pdf" || doc.IsEnvelope {
		return nil, errors.New("prepare PDF signature: standalone PDF and recipient required")
	}
	if !doc.PdfStorageKey.Valid || strings.TrimSpace(doc.PdfStorageKey.String) == "" || len(doc.PdfSha256) != sha256.Size ||
		(doc.EvidenceVersionPinsRequired && (!doc.PdfStorageVersionID.Valid || strings.TrimSpace(doc.PdfStorageVersionID.String) == "")) {
		return nil, errors.New("prepare PDF signature: exact retained source commitment unavailable")
	}
	if len(rows) == 0 || len(rows) > pdflayout.MaxFields {
		return nil, errors.New("prepare PDF signature: placed fields unavailable or unbounded")
	}
	p := &manualSignatureTargets{
		documentID: doc.ID, orgID: doc.OrgID, recipientID: recipientID,
		sourceKey: doc.PdfStorageKey, sourceVersion: doc.PdfStorageVersionID,
		versionPinsRequired: doc.EvidenceVersionPinsRequired,
	}
	copy(p.sourceSHA[:], doc.PdfSha256)
	seen := make(map[uuid.UUID]bool, len(rows))
	for _, f := range rows {
		if f == nil || f.ID == uuid.Nil || f.DocumentID != doc.ID || seen[f.ID] {
			return nil, errors.New("prepare PDF signature: duplicate, absent or foreign field")
		}
		seen[f.ID] = true
		if f.Type != "signature" || !f.RecipientID.Valid || uuid.UUID(f.RecipientID.Bytes) != recipientID {
			continue
		}
		// Refuse damaged coefficients before ValidPlacement converts them to
		// decimal text. Database rows are intrinsically NUMERIC(7,4), but this
		// helper also handles in-memory inputs.
		for _, n := range []pgtype.Numeric{f.XPct, f.YPct, f.WPct, f.HPct} {
			if !n.Valid || n.Int == nil || n.NaN || n.InfinityModifier != pgtype.Finite || n.Exp < -32 || n.Exp > 32 || n.Int.BitLen() > 256 {
				return nil, errors.New("prepare PDF signature: invalid or unbounded coordinate representation")
			}
		}
		if !f.Required || !pdflayout.ValidPlacement(f, 0) {
			return nil, errors.New("prepare PDF signature: every assigned signature needs a required visible placement")
		}
		// Numeric.Value preserves the database decimal, avoiding float rounding
		// that could hide a changed placement. ValidPlacement has already refused
		// null, infinite, NaN and out-of-viewport coordinates.
		values := [4]string{}
		for i, n := range []pgtype.Numeric{f.XPct, f.YPct, f.WPct, f.HPct} {
			v, err := n.Value()
			if err != nil {
				return nil, fmt.Errorf("prepare PDF signature: coordinate: %w", err)
			}
			var ok bool
			values[i], ok = v.(string)
			if !ok {
				return nil, errors.New("prepare PDF signature: coordinate has no decimal representation")
			}
		}
		p.fields = append(p.fields, manualSignatureTarget{id: f.ID, page: f.Page, required: f.Required,
			x: values[0], y: values[1], w: values[2], h: values[3]})
	}
	if len(p.fields) == 0 {
		return nil, errors.New("prepare PDF signature: recipient has no placed signature field")
	}
	sort.Slice(p.fields, func(i, j int) bool { return bytes.Compare(p.fields[i].id[:], p.fields[j].id[:]) < 0 })
	return p, nil
}

// validateLockedManualSignatureTargets runs under the parent document lock,
// before any retained signature write or row insert. Status/updated_at are
// intentionally excluded: another party signing the same source is legitimate.
// Ordinary field/source writers also hold the parent lock.
func validateLockedManualSignatureTargets(p *manualSignatureTargets, doc *generated.Document, recipientID uuid.UUID, rows []*generated.DocumentField) (*generated.DocumentField, error) {
	if p == nil {
		return nil, ErrSignaturePreparationChanged
	}
	fresh, err := captureManualSignatureTargets(doc, recipientID, rows)
	if err != nil || p.documentID != fresh.documentID || p.orgID != fresh.orgID || p.recipientID != fresh.recipientID ||
		p.sourceKey != fresh.sourceKey || p.sourceVersion != fresh.sourceVersion || p.sourceSHA != fresh.sourceSHA ||
		p.versionPinsRequired != fresh.versionPinsRequired || len(p.fields) != len(fresh.fields) {
		return nil, ErrSignaturePreparationChanged
	}
	for i := range p.fields {
		if p.fields[i] != fresh.fields[i] {
			return nil, ErrSignaturePreparationChanged
		}
	}
	// Choose a deterministic representative for the existing single signature
	// row; finalization stamps that recipient's archive in all assigned fields.
	for _, f := range rows {
		if f.ID == p.fields[0].id {
			return f, nil
		}
	}
	return nil, ErrSignaturePreparationChanged
}
