// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"bytes"
	"encoding/json"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// These literal capitalized V1 keys and order match the authenticated frozen
// finalization basis. Archive recovery never reconstructs them from hot rows.
type indexFieldBasisV1 struct {
	ID             uuid.UUID
	RecipientID    uuid.UUID
	RecipientValid bool
	Type           string
	Page           int32
	Required       bool
	X, Y, W, H     string
	ValueValid     bool
	Value          string
}
type indexLegacyBasisV1 struct {
	DocumentID, ID, RecipientID, FieldID uuid.UUID
	Kind                                 string
	SignedAt                             time.Time
	Object                               ObjectPinV1
	Name, Font, SpanSHA256               string
}
type indexFieldBasisDocumentV1 struct {
	Schema     string
	DocumentID uuid.UUID
	Fields     []indexFieldBasisV1
	Legacy     []indexLegacyBasisV1
}

var fieldDecimalPatternV1 = regexp.MustCompile("^-?[0-9]+(?:[.][0-9]+)?$")

func fieldDecimalV1(raw string) (*big.Rat, error) {
	if len(raw) < 1 || len(raw) > 128 || !fieldDecimalPatternV1.MatchString(raw) {
		return nil, ErrFitsIndexV1
	}
	number, ok := new(big.Rat).SetString(raw)
	if !ok || number.Num().BitLen() > 512 || number.Denom().BitLen() > 512 {
		return nil, ErrFitsIndexV1
	}
	return number, nil
}
func fieldCoordinatesV1(field indexFieldBasisV1) bool {
	x, e1 := fieldDecimalV1(field.X)
	y, e2 := fieldDecimalV1(field.Y)
	w, e3 := fieldDecimalV1(field.W)
	h, e4 := fieldDecimalV1(field.H)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || x.Sign() < 0 || y.Sign() < 0 || w.Sign() <= 0 || h.Sign() <= 0 {
		return false
	}
	limit := big.NewRat(100, 1)
	return new(big.Rat).Add(x, w).Cmp(limit) <= 0 && new(big.Rat).Add(y, h).Cmp(limit) <= 0
}
func sameFieldDecimalV1(a, b string) bool {
	x, e1 := fieldDecimalV1(a)
	y, e2 := fieldDecimalV1(b)
	return e1 == nil && e2 == nil && x.Cmp(y) == 0
}
func frozenTruthyV1(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "on", "checked", "x":
		return true
	}
	return false
}

type indexFieldFitV1 struct {
	RecipientID uuid.UUID
	Targets     []TargetV1
}

func validateIndexFieldBasisV1(doc indexDocumentWireV1, fits []indexFieldFitV1, legacy []indexLegacyWireV1) error {
	raw := doc.FieldSnapshotJSON
	if len(raw) < 1 || len(raw) > MaxAuthorityBytesV1 || authoritySHA256V1(raw) != doc.FieldSnapshotSHA256 {
		return ErrFitsIndexV1
	}
	var basis indexFieldBasisDocumentV1
	if closedCanonicalV1(raw, &basis) != nil || basis.Schema != "hash-manual-finalization-field-basis-v1" || basis.DocumentID != doc.DocumentID || basis.Fields == nil || basis.Legacy == nil || len(basis.Fields) > 10000 {
		return ErrFitsIndexV1
	}
	fields := map[uuid.UUID]indexFieldBasisV1{}
	for j, field := range basis.Fields {
		if field.ID == uuid.Nil || field.Page < 1 || int(field.Page) > len(doc.Geometry.Pages) || strings.TrimSpace(field.Type) == "" || len(field.Type) > 64 || (!field.RecipientValid && field.RecipientID != uuid.Nil) || (field.RecipientValid && field.RecipientID == uuid.Nil) || !fieldCoordinatesV1(field) || (j > 0 && bytes.Compare(basis.Fields[j-1].ID[:], field.ID[:]) >= 0) {
			return ErrFitsIndexV1
		}
		fields[field.ID] = field
	}
	fittedRecipients := map[uuid.UUID]bool{}
	fittedTargets := map[uuid.UUID]map[uuid.UUID]bool{}
	for _, fit := range fits {
		fittedRecipients[fit.RecipientID] = true
		fittedTargets[fit.RecipientID] = map[uuid.UUID]bool{}
		for _, target := range fit.Targets {
			field, ok := fields[target.ID]
			if !ok || field.Type != "signature" || !field.RecipientValid || field.RecipientID != fit.RecipientID || field.Page != int32(target.Page) || field.Required != target.Required || !sameFieldDecimalV1(field.X, target.X) || !sameFieldDecimalV1(field.Y, target.Y) || !sameFieldDecimalV1(field.W, target.W) || !sameFieldDecimalV1(field.H, target.H) {
				return ErrFitsIndexV1
			}
			fittedTargets[fit.RecipientID][target.ID] = true
		}
	}
	expectedLegacy := map[uuid.UUID]indexLegacyWireV1{}
	for _, entry := range legacy {
		if entry.DocumentID == doc.DocumentID {
			expectedLegacy[entry.SignatureID] = entry
		}
	}
	if len(expectedLegacy) != len(basis.Legacy) {
		return ErrFitsIndexV1
	}
	for j, old := range basis.Legacy {
		entry, ok := expectedLegacy[old.ID]
		at, err := indexTimeV1(entry.SignedAt)
		field, found := fields[old.FieldID]
		if !ok || err != nil || !found || field.Type != "signature" || !field.RecipientValid || field.RecipientID != old.RecipientID || old.DocumentID != entry.DocumentID || old.RecipientID != entry.RecipientID || old.FieldID != entry.FieldID || old.Kind != entry.Kind || !old.SignedAt.Equal(at) || old.SignedAt.UTC().Format(time.RFC3339Nano) != old.SignedAt.Format(time.RFC3339Nano) || old.Object != entry.Object || old.Name != entry.OriginalName || old.Font != entry.Font || old.SpanSHA256 != entry.SpanSHA256 || (j > 0 && bytes.Compare(basis.Legacy[j-1].ID[:], old.ID[:]) >= 0) {
			return ErrFitsIndexV1
		}
	}
	needed := map[int]bool{}
	for _, field := range basis.Fields {
		if field.Type == "signature" {
			if field.RecipientValid && !fittedRecipients[field.RecipientID] {
				needed[int(field.Page)] = true
			}
		} else if field.ValueValid && strings.TrimSpace(field.Value) != "" && (field.Type != "checkbox" || frozenTruthyV1(field.Value)) {
			needed[int(field.Page)] = true
		}
	}
	if len(needed) != len(doc.BasePages) {
		return ErrFitsIndexV1
	}
	for _, base := range doc.BasePages {
		if !needed[base.Page] {
			return ErrFitsIndexV1
		}
	}
	// A fitted authority must include every required signature field for its
	// recipient; archived all-field rows cannot hide another occupied target.
	for _, field := range basis.Fields {
		if field.Type == "signature" && field.Required && fittedRecipients[field.RecipientID] && !fittedTargets[field.RecipientID][field.ID] {
			return ErrFitsIndexV1
		}
	}
	return nil
}

// OriginalFieldSnapshotJSONV1 returns an immutable clone of the signed frozen
// all-field/legacy basis. It is retained private evidence, not a DSR projection.
func (i *FitsIndexV1) OriginalFieldSnapshotJSONV1(documentID uuid.UUID) (json.RawMessage, error) {
	if i == nil {
		return nil, ErrFitsIndexV1
	}
	for _, doc := range i.wire.Documents {
		if doc.DocumentID == documentID {
			return bytes.Clone(doc.FieldSnapshotJSON), nil
		}
	}
	return nil, ErrFitsIndexV1
}
