// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"sort"
	"strings"
	"unsafe"
)

// The original PDF target commitment is produced from the actual Reader's
// source tuple and the actual first native field read. It is never a mutable
// caller Document, a supplied field slice, or static fitting authority.
type historicalPDFSignatureTargetsV1 struct {
	document, org, recipient uuid.UUID
	key, version             pgtype.Text
	sha                      [sha256.Size]byte
	pinsRequired             bool
	fields                   []historicalPDFSignatureTargetV1
}
type historicalPDFSignatureTargetV1 struct {
	id          uuid.UUID
	page        int32
	required    bool
	coordinates [4]string
}

var ErrHistoricalPDFSignaturePreparationChangedV1 = errors.New("signature source or placement changed; reload the document before signing")

func historicalPDFTargetResourcesV1(rows []*generated.DocumentField) (int64, error) {
	n := int64(0)
	// NUMERIC(7,4) is the real field schema. Its bounded decimal and big.Int
	// representations, both target generations, sorting and UUID maps are funded
	// before capture; this does not add a new placement or field-count limit.
	if !htmlInputAddV1(&n, int64(len(rows)), 4*int64(unsafe.Sizeof(historicalPDFSignatureTargetV1{}))+8*int64(unsafe.Sizeof(uuid.UUID{}))+8*int64(unsafe.Sizeof(uintptr(0)))+4*4*32) || !htmlInputAddV1(&n, 1, 4*int64(unsafe.Sizeof(historicalPDFSignatureTargetsV1{}))) {
		return 0, ErrBlockSignatureRequestV1
	}
	return n, nil
}
func captureHistoricalPDFTargetsV1(doc *generated.Document, recipient uuid.UUID, rows []*generated.DocumentField) (*historicalPDFSignatureTargetsV1, error) {
	if doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || recipient == uuid.Nil || doc.SourceKind != "pdf" || doc.IsEnvelope {
		return nil, errors.New("prepare PDF signature: standalone PDF and recipient required")
	}
	if !doc.PdfStorageKey.Valid || strings.TrimSpace(doc.PdfStorageKey.String) == "" || len(doc.PdfSha256) != sha256.Size || (doc.EvidenceVersionPinsRequired && (!doc.PdfStorageVersionID.Valid || strings.TrimSpace(doc.PdfStorageVersionID.String) == "")) {
		return nil, errors.New("prepare PDF signature: exact retained source commitment unavailable")
	}
	if len(rows) == 0 || len(rows) > pdflayout.MaxFields {
		return nil, errors.New("prepare PDF signature: placed fields unavailable or unbounded")
	}
	target := &historicalPDFSignatureTargetsV1{document: doc.ID, org: doc.OrgID, recipient: recipient, key: doc.PdfStorageKey, version: doc.PdfStorageVersionID, pinsRequired: doc.EvidenceVersionPinsRequired}
	copy(target.sha[:], doc.PdfSha256)
	seen := make(map[uuid.UUID]bool, len(rows))
	for _, field := range rows {
		if field == nil || field.ID == uuid.Nil || field.DocumentID != doc.ID || seen[field.ID] {
			return nil, errors.New("prepare PDF signature: duplicate, absent or foreign field")
		}
		seen[field.ID] = true
		if field.Type != "signature" || !field.RecipientID.Valid || uuid.UUID(field.RecipientID.Bytes) != recipient {
			continue
		}
		for _, numeric := range []pgtype.Numeric{field.XPct, field.YPct, field.WPct, field.HPct} {
			if !numeric.Valid || numeric.Int == nil || numeric.NaN || numeric.InfinityModifier != pgtype.Finite || numeric.Exp < -32 || numeric.Exp > 32 || numeric.Int.BitLen() > 256 {
				return nil, errors.New("prepare PDF signature: invalid or unbounded coordinate representation")
			}
		}
		if !field.Required || !pdflayout.ValidPlacement(field, 0) {
			return nil, errors.New("prepare PDF signature: every assigned signature needs a required visible placement")
		}
		coordinates := [4]string{}
		for i, numeric := range []pgtype.Numeric{field.XPct, field.YPct, field.WPct, field.HPct} {
			value, err := numeric.Value()
			if err != nil {
				return nil, fmt.Errorf("prepare PDF signature: coordinate: %w", err)
			}
			text, ok := value.(string)
			if !ok {
				return nil, errors.New("prepare PDF signature: coordinate has no decimal representation")
			}
			coordinates[i] = text
		}
		target.fields = append(target.fields, historicalPDFSignatureTargetV1{id: field.ID, page: field.Page, required: field.Required, coordinates: coordinates})
	}
	if len(target.fields) == 0 {
		return nil, errors.New("prepare PDF signature: recipient has no placed signature field")
	}
	sort.Slice(target.fields, func(i, j int) bool { return bytes.Compare(target.fields[i].id[:], target.fields[j].id[:]) < 0 })
	return target, nil
}
func validateHistoricalPDFTargetsV1(original *historicalPDFSignatureTargetsV1, doc *generated.Document, recipient uuid.UUID, rows []*generated.DocumentField) (*generated.DocumentField, error) {
	if original == nil {
		return nil, ErrHistoricalPDFSignaturePreparationChangedV1
	}
	fresh, err := captureHistoricalPDFTargetsV1(doc, recipient, rows)
	if err != nil || original.document != fresh.document || original.org != fresh.org || original.recipient != fresh.recipient || original.key != fresh.key || original.version != fresh.version || original.sha != fresh.sha || original.pinsRequired != fresh.pinsRequired || len(original.fields) != len(fresh.fields) {
		return nil, ErrHistoricalPDFSignaturePreparationChangedV1
	}
	for i := range original.fields {
		if original.fields[i] != fresh.fields[i] {
			return nil, ErrHistoricalPDFSignaturePreparationChangedV1
		}
	}
	for _, field := range rows {
		if field.ID == original.fields[0].id {
			return field, nil
		}
	}
	return nil, ErrHistoricalPDFSignaturePreparationChangedV1
}
func (h *ApplicationBlockSignatureRequestV1) PrepareHistoricalPDFV1(call context.Context, w *ApplicationHTMLSendWorkV1) error {
	if h == nil || h.state == nil || w == nil || w.self != w {
		return ErrBlockSignatureRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if s.self != s || s.closed || s.prepared || s.snapshot == nil || s.snapshot.sourceKind != "pdf" || s.snapshot.isEnvelope || s.ctx.Err() != nil || !w.valid(call) || w.stage.purpose != HTMLBlockSignPreparationV1 || w.stage.operation.factory != s.reader.factory || w.sourceDocument == nil || w.sourceDocument.ID != s.snapshot.document || w.sourceDocument.OrgID != s.snapshot.org || !w.fieldsRead {
		return ErrBlockSignatureRequestV1
	}
	resources, err := historicalPDFTargetResourcesV1(w.sourceFields)
	if err != nil {
		return err
	}
	if err = s.grant.TryGrowParentV1(s.ctx, resources); err != nil {
		return errors.Join(ErrBlockSignatureRequestV1, err)
	}
	original := &generated.Document{ID: s.snapshot.document, OrgID: s.snapshot.org, SourceKind: s.snapshot.sourceKind, IsEnvelope: s.snapshot.isEnvelope, PdfStorageKey: s.snapshot.pdfKey, PdfStorageVersionID: s.snapshot.pdfVersion, PdfSha256: s.snapshot.pdfSHA, EvidenceVersionPinsRequired: s.snapshot.versionPinsRequired}
	target, err := captureHistoricalPDFTargetsV1(original, s.snapshot.recipient, w.sourceFields)
	if err != nil {
		return err
	}
	span, err := render.RenderSignatureSpan(s.typedName, s.font)
	if err != nil {
		return fmt.Errorf("prepare signature: %w", err)
	}
	s.pdfTargets = target
	s.span = []byte(span)
	s.digest = sha256.Sum256(s.span)
	s.prepared = true
	return nil
}
func (w *ApplicationHTMLSendWorkV1) ValidateHistoricalPDFSignatureTargetsV1(call context.Context) error {
	s := w.blockSignatureRequestV1()
	if s == nil {
		return ErrBlockSignatureRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.blockSignature
	if !w.valid(call) || s.closed || s.snapshot == nil || s.snapshot.sourceKind != "pdf" || s.pdfTargets == nil || m == nil || m.fieldAttempted || !w.fieldsRead {
		return ErrBlockSignatureRequestV1
	}
	m.fieldAttempted = true
	field, err := validateHistoricalPDFTargetsV1(s.pdfTargets, w.sourceDocument, s.snapshot.recipient, w.sourceFields)
	if err != nil {
		return err
	}
	m.field = htmlSendCloneFieldV1(field)
	return nil
}
