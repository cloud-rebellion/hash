// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"
	"unsafe"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const signerFieldsFrozenSQLV1 = `WITH parent AS MATERIALIZED (
 SELECT id FROM documents WHERE id=$1 AND org_id=$2 AND deleted_at IS NULL FOR UPDATE
) SELECT EXISTS(SELECT 1 FROM signatures s WHERE s.document_id=d.id)
 OR EXISTS(SELECT 1 FROM recipients r WHERE r.document_id=d.id AND (r.status='signed' OR r.signed_at IS NOT NULL)) FROM parent d`

// Exact original PDF freeze decision. Filled or accepted fields/recipients are
// not signatures; repeated autosaves remain valid before the first signature.
func (w *ApplicationHTMLSendWorkV1) SignerFieldsFrozenV1(call context.Context) (bool, error) {
	s := w.signerFieldsRequestV1()
	if s == nil {
		return false, ErrSignerFieldsRequestV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.signerFields == nil || !w.signerFields.materialized || w.sourceDocument == nil || w.sourceDocument.SourceKind != "pdf" || w.signerFields.freezeChecked {
		return false, ErrSignerFieldsRequestV1
	}
	var frozen bool
	err := (&applicationOwnedDBTXV1{session: w.session.state}).QueryRow(call, signerFieldsFrozenSQLV1, s.document, s.org).Scan(&frozen)
	if err == nil {
		w.signerFields.freezeChecked = true
		w.signerFields.frozen = frozen
	}
	return frozen, err
}

// Header-derived fields and actual captured inputs fund the fixed validation,
// response and post-commit audit bookkeeping before maps/slices are built.
// Individual UPDATE-return/DTO producers are admitted separately below.
func (w *ApplicationHTMLSendWorkV1) AdmitSignerFieldsPreparationV1(call context.Context) error {
	s := w.signerFieldsRequestV1()
	if s == nil {
		return ErrSignerFieldsRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.signerFields
	if !w.valid(call) || s.consumerClosed || s.closed || s.ctx.Err() != nil || m == nil || m.request != s || m.done || m.prepared || !m.materialized || !w.fieldsRead {
		return ErrSignerFieldsRequestV1
	}
	raw := int64(0)
	for _, part := range [][2]int64{{int64(len(w.sourceFields)), 4 * (int64(unsafe.Sizeof((*generated.DocumentField)(nil))) + 36)}, {int64(len(s.inputs)), 4 * (int64(unsafe.Sizeof(audit.PendingEvent{})) + int64(unsafe.Sizeof((*ApplicationHTMLAuditEventConsumerV1)(nil))) + int64(unsafe.Sizeof(generated.DocumentField{})) + int64(unsafe.Sizeof(generated.UpdateFieldValueParams{})) + 64)}} {
		if !htmlInputAddV1(&raw, part[0], part[1]) {
			return ErrSignerFieldsRequestV1
		}
	}
	// This existing general map producer includes old/new growth storage and
	// directory overhead; unlike template-definition maps it has no64-row cap.
	for _, shape := range [][3]int64{{int64(len(w.sourceFields)), 16, 8}, {int64(len(s.inputs)), 16, 1}} {
		n, err := pdfLayoutExportMapRawV1(shape[0], shape[1], shape[2])
		if err != nil || !htmlInputAddV1(&raw, n, 1) {
			return ErrSignerFieldsRequestV1
		}
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return errors.Join(ErrSignerFieldsRequestV1, err)
	}
	w.closes = append(w.closes, closeBody)
	m.results = make([]*generated.DocumentField, 0, len(s.inputs))
	m.prepared = true
	return nil
}

// Only the next actually captured input may update its genuine private field.
// The caller still runs the original complete-batch policy before this method.
func (w *ApplicationHTMLSendWorkV1) UpdateSignerFieldValueV1(call context.Context, id uuid.UUID, value string) (*generated.DocumentField, error) {
	s := w.signerFieldsRequestV1()
	if s == nil {
		return nil, ErrSignerFieldsRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.signerFields
	if !w.valid(call) || s.consumerClosed || s.closed || s.ctx.Err() != nil || m == nil || m.request != s || m.done || !m.prepared || !m.materialized || m.written >= len(s.inputs) || w.sourceDocument == nil || (w.sourceDocument.Status != "sent" && w.sourceDocument.Status != "in_progress") {
		return nil, ErrSignerFieldsRequestV1
	}
	if w.sourceDocument.SourceKind == "pdf" && (!m.freezeChecked || m.frozen) {
		return nil, ErrSignerFieldsRequestV1
	}
	input := s.inputs[m.written]
	if input.FieldID != id.String() || strings.TrimSpace(input.Value) != value {
		return nil, ErrSignerFieldsRequestV1
	}
	var original *generated.DocumentField
	for _, f := range w.sourceFields {
		if f.ID == id {
			original = f
			break
		}
	}
	if original == nil || original.DocumentID != s.document || original.Type == "signature" || (original.RecipientID.Valid && uuid.UUID(original.RecipientID.Bytes) != s.recipient) {
		return nil, ErrSignerFieldsRequestV1
	}
	// Concrete returned row/clone, four NUMERIC coefficients, big.Float scratch,
	// one maximum15-key DTO, UUID/time/number output and exact escaped strings.
	raw := int64(4*unsafe.Sizeof(generated.DocumentField{})+2*unsafe.Sizeof(generated.UpdateFieldValueParams{})) + 8*4*(int64(unsafe.Sizeof(big.Int{}))+int64(unsafe.Sizeof(big.Float{}))+32)
	dto, err := htmlStoredRetentionMapV1(15)
	if err != nil || !htmlInputAddV1(&raw, dto, 2) {
		return nil, ErrSignerFieldsRequestV1
	}
	wire := int64(2 + 14 + 3*36 + 64 + 4*24 + 20 + 5 + 2*15)
	for _, k := range [...]string{"id", "document_id", "type", "page", "x_pct", "y_pct", "w_pct", "h_pct", "required", "recipient_id", "label", "value", "completed_at", "options"} {
		if !htmlInputAddV1(&wire, int64(len(k)), 6) || !htmlInputAddV1(&wire, 1, 3) {
			return nil, ErrSignerFieldsRequestV1
		}
	}
	for _, n := range [...]int64{int64(len(original.Type)), signerTextBytesV1(original.Label), int64(len(value)), int64(len(original.OptionsJson))} {
		if !htmlInputAddV1(&raw, n, 8) || !htmlInputAddV1(&wire, n, 6) {
			return nil, ErrSignerFieldsRequestV1
		}
	}
	if !htmlInputAddV1(&raw, wire, 4) {
		return nil, ErrSignerFieldsRequestV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return nil, errors.Join(ErrSignerFieldsRequestV1, err)
	}
	w.closes = append(w.closes, closeBody)
	expected := pgtype.Text{String: value, Valid: value != ""}
	row, err := w.queries.UpdateFieldValue(call, generated.UpdateFieldValueParams{ID: id, DocumentID: s.document, Value: expected, RecipientID: pgtype.UUID{Bytes: s.recipient, Valid: true}})
	if err != nil {
		return nil, err
	}
	if row == nil || row.Value != expected || !applicationStampV1(row.CompletedAt) {
		return nil, ErrSignerFieldsRequestV1
	}
	before := *original
	before.Value = row.Value
	before.CompletedAt = row.CompletedAt
	if !htmlSendFieldsEqualV1([]*generated.DocumentField{&before}, []*generated.DocumentField{row}) || !bytes.Equal(original.OptionsJson, row.OptionsJson) {
		return nil, ErrSignerFieldsRequestV1
	}
	m.written++
	m.results = append(m.results, htmlSendCloneFieldV1(row))
	return row, nil
}

func (w *ApplicationHTMLSendWorkV1) SignerFieldsWritesCompleteV1(call context.Context) error {
	s := w.signerFieldsRequestV1()
	if s == nil {
		return ErrSignerFieldsRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.signerFields
	if !w.valid(call) || s.consumerClosed || s.closed || s.ctx.Err() != nil || m == nil || m.done || !m.prepared || m.written != len(s.inputs) {
		return ErrSignerFieldsRequestV1
	}
	return nil
}
