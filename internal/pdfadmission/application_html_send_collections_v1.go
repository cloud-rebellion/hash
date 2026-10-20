// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
)

type htmlSendCollectionPurposeV1 uint8

const (
	htmlSendRecipientCollectionV1 htmlSendCollectionPurposeV1 = iota + 1
	htmlSendBindingCollectionV1
	htmlSendFieldCollectionV1
)

// Caller holds the actual Work mutex. Scalar aggregate first, genuine fixed
// purpose loan before scalable UUID/cache/name pins, then a fresh scalar check.
// Missing field-option bodies are demanded ONLY by the real field purpose.
// Recipient/binding purposes retain all pin/model/raw staging but expand no
// options, and therefore cannot make an unrelated missing cache win an earlier
// business decision. Every actual field body still requires its exact cache.
func (w *ApplicationHTMLSendWorkV1) collectionHeaderAndPinsV1(call context.Context, purpose htmlSendCollectionPurposeV1) (*generated.GetHTMLSendCollectionReadHeaderV1Row, error) {
	if !w.valid(call) || w.sourceDocument == nil || w.models == nil || (w.historicalSigningCollectionsV1() && purpose == htmlSendBindingCollectionV1) {
		return nil, ErrHTMLSendWorkV1
	}
	s := w.session.state
	h, err := w.readCollectionHeaderForPurposeV1(call)
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != w.logicalDocumentV1() || h.OrgID != s.org || h.ServerVersionNum <= 0 || h.FieldMissingSizeCount < 0 || h.FieldMissingSizeCount > h.FieldCount {
		return nil, ErrHTMLSendWorkV1
	}
	if purpose == htmlSendFieldCollectionV1 && (h.FieldMissingSizeCount != 0 || h.FieldMeasurementServerMismatchCount != 0) {
		return nil, ErrHTMLSendWorkV1
	}
	closeRows, err := w.holdCollectionV1(call, *h, purpose)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeRows)
	pins, err := w.lockCollectionRowsForPurposeV1(call)
	if err != nil {
		return nil, err
	}
	if pins == nil || pins.DocumentID != w.logicalDocumentV1() || pins.OrgID != s.org || pins.RecipientCount != h.RecipientCount || pins.FieldCount != h.FieldCount || pins.FieldCacheCount != h.FieldCount-h.FieldMissingSizeCount || pins.BindingCount != h.BindingCount {
		return nil, ErrHTMLSendWorkV1
	}
	fresh, err := w.readCollectionHeaderForPurposeV1(call)
	if err != nil {
		return nil, err
	}
	if fresh == nil || *fresh != *h {
		return nil, ErrHTMLSendWorkV1
	}
	if purpose == htmlSendFieldCollectionV1 {
		verify, err := w.verifyCollectionHeaderForPurposeV1(call, h)
		if err != nil {
			return nil, err
		}
		if verify == nil || verify.DocumentID != w.logicalDocumentV1() || verify.OrgID != s.org {
			return nil, ErrHTMLSendWorkV1
		}
	}
	return h, nil
}
func (w *ApplicationHTMLSendWorkV1) ReadRecipientsV1(call context.Context) ([]*generated.Recipient, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.models == nil {
		return nil, ErrHTMLSendWorkV1
	}
	if w.recipientsRead {
		return w.models.Recipients, nil
	}
	if w.recipientsAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	w.recipientsAttempted = true
	h, err := w.collectionHeaderAndPinsV1(call, htmlSendRecipientCollectionV1)
	if err != nil {
		return nil, err
	}
	rows, err := w.listCollectionRecipientsForPurposeV1(call, h)
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != h.RecipientCount {
		return nil, ErrHTMLSendWorkV1
	}
	raw := int64(0)
	for _, r := range rows {
		if r == nil || r.DocumentID != w.logicalDocumentV1() {
			return nil, ErrHTMLSendWorkV1
		}
		n, e := htmlAuthoringSumV1(int64(len(r.Role)), int64(len(r.Email)), int64(len(r.Name)), int64(len(r.Status)), int64(len(r.Locale)), int64(len(r.DeclinedReason.String)), int64(len(r.MagicTokenHash)))
		if e != nil || !htmlInputAddV1(&raw, n, 1) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if raw != h.RecipientRawBytes {
		return nil, ErrHTMLSendWorkV1
	}
	w.sourceRecipients = make([]*generated.Recipient, len(rows))
	for i, row := range rows {
		w.sourceRecipients[i] = htmlSendCloneRecipientV1(row)
	}
	w.models.Recipients = rows
	w.recipientsRead = true
	return rows, nil
}
func (w *ApplicationHTMLSendWorkV1) ReadFieldsV1(call context.Context) ([]*generated.DocumentField, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.models == nil {
		return nil, ErrHTMLSendWorkV1
	}
	if w.fieldsRead {
		return w.models.Fields, nil
	}
	if w.fieldsAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	w.fieldsAttempted = true
	h, err := w.collectionHeaderAndPinsV1(call, htmlSendFieldCollectionV1)
	if err != nil {
		return nil, err
	}
	rows, err := w.listCollectionFieldsForPurposeV1(call, h)
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != h.FieldCount {
		return nil, ErrHTMLSendWorkV1
	}
	raw, wire := int64(0), int64(0)
	for _, f := range rows {
		if f == nil || f.DocumentID != w.logicalDocumentV1() {
			return nil, ErrHTMLSendWorkV1
		}
		n, e := htmlAuthoringSumV1(int64(len(f.Type)), int64(len(f.Label.String)), int64(len(f.Value.String)))
		if e != nil || !htmlInputAddV1(&raw, n, 1) || !htmlInputAddV1(&wire, int64(len(f.OptionsJson)), 1) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if raw != h.FieldRawBytes || wire != h.FieldOptionsWireBytes {
		return nil, ErrHTMLSendWorkV1
	}
	w.sourceFields = make([]*generated.DocumentField, len(rows))
	for i, row := range rows {
		w.sourceFields[i] = htmlSendCloneFieldV1(row)
	}
	w.models.Fields = rows
	w.fieldsRead = true
	return rows, nil
}
func (w *ApplicationHTMLSendWorkV1) ReadBindingsV1(call context.Context) ([]*generated.DocumentVariableBinding, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.models == nil {
		return nil, ErrHTMLSendWorkV1
	}
	if w.bindingsRead {
		return w.models.Bindings, nil
	}
	if w.bindingsAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	w.bindingsAttempted = true
	h, err := w.collectionHeaderAndPinsV1(call, htmlSendBindingCollectionV1)
	if err != nil {
		return nil, err
	}
	s := w.session.state
	rows, err := w.queries.ListHTMLSendBindingsV1(call, generated.ListHTMLSendBindingsV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org, ExpectedCount: h.BindingCount, ExpectedRawBytes: h.BindingRawBytes})
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != h.BindingCount {
		return nil, ErrHTMLSendWorkV1
	}
	raw := int64(0)
	for _, b := range rows {
		if b == nil || b.DocumentID != w.logicalDocumentV1() {
			return nil, ErrHTMLSendWorkV1
		}
		n, e := htmlAuthoringSumV1(int64(len(b.VariableName)), int64(len(b.SourceKind)), int64(len(b.SourceRef)), int64(len(b.SourcePath)), int64(len(b.Fallback)), int64(len(b.LastValue)), int64(len(b.LastError)))
		if e != nil || !htmlInputAddV1(&raw, n, 1) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if raw != h.BindingRawBytes {
		return nil, ErrHTMLSendWorkV1
	}
	w.sourceBindings = make([]*generated.DocumentVariableBinding, len(rows))
	for i, row := range rows {
		copy := *row
		w.sourceBindings[i] = &copy
	}
	w.models.Bindings = rows
	w.bindingsRead = true
	return rows, nil
}
