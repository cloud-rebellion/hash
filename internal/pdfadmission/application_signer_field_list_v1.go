// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

func (w *ApplicationHTMLSendWorkV1) fieldListScopeV1() *applicationSignerScopeSnapshotV1 {
	if w == nil || w.self != w || w.stage == nil || w.stage.operation == nil || w.stage.purpose != HTMLSignerFieldListReadV1 {
		return nil
	}
	s := w.stage.operation.fieldListScope
	if s == nil || s.org != w.session.state.org || s.document != w.logicalDocumentV1() || s.recipient == uuid.Nil {
		return nil
	}
	return s
}

// No caller can provide a replacement recipient or credential. The immutable
// private scope comes from the genuine registered response-reader producer.
func (w *ApplicationHTMLSendWorkV1) ReadSignerFieldListCredentialV1(call context.Context) (ApplicationSignerReadAccessV1, error) {
	if w == nil || w.self != w {
		return ApplicationSignerReadAccessV1{}, ErrSignerFieldListV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.state == nil || w.fieldListCredentialRead {
		return ApplicationSignerReadAccessV1{}, ErrSignerFieldListV1
	}
	s := w.fieldListScopeV1()
	if s == nil {
		return ApplicationSignerReadAccessV1{}, ErrSignerFieldListV1
	}
	w.fieldListCredentialRead = true
	fixed := int64(2*unsafe.Sizeof(generated.GetSignerRecipientReadHeaderV1Row{}) + 2*unsafe.Sizeof(generated.GetSignerRecipientReadHeaderV1Params{}) + 2*unsafe.Sizeof(ApplicationSignerReadAccessV1{}) + 128)
	closeHeader, err := w.actor.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if err != nil {
		return ApplicationSignerReadAccessV1{}, errors.Join(ErrSignerFieldListV1, err)
	}
	w.closes = append(w.closes, closeHeader)
	h, err := w.queries.GetSignerRecipientReadHeaderV1(call, generated.GetSignerRecipientReadHeaderV1Params{DocumentID: s.document, OrgID: s.org, RecipientID: s.recipient, TokenHash: s.hash[:]})
	if err != nil {
		return ApplicationSignerReadAccessV1{}, err
	}
	if h == nil || h.DocumentID != s.document || h.OrgID != s.org || h.RecipientID != s.recipient || !bytes.Equal(h.MagicTokenHash, s.hash[:]) {
		return ApplicationSignerReadAccessV1{}, ErrSignerReadCredentialV1
	}
	status := w.state.BoundedStatus
	return ApplicationSignerReadAccessV1{DocumentExpiresAt: w.state.ExpiresAt, RecipientExpiresAt: h.MagicTokenExpiresAt, ActiveCeremony: status == "sent" || status == "in_progress" || status == "changes_requested"}, nil
}

func signerFieldListCostsV1(count, raw, options int64) (retained, wire, upper int64, err error) {
	total, err := htmlAuthoringSumV1(raw, options)
	if err != nil || count < 0 {
		return 0, 0, 0, ErrSignerFieldListV1
	}
	// Generated row/slice growth, DTO maps and buckets, UUID/time/optional
	// strings, four NUMERIC(7,4) backings plus conversion scratch coexist with
	// source JSON and encoding/json's scratch and final output. Fixed-width pin
	// arrays are paid here BEFORE the SQL pin/sort. Both text AND options may
	// escape sixfold; no caller or compressed-storage scalar supplies a size.
	perRow := int64(4*unsafe.Sizeof(generated.DocumentField{}) + 16*unsafe.Sizeof(uintptr(0)) + 16*4*(unsafe.Sizeof(struct {
		K string
		V any
	}{})+64) + 16*(unsafe.Sizeof(big.Int{})+unsafe.Sizeof(big.Float{})+128) + 2048)
	retained, wire, upper = 8192, 512, 512
	if !htmlInputAddV1(&retained, total, 4) || !htmlInputAddV1(&retained, count, perRow) || !htmlInputAddV1(&wire, total, 1) || !htmlInputAddV1(&wire, count, 1024) || !htmlInputAddV1(&upper, total, 6) || !htmlInputAddV1(&upper, count, 1024) {
		return 0, 0, 0, ErrSignerFieldListV1
	}
	return retained, wire, upper, nil
}

// Read and serialize a complete own+unassigned field response under the SAME
// native parent, recipient, field and M91 locks. This grants no access policy;
// core must still run the full original source/notice/credential final recheck.
func (w *ApplicationHTMLSendWorkV1) ReadSignerFieldListV1(call context.Context) (body []byte, finish func(), failure error) {
	if w == nil || w.self != w {
		return nil, nil, ErrSignerFieldListV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.state == nil || !w.fieldListCredentialRead || w.fieldListRead || w.familyRoot != nil {
		return nil, nil, ErrSignerFieldListV1
	}
	s := w.fieldListScopeV1()
	if s == nil {
		return nil, nil, ErrSignerFieldListV1
	}
	w.fieldListRead = true
	fixed := int64(4*unsafe.Sizeof(generated.GetSignerFieldListReadHeaderV1Row{}) + 2*unsafe.Sizeof(generated.LockSignerFieldListReadRowsV1Row{}) + 2*unsafe.Sizeof(generated.ListSignerFieldListReadRowsV1Params{}) + 8*unsafe.Sizeof(sync.Once{}) + 4096)
	closeHeaders, err := w.actor.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if err != nil {
		return nil, nil, errors.Join(ErrSignerFieldListV1, err)
	}
	// Header rows are transient. Their actual SQL fence still gates credit.
	defer closeHeaders()
	params := generated.GetSignerFieldListReadHeaderV1Params{DocumentID: s.document, OrgID: s.org, RecipientID: s.recipient}
	h, err := w.queries.GetSignerFieldListReadHeaderV1(call, params)
	if err != nil {
		return nil, nil, err
	}
	if h == nil || h.DocumentID != s.document || h.OrgID != s.org || h.ServerVersionNum <= 0 || h.FieldCount < 0 || h.RawBytes < 0 || h.OptionsWireBytes < 0 || h.MissingSizeCount != 0 || h.ServerMismatchCount != 0 {
		return nil, nil, ErrSignerFieldListV1
	}
	raw, wire, upper, err := signerFieldListCostsV1(h.FieldCount, h.RawBytes, h.OptionsWireBytes)
	if err != nil {
		return nil, nil, err
	}
	controls, err := readJSONRetainedControlBytesV1()
	if err != nil || !htmlInputAddV1(&raw, controls, 1) {
		return nil, nil, ErrSignerFieldListV1
	}
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return nil, nil, errors.Join(ErrSignerFieldListV1, err)
	}
	// Only independently admitted JSON ownership escapes this producer.
	consumer := &applicationReadJSONConsumerV1{release: closeRows}
	defer func() {
		if failure != nil {
			consumer.CloseConsumerV1()
			body, finish = nil, nil
		}
	}()
	pins, err := w.queries.LockSignerFieldListReadRowsV1(call, generated.LockSignerFieldListReadRowsV1Params{DocumentID: s.document, OrgID: s.org, RecipientID: s.recipient})
	if err != nil {
		return nil, nil, err
	}
	if pins == nil || pins.DocumentID != s.document || pins.OrgID != s.org || pins.FieldCount != h.FieldCount || pins.CacheCount != h.FieldCount {
		return nil, nil, ErrSignerFieldListV1
	}
	fresh, err := w.queries.GetSignerFieldListReadHeaderV1(call, params)
	if err != nil {
		return nil, nil, err
	}
	if fresh == nil || *fresh != *h {
		return nil, nil, ErrSignerFieldListV1
	}
	rows, err := w.queries.ListSignerFieldListReadRowsV1(call, generated.ListSignerFieldListReadRowsV1Params{DocumentID: s.document, OrgID: s.org, RecipientID: s.recipient, ExpectedCount: h.FieldCount, ExpectedRawBytes: h.RawBytes, ExpectedOptionsWireBytes: h.OptionsWireBytes})
	if err != nil {
		return nil, nil, err
	}
	if int64(len(rows)) != h.FieldCount {
		return nil, nil, ErrSignerFieldListV1
	}
	actualRaw, actualOptions := int64(0), int64(0)
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if row == nil || row.ID == uuid.Nil || row.DocumentID != s.document || (row.RecipientID.Valid && uuid.UUID(row.RecipientID.Bytes) != s.recipient) {
			return nil, nil, ErrSignerFieldListV1
		}
		n, err := htmlAuthoringSumV1(int64(len(row.Type)), signerTextBytesV1(row.Label), signerTextBytesV1(row.Value))
		if err != nil || !htmlInputAddV1(&actualRaw, n, 1) || !htmlInputAddV1(&actualOptions, int64(len(row.OptionsJson)), 1) {
			return nil, nil, ErrSignerFieldListV1
		}
		out = append(out, DocumentFieldDTOV1(row))
	}
	if actualRaw != h.RawBytes || actualOptions != h.OptionsWireBytes {
		return nil, nil, ErrSignerFieldListV1
	}
	body, err = json.Marshal(struct {
		Fields []map[string]any `json:"fields"`
		Count  int              `json:"count"`
	}{out, len(out)})
	if err != nil || int64(len(body)) > upper || call.Err() != nil {
		return nil, nil, errors.Join(ErrSignerFieldListV1, err, call.Err())
	}
	return body, consumer.CloseConsumerV1, nil
}
