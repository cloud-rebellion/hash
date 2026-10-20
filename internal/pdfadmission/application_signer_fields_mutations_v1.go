// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type applicationSignerFieldsMutationV1 struct {
	request                      *applicationSignerFieldsRequestV1
	recipient                    *generated.Recipient
	recipientReads               int
	prepared, materialized, done bool
	freezeChecked, frozen        bool
	written                      int
	results                      []*generated.DocumentField
}

func (w *ApplicationHTMLSendWorkV1) BeginSignerFieldsMutationV1(call context.Context, h *ApplicationSignerFieldsRequestV1) (func(), error) {
	if w == nil || w.self != w || h == nil || h.state == nil {
		return nil, ErrSignerFieldsRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.signerFields != nil || w.stage == nil || w.stage.purpose != HTMLSignerFieldsMutationV1 || w.familyRoot != nil || w.sourceDocument == nil || s.self != s || s.consumerClosed || s.closed || s.bound || !s.captured || s.reader == nil || s.grant == nil || s.capturedGrant == nil || s.ctx == nil || s.ctx.Err() != nil || w.stage.operation.factory != s.factory || w.sourceDocument.ID != s.document || w.sourceDocument.OrgID != s.org {
		return nil, ErrSignerFieldsRequestV1
	}
	raw := int64(2*unsafe.Sizeof(applicationSignerFieldsMutationV1{}) + 2*unsafe.Sizeof(generated.SetRecipientStatusParams{}) + 2*unsafe.Sizeof(generated.GetRecipientForShareParams{}) + 2*unsafe.Sizeof(generated.GetSignerRecipientReadHeaderV1Params{}))
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return nil, errors.Join(ErrSignerFieldsRequestV1, err)
	}
	w.closes = append(w.closes, closeBody)
	w.signerFields = &applicationSignerFieldsMutationV1{request: s}
	s.bound = true
	s.active++
	w.sourceBorrowers++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			w.mu.Lock()
			w.signerFields.done = true
			w.sourceBorrowers--
			s.active--
			closes, actor := w.retireSourcesLockedV1()
			reader, grant, captured := s.retireLockedV1()
			w.mu.Unlock()
			s.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			retireSignerFieldsRequestV1(reader, grant, captured)
		})
	}, nil
}

func (w *ApplicationHTMLSendWorkV1) signerFieldsRequestV1() *applicationSignerFieldsRequestV1 {
	if w == nil || w.self != w {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.signerFields == nil || w.signerFields.done {
		return nil
	}
	return w.signerFields.request
}

// The exact intended-recipient scalar/header precedes the body read. It does
// not use signing collection predicates, preserving paused-ceremony views and
// all viewing roles. Both locks belong to this actual native transaction.
func (w *ApplicationHTMLSendWorkV1) ReadSignerFieldsRecipientV1(call context.Context) (*generated.Recipient, error) {
	s := w.signerFieldsRequestV1()
	if s == nil {
		return nil, ErrSignerFieldsRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.signerFields
	if !w.valid(call) || s.consumerClosed || s.closed || s.ctx.Err() != nil || m == nil || m.done || m.request != s || m.recipientReads >= 2 || w.sourceDocument == nil {
		return nil, ErrSignerFieldsRequestV1
	}
	m.recipientReads++
	h, err := w.queries.GetSignerRecipientReadHeaderV1(call, generated.GetSignerRecipientReadHeaderV1Params{DocumentID: s.document, OrgID: s.org, RecipientID: s.recipient, TokenHash: s.hash[:]})
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != s.document || h.OrgID != s.org || h.RecipientID != s.recipient || !bytes.Equal(h.MagicTokenHash, s.hash[:]) || h.RawTextBytes < 0 {
		return nil, ErrSignerFieldsRequestV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, h.RawTextBytes, h.RawTextBytes)
	if err != nil {
		return nil, errors.Join(ErrSignerFieldsRequestV1, err)
	}
	w.closes = append(w.closes, closeBody)
	r, err := w.queries.GetRecipientForShare(call, generated.GetRecipientForShareParams{ID: s.recipient, DocumentID: s.document, OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if r == nil || r.ID != s.recipient || r.DocumentID != s.document || !bytes.Equal(r.MagicTokenHash, s.hash[:]) || r.MagicTokenExpiresAt != h.MagicTokenExpiresAt {
		return nil, ErrSignerFieldsRequestV1
	}
	raw, err := htmlAuthoringSumV1(int64(len(r.Role)), int64(len(r.Email)), int64(len(r.Name)), int64(len(r.Status)), int64(len(r.Locale)), int64(len(r.MagicTokenHash)), signerTextBytesV1(r.DeclinedReason), int64(len(w.sourceDocument.Status)))
	if err != nil || raw != h.RawTextBytes {
		return nil, ErrSignerFieldsRequestV1
	}
	m.recipient = htmlSendCloneRecipientV1(r)
	return r, nil
}
