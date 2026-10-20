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
	"github.com/jackc/pgx/v5/pgtype"
)

type applicationSignerViewMutationV1 struct {
	request        *applicationSignerViewRequestV1
	recipient      *generated.Recipient
	recipientReads int
	marked, done   bool
}

func (w *ApplicationHTMLSendWorkV1) BeginSignerViewMutationV1(call context.Context, h *ApplicationSignerViewRequestV1) (func(), error) {
	if w == nil || w.self != w || h == nil || h.state == nil {
		return nil, ErrSignerViewRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.signerView != nil || w.stage == nil || w.stage.purpose != HTMLSignerViewMutationV1 || w.familyRoot != nil || w.sourceDocument == nil || s.self != s || s.consumerClosed || s.closed || s.bound || s.reader == nil || s.grant == nil || s.ctx == nil || s.ctx.Err() != nil || w.stage.operation.factory != s.factory || w.sourceDocument.ID != s.document || w.sourceDocument.OrgID != s.org {
		return nil, ErrSignerViewRequestV1
	}
	raw := int64(2*unsafe.Sizeof(applicationSignerViewMutationV1{}) + 2*unsafe.Sizeof(generated.SetRecipientStatusParams{}) + 2*unsafe.Sizeof(generated.GetRecipientForShareParams{}) + 2*unsafe.Sizeof(generated.GetSignerRecipientReadHeaderV1Params{}))
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return nil, errors.Join(ErrSignerViewRequestV1, err)
	}
	w.closes = append(w.closes, closeBody)
	w.signerView = &applicationSignerViewMutationV1{request: s}
	s.bound = true
	s.active++
	w.sourceBorrowers++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			w.mu.Lock()
			w.signerView.done = true
			w.sourceBorrowers--
			s.active--
			closes, actor := w.retireSourcesLockedV1()
			reader, grant := s.retireLockedV1()
			w.mu.Unlock()
			s.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			retireSignerViewRequestV1(reader, grant)
		})
	}, nil
}

func (w *ApplicationHTMLSendWorkV1) signerViewRequestV1() *applicationSignerViewRequestV1 {
	if w == nil || w.self != w {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.signerView == nil || w.signerView.done {
		return nil
	}
	return w.signerView.request
}

// The exact intended-recipient scalar/header precedes the body read. It does
// not use signing collection predicates, preserving paused-ceremony views and
// all viewing roles. Both locks belong to this actual native transaction.
func (w *ApplicationHTMLSendWorkV1) ReadSignerViewRecipientV1(call context.Context) (*generated.Recipient, error) {
	s := w.signerViewRequestV1()
	if s == nil {
		return nil, ErrSignerViewRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.signerView
	if !w.valid(call) || s.consumerClosed || s.closed || s.ctx.Err() != nil || m == nil || m.done || m.request != s || m.recipientReads >= 2 || w.sourceDocument == nil {
		return nil, ErrSignerViewRequestV1
	}
	m.recipientReads++
	h, err := w.queries.GetSignerRecipientReadHeaderV1(call, generated.GetSignerRecipientReadHeaderV1Params{DocumentID: s.document, OrgID: s.org, RecipientID: s.recipient, TokenHash: s.hash[:]})
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != s.document || h.OrgID != s.org || h.RecipientID != s.recipient || !bytes.Equal(h.MagicTokenHash, s.hash[:]) || h.RawTextBytes < 0 {
		return nil, ErrSignerViewRequestV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, h.RawTextBytes, h.RawTextBytes)
	if err != nil {
		return nil, errors.Join(ErrSignerViewRequestV1, err)
	}
	w.closes = append(w.closes, closeBody)
	r, err := w.queries.GetRecipientForShare(call, generated.GetRecipientForShareParams{ID: s.recipient, DocumentID: s.document, OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if r == nil || r.ID != s.recipient || r.DocumentID != s.document || !bytes.Equal(r.MagicTokenHash, s.hash[:]) || r.MagicTokenExpiresAt != h.MagicTokenExpiresAt {
		return nil, ErrSignerViewRequestV1
	}
	raw, err := htmlAuthoringSumV1(int64(len(r.Role)), int64(len(r.Email)), int64(len(r.Name)), int64(len(r.Status)), int64(len(r.Locale)), int64(len(r.MagicTokenHash)), signerTextBytesV1(r.DeclinedReason), int64(len(w.sourceDocument.Status)))
	if err != nil || raw != h.RawTextBytes {
		return nil, ErrSignerViewRequestV1
	}
	m.recipient = htmlSendCloneRecipientV1(r)
	return r, nil
}

func (w *ApplicationHTMLSendWorkV1) MarkSignerViewedV1(call context.Context) error {
	s := w.signerViewRequestV1()
	if s == nil {
		return ErrSignerViewRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.signerView
	if !w.valid(call) || s.consumerClosed || s.closed || s.ctx.Err() != nil || m == nil || m.done || m.request != s || m.recipient == nil || m.marked || (m.recipient.Status != "pending" && m.recipient.Status != "sent") {
		return ErrSignerViewRequestV1
	}
	m.marked = true
	return w.queries.SetRecipientStatus(call, generated.SetRecipientStatusParams{ID: s.recipient, DocumentID: s.document, Status: "viewed", DeclinedReason: pgtype.Text{}})
}
