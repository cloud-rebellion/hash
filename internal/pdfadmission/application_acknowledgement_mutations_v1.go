// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
)

type applicationAcknowledgementMutationV1 struct {
	request               *applicationAcknowledgementRequestV1
	recipient             *generated.Recipient
	recipientReads        int
	marked, counted, done bool
}

func (w *ApplicationHTMLSendWorkV1) BeginAcknowledgementMutationV1(call context.Context, h *ApplicationAcknowledgementRequestV1) (func(), error) {
	if w == nil || w.self != w || h == nil || h.state == nil {
		return nil, ErrAcknowledgementRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.acknowledgement != nil || w.stage == nil || w.stage.purpose != HTMLAcknowledgementMutationV1 || w.familyRoot != nil || w.sourceDocument == nil || s.self != s || s.consumerClosed || s.closed || s.bound || s.reader == nil || s.grant == nil || s.ctx == nil || s.ctx.Err() != nil || w.stage.operation.factory != s.factory || w.sourceDocument.ID != s.document || w.sourceDocument.OrgID != s.org {
		return nil, ErrAcknowledgementRequestV1
	}
	// Fixed mutation state and parameters are admitted before allocation. Actual
	// recipient strings/rows are separately priced by the genuine collection
	// scalar header before GetRecipient at its original policy point.
	raw := int64(2*unsafe.Sizeof(applicationAcknowledgementMutationV1{}) + 2*unsafe.Sizeof(generated.SetRecipientStatusParams{}) + 2*unsafe.Sizeof(generated.GetRecipientParams{}) + unsafe.Sizeof(generated.SetDocumentStatusParams{}))
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return nil, errors.Join(ErrAcknowledgementRequestV1, err)
	}
	w.closes = append(w.closes, closeBody)
	w.acknowledgement = &applicationAcknowledgementMutationV1{request: s}
	s.bound = true
	s.active++
	w.sourceBorrowers++
	// A copied request close, original operation close or cancellation cannot
	// credit this metadata/body while the actual mutation callback still uses it.
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			w.mu.Lock()
			w.acknowledgement.done = true
			w.sourceBorrowers--
			s.active--
			closes, actor := w.retireSourcesLockedV1()
			reader, grant := s.retireLockedV1()
			w.mu.Unlock()
			s.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			retireAcknowledgementRequestV1(reader, grant)
		})
	}, nil
}

func (w *ApplicationHTMLSendWorkV1) acknowledgementRequestV1() *applicationAcknowledgementRequestV1 {
	if w == nil || w.self != w {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.acknowledgement == nil || w.acknowledgement.done {
		return nil
	}
	return w.acknowledgement.request
}

func (w *ApplicationHTMLSendWorkV1) ReadAcknowledgementRecipientV1(call context.Context) (*generated.Recipient, error) {
	s := w.acknowledgementRequestV1()
	if s == nil {
		return nil, ErrAcknowledgementRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.acknowledgement
	if !w.valid(call) || s.consumerClosed || s.closed || m == nil || m.done || m.request != s || m.recipientReads >= 2 {
		return nil, ErrAcknowledgementRequestV1
	}
	m.recipientReads++
	if _, err := w.collectionHeaderAndPinsV1(call, htmlSendRecipientCollectionV1); err != nil {
		return nil, err
	}
	row, err := w.queries.GetRecipient(call, generated.GetRecipientParams{ID: s.recipient, OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != s.recipient || row.DocumentID != s.document {
		return nil, ErrAcknowledgementRequestV1
	}
	m.recipient = htmlSendCloneRecipientV1(row)
	return row, nil
}

func (w *ApplicationHTMLSendWorkV1) MarkAcknowledgementAcceptedV1(call context.Context) error {
	s := w.acknowledgementRequestV1()
	if s == nil {
		return ErrAcknowledgementRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.acknowledgement
	if !w.valid(call) || s.consumerClosed || s.closed || m == nil || m.done || m.request != s || m.recipient == nil || m.marked || w.sourceDocument == nil {
		return ErrAcknowledgementRequestV1
	}
	m.marked = true
	if err := w.queries.SetRecipientStatus(call, generated.SetRecipientStatusParams{ID: s.recipient, DocumentID: s.document, Status: "accepted", DeclinedReason: pgtype.Text{}}); err != nil {
		return fmt.Errorf("set recipient accepted: %w", err)
	}
	if w.sourceDocument.Status != "sent" {
		return nil
	}
	raw, _, err := w.admitDocumentReturnV1(call, int64(len("in_progress")))
	if err != nil {
		return err
	}
	row, err := w.queries.SetDocumentStatus(call, generated.SetDocumentStatusParams{ID: s.document, OrgID: s.org, Status: "in_progress"})
	if err != nil {
		return fmt.Errorf("transition to in_progress: %w", err)
	}
	if !w.verifyDocumentReturnV1(row, raw) || row.Status != "in_progress" {
		return ErrAcknowledgementRequestV1
	}
	before := *w.sourceDocument
	before.Status, before.UpdatedAt = row.Status, row.UpdatedAt
	if !htmlSendDocumentExactTupleEqualV1(&before, row) {
		return ErrAcknowledgementRequestV1
	}
	w.sourceDocument = htmlSendCloneDocumentV1(row)
	return nil
}

func (w *ApplicationHTMLSendWorkV1) CountAcknowledgementPendingV1(call context.Context) (int64, error) {
	s := w.acknowledgementRequestV1()
	if s == nil {
		return 0, ErrAcknowledgementRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.acknowledgement
	if !w.valid(call) || s.consumerClosed || s.closed || m == nil || m.done || m.request != s || !m.marked || m.counted {
		return 0, ErrAcknowledgementRequestV1
	}
	m.counted = true
	return w.queries.CountPendingAcceptors(call, s.document)
}
