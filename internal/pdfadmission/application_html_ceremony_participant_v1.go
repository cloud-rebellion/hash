// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"strings"
	"sync"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These are actual producer inputs, never caller size/count/row authority.
// The transport preserves its original1MiB decode limit and notice validation.
type HTMLParticipantChangeInputV1 struct {
	Message, BlockID, Quote, Context, Proposed string
}

func htmlCeremonyChangeRawV1(change *generated.ChangeRequest) (int64, error) {
	if change == nil {
		return 0, ErrHTMLCeremonyWorkflowV1
	}
	resolution := int64(0)
	if change.Resolution.Valid {
		resolution = int64(len(change.Resolution.String))
	}
	return htmlAuthoringSumV1(int64(len(change.Message)), int64(len(change.Status)), int64(len(change.BlockID)),
		int64(len(change.Quote)), int64(len(change.Context)), int64(len(change.Proposed)), resolution)
}
func (w *ApplicationHTMLCeremonyWorkflowV1) CreateParticipantChangeV1(call context.Context, in HTMLParticipantChangeInputV1) (*generated.ChangeRequest, error) {
	if !w.validCallV1(call) || w.operation.state.workflow != htmlCeremonyParticipantChangeV1 || w.operation.state.participant == nil {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	if err := w.captureBodyV1(call); err != nil {
		return nil, err
	}
	scope := w.operation.state.participant
	w.mu.Lock()
	if w.changeAttempted || w.participant == nil || w.participant.ID != scope.recipient || w.participant.DocumentID != scope.document {
		w.mu.Unlock()
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.changeAttempted = true
	w.mu.Unlock()
	raw, err := htmlAuthoringSumV1(int64(len(in.Message)), int64(len(in.BlockID)), int64(len(in.Quote)), int64(len(in.Context)), int64(len(in.Proposed)), int64(len("open")))
	if err != nil {
		return nil, err
	}
	if err = w.retainV1(call, raw, 0); err != nil {
		return nil, err
	}
	// Detach every actual declared string before SQL. Future notification/event
	// producers consume this exact immutable private value, never caller rewrites.
	owned := HTMLParticipantChangeInputV1{Message: strings.Clone(in.Message), BlockID: strings.Clone(in.BlockID), Quote: strings.Clone(in.Quote), Context: strings.Clone(in.Context), Proposed: strings.Clone(in.Proposed)}
	q, err := w.queriesV1(call)
	if err != nil {
		return nil, err
	}
	change, err := q.CreateChangeRequest(call, generated.CreateChangeRequestParams{DocumentID: scope.document, RecipientID: pgtype.UUID{Bytes: scope.recipient, Valid: true},
		Message: owned.Message, BlockID: owned.BlockID, Quote: owned.Quote, Context: owned.Context, Proposed: owned.Proposed})
	if err != nil {
		return nil, err
	}
	if change == nil || change.ID == uuid.Nil || change.DocumentID != scope.document || !change.RecipientID.Valid || uuid.UUID(change.RecipientID.Bytes) != scope.recipient {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	actual, err := htmlCeremonyChangeRawV1(change)
	if err != nil || actual > raw {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	if !w.validCallV1(call) {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	copy := *change
	w.change = &copy
	w.changeInput = owned
	w.mu.Unlock()
	return change, nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) ParticipantChangeInputV1(call context.Context) (HTMLParticipantChangeInputV1, error) {
	if !w.validCallV1(call) {
		return HTMLParticipantChangeInputV1{}, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.change == nil || w.closed {
		return HTMLParticipantChangeInputV1{}, ErrHTMLCeremonyWorkflowV1
	}
	return w.changeInput, nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) BorrowChangeV1(call context.Context) (*generated.ChangeRequest, func(), error) {
	if !w.validCallV1(call) {
		return nil, nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	if w.closed || w.resourcesClosed || w.change == nil {
		w.mu.Unlock()
		return nil, nil, ErrHTMLCeremonyWorkflowV1
	}
	w.active++
	change := *w.change
	w.mu.Unlock()
	var once sync.Once
	return &change, func() { once.Do(w.doneV1) }, nil
}
