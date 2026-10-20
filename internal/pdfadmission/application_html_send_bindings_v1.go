// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrHTMLSendBindingChangedV1 = errors.New("send binding snapshot changed")

// VerifyAndPersistResolutionV1 preserves the original final account check,
// fresh complete binding comparison, and ordered CAS observation writes. Only
// this same operation's actual resolver output can supply definitions/reports
// or parameters. No public snapshot/value/byte view authorizes a write.
func (w *ApplicationHTMLSendWorkV1) VerifyAndPersistResolutionV1(call context.Context, h *ApplicationHTMLSendResolutionV1) error {
	if w == nil || w.self != w || w.stage == nil || w.stage.operation == nil || h == nil || h.state == nil {
		return ErrHTMLSendWorkV1
	}
	p := h.state
	p.mu.Lock()
	if !p.liveV1() || !p.attempted || p.failure != nil || p.active != 0 || p.work.stage.operation != w.stage.operation {
		p.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	p.active++
	doc, reports, before, observations := p.document, p.crmReports, p.bindings, p.observations
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.active--; p.retireV1(); p.mu.Unlock() }()
	w.mu.Lock()
	if !w.valid(call) || w.observationsAttempted || w.sourceDocument == nil || w.sourceDocument.ID != doc.ID || w.sourceDocument.OrgID != doc.OrgID {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	w.observationsAttempted = true
	w.mu.Unlock()
	store := &htmlSendCRMPolicyReadsV1{work: w, ctx: call}
	if err := resolver.CheckCRMReports(call, store, doc.OrgID, reports); err != nil {
		return err
	}
	current, err := w.readCurrentBindingModelsV1(call)
	if err != nil {
		return fmt.Errorf("recheck send variable bindings: %w", err)
	}
	if len(current) != len(before) {
		return fmt.Errorf("%w: variable binding membership changed", ErrHTMLSendBindingChangedV1)
	}
	for i, b := range before {
		a := current[i]
		if a == nil || b == nil || b.DocumentID != a.DocumentID || b.VariableName != a.VariableName || b.SourceKind != a.SourceKind || b.SourceRef != a.SourceRef || b.SourcePath != a.SourcePath || b.Fallback != a.Fallback || !htmlSendSameBindingTimestampV1(b.CreatedAt, a.CreatedAt) || !htmlSendSameBindingTimestampV1(b.UpdatedAt, a.UpdatedAt) {
			return fmt.Errorf("%w: variable binding changed", ErrHTMLSendBindingChangedV1)
		}
	}
	for _, observation := range observations {
		rows, err := w.persistActualBindingObservationV1(call, observation)
		if err != nil {
			return fmt.Errorf("persist send binding observation: %w", err)
		}
		if rows != 1 {
			return fmt.Errorf("%w: binding observation revision changed", ErrHTMLSendBindingChangedV1)
		}
	}
	return nil
}
func htmlSendSameBindingTimestampV1(a, b pgtype.Timestamptz) bool {
	return a.Valid == b.Valid && (!a.Valid || a.Time.Equal(b.Time))
}
func (w *ApplicationHTMLSendWorkV1) readCurrentBindingModelsV1(call context.Context) ([]*generated.DocumentVariableBinding, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) {
		return nil, ErrHTMLSendWorkV1
	}
	s := w.session.state
	h, err := w.collectionHeaderAndPinsV1(call, htmlSendBindingCollectionV1)
	if err != nil {
		return nil, err
	}
	rows, err := w.queries.ListHTMLSendBindingsV1(call, generated.ListHTMLSendBindingsV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org, ExpectedCount: h.BindingCount, ExpectedRawBytes: h.BindingRawBytes})
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != h.BindingCount {
		return nil, ErrHTMLSendWorkV1
	}
	return rows, nil
}
func (w *ApplicationHTMLSendWorkV1) persistActualBindingObservationV1(call context.Context, o HTMLSendBindingObservationV1) (int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) {
		return 0, ErrHTMLSendWorkV1
	}
	s := w.session.state
	raw := int64(0)
	var err error
	if o.Failed != nil {
		if o.Resolved != nil || (o.Failed.DocumentID != w.logicalDocumentV1() || o.Failed.OrgID != s.org) {
			return 0, ErrHTMLSendWorkV1
		}
		raw, err = htmlAuthoringSumV1(int64(len(o.Failed.VariableName)), int64(len(o.Failed.LastError)))
	} else if o.Resolved != nil {
		if o.Resolved.DocumentID != w.logicalDocumentV1() || o.Resolved.OrgID != s.org {
			return 0, ErrHTMLSendWorkV1
		}
		raw, err = htmlAuthoringSumV1(int64(len(o.Resolved.VariableName)), int64(len(o.Resolved.LastValue)))
	} else {
		return 0, errors.New("send preparation: empty binding observation")
	}
	if err != nil {
		return 0, err
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return 0, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	if o.Failed != nil {
		return w.queries.UpdateVariableBindingError(call, *o.Failed)
	}
	return w.queries.UpdateVariableBindingResolved(call, *o.Resolved)
}
