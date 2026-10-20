// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"sync"
	"unsafe"
)

func historicalRenderContinuationStateMatchesV1(d *generated.Document, h *generated.GetHTMLSendDocumentStateHeaderV1Row) bool {
	return d != nil && h != nil && (d.SourceKind == "pdf" || d.SourceKind == "blocks") &&
		d.ID == h.ID && d.OrgID == h.OrgID && d.Status == "finalizing" && h.BoundedStatus == d.Status &&
		d.IsEnvelope == h.IsEnvelope && d.ParentEnvelopeID == h.ParentEnvelopeID && d.RequiresSignature == h.RequiresSignature &&
		(d.SourceKind == "pdf") == h.IsPdfSource && applicationStampV1(d.UpdatedAt) && applicationStampV1(h.UpdatedAt) &&
		d.UpdatedAt == h.UpdatedAt && d.EvidenceVersionPinsRequired == h.EvidenceVersionPinsRequired
}

// A fresh actual scalar FOR UPDATE State binds the original private source
// body to a later fixed render/stamp/certificate callback on the SAME operation.
// No caller Document, source bytes, row clock, cost, DBTX or child UUID can
// establish the loan. An independently admitted public clone cannot mutate it.
// The root loan is registered in this Work's actual retirement list, so it
// survives every derived native source/CPU borrower until their last use.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) NewHistoricalRenderContinuationV1(call context.Context, w *ApplicationHTMLSendWorkV1) (*generated.Document, error) {
	if e == nil || e.self != e || w == nil || w.self != w {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer e.unlockV1()
	if !e.validV1() || !e.sourceChecked || e.document == nil || e.work == w {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	old := e.work
	old.mu.Lock()
	version := old.sourceServerVersion
	operation := old.stage.operation
	live := !old.closed && !old.resourcesClosed && old.historicalSourceEvidence == e && old.sourceDocument == e.document && old.sourceBorrowers > 0
	old.mu.Unlock()
	if !live || version <= 0 {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLHistoricalFinalizationSourceV1 || w.stage.operation != operation ||
		w.stage.operation.factory != operation.factory || w.logicalDocumentV1() != e.document.ID || w.sourceDocument != nil || w.models != nil || w.modelsRead || w.sourceStarted ||
		!historicalRenderContinuationStateMatchesV1(e.document, w.state) ||
		(e.document.ParentEnvelopeID.Valid != (w.familyRoot != nil)) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	// Existing child slots must come from the actual current root's private
	// native inventory. They cannot be supplied by a caller as free child scope.
	if w.familyRoot != nil && (w.familyPin == nil || w.familyPin.ID != e.document.ID || w.familyPin.OrgID != e.document.OrgID ||
		w.familyRoot.stage == nil || w.familyRoot.stage.operation != operation) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	raw, err := htmlAuthoringSumV1(signerDocumentRawBytesV1(e.document), 4*int64(unsafe.Sizeof(generated.Document{})),
		4*int64(unsafe.Sizeof(HTMLSendModelsV1{})), 4*int64(unsafe.Sizeof(sync.Once{})), 16*int64(unsafe.Sizeof(uintptr(0))))
	if err != nil {
		return nil, err
	}
	closeView, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return nil, err
	}
	if !e.beginBodyBorrowLockedV1() {
		closeView()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	w.closes = append(w.closes, closeView)
	var once sync.Once
	w.closes = append(w.closes, func() { once.Do(e.finishBodyBorrowV1) })
	view := htmlSendCloneDocumentV1(e.document)
	w.sourceDocument = e.document
	w.sourceServerVersion = version
	w.models = &HTMLSendModelsV1{Document: view}
	w.modelsRead = true
	return view, nil
}

// The only member selector is the fresh native Work already registered by
// ReadEnvelopeMembersV1. Its actual ID selects an original private source.
func (f *ApplicationHistoricalFinalizationSourceFamilyV1) NewHistoricalRenderMemberContinuationV1(call context.Context, member *ApplicationHTMLSendWorkV1) (*generated.Document, error) {
	if f == nil || f.self != f || f.work == nil || member == nil || member.self != member || member.familyRoot == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	e, err := f.memberV1(member.logicalDocumentV1())
	if err != nil {
		return nil, err
	}
	return e.NewHistoricalRenderContinuationV1(call, member)
}
