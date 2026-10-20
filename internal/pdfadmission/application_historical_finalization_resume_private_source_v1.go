// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"sync"
	"unsafe"
)

// Every generated mutable document field is deeply copied by the existing
// native clone. Price its full source JSON/wire as well as text/digests before
// either independent private or public clone is produced. Unlike normal
// rendering, Resume needs no archived bytes or old signature inventory after
// this exact compatibility stage, so no predecessor body loan is registered.
func historicalResumeDocumentRawBytesV1(doc *generated.Document) (int64, error) {
	if doc == nil {
		return 0, ErrHistoricalFinalizationSourceV1
	}
	full := signerDocumentRawBytesV1(doc)
	for _, raw := range [][]byte{doc.BlocksJson, doc.VariablesJson, doc.Metadata, doc.MetadataRedactionReport, doc.HtmlSourceJson, doc.HtmlCurrentSourceJson} {
		if !htmlInputAddV1(&full, int64(len(raw)), 1) {
			return 0, ErrHistoricalFinalizationSourceV1
		}
	}
	return full, nil
}
func historicalResumeDocumentCloneRawV1(doc *generated.Document) (int64, error) {
	full, err := historicalResumeDocumentRawBytesV1(doc)
	if err != nil {
		return 0, err
	}
	price := int64(0)
	if !htmlInputAddV1(&price, full, 2) || !htmlInputAddV1(&price, 1, 8*int64(unsafe.Sizeof(generated.Document{}))+4*int64(unsafe.Sizeof(HTMLSendModelsV1{}))+4*int64(unsafe.Sizeof(sync.Once{}))+16*int64(unsafe.Sizeof(uintptr(0)))) {
		return 0, ErrHistoricalFinalizationSourceV1
	}
	return price, nil
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) newHistoricalPrivateIntentContinuationV1(call context.Context, w *ApplicationHTMLSendWorkV1) (*generated.Document, *ApplicationHistoricalFinalizationSourceEvidenceV1, error) {
	if e == nil || e.self != e || w == nil || w.self != w {
		return nil, nil, ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return nil, nil, ErrHistoricalFinalizationSourceV1
	}
	defer e.unlockV1()
	if !e.validV1() || !e.sourceChecked || e.document == nil || e.work == w {
		return nil, nil, ErrHistoricalFinalizationSourceV1
	}
	old := e.work
	old.mu.Lock()
	version := old.sourceServerVersion
	operation := old.stage.operation
	live := !old.closed && !old.resourcesClosed && old.historicalSourceEvidence == e && old.sourceDocument == e.document && old.sourceBorrowers > 0
	old.mu.Unlock()
	if !live || version <= 0 || !historicalSourceWorkCommittedV1(old) {
		return nil, nil, ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLHistoricalFinalizationSourceV1 || w.stage.operation != operation || w.stage.operation.factory != operation.factory || w.logicalDocumentV1() != e.document.ID || w.familyRoot != nil || w.sourceDocument != nil || w.models != nil || w.modelsRead || w.sourceStarted || !historicalRenderContinuationStateMatchesV1(e.document, w.state) {
		w.mu.Unlock()
		return nil, nil, ErrHistoricalFinalizationSourceV1
	}
	price, err := historicalResumeDocumentCloneRawV1(e.document)
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	closeClones, err := w.actor.acquireOwnedRetainedBodyV1(call, price, 0)
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	w.closes = append(w.closes, closeClones)
	private := htmlSendCloneDocumentV1(e.document)
	view := htmlSendCloneDocumentV1(private)
	// No pointer into the predecessor document/model/signature arrays or its
	// private CPU context is retained. The original request/deadline belongs to
	// the same real operation; the new SourceEvidence captures its own Work.
	w.sourceDocument = private
	w.sourceServerVersion = version
	w.models = &HTMLSendModelsV1{Document: view}
	w.modelsRead = true
	w.mu.Unlock()
	next, err := w.NewHistoricalFinalizationSourceEvidenceV1(call, e.client)
	if err != nil {
		return nil, nil, err
	}
	if !next.lockV1() {
		next.CloseConsumerV1()
		return nil, nil, ErrHistoricalFinalizationSourceV1
	}
	if !next.validV1() {
		next.unlockV1()
		next.CloseConsumerV1()
		return nil, nil, ErrHistoricalFinalizationSourceV1
	}
	next.sourceAttempted = true
	next.sourceChecked = true
	next.resumePredecessor = e
	next.unlockV1()
	return view, next, nil
}

// Only the same real, acknowledged successor created above can retire its
// ended original root version-check Work. It has no predecessor body borrower;
// all full private source/intent data needed next has independent real grants.
// Normal render/family continuations keep their original byte/SDK loans.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) RetireHistoricalVersionConsumersV1(next *ApplicationHistoricalFinalizationSourceEvidenceV1) error {
	if e == nil || e.self != e || next == nil || next.self != next || e == next {
		return ErrHistoricalFinalizationSourceV1
	}
	if !next.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	if !next.validV1() || !next.sourceChecked || next.resumePredecessor != e || next.work == nil || next.bodyBorrowers != 0 {
		next.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	current := next.work
	current.mu.Lock()
	registered := current.historicalSourceEvidence == next && current.sourceDocument == next.document && current.sourceDocument != nil && current.models != nil && current.models.Document == next.view
	current.mu.Unlock()
	nextDocument := next.document
	next.unlockV1()
	if !registered || !historicalSourceWorkCommittedV1(current) {
		return ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	if !e.validV1() || !e.sourceChecked || e.bodyBorrowers != 0 || e.work == nil || e.document == nextDocument {
		e.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	old := e.work
	old.mu.Lock()
	valid := old.familyRoot == nil && old.stage.operation == current.stage.operation && old.sourceDocument == e.document && old.historicalSourceEvidence == e && old.logicalDocumentV1() == current.logicalDocumentV1() && old.session.state.org == current.session.state.org
	old.mu.Unlock()
	e.unlockV1()
	if !valid || !historicalSourceWorkCommittedV1(old) {
		return ErrHistoricalFinalizationSourceV1
	}
	if !next.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	if !next.validV1() || next.resumePredecessor != e || next.work != current {
		next.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	next.resumePredecessor = nil
	next.unlockV1()
	// All actual metadata/provider/body consumers returned and their views were
	// dropped by Resume. Original Work.Close joins any real registered borrowers;
	// it does not refund a still-live loan or close the new intent/artifact Work.
	old.CloseConsumerV1()
	return nil
}
