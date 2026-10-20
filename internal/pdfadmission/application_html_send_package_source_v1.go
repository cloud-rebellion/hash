// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"maps"
	"unsafe"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// MatchesPackageOriginalV1 compares only this Work's actual resolved candidate
// with its actual locked original, after BOTH independent review/current checks.
// PostgreSQL JSONB and the resolver Marshal may spell the same string map
// differently. No other tuple pin changes, and neither tuple is rewritten.
// This is not a replacement for the strict public-view MatchesDocumentV1.
func (h *ApplicationHTMLSendSourceV1) MatchesPackageOriginalV1(call context.Context, original *ApplicationHTMLSendSourceV1) (bool, error) {
	if !applicationContextV1(call) || h == nil || h.state == nil || original == nil || original.state == nil || h.state == original.state {
		return false, ErrHTMLSendWorkV1
	}
	candidate, source := h.state, original.state
	w := source.work
	if w == nil || w.self != w || candidate.work != w || source.candidate || !candidate.candidate {
		return false, ErrHTMLSendWorkV1
	}
	// Roles fix the order: original BEFORE candidate. Register each actual CPU
	// frame before any mutex wait, so Close cannot refund either source early.
	if !source.lockV1() {
		return false, ErrHTMLSendWorkV1
	}
	defer source.unlockV1()
	if !candidate.lockV1() {
		return false, ErrHTMLSendWorkV1
	}
	defer candidate.unlockV1()
	if source.closeRequested.Load() || candidate.closeRequested.Load() || source.owner == nil || candidate.owner == nil || source.owner == candidate.owner ||
		!source.attempted || source.failure != nil || !source.currentAttempted || source.currentFailure != nil ||
		!candidate.attempted || candidate.failure != nil || !candidate.currentAttempted || candidate.currentFailure != nil {
		return false, ErrHTMLSendWorkV1
	}
	beforeOwner, afterOwner := source.owner, candidate.owner
	if beforeOwner.purpose != htmlSendSourcePurposeV1 || afterOwner.purpose != htmlSendSourcePurposeV1 {
		return false, ErrHTMLSendWorkV1
	}
	if err := beforeOwner.beginV1(); err != nil {
		return false, err
	}
	defer beforeOwner.finishV1()
	if err := afterOwner.beginV1(); err != nil {
		return false, err
	}
	defer afterOwner.finishV1()
	w.mu.Lock()
	valid := w.valid(call) && !w.resourcesClosed && w.familyRoot == nil && w.stage != nil && w.stage.self == w.stage &&
		w.stage.purpose == HTMLSendAdmissionV1 && w.stage.work == w && w.stage.session == w.session &&
		w.stage.operation != nil && w.stage.operation.self == w.stage.operation &&
		w.sourceState == source && w.sourceOwner == beforeOwner && w.resolvedState == candidate && w.resolvedOwner == afterOwner &&
		w.reviewedOriginalValidated && w.reviewedCandidateValidated && w.packageInitialSelectionChecked
	w.mu.Unlock()
	if !valid || beforeOwner.binding == nil || afterOwner.binding == nil ||
		beforeOwner.binding.factory != afterOwner.binding.factory || beforeOwner.binding.session != w.session || afterOwner.binding.session != w.session ||
		beforeOwner.binding.admission != afterOwner.binding.admission || beforeOwner.binding.org != afterOwner.binding.org ||
		beforeOwner.binding.document != afterOwner.binding.document || beforeOwner.binding.org != w.session.state.org ||
		beforeOwner.binding.document != w.logicalDocumentV1() || beforeOwner.binding.ctx.Err() != nil || afterOwner.binding.ctx.Err() != nil {
		return false, ErrHTMLSendWorkV1
	}
	beforeOwner.mu.Lock()
	beforeSnapshot, beforeValidation := beforeOwner.snapshot, beforeOwner.validation
	beforeValid := !beforeOwner.processing && beforeOwner.currentAttempted && beforeOwner.currentValidated
	beforeOwner.mu.Unlock()
	afterOwner.mu.Lock()
	afterSnapshot, afterValidation := afterOwner.snapshot, afterOwner.validation
	afterValid := !afterOwner.processing && afterOwner.currentAttempted && afterOwner.currentValidated
	afterOwner.mu.Unlock()
	if !beforeValid || !afterValid || beforeSnapshot == nil || beforeSnapshot.document == nil || beforeValidation == nil ||
		afterSnapshot == nil || afterSnapshot.document == nil || afterValidation == nil {
		return false, ErrHTMLSendWorkV1
	}
	before, after := beforeSnapshot.document, afterSnapshot.document
	if before.SourceKind != "pdf" || after.SourceKind != "pdf" || before.IsEnvelope || after.IsEnvelope ||
		before.ParentEnvelopeID.Valid || after.ParentEnvelopeID.Valid || before.DeletedAt.Valid || after.DeletedAt.Valid ||
		!beforeValidation.MatchesDocumentV1(before) || !afterValidation.MatchesDocumentV1(after) {
		return false, ErrHTMLSendWorkV1
	}
	if err := call.Err(); err != nil {
		return false, err
	}
	if bytes.Equal(before.VariablesJson, after.VariablesJson) && (before.VariablesJson == nil) == (after.VariablesJson == nil) {
		return htmlSendPackageSourceVerdictV1(call, source, candidate, afterValidation.MatchesDocumentV1(before))
	}
	// Missing/empty raw bytes and JSON null must not become an object through
	// ParseVariableValues' legacy empty-input convenience. Real JSON objects
	// alone qualify for the spelling exception; no caller raw value is adopted.
	beforeRaw, afterRaw := bytes.TrimSpace(before.VariablesJson), bytes.TrimSpace(after.VariablesJson)
	if len(beforeRaw) == 0 || beforeRaw[0] != '{' || len(afterRaw) == 0 || afterRaw[0] != '{' {
		return false, nil
	}
	cost, err := htmlSendPackageSourceComparisonLogicalV1(int64(len(beforeRaw)), int64(len(afterRaw)))
	if err != nil {
		return false, err
	}
	// One actual candidate-owner loan grows BEFORE either strict parse or the
	// temporary Document tuple. Both source borrowers stay active until return.
	// These are serialized CPU scratch components, never new SQL authority.
	if err = afterOwner.holdV1(htmlRevisionSourcePrepareV1, cost, 0); err != nil {
		return false, err
	}
	beforeValues, err := blocks.ParseVariableValues(beforeRaw)
	if err != nil {
		return false, nil
	}
	afterValues, err := blocks.ParseVariableValues(afterRaw)
	if err != nil || !maps.Equal(beforeValues, afterValues) {
		return false, nil
	}
	if err = call.Err(); err != nil {
		return false, err
	}
	// Only this stack view aliases the genuine candidate Vars spelling. The
	// unchanged all81-field matcher still binds every OTHER field exactly.
	comparison := *before
	comparison.VariablesJson = after.VariablesJson
	return htmlSendPackageSourceVerdictV1(call, source, candidate, afterValidation.MatchesDocumentV1(&comparison))
}

func htmlSendPackageSourceComparisonLogicalV1(before, after int64) (int64, error) {
	if before < 0 || after < 0 {
		return 0, ErrHTMLSendWorkV1
	}
	n := int64(unsafe.Sizeof(generated.Document{})) + 8*int64(unsafe.Sizeof(map[string]string(nil))) + 4*int64(unsafe.Sizeof([]byte(nil)))
	for _, raw := range [2]int64{before, after} {
		// Each ParseVariableValues performs RawMessage-object then exact-string
		// decoding. Price both live maps, raw/value/error buffers, and even a
		// rejected nested prefix up to encoding/json's original10000-depth gate.
		part, err := htmlSendResolverParseDepthLogicalV1(raw, 2, min(raw, 10000)+1)
		if err != nil || htmlSendResolverAddV1(&n, 1, part) != nil || htmlSendResolverAddV1(&n, raw, 8) != nil {
			return 0, ErrHTMLSendWorkV1
		}
	}
	return n, nil
}

// Called only while BOTH registered policy frames and original owner borrowers
// remain held. Close may cancel a source's private context while call stays
// live; a true verdict therefore rechecks actual registration and BOTH contexts.
func htmlSendPackageSourceVerdictV1(call context.Context, source, candidate *applicationHTMLSendSourceStateV1, matches bool) (bool, error) {
	if !matches {
		return false, nil
	}
	if source == nil || candidate == nil || source.closeRequested.Load() || candidate.closeRequested.Load() ||
		source.owner == nil || candidate.owner == nil || source.owner.binding == nil || candidate.owner.binding == nil ||
		!applicationContextV1(source.owner.binding.ctx) || !applicationContextV1(candidate.owner.binding.ctx) {
		return false, ErrHTMLSendWorkV1
	}
	w := source.work
	if w == nil || w.self != w || candidate.work != w {
		return false, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	valid := w.valid(call) && !w.resourcesClosed && w.familyRoot == nil && w.stage != nil && w.stage.purpose == HTMLSendAdmissionV1 &&
		w.stage.work == w && w.stage.session == w.session && w.sourceState == source && w.sourceOwner == source.owner &&
		w.resolvedState == candidate && w.resolvedOwner == candidate.owner && w.packageInitialSelectionChecked &&
		w.reviewedOriginalValidated && w.reviewedCandidateValidated
	w.mu.Unlock()
	if !valid {
		return false, ErrHTMLSendWorkV1
	}
	if err := call.Err(); err != nil {
		return false, err
	}
	if source.closeRequested.Load() || candidate.closeRequested.Load() ||
		!applicationContextV1(source.owner.binding.ctx) || !applicationContextV1(candidate.owner.binding.ctx) {
		return false, ErrHTMLSendWorkV1
	}
	return true, nil
}
