// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"strings"
	"unsafe"
)

// This is the original frozenBlockDocument projection and immutable evidence
// decision at Resume's old policy point. Both JSON/decimal projections run on
// the genuine private source and its actual CPU/body grant.
func (h *ApplicationHTMLSendSourceV1) validateHistoricalFrozenBlocksV1() error {
	if h == nil || h.state == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	s := h.state
	if !s.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if err := s.owner.beginV1(); err != nil {
		return err
	}
	defer s.owner.finishV1()
	if err := s.blockSigningValuesV1(); err != nil {
		return err
	}
	return blocks.ValidateImmutableSigningEvidence(s.blockTree)
}
func (w *ApplicationHTMLSendWorkV1) ValidateHistoricalFinalizationFrozenFamilyV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.stage.purpose != HTMLHistoricalFinalizationResumeV1 || w.sourceDocument == nil {
		w.mu.Unlock()
		return ErrHistoricalFinalizationSourceV1
	}
	d := w.sourceDocument
	w.mu.Unlock()
	if !d.IsEnvelope {
		if d.SourceKind != "blocks" {
			return w.ValidateHistoricalFinalizationSigningPageV1(call)
		}
		source, err := w.historicalFinalizationSourceV1(call)
		if err != nil {
			return err
		}
		return source.validateHistoricalFrozenBlocksV1()
	}
	children, err := w.HistoricalFinalizationMembersV1(call)
	if err != nil {
		return fmt.Errorf("validate frozen evidence: list envelope children: %w", err)
	}
	if len(children) == 0 {
		return errors.New("validate frozen evidence: envelope has no children")
	}
	for index, child := range children {
		if child == nil {
			return fmt.Errorf("validate frozen evidence: child %d is nil", index+1)
		}
		if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != d.ID {
			return fmt.Errorf("validate frozen evidence: child %s is not attached", child.ID)
		}
		if !historicalSourceChildStatusMatchesV1(d.Status, child.Status) {
			return fmt.Errorf("validate frozen evidence: child %s status %s does not match envelope status %s", child.ID, child.Status, d.Status)
		}
		if child.SourceKind != "blocks" {
			return fmt.Errorf("validate frozen evidence: child %s: frozen blocks document required", child.ID)
		}
		member := w.EnvelopeMemberForAuditV1(call, child.ID)
		if member == nil {
			return ErrHistoricalFinalizationSourceV1
		}
		source, err := member.historicalFinalizationSourceV1(call)
		if err == nil {
			err = source.validateHistoricalFrozenBlocksV1()
		}
		if err != nil {
			return fmt.Errorf("validate frozen evidence: child %s: %w", child.ID, err)
		}
	}
	return nil
}

// The previous private checked source, genuine fresh scalar State and actual
// same-operation registered Work supply an independently funded private/public
// source clone. No caller source/row/pin/success flag establishes provenance.
// The predecessor can retire only after this actual successor is acknowledged;
// normal render/family continuations retain their separate original body loans.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) NewHistoricalIntentContinuationV1(call context.Context, w *ApplicationHTMLSendWorkV1) (*generated.Document, *ApplicationHistoricalFinalizationSourceEvidenceV1, error) {
	return e.newHistoricalPrivateIntentContinuationV1(call, w)
}

func historicalSourceWorkCommittedV1(w *ApplicationHTMLSendWorkV1) bool {
	if w == nil || w.self != w || w.stage == nil || w.stage.operation == nil || w.session == nil || w.session.state == nil {
		return false
	}
	op := w.stage.operation
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.closed || op.original == nil || op.original.Err() != nil || w.stage.active || w.stage.opening || !w.stage.used {
		return false
	}
	session := w.session.state
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.ended && session.commitAttempted && !session.commitUnknown && !session.callbackActive && !session.sqlActive && session.active == 0
}

// Resume's child-version compatibility views have ended. Close only that
// exact acknowledged family Work/member consumers before fresh retention
// inventory is admitted. Normal rendering keeps its family until PDF last use.
func (f *ApplicationHistoricalFinalizationSourceFamilyV1) RetireVersionConsumersV1() error {
	if f == nil || f.self != f || f.work == nil || !historicalSourceWorkCommittedV1(f.work) {
		return ErrHistoricalFinalizationSourceV1
	}
	for _, member := range f.members {
		e := member.evidence
		if e == nil || e.self != e {
			return ErrHistoricalFinalizationSourceV1
		}
		if !e.lockV1() {
			return ErrHistoricalFinalizationSourceV1
		}
		valid := e.validV1() && e.sourceChecked && (!e.document.RequiresSignature || e.signaturesChecked) && e.bodyBorrowers == 0
		e.unlockV1()
		if !valid {
			return ErrHistoricalFinalizationSourceV1
		}
	}
	w := f.work
	f.views = nil
	f.members = nil
	f.work = nil
	w.CloseConsumerV1()
	return nil
}

// Every generated column is protected, including checkpoint/failure/fitted state.
// Nullable timestamps compare as database instants rather than Go locations.
func historicalIntentExactRowV1(a, b *generated.DocumentFinalizationIntent) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.DocumentID == b.DocumentID && a.OrgID == b.OrgID && a.Mode == b.Mode &&
		a.FinalPdfKey == b.FinalPdfKey && bytes.Equal(a.FinalPdfSha256, b.FinalPdfSha256) && a.FinalPdfVersionID == b.FinalPdfVersionID &&
		a.AuditCertKey == b.AuditCertKey && bytes.Equal(a.AuditCertSha256, b.AuditCertSha256) && a.AuditCertVersionID == b.AuditCertVersionID &&
		a.AuditPayloadKey == b.AuditPayloadKey && bytes.Equal(a.AuditPayloadSha256, b.AuditPayloadSha256) && a.AuditPayloadVersionID == b.AuditPayloadVersionID &&
		a.AuditSignatureKey == b.AuditSignatureKey && bytes.Equal(a.AuditSignatureSha256, b.AuditSignatureSha256) && a.AuditSignatureVersionID == b.AuditSignatureVersionID &&
		a.EvidenceVersionPinsRequired == b.EvidenceVersionPinsRequired && historicalIntentClockEqualV1(a.RetentionStartedAt, b.RetentionStartedAt) && historicalIntentClockEqualV1(a.RetentionCompletedAt, b.RetentionCompletedAt) &&
		a.Attempts == b.Attempts && a.LastError == b.LastError && historicalIntentClockEqualV1(a.CreatedAt, b.CreatedAt) && historicalIntentClockEqualV1(a.UpdatedAt, b.UpdatedAt) &&
		historicalIntentClockEqualV1(a.CompletionEffectiveAt, b.CompletionEffectiveAt) && historicalIntentClockEqualV1(a.RetainUntil, b.RetainUntil) &&
		a.FittedPreparationID == b.FittedPreparationID && a.FitsIndexStorageKey == b.FitsIndexStorageKey && a.FitsIndexVersionID == b.FitsIndexVersionID && bytes.Equal(a.FitsIndexSha256, b.FitsIndexSha256) && a.FitsIndexBytes == b.FitsIndexBytes
}
func historicalDetachedIntentV1(intent *generated.DocumentFinalizationIntent) *generated.DocumentFinalizationIntent {
	copy := historicalFinalizationCloneIntentV1(intent)
	copy.Mode = strings.Clone(intent.Mode)
	copy.FinalPdfKey = strings.Clone(intent.FinalPdfKey)
	copy.FinalPdfVersionID.String = strings.Clone(intent.FinalPdfVersionID.String)
	copy.AuditCertKey = strings.Clone(intent.AuditCertKey)
	copy.AuditCertVersionID.String = strings.Clone(intent.AuditCertVersionID.String)
	copy.AuditPayloadKey = strings.Clone(intent.AuditPayloadKey)
	copy.AuditPayloadVersionID.String = strings.Clone(intent.AuditPayloadVersionID.String)
	copy.AuditSignatureKey = strings.Clone(intent.AuditSignatureKey)
	copy.AuditSignatureVersionID.String = strings.Clone(intent.AuditSignatureVersionID.String)
	copy.FitsIndexStorageKey.String = strings.Clone(intent.FitsIndexStorageKey.String)
	copy.FitsIndexVersionID.String = strings.Clone(intent.FitsIndexVersionID.String)
	copy.LastError.String = strings.Clone(intent.LastError.String)
	return copy
}

// Only acknowledged real Source24 SQL may advance the independent advisory
// witness after its genuine four-pin CAS/reload. A caller intent, matching hash
// or reported commit cannot replace private before/after rows or old debt.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) ConfirmHistoricalPublicationIntentV1(reference *ApplicationHistoricalFinalizationStageReferenceV1) (*ApplicationHistoricalFinalizationPublicationReferenceV1, error) {
	if e == nil || e.self != e || reference == nil {
		return nil, ErrHistoricalFinalizationLockV1
	}
	if !e.lockV1() {
		return nil, ErrHistoricalFinalizationLockV1
	}
	defer e.unlockV1()
	if !e.validV1() || !e.intentVersionsAttempted || e.intentVersionOriginal == nil || !historicalLegacyIntentHasPinsV1(e.intentVersionPinned) || !historicalSourceWorkCommittedV1(e.work) {
		return nil, ErrHistoricalFinalizationLockV1
	}
	w := e.work
	owner, err := reference.ownerV1(w.stage.operation.factory)
	if err != nil {
		return nil, err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	before, pinned := e.intentVersionOriginal, e.intentVersionPinned
	if owner.closed || !owner.acquired || !owner.stagePrepared || owner.publicationGrant == nil || owner.publicationIntent == nil || before.DocumentID != owner.document || before.OrgID != owner.org || !historicalFinalizationStageCommitmentMatchesV1(owner.stageCommitment, e.document) || !historicalIntentExactRowV1(owner.publicationIntent, before) {
		return nil, ErrHistoricalFinalizationLockV1
	}
	if before.EvidenceVersionPinsRequired {
		if !historicalIntentExactRowV1(before, pinned) {
			return nil, ErrHistoricalFinalizationLockV1
		}
		return &owner.publicationReference, nil
	}
	versions := [4]string{pinned.FinalPdfVersionID.String, pinned.AuditCertVersionID.String, pinned.AuditPayloadVersionID.String, pinned.AuditSignatureVersionID.String}
	if before.FinalPdfVersionID.Valid || before.AuditCertVersionID.Valid || before.AuditPayloadVersionID.Valid || before.AuditSignatureVersionID.Valid || !historicalLegacyIntentPinTupleV1(before, pinned, versions) {
		return nil, ErrHistoricalFinalizationLockV1
	}
	raw, err := historicalFinalizationIntentRawV1(pinned)
	if err != nil {
		return nil, err
	}
	fixed := 4*int64(unsafe.Sizeof(generated.DocumentFinalizationIntent{})) + 4*int64(unsafe.Sizeof(workguard.GrantV1{})) + 8*int64(unsafe.Sizeof(uintptr(0)))
	resources, err := htmlAuthoringSumV1(fixed, raw)
	if err != nil || resources > int64(^uint64(0)>>1)/8 {
		return nil, ErrHistoricalFinalizationLockV1
	}
	factory := owner.factory.state
	factory.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !factory.closing && factory.work != nil {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if coordinator == nil {
		return nil, ErrHistoricalFinalizationLockV1
	}
	grant, err := coordinator.TryAcquireV1(w.stage.operation.original, owner.org, workguard.VectorV1{ParentBytes: 8 * resources})
	if err != nil {
		return nil, err
	}
	copy := historicalDetachedIntentV1(pinned)
	if w.stage.operation.original.Err() != nil {
		copy = nil
		grant.Close()
		return nil, ErrHistoricalFinalizationLockV1
	}
	previous := owner.publicationGrant
	owner.publicationIntent = copy
	owner.publicationGrant = grant
	before = nil
	pinned = nil
	previous.Close()
	return &owner.publicationReference, nil
}

// The post-compatibility Resume policy returned only a scalar party count and
// mode decision. Its actual CPU/tree/validation consumer has ended; retain the
// Work's independently owned document/intent/evidence/root loan for subsequent
// artifact verification and retention. Closing this source grants no policy
// success or SQL authority, and later reuse of its closed cache must refuse.
// The adapter calls this only after its original mode decision succeeds; an
// error keeps the CPU/error owner through the original response last use.
func (w *ApplicationHTMLSendWorkV1) RetireHistoricalFinalizationModeConsumerV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLHistoricalFinalizationSourceV1 || w.familyRoot != nil ||
		w.finalization == nil || !w.finalization.intentRead || w.finalization.intent == nil || w.finalization.source == nil ||
		w.sourceState == nil || w.finalization.source.state != w.sourceState || w.historicalSourceEvidence == nil {
		w.mu.Unlock()
		return ErrHistoricalFinalizationSourceV1
	}
	evidence, state := w.historicalSourceEvidence, w.sourceState
	w.mu.Unlock()
	if !evidence.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	valid := evidence.validV1() && evidence.work == w && evidence.sourceChecked
	evidence.unlockV1()
	if !valid {
		return ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	valid = w.valid(call) && w.historicalSourceEvidence == evidence && w.sourceState == state && w.finalization != nil &&
		w.finalization.source != nil && w.finalization.source.state == state && state.work == w && state.owner != nil &&
		state.owner.purpose == htmlSendSourcePurposeV1 && state.owner.binding != nil && state.owner.binding.session == w.session &&
		state.owner.binding.factory == w.session.state.factory && state.owner.binding.org == w.session.state.org &&
		state.owner.binding.document == w.logicalDocumentV1()
	w.mu.Unlock()
	if !valid {
		return ErrHistoricalFinalizationSourceV1
	}
	// Original Close runs outside both native Work/evidence locks. Its active
	// CPU borrower and joined-close handshake remain the sole loan retirement.
	state.closeV1()
	return nil
}
