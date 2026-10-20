// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"strings"
	"unsafe"
)

// Exact private intent strings/digests are copied under their own same-org
// Parent-only grant before the old SQL/source owner ends. No new database
// staging is charged because this operation copies already-owned native data.
// The actual serialization owner retains/clears this one fixed-purpose slot;
// it is not caller-constructed row, reported size, hash substitute or pool proof.
type ApplicationHistoricalFinalizationPublicationReferenceV1 struct {
	owner *applicationHistoricalFinalizationLockStateV1
}

func (w *ApplicationHTMLSendWorkV1) NewHistoricalPublicationReferenceV1(call context.Context, reference *ApplicationHistoricalFinalizationStageReferenceV1) (*ApplicationHistoricalFinalizationPublicationReferenceV1, error) {
	if w == nil || w.self != w || reference == nil || w.stage == nil || w.stage.operation == nil {
		return nil, ErrHistoricalFinalizationLockV1
	}
	owner, err := reference.ownerV1(w.stage.operation.factory)
	if err != nil {
		return nil, err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if owner.closed || !owner.stagePrepared || owner.publicationIntent != nil || owner.publicationGrant != nil || !w.valid(call) || w.stage.purpose != HTMLHistoricalFinalizationResumeV1 || w.familyRoot != nil || w.sourceDocument == nil || w.finalization == nil || !w.finalization.intentRead || w.finalization.intent == nil || w.sourceDocument.ID != owner.document || w.sourceDocument.OrgID != owner.org || !historicalFinalizationStageCommitmentMatchesV1(owner.stageCommitment, w.sourceDocument) {
		return nil, ErrHistoricalFinalizationLockV1
	}
	intent := w.finalization.intent
	if intent.DocumentID != owner.document || intent.OrgID != owner.org {
		return nil, ErrHistoricalFinalizationLockV1
	}
	raw, err := historicalFinalizationIntentRawV1(intent)
	if err != nil {
		return nil, err
	}
	fixed := 4*int64(unsafe.Sizeof(generated.DocumentFinalizationIntent{})) + 4*int64(unsafe.Sizeof(workguard.GrantV1{})) + 8*int64(unsafe.Sizeof(uintptr(0)))
	resources, err := htmlAuthoringSumV1(fixed, raw)
	if err != nil || resources > (int64(^uint64(0)>>1))/8 {
		return nil, ErrHistoricalFinalizationLockV1
	}
	factory := owner.factory.state
	factory.mu.Lock()
	available := !factory.closing && factory.work != nil && factory.work.coordinator != nil
	var coordinator *workguard.CoordinatorV1
	if available {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if !available {
		return nil, ErrHistoricalFinalizationLockV1
	}
	grant, err := coordinator.TryAcquireV1(w.stage.operation.original, owner.org, workguard.VectorV1{ParentBytes: 8 * resources})
	if err != nil {
		return nil, err
	}
	// All retained variable fields detach from the retiring driver/private row.
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
	if call.Err() != nil {
		grant.Close()
		return nil, ErrHistoricalFinalizationLockV1
	}
	owner.publicationIntent = copy
	owner.publicationGrant = grant
	owner.publicationReference.owner = owner
	return &owner.publicationReference, nil
}
func (r *ApplicationHistoricalFinalizationPublicationReferenceV1) ScopeV1(ctx context.Context, factory *ApplicationSessionFactoryV1) (uuid.UUID, uuid.UUID, error) {
	if r == nil || r.owner == nil || factory == nil {
		return uuid.Nil, uuid.Nil, ErrHistoricalFinalizationLockV1
	}
	owner := r.owner
	owner.mu.Lock()
	valid := owner.self == owner && !owner.closed && owner.acquired && owner.factory == factory && r == &owner.publicationReference && owner.publicationIntent != nil && owner.publicationGrant != nil
	owner.mu.Unlock()
	if !valid {
		return uuid.Nil, uuid.Nil, ErrHistoricalFinalizationLockV1
	}
	lock := &ApplicationHistoricalFinalizationLockV1{state: owner}
	if err := lock.VerifyV1(ctx); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.publicationIntent == nil || owner.publicationGrant == nil {
		return uuid.Nil, uuid.Nil, ErrHistoricalFinalizationLockV1
	}
	return owner.org, owner.document, nil
}
func (r *ApplicationHistoricalFinalizationPublicationReferenceV1) MatchesIntentV1(actual *generated.DocumentFinalizationIntent) bool {
	if r == nil || r.owner == nil {
		return false
	}
	owner := r.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.self == owner && !owner.closed && r == &owner.publicationReference && owner.publicationGrant != nil && historicalFinalizationSameIntentV1(owner.publicationIntent, actual)
}
