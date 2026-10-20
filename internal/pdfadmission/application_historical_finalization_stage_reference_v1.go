// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This handle names only the immutable scalar commitment of an acknowledged
// native Claim. Its storage is part of the already-admitted actual advisory
// lock owner, whose sizeof is priced before allocation. It retains no source,
// recipient, field, policy tree, SQL row or old Claim operation. A caller row
// cannot construct or replace this reference.
type ApplicationHistoricalFinalizationStageReferenceV1 struct {
	owner *applicationHistoricalFinalizationLockStateV1
}
type applicationHistoricalFinalizationStageCommitmentV1 struct {
	completion, retain pgtype.Timestamptz
	requiresSignature  bool
}

func historicalFinalizationStageCommitmentV1(doc *generated.Document) (applicationHistoricalFinalizationStageCommitmentV1, bool) {
	if doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || doc.Status != "finalizing" || !doc.CompletionEffectiveAtBound || !doc.CompletionEffectiveAt.Valid || doc.CompletionEffectiveAt.InfinityModifier != pgtype.Finite || doc.CompletionEffectiveAt.Time.IsZero() || !doc.FinalizationRetainUntil.Valid || doc.FinalizationRetainUntil.InfinityModifier != pgtype.Finite || doc.FinalizationRetainUntil.Time.IsZero() {
		return applicationHistoricalFinalizationStageCommitmentV1{}, false
	}
	// UTC strips a source time.Location reference; the long-lived owner retains
	// only these fixed scalar instants and one mode bit.
	return applicationHistoricalFinalizationStageCommitmentV1{completion: pgtype.Timestamptz{Time: doc.CompletionEffectiveAt.Time.UTC(), Valid: true}, retain: pgtype.Timestamptz{Time: doc.FinalizationRetainUntil.Time.UTC(), Valid: true}, requiresSignature: doc.RequiresSignature}, true
}
func historicalFinalizationStageCommitmentMatchesV1(want applicationHistoricalFinalizationStageCommitmentV1, doc *generated.Document) bool {
	actual, ok := historicalFinalizationStageCommitmentV1(doc)
	return ok && actual.requiresSignature == want.requiresSignature && actual.completion.Time.Equal(want.completion.Time) && actual.retain.Time.Equal(want.retain.Time)
}

// The actual native operation must have exactly one completed Claim callback,
// an acknowledged COMMIT and its still-live private original/returned row. No
// caller-supplied model, completion time, size or success boolean is accepted.
func (h *ApplicationHistoricalFinalizationLockV1) NewStageReferenceV1(ctx context.Context, operation *ApplicationHTMLSendOperationV1) (*ApplicationHistoricalFinalizationStageReferenceV1, error) {
	if h == nil || h.state == nil || operation == nil || operation.self != operation || !applicationContextV1(ctx) {
		return nil, ErrHistoricalFinalizationLockV1
	}
	if err := h.VerifyV1(ctx); err != nil {
		return nil, err
	}
	owner := h.state
	owner.mu.Lock()
	defer owner.mu.Unlock()
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if owner.self != owner || owner.closed || !owner.acquired || owner.stagePrepared || owner.factory == nil || owner.factory != operation.factory || operation.closed || operation.original == nil || operation.original.Err() != nil || operation.org != owner.org || operation.document != owner.document || len(operation.stages) != 1 {
		return nil, ErrHistoricalFinalizationLockV1
	}
	stage := operation.stages[0]
	if stage == nil || stage.self != stage || stage.operation != operation || stage.purpose != HTMLHistoricalFinalizationClaimV1 || stage.opening || stage.active || !stage.used || stage.work == nil || stage.session == nil || stage.session.state == nil {
		return nil, ErrHistoricalFinalizationLockV1
	}
	work := stage.work
	work.mu.Lock()
	defer work.mu.Unlock()
	if work.self != work || work.closed || work.resourcesClosed || work.stage != stage || work.session != stage.session || work.familyRoot != nil || work.finalization == nil {
		return nil, ErrHistoricalFinalizationLockV1
	}
	session := stage.session.state
	session.mu.Lock()
	committed := session.factory == owner.factory.state && session.org == owner.org && session.document == owner.document && session.ended && session.commitAttempted && !session.commitUnknown && !session.callbackActive && !session.sqlActive && session.active == 0
	session.mu.Unlock()
	if !committed {
		return nil, ErrHistoricalFinalizationLockV1
	}
	doc := work.finalization.claimed
	if doc == nil {
		doc = work.sourceDocument
	}
	if doc == nil || doc.ID != owner.document || doc.OrgID != owner.org {
		return nil, ErrHistoricalFinalizationLockV1
	}
	commitment, ok := historicalFinalizationStageCommitmentV1(doc)
	if !ok {
		return nil, ErrHistoricalFinalizationLockV1
	}
	owner.stageCommitment = commitment
	owner.stageReference.owner = owner
	owner.stagePrepared = true
	return &owner.stageReference, nil
}

func (r *ApplicationHistoricalFinalizationStageReferenceV1) ownerV1(factory *ApplicationSessionFactoryV1) (*applicationHistoricalFinalizationLockStateV1, error) {
	if r == nil || r.owner == nil || factory == nil || factory.state == nil {
		return nil, ErrHistoricalFinalizationLockV1
	}
	owner := r.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.self != owner || r != &owner.stageReference || owner.closed || !owner.acquired || !owner.stagePrepared || owner.factory != factory || owner.org == uuid.Nil || owner.document == uuid.Nil {
		return nil, ErrHistoricalFinalizationLockV1
	}
	return owner, nil
}

// Rechecks the original actual advisory backend, never a caller lock boolean.
func (r *ApplicationHistoricalFinalizationStageReferenceV1) ScopeV1(ctx context.Context, factory *ApplicationSessionFactoryV1) (uuid.UUID, uuid.UUID, error) {
	owner, err := r.ownerV1(factory)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	lock := &ApplicationHistoricalFinalizationLockV1{state: owner}
	if err = lock.VerifyV1(ctx); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || !owner.stagePrepared || r != &owner.stageReference {
		return uuid.Nil, uuid.Nil, ErrHistoricalFinalizationLockV1
	}
	return owner.org, owner.document, nil
}
func (r *ApplicationHistoricalFinalizationStageReferenceV1) MatchesDocumentV1(ctx context.Context, factory *ApplicationSessionFactoryV1, doc *generated.Document) error {
	org, document, err := r.ScopeV1(ctx, factory)
	if err != nil {
		return err
	}
	owner := r.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || !owner.stagePrepared || doc == nil || doc.OrgID != org || doc.ID != document || !historicalFinalizationStageCommitmentMatchesV1(owner.stageCommitment, doc) {
		return ErrHistoricalFinalizationLockV1
	}
	return nil
}

// At the new Stage's original fresh locked-model gate, compare only the exact
// Claim commitment carried by the genuine serialization owner. All source and
// party validation continues against this new Work's actual native rows.
func (w *ApplicationHTMLSendWorkV1) ValidateHistoricalFinalizationStageReferenceV1(call context.Context, reference *ApplicationHistoricalFinalizationStageReferenceV1) error {
	if w == nil || w.self != w || reference == nil || w.stage == nil || w.stage.operation == nil {
		return ErrHTMLSendWorkV1
	}
	factory := w.stage.operation.factory
	owner, err := reference.ownerV1(factory)
	if err != nil {
		return err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if owner.closed || !owner.stagePrepared || !w.valid(call) || w.stage.purpose != HTMLHistoricalFinalizationStageV1 || w.familyRoot != nil || w.sourceDocument == nil || w.sourceDocument.OrgID != owner.org || w.sourceDocument.ID != owner.document || !historicalFinalizationStageCommitmentMatchesV1(owner.stageCommitment, w.sourceDocument) {
		return ErrHTMLSendWorkV1
	}
	return nil
}
