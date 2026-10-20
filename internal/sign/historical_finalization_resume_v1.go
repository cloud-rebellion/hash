// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

type ownedHistoricalFinalizationResumeV1 struct {
	operation          *ownedBlocksSignatureOperationV1
	document           *generated.Document
	evidence           *pdfadmission.ApplicationHistoricalFinalizationEvidenceV1
	evidenceFailure    error
	publication        *pdfadmission.ApplicationHistoricalFinalizationPublicationReferenceV1
	publicationFailure error
	frozenFailure      error
}

func (o *ownedHistoricalFinalizationResumeV1) closeV1() {
	if o != nil && o.operation != nil {
		_ = o.operation.closeV1()
	}
}

// Only the actual initial-claim operation from this same finalizer may retire.
// A genuine new native root is already the caller's replacement local view;
// the old renderer/certificate/source consumers returned before entering resume.
// This closes no global/neighbor operation and infers no physical retirement.
func (o *ownedHistoricalFinalizationClaimV1) retireAtResumeV1(e *Engine, doc *generated.Document, next *ownedHistoricalFinalizationResumeV1) error {
	if o == nil || o.operation == nil || e == nil || e.WorkRuntime == nil || next == nil || next.operation == nil || next.document == nil || next.document != doc || next.operation == o.operation || o.operation.factory != e.WorkRuntime.SessionsV1() || next.operation.factory != o.operation.factory || doc.ID != o.document || doc.OrgID != o.org {
		return ErrSigningAdmissionUnavailableV1
	}
	return o.operation.closeV1()
}

// Actual intent metadata/body precedes source JSON/current policy expansion,
// preserving the original missing-intent decision. Every recovery caller then
// rechecks original historical admission, signing-page, parties/mode/readiness
// and chronological completion commitments under this same actual parent lock.
func (e *Engine) loadHistoricalFinalizationResumeOwnedV1(ctx context.Context, org, document uuid.UUID, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) (doc *generated.Document, intent *generated.DocumentFinalizationIntent, owner *ownedHistoricalFinalizationResumeV1, failure error) {
	if e == nil || ctx == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, nil, nil, ErrSigningAdmissionUnavailableV1
	}
	factory := e.WorkRuntime.SessionsV1()
	native, err := factory.NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return nil, nil, nil, blockSignatureFailureV1(err)
	}
	operation := &ownedBlocksSignatureOperationV1{native: native, factory: factory, original: ctx}
	var evidence *pdfadmission.ApplicationHistoricalFinalizationEvidenceV1
	var publication *pdfadmission.ApplicationHistoricalFinalizationPublicationReferenceV1
	var evidenceFailure, publicationFailure, frozenFailure error
	keep := false
	defer func() {
		if !keep {
			failure = errors.Join(failure, operation.closeV1())
		}
		failure = blockSignatureFailureV1(failure)
	}()
	err = operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationResumeV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return fmt.Errorf("resume finalization: load intent: %w", err)
		}
		row, err := w.ReadHistoricalFinalizationIntentV1(call)
		if err != nil {
			return fmt.Errorf("resume finalization: load intent: %w", err)
		}
		intent = row
		models, err := w.ReadModelsV1(call)
		if err != nil {
			return fmt.Errorf("claim finalization: lock document: %w", err)
		}
		locked := models.Document
		if err = requireHistoricalSigningAdmissionV1(locked); err != nil {
			return err
		}
		if err = w.ValidateHistoricalFinalizationSigningPageV1(call); err != nil {
			return err
		}
		if locked.Status != "finalizing" {
			return ErrDocumentRevisedDuringFinalize
		}
		parties, err := validateHistoricalFinalizationModeOwnedV1(call, w, locked, intent.Mode)
		if err != nil {
			return err
		}
		if parties != 0 {
			if err = e.historicalFinalizationReadinessOwnedV1(call, w, intent.Mode); err != nil {
				return err
			}
		}
		if !locked.CompletionEffectiveAtBound {
			return errors.New("claim finalization: completion-effective timestamp is not bound")
		}
		if _, err = canonicalCompletionEffectiveAt(locked.CompletionEffectiveAt); err != nil {
			return fmt.Errorf("claim finalization: %w", err)
		}
		if _, err = finalizationRetentionDeadline(locked); err != nil {
			return fmt.Errorf("claim finalization: %w", err)
		}
		doc = locked
		// Prepare only the genuine already-pinned metadata under this SAME native
		// callback. Surface constructor failures at the original later evidence gate,
		// after the original frozen-source/compatibility/intent policy decisions.
		if reference != nil && intent.EvidenceVersionPinsRequired {
			client, ok := e.Storage.(*storage.Client)
			if !ok || client == nil {
				evidenceFailure = errors.New("resume finalization: concrete evidence storage unavailable")
			} else {
				evidence, evidenceFailure = w.NewHistoricalFinalizationEvidenceV1(call, client)
			}
		}
		// The exact full intent witness is independently funded for pinned AND
		// legacy intents before any old Resume body/source can retire.
		if reference != nil {
			publication, publicationFailure = w.NewHistoricalPublicationReferenceV1(call, reference)
		}
		frozenFailure = w.ValidateHistoricalFinalizationFrozenFamilyV1(call)
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	owner = &ownedHistoricalFinalizationResumeV1{operation: operation, document: doc, evidence: evidence, evidenceFailure: evidenceFailure, publication: publication, publicationFailure: publicationFailure, frozenFailure: frozenFailure}
	keep = true
	return doc, intent, owner, nil
}
