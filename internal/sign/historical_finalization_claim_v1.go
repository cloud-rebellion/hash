// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Owns the actual claim's old/new source views until its outer finalizer's last
// consumer finishes. Closing SQL or returning one model never credits it early.
type ownedHistoricalFinalizationClaimV1 struct {
	operation     *ownedBlocksSignatureOperationV1
	org, document uuid.UUID
}

func (h *ownedHistoricalFinalizationClaimV1) closeV1() {
	if h != nil && h.operation != nil {
		_ = h.operation.closeV1()
	}
}
func validateHistoricalFinalizationModeOwnedV1(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1, doc *generated.Document, mode string) (int, error) {
	parties, err := w.HistoricalFinalizationPartiesV1(call)
	if err != nil {
		return 0, err
	}
	switch mode {
	case "signature":
		if !doc.RequiresSignature {
			return 0, ErrNotAcknowledgement
		}
	case "acknowledgement":
		if doc.RequiresSignature {
			return 0, ErrNotAcknowledgement
		}
	default:
		return 0, errors.New("finalization: invalid mode")
	}
	return len(parties), nil
}
func (e *Engine) historicalFinalizationReadinessOwnedV1(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1, mode string) error {
	if _, err := w.ReadRecipientsV1(call); err != nil {
		return fmt.Errorf("finalization: list recipients: %w", err)
	}
	if mode == "signature" {
		if _, err := w.HistoricalFinalizationRolesV1(call); err != nil {
			return err
		}
	}
	if err := w.ValidateHistoricalFinalizationReadinessV1(call, mode); err != nil {
		if errors.Is(err, pdfadmission.ErrHistoricalFinalizationNotReadyV1) {
			return fmt.Errorf("%w: %v", ErrDocumentNotReadyToFinalize, err)
		}
		return err
	}
	return nil
}
func (e *Engine) claimHistoricalFinalizingOwnedV1(ctx context.Context, org, document uuid.UUID, mode string) (claimed *generated.Document, owner *ownedHistoricalFinalizationClaimV1, failure error) {
	if e == nil || ctx == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, nil, ErrSigningAdmissionUnavailableV1
	}
	native, err := e.WorkRuntime.SessionsV1().NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return nil, nil, blockSignatureFailureV1(err)
	}
	operation := &ownedBlocksSignatureOperationV1{native: native, factory: e.WorkRuntime.SessionsV1(), original: ctx}
	keep := false
	defer func() {
		if !keep {
			failure = errors.Join(failure, operation.closeV1())
		}
		failure = blockSignatureFailureV1(failure)
	}()
	err = operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationClaimV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return fmt.Errorf("claim finalization: lock document: %w", err)
		}
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
		if locked.Status == "finalizing" {
			parties, err := validateHistoricalFinalizationModeOwnedV1(call, w, locked, mode)
			if err != nil {
				return err
			}
			if parties != 0 {
				if err = e.historicalFinalizationReadinessOwnedV1(call, w, mode); err != nil {
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
			claimed = locked
			return nil
		}
		if locked.Status != "in_progress" {
			return ErrDocumentRevisedDuringFinalize
		}
		if _, err = validateHistoricalFinalizationModeOwnedV1(call, w, locked, mode); err != nil {
			return err
		}
		if err = e.historicalFinalizationReadinessOwnedV1(call, w, mode); err != nil {
			return err
		}
		// Native member pins lock in the original UUID order before the exact SQL
		// completion clock is allocated. Actual source/role order remains display order.
		children, err := w.HistoricalFinalizationMembersV1(call)
		if err != nil {
			return err
		}
		for _, child := range children {
			if child == nil || child.OrgID != org || child.IsEnvelope || !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != document || child.DeletedAt.Valid || (child.Status != "sent" && child.Status != "in_progress") {
				return errors.New("claim finalization: envelope child is not an active attached document")
			}
		}
		row, frozen, err := w.BeginHistoricalFinalizingV1(call)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDocumentRevisedDuringFinalize
		}
		if err != nil {
			return fmt.Errorf("claim finalization: transition: %w", err)
		}
		if row == nil || row.Status != "finalizing" {
			return errors.New("claim finalization: transition returned invalid state")
		}
		if !row.CompletionEffectiveAtBound {
			return errors.New("claim finalization: completion-effective timestamp is not bound")
		}
		if _, err = canonicalCompletionEffectiveAt(row.CompletionEffectiveAt); err != nil {
			return fmt.Errorf("claim finalization: %w", err)
		}
		if _, err = finalizationRetentionDeadline(row); err != nil {
			return fmt.Errorf("claim finalization: %w", err)
		}
		if row.IsEnvelope {
			if err = validateEnvelopeChildrenFinalizationFreeze(row, children, frozen); err != nil {
				return fmt.Errorf("claim finalization: %w", err)
			}
		}
		claimed = row
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	owner = &ownedHistoricalFinalizationClaimV1{operation: operation, org: org, document: document}
	keep = true
	return claimed, owner, nil
}
