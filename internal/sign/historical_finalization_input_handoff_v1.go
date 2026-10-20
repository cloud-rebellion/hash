// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// One finalization branch has one genuine Source24 operation. Its original
// source/signature/CSS views survive all synchronous consumers, including an
// early/error response. A second branch is never substituted into that slot.
func retainHistoricalFinalizationInputV1(capture *completionCredentialCapture, input *ownedHistoricalFinalizationSourceV1) {
	if input == nil {
		return
	}
	if capture == nil {
		_ = input.closeV1()
		return
	}
	if capture.finalizationInput == nil {
		capture.finalizationInput = input
		return
	}
	// The existing registered owner still owns its original consumer. This
	// unreachable duplicate must retire only the new actual operation, never
	// replace or credit the earlier source.
	if capture.finalizationInput != input {
		_ = input.closeV1()
	}
}

func (l *signerReadLeaseV1) registerHistoricalFinalizationInputV1(e *Engine, input *ownedHistoricalFinalizationSourceV1) error {
	if l == nil || e == nil || input == nil || input.operation == nil || e.WorkRuntime == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.issuer != e || l.reader == nil || l.original == nil || l.original.Document == nil || l.finalizationInput != nil ||
		input.operation.factory != e.WorkRuntime.SessionsV1() || input.org != l.original.Document.OrgID || input.document != l.original.Document.ID {
		return ErrSigningAdmissionUnavailableV1
	}
	l.finalizationInput = input
	return nil
}

func (e *Engine) retainHistoricalFinalizationInputForRecipientV1(rc *RecipientContext, capture *completionCredentialCapture) error {
	if capture == nil || capture.finalizationInput == nil {
		return nil
	}
	input := capture.finalizationInput
	if rc == nil || rc.readLease == nil {
		capture.finalizationInput = nil
		return errors.Join(ErrSigningAdmissionUnavailableV1, input.closeV1())
	}
	if err := rc.readLease.registerHistoricalFinalizationInputV1(e, input); err != nil {
		capture.finalizationInput = nil
		return errors.Join(err, input.closeV1())
	}
	capture.finalizationInput = nil
	return nil
}

func (e *Engine) resolveBrandingCSSForFinalizationOwnedV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1, input *ownedHistoricalFinalizationSourceV1) (string, error) {
	if e == nil || input == nil || input.operation == nil || input.css != nil || e.WorkRuntime == nil || input.operation.factory != e.WorkRuntime.SessionsV1() || input.reference != reference {
		return "", ErrSigningAdmissionUnavailableV1
	}
	css, owner, err := e.resolveBrandingCSSOwnedV1(ctx, reference)
	if err != nil {
		return "", err
	}
	input.css = owner
	return css, nil
}
