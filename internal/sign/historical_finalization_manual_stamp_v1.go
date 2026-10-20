// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"fmt"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// The genuine opaque SDK-body scope spans fresh native rows, original worker
// inspection/composition, renderer output and the actual final-PDF consumer.
// No caller bytes, geometry, row, hash or cost establishes native provenance.
func (h *ownedHistoricalFinalizationSourceV1) stampManualPDFV1(e *Engine, consume func(*pdfadmission.ApplicationHistoricalFinalizationPDFV1) error) error {
	if h == nil || h.manualError != nil || h.operation == nil || h.source == nil || e == nil || e.PDF == nil || e.WorkRuntime == nil || h.operation.factory != e.WorkRuntime.SessionsV1() || consume == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	var callbackFailure error
	err := h.source.WithManualPDFSourceV1(func(input *pdfadmission.ApplicationHistoricalManualPDFSourceV1) error {
		stamped, err := input.InspectManualPDFV1()
		if err != nil {
			h.manualError = stamped
			callbackFailure = fmt.Errorf("stamp pdf: %w", historicalFinalizationSourceErrorV1(err))
			return callbackFailure
		}
		var stampWork *pdfadmission.ApplicationHTMLSendWorkV1
		err = h.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationSourceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
			if _, err := w.StateV1(call); err != nil {
				return err
			}
			if _, err := h.source.NewHistoricalRenderContinuationV1(call, w); err != nil {
				return err
			}
			if err := w.CompleteHistoricalManualStampV1(call, input, stamped, h.source, e.PDF); err != nil {
				return err
			}
			stampWork = w
			return nil
		})
		if err != nil {
			h.manualError = stamped
			callbackFailure = fmt.Errorf("stamp pdf: %w", historicalFinalizationSourceErrorV1(err))
			return callbackFailure
		}
		if stamped == nil {
			callbackFailure = ErrSigningAdmissionUnavailableV1
			return callbackFailure
		}
		// Original worker/overlays/native row consumers and native COMMIT joined.
		// The independent stamped-PDF owner and actual SDK source input still own
		// every final byte; this ended row/geometry Work has no remaining consumer.
		if stampWork != nil {
			stampWork.CloseConsumerV1()
			stampWork = nil
		}
		final, err := stamped.FinalPDFV1()
		if err != nil {
			h.manualError = stamped
			callbackFailure = err
			return err
		}
		callbackFailure = consume(final)
		if callbackFailure != nil {
			h.finalError = final
		}
		return callbackFailure
	})
	if callbackFailure != nil {
		return callbackFailure
	}
	return historicalFinalizationSourceErrorV1(err)
}
