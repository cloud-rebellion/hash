// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"time"
)

// The actual fresh Source24 SQL callback owns canonical block/variable/decimal,
// signature/recipient and native family projections. Independent HTML and the
// renderer's own actual local IO/PDF grants span every synchronous consumer.
func (h *ownedHistoricalFinalizationSourceV1) renderFinalBlocksPDFV1(e *Engine) (*pdfadmission.ApplicationHistoricalFinalizationPDFV1, error) {
	if h == nil || h.renderError != nil || h.operation == nil || h.source == nil || h.css == nil || h.css.output == nil || e == nil || e.WorkRuntime == nil || h.operation.factory != e.WorkRuntime.SessionsV1() {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	renderer := e.PDF
	if renderer == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	var html *pdfadmission.ApplicationHistoricalFinalizationHTMLV1
	var renderWork *pdfadmission.ApplicationHTMLSendWorkV1
	defer func() {
		if html != nil {
			html.CloseConsumerV1()
		}
	}()
	err := h.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationSourceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		if _, err := h.source.NewHistoricalRenderContinuationV1(call, w); err != nil {
			return err
		}
		var err error
		html, err = w.NewHistoricalFinalBlocksHTMLV1(call, h.source, h.family, h.css.output, "en")
		if err == nil {
			renderWork = w
		}
		return err
	})
	if err != nil {
		return nil, historicalFinalizationSourceErrorV1(err)
	}
	// Every actual tree/decimal/archive/row consumer returned, the native SQL
	// COMMIT joined, and independent HTML already owns its full immutable bytes.
	// Retire only this ended render Work before the actual renderer producer.
	// Original source/family/CSS and error owners retain their own real loans.
	if renderWork != nil {
		renderWork.CloseConsumerV1()
		renderWork = nil
		// phaseV1 has acknowledged COMMIT and run its original SQL close. The
		// independent immutable HTML remains live; only original factory fences
		// may retire these ended tree/row consumers before the next SQL reader.
		cleanup, stop := context.WithTimeout(context.WithoutCancel(h.operation.original), 5*time.Second)
		defer stop()
		err = h.operation.factory.ReconcileCleanupV1(cleanup)
		if err != nil && (!errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return nil, historicalFinalizationSourceErrorV1(err)
		}
	}
	pdf, err := html.RenderFinalPDFV1(renderer, render.PDFOptions{WaitDelay: "1500ms"}, h.source)
	if err != nil {
		// The original provider error may retain response/URL text. Its actual
		// renderer Parent owner follows the same source error/readLease lastuse;
		// only proven joined local IO may independently release ProviderStreams.
		h.finalError = pdf
		return nil, fmt.Errorf("gotenberg render: %w", err)
	}
	return pdf, nil
}
