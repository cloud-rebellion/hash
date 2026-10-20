// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"sync"
)

type ownedHistoricalFinalizationCSSV1 struct {
	once   sync.Once
	output *pdfadmission.ApplicationHistoricalFinalizationCSSV1
	finish func()
}

func (h *ownedHistoricalFinalizationCSSV1) closeV1() {
	if h == nil {
		return
	}
	h.once.Do(func() {
		// The caller has dropped its last CSS view before retiring this borrower.
		if h.finish != nil {
			h.finish()
			h.finish = nil
		}
		if h.output != nil {
			h.output.CloseConsumerV1()
			h.output = nil
		}
	})
}

// The actual frozen row and generator are shared with Branding.ResolveFrozen.
// SQL/header/body work is short lived; only a separately admitted CSS output
// remains with its real render/certificate consumer after this returns.
func (e *Engine) resolveBrandingCSSOwnedV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) (css string, owner *ownedHistoricalFinalizationCSSV1, failure error) {
	if e == nil || ctx == nil || reference == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return "", nil, ErrSigningAdmissionUnavailableV1
	}
	factory := e.WorkRuntime.SessionsV1()
	org, document, err := reference.ScopeV1(ctx, factory)
	if err != nil {
		return "", nil, blockSignatureFailureV1(err)
	}
	native, err := factory.NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return "", nil, blockSignatureFailureV1(err)
	}
	operation := &ownedBlocksSignatureOperationV1{native: native, factory: factory, original: ctx}
	var output *pdfadmission.ApplicationHistoricalFinalizationCSSV1
	err = operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationCertificateRenderV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		var err error
		output, err = w.NewHistoricalFinalizationFrozenCSSV1(call, reference)
		return err
	})
	// Every native callback, COMMIT, driver close and cleanup must join before
	// retiring the short metadata frame. A retained CSS output is not SQL proof.
	closeErr := operation.closeV1()
	if err != nil || closeErr != nil {
		if output != nil {
			output.CloseConsumerV1()
		}
		return "", nil, blockSignatureFailureV1(errors.Join(err, closeErr))
	}
	css, finish, err := output.BorrowCSSV1()
	if err != nil {
		output.CloseConsumerV1()
		return "", nil, blockSignatureFailureV1(err)
	}
	return css, &ownedHistoricalFinalizationCSSV1{output: output, finish: finish}, nil
}
