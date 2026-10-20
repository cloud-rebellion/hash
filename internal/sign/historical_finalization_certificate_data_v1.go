// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

type ownedHistoricalCertificateDataV1 struct {
	operation *ownedBlocksSignatureOperationV1
}

func (o *ownedHistoricalCertificateDataV1) closeV1() error {
	if o == nil || o.operation == nil {
		return nil
	}
	operation := o.operation
	o.operation = nil
	return operation.closeV1()
}

// A short-lived metadata owner reads no document/current body. The original
// actual source/CSS owner remains live through certificate rendering. This
// The fixed canonical claim output remains funded until the certificate call
// returns; that exact last-use closes this metadata/output frame before Stage.
func (e *Engine) loadHistoricalCertificateDataOwnedV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) (head *generated.LatestEventChainHeadForOrgRow, events []*generated.Event, owner *ownedHistoricalCertificateDataV1, failure error) {
	if e == nil || ctx == nil || reference == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, nil, nil, ErrSigningAdmissionUnavailableV1
	}
	factory := e.WorkRuntime.SessionsV1()
	org, document, err := reference.ScopeV1(ctx, factory)
	if err != nil {
		return nil, nil, nil, blockSignatureFailureV1(err)
	}
	native, err := factory.NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return nil, nil, nil, blockSignatureFailureV1(err)
	}
	operation := &ownedBlocksSignatureOperationV1{native: native, factory: factory, original: ctx}
	keep := false
	defer func() {
		if !keep {
			failure = errors.Join(failure, operation.closeV1())
		}
		failure = blockSignatureFailureV1(failure)
	}()
	err = operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationCertificateDataV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return fmt.Errorf("load pre-final audit chain head: %w", err)
		}
		var err error
		if err = w.ValidateHistoricalCertificateReferenceV1(call, reference); err != nil {
			return err
		}
		head, err = w.ReadHistoricalCertificateChainHeadV1(call)
		if err != nil {
			return fmt.Errorf("load pre-final audit chain head: %w", err)
		}
		events, err = w.ReadHistoricalCertificateEventsV1(call)
		if errors.Is(err, pdfadmission.ErrHistoricalCertificateEventLimitV1) {
			return fmt.Errorf("audit certificate: document has more than %d pre-final events", maxCertificateDocumentEvents)
		}
		if err != nil {
			return fmt.Errorf("audit certificate: load pre-final document events: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	owner = &ownedHistoricalCertificateDataV1{operation: operation}
	keep = true
	return head, events, owner, nil
}
