// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
)

type ownedHistoricalFinalizationEvidenceV1 struct {
	operation *ownedBlocksSignatureOperationV1
	evidence  *pdfadmission.ApplicationHistoricalFinalizationEvidenceV1
}

func (o *ownedHistoricalFinalizationEvidenceV1) closeV1() {
	if o == nil {
		return
	}
	if o.evidence != nil {
		o.evidence.CloseConsumerV1()
	}
	if o.operation != nil {
		_ = o.operation.closeV1()
	}
}
func (e *Engine) newHistoricalFinalizationEvidenceOwnedV1(ctx context.Context, expected *generated.DocumentFinalizationIntent) (owner *ownedHistoricalFinalizationEvidenceV1, failure error) {
	if e == nil || ctx == nil || expected == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	client, ok := e.Storage.(*storage.Client)
	if !ok || client == nil {
		return nil, errors.New("resume finalization: concrete evidence storage unavailable")
	}
	factory := e.WorkRuntime.SessionsV1()
	native, err := factory.NewHTMLSendOperationV1(ctx, expected.OrgID, expected.DocumentID)
	if err != nil {
		return nil, blockSignatureFailureV1(err)
	}
	operation := &ownedBlocksSignatureOperationV1{native: native, factory: factory, original: ctx}
	var evidence *pdfadmission.ApplicationHistoricalFinalizationEvidenceV1
	keep := false
	defer func() {
		if !keep {
			if evidence != nil {
				evidence.CloseConsumerV1()
			}
			failure = errors.Join(failure, operation.closeV1())
		}
		failure = blockSignatureFailureV1(failure)
	}()
	err = operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationEvidenceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		if _, err := w.ReadHistoricalFinalizationIntentV1(call); err != nil {
			return err
		}
		var err error
		evidence, err = w.NewHistoricalFinalizationEvidenceV1(call, client)
		if err != nil {
			return err
		}
		if !evidence.MatchesIntentV1(expected) {
			return errors.New("resume finalization: actual intent changed before artifact verification")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	owner = &ownedHistoricalFinalizationEvidenceV1{operation: operation, evidence: evidence}
	keep = true
	return owner, nil
}

// No fresh metadata read/header is needed for a pinned intent already captured
// by the genuine Resume callback. This comparison rejects caller mutation; it
// never adopts the expected view as native provider authority.
func (o *ownedHistoricalFinalizationResumeV1) evidenceOwnedV1(e *Engine, ctx context.Context, expected *generated.DocumentFinalizationIntent) (*ownedHistoricalFinalizationEvidenceV1, error) {
	if o == nil || o.operation == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if o.evidenceFailure != nil {
		return nil, blockSignatureFailureV1(o.evidenceFailure)
	}
	if o.evidence == nil {
		return e.newHistoricalFinalizationEvidenceOwnedV1(ctx, expected)
	}
	if !o.evidence.MatchesIntentV1(expected) {
		return nil, errors.New("resume finalization: actual intent changed before artifact verification")
	}
	return &ownedHistoricalFinalizationEvidenceV1{operation: o.operation, evidence: o.evidence}, nil
}
