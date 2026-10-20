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

// This is the original post-source/signature/family intent compatibility gate.
// Real source private data is independently cloned into a fresh same-operation Work;
// four legacy object versions can only come from its concrete SDK/native CAS.
// Commit acknowledgment precedes advancing the independently funded witness.
func (h *ownedHistoricalFinalizationSourceV1) resumeIntentVersionsV1(e *Engine) (doc *generated.Document, intent *generated.DocumentFinalizationIntent, publication *pdfadmission.ApplicationHistoricalFinalizationPublicationReferenceV1, failure error) {
	if h == nil || h.operation == nil || h.source == nil || h.resumeSource != nil || e == nil || e.WorkRuntime == nil || h.operation.factory != e.WorkRuntime.SessionsV1() {
		return nil, nil, nil, ErrSigningAdmissionUnavailableV1
	}
	client, ok := e.Storage.(*storage.Client)
	if !ok || client == nil {
		return nil, nil, nil, errors.New("resume finalization: concrete evidence storage unavailable")
	}
	err := h.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationSourceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		var err error
		doc, h.resumeSource, err = h.source.NewHistoricalIntentContinuationV1(call, w)
		if err != nil {
			return err
		}
		intent, err = h.resumeSource.EnsureIntentVersionsV1(call)
		if err != nil {
			return err
		}
		// The original post-compatibility mode gate uses THIS fresh private source
		// CPU owner, not a second unadmitted decode of the public returned model.
		_, h.resumeIntentPolicyFailure = validateHistoricalFinalizationModeOwnedV1(call, w, doc, intent.Mode)
		if h.resumeIntentPolicyFailure == nil {
			if err = w.RetireHistoricalFinalizationModeConsumerV1(call); err != nil {
				return err
			}
		}
		// Preserve successful compatibility CAS even when later evidence allocation
		// refuses. Surface that stored failure at the original evidence gate.
		h.resumeEvidence, h.resumeEvidenceFailure = w.NewHistoricalFinalizationEvidenceV1(call, client)
		return nil
	})
	if err != nil {
		return nil, nil, nil, historicalFinalizationSourceErrorV1(err)
	}
	publication, err = h.resumeSource.ConfirmHistoricalPublicationIntentV1(h.reference)
	if err != nil {
		return nil, nil, nil, historicalFinalizationSourceErrorV1(err)
	}
	// The genuinely acknowledged continuation owns independent private/public
	// source clones. No original version-source/model/signature view remains in
	// this Resume consumer; retire only that ended Work, never the operation or
	// the new intent/artifact owners. Refusal keeps its debt for error last use.
	previous := h.source
	h.source = nil
	h.signatures = nil
	if err = previous.RetireHistoricalVersionConsumersV1(h.resumeSource); err != nil {
		return nil, nil, nil, historicalFinalizationSourceErrorV1(err)
	}
	previous = nil
	return doc, intent, publication, nil
}
func (h *ownedHistoricalFinalizationSourceV1) retireResumeVersionFamilyV1() error {
	if h == nil || h.operation == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	if h.family == nil {
		return nil
	}
	if err := h.family.RetireVersionConsumersV1(); err != nil {
		return historicalFinalizationSourceErrorV1(err)
	}
	h.family = nil
	return nil
}

func (h *ownedHistoricalFinalizationSourceV1) retainResumeSignatureInputsV1(e *Engine, publication *pdfadmission.ApplicationHistoricalFinalizationPublicationReferenceV1) error {
	if h == nil || h.operation == nil || h.resumeSource == nil || publication == nil || e == nil || e.WorkRuntime == nil || h.operation.factory != e.WorkRuntime.SessionsV1() {
		return ErrSigningAdmissionUnavailableV1
	}
	client, ok := e.Storage.(*storage.Client)
	if !ok || client == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	var retentionWork *pdfadmission.ApplicationHTMLSendWorkV1
	err := h.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationSourceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		_, _, err := h.resumeSource.NewHistoricalIntentContinuationV1(call, w)
		if err != nil {
			return err
		}
		actual, err := w.ReadHistoricalFinalizationIntentV1(call)
		if err != nil {
			return err
		}
		if !publication.MatchesIntentV1(actual) {
			return errors.New("resume finalization: intent changed during signature retention")
		}
		if err = w.RetainHistoricalFinalizationSignatureInputsV1(call, client); err != nil {
			return err
		}
		retentionWork = w
		return nil
	})
	if err == nil && retentionWork != nil {
		// Actual native retention/SDK consumers and the original COMMIT returned.
		// No row/body/output view escapes this callback; the separate artifact
		// evidence Work stays live for its following original retain calls.
		retentionWork.CloseConsumerV1()
		retentionWork = nil
	}
	return historicalFinalizationSourceErrorV1(err)
}
