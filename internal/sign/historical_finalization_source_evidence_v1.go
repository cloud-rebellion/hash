// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"sync"
)

// The actual native operation outlives every returned model, signature view,
// synchronous source consumer and error consumer. Callers must replace/drop
// these views before closing; neither a SQL Close nor cancellation credits it.
type ownedHistoricalFinalizationSourceV1 struct {
	ordinaryError                                    *ordinaryFinalizationErrorV1
	once                                             sync.Once
	operation                                        *ownedBlocksSignatureOperationV1
	reference                                        *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1
	source                                           *pdfadmission.ApplicationHistoricalFinalizationSourceEvidenceV1
	signatures                                       *pdfadmission.ApplicationHistoricalFinalizationSourceEvidenceV1
	family                                           *pdfadmission.ApplicationHistoricalFinalizationSourceFamilyV1
	css                                              *ownedHistoricalFinalizationCSSV1
	resumeSource                                     *pdfadmission.ApplicationHistoricalFinalizationSourceEvidenceV1
	resumeEvidence                                   *pdfadmission.ApplicationHistoricalFinalizationEvidenceV1
	resumeEvidenceFailure, resumeIntentPolicyFailure error
	renderError                                      *render.HTMLLocalPDFV1
	manualError                                      *pdfadmission.ApplicationHistoricalFinalizationManualPDFV1
	finalError                                       *pdfadmission.ApplicationHistoricalFinalizationPDFV1
	certificateError                                 *pdfadmission.ApplicationHistoricalAuditCertificateV1
	certificateDataError                             *ownedHistoricalCertificateSnapshotV1
	org, document                                    uuid.UUID
	err                                              error
}

func (h *ownedHistoricalFinalizationSourceV1) closeV1() error {
	if h == nil {
		return nil
	}
	h.once.Do(func() {
		if h.ordinaryError != nil {
			h.ordinaryError.closeV1()
			h.ordinaryError = nil
		}
		if h.finalError != nil {
			h.finalError.CloseConsumerV1()
			h.finalError = nil
		}
		if h.certificateError != nil {
			h.certificateError.CloseConsumerV1()
			h.certificateError = nil
		}
		if h.certificateDataError != nil {
			h.certificateDataError.closeV1()
			h.certificateDataError = nil
		}
		if h.manualError != nil {
			h.manualError.CloseConsumerV1()
			h.manualError = nil
		}
		if h.renderError != nil {
			h.renderError.CloseConsumerV1()
			h.renderError = nil
		}
		if h.css != nil {
			h.css.closeV1()
			h.css = nil
		}
		if h.operation != nil {
			h.err = h.operation.closeV1()
		}
	})
	return h.err
}
func historicalFinalizationSourceErrorV1(err error) error {
	if errors.Is(err, pdfadmission.ErrHistoricalFittedPublicationV1) {
		return ErrFittedCompositionRequiredV1
	}
	if errors.Is(err, pdfadmission.ErrHistoricalFinalizationSourceV1) {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	return blockSignatureFailureV1(err)
}
func (e *Engine) newHistoricalFinalizationSourceOwnerV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) (*ownedHistoricalFinalizationSourceV1, error) {
	if e == nil || ctx == nil || reference == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	org, document, err := reference.ScopeV1(ctx, e.WorkRuntime.SessionsV1())
	if err != nil {
		return nil, historicalFinalizationSourceErrorV1(err)
	}
	native, err := e.WorkRuntime.SessionsV1().NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return nil, historicalFinalizationSourceErrorV1(err)
	}
	return &ownedHistoricalFinalizationSourceV1{operation: &ownedBlocksSignatureOperationV1{native: native, factory: e.WorkRuntime.SessionsV1(), original: ctx}, reference: reference, org: org, document: document}, nil
}

// This entry point accepts only the genuinely acknowledged serialization/Claim
// reference. A caller Document or alternate key never establishes source scope.
func (e *Engine) loadHistoricalFinalizationSourceOwnedV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) (*generated.Document, *ownedHistoricalFinalizationSourceV1, error) {
	return e.loadHistoricalFinalizationRootSourceOwnedV1(ctx, reference, false)
}

// The signature finalizer's original root source and then signature checks share
// one actual locked Source24 Work/header and one private captured source owner.
// Deadline/branding and the later envelope-child gate remain caller decisions.
// Acknowledgement keeps the source-only entry above; no signature work moves
// ahead of an original acknowledgement or later family error gate.
func (e *Engine) loadHistoricalFinalizationSignatureSourceOwnedV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) (*generated.Document, *ownedHistoricalFinalizationSourceV1, error) {
	return e.loadHistoricalFinalizationRootSourceOwnedV1(ctx, reference, true)
}
func (e *Engine) loadHistoricalFinalizationRootSourceOwnedV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1, rootSignatures bool) (document *generated.Document, owner *ownedHistoricalFinalizationSourceV1, failure error) {
	owner, err := e.newHistoricalFinalizationSourceOwnerV1(ctx, reference)
	if err != nil {
		return nil, nil, err
	}
	client, ok := e.Storage.(*storage.Client)
	if !ok || client == nil {
		return nil, owner, ErrSigningAdmissionUnavailableV1
	}
	err = owner.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationSourceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		models, err := w.ReadModelsV1(call)
		if err != nil {
			return err
		}
		if err = reference.MatchesDocumentV1(call, owner.operation.factory, models.Document); err != nil {
			return err
		}
		owner.source, err = w.NewHistoricalFinalizationSourceEvidenceV1(call, client)
		if err != nil {
			return err
		}
		document, err = owner.source.EnsureSourceVersionsV1(call)
		if err != nil {
			return err
		}
		if rootSignatures {
			if err = owner.source.EnsureSignatureVersionsV1(call); err != nil {
				return err
			}
			owner.signatures = owner.source
		}
		return nil
	})
	if err != nil {
		return nil, owner, historicalFinalizationSourceErrorV1(err)
	}
	return document, owner, nil
}
func (h *ownedHistoricalFinalizationSourceV1) ensureSignatureVersionsV1(e *Engine) error {
	if h == nil || h.operation == nil || h.source == nil || h.signatures != nil || e == nil || e.WorkRuntime == nil || h.operation.factory != e.WorkRuntime.SessionsV1() {
		return ErrSigningAdmissionUnavailableV1
	}
	client, ok := e.Storage.(*storage.Client)
	if !ok || client == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	err := h.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationSourceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		models, err := w.ReadModelsV1(call)
		if err != nil {
			return err
		}
		if !h.source.MatchesDocumentV1(models.Document) {
			return ErrDocumentRevisedDuringFinalize
		}
		h.signatures, err = w.NewHistoricalFinalizationSourceEvidenceV1(call, client)
		if err != nil {
			return err
		}
		return h.signatures.EnsureSignatureVersionsV1(call)
	})
	return historicalFinalizationSourceErrorV1(err)
}
func (h *ownedHistoricalFinalizationSourceV1) ensureEnvelopeChildrenEvidenceVersionsV1(e *Engine) (children []*generated.Document, failure error) {
	if h == nil || h.operation == nil || h.source == nil || h.family != nil || e == nil || e.WorkRuntime == nil || h.operation.factory != e.WorkRuntime.SessionsV1() {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	err := h.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationSourceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		var err error
		h.family, err = h.source.ContinueEnvelopeSourceVersionsV1(call, w)
		if err != nil {
			return err
		}
		if h.family == nil {
			return nil
		}
		children, err = h.family.DocumentsV1()
		return err
	})
	if err != nil {
		return nil, historicalFinalizationSourceErrorV1(err)
	}
	return children, nil
}

func (h *ownedHistoricalFinalizationSourceV1) withSourcePDFV1(document uuid.UUID, consume func([]byte) error) error {
	if h == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	if document == h.document && h.source != nil {
		return historicalFinalizationSourceErrorV1(h.source.WithSourcePDFV1(consume))
	}
	if h.family != nil {
		return historicalFinalizationSourceErrorV1(h.family.WithSourcePDFV1(document, consume))
	}
	return ErrSigningAdmissionUnavailableV1
}
func (h *ownedHistoricalFinalizationSourceV1) signatureRowsV1(document uuid.UUID) ([]*generated.Signature, error) {
	if h == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if document == h.document && h.signatures != nil {
		return h.signatures.SignatureRowsV1()
	}
	if h.family != nil {
		return h.family.SignatureRowsV1(document)
	}
	return nil, ErrSigningAdmissionUnavailableV1
}
func (h *ownedHistoricalFinalizationSourceV1) withSignatureBodyV1(document, signature uuid.UUID, consume func([]byte) error) error {
	if h == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	if document == h.document && h.signatures != nil {
		return historicalFinalizationSourceErrorV1(h.signatures.WithSignatureBodyV1(signature, consume))
	}
	if h.family != nil {
		return historicalFinalizationSourceErrorV1(h.family.WithSignatureBodyV1(document, signature, consume))
	}
	return ErrSigningAdmissionUnavailableV1
}

func (e *Engine) retainHistoricalFinalizationSignatureInputsOwnedV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1, expected *generated.DocumentFinalizationIntent) (owner *ownedHistoricalFinalizationSourceV1, failure error) {
	owner, err := e.newHistoricalFinalizationSourceOwnerV1(ctx, reference)
	if err != nil {
		return nil, err
	}
	client, ok := e.Storage.(*storage.Client)
	if !ok || client == nil || expected == nil {
		return owner, ErrSigningAdmissionUnavailableV1
	}
	err = owner.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationSourceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		models, err := w.ReadModelsV1(call)
		if err != nil {
			return err
		}
		if err = reference.MatchesDocumentV1(call, owner.operation.factory, models.Document); err != nil {
			return err
		}
		actual, err := w.ReadHistoricalFinalizationIntentV1(call)
		if err != nil {
			return err
		}
		if !finalizationIntentsEqual(actual, expected) {
			return errors.New("resume finalization: intent changed during signature retention")
		}
		return w.RetainHistoricalFinalizationSignatureInputsV1(call, client)
	})
	return owner, historicalFinalizationSourceErrorV1(err)
}
