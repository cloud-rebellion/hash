// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"time"
)

// The copied ledger and claims have independent native Parent ownership. The
// actual metadata reader can retire after copy+COMMIT; any Close failure is
// reported only at its original later certificate-close point. Error paths
// retain both original reader/error and independent snapshot through readLease.
type ownedHistoricalCertificateSnapshotV1 struct {
	operation    *ownedBlocksSignatureOperationV1
	snapshot     *pdfadmission.ApplicationHistoricalCertificateSnapshotV1
	closeFailure error
}

func (o *ownedHistoricalCertificateSnapshotV1) retireReaderV1() {
	if o != nil && o.operation != nil {
		operation := o.operation
		o.operation = nil
		o.closeFailure = errors.Join(o.closeFailure, operation.closeV1())
	}
}
func (o *ownedHistoricalCertificateSnapshotV1) retireClaimsV1() {
	if o != nil && o.snapshot != nil {
		o.snapshot.CloseConsumerV1()
		o.snapshot = nil
	}
}
func (o *ownedHistoricalCertificateSnapshotV1) closeV1() error {
	if o == nil {
		return nil
	}
	o.retireClaimsV1()
	o.retireReaderV1()
	return o.closeFailure
}
func (e *Engine) loadHistoricalCertificateSnapshotOwnedV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) (owner *ownedHistoricalCertificateSnapshotV1, failure error) {
	if e == nil || ctx == nil || reference == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	factory := e.WorkRuntime.SessionsV1()
	org, document, err := reference.ScopeV1(ctx, factory)
	if err != nil {
		return nil, blockSignatureFailureV1(err)
	}
	native, err := factory.NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return nil, blockSignatureFailureV1(err)
	}
	owner = &ownedHistoricalCertificateSnapshotV1{operation: &ownedBlocksSignatureOperationV1{native: native, factory: factory, original: ctx}}
	err = owner.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationCertificateDataV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return fmt.Errorf("load pre-final audit chain head: %w", err)
		}
		if err := w.ValidateHistoricalCertificateReferenceV1(call, reference); err != nil {
			return err
		}
		if _, err := w.ReadHistoricalCertificateChainHeadV1(call); err != nil {
			return fmt.Errorf("load pre-final audit chain head: %w", err)
		}
		if _, err := w.ReadHistoricalCertificateEventsV1(call); errors.Is(err, pdfadmission.ErrHistoricalCertificateEventLimitV1) {
			return fmt.Errorf("audit certificate: document has more than %d pre-final events", maxCertificateDocumentEvents)
		} else if err != nil {
			return fmt.Errorf("audit certificate: load pre-final document events: %w", err)
		}
		var err error
		owner.snapshot, err = w.SnapshotHistoricalCertificateDataV1(call)
		return err
	})
	if err != nil {
		return owner, blockSignatureFailureV1(err)
	}
	owner.retireReaderV1()
	return owner, nil
}
func (h *ownedHistoricalFinalizationSourceV1) terminalManifestV1(e *Engine) (*pdfadmission.ApplicationHistoricalTerminalManifestV1, error) {
	if h == nil || h.source == nil || h.family == nil || h.operation == nil || e == nil || e.WorkRuntime == nil || h.operation.factory != e.WorkRuntime.SessionsV1() {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	var manifest *pdfadmission.ApplicationHistoricalTerminalManifestV1
	var ended *pdfadmission.ApplicationHTMLSendWorkV1
	err := h.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationSourceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		if _, err := h.source.NewHistoricalRenderContinuationV1(call, w); err != nil {
			return err
		}
		var err error
		manifest, err = w.NewHistoricalTerminalManifestV1(call, h.source, h.family)
		if err == nil {
			ended = w
		}
		return err
	})
	if err != nil {
		if manifest != nil {
			manifest.CloseConsumerV1()
		}
		return nil, historicalFinalizationSourceErrorV1(err)
	}
	if ended != nil {
		// The manifest owns independent immutable HTML. Its native parse/hash/row
		// consumers and acknowledged COMMIT returned; phaseV1 has closed SQL.
		// Close only this ended Work, then let the original factory/fences prove
		// which actual consumer-closed loans can retire. The source/family/native
		// operation and manifest HTML remain live for the following render.
		ended.CloseConsumerV1()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(h.operation.original), 5*time.Second)
		defer stop()
		err = h.operation.factory.ReconcileCleanupV1(cleanup)
		if err != nil && (!errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			if manifest != nil {
				manifest.CloseConsumerV1()
			}
			return nil, historicalFinalizationSourceErrorV1(err)
		}
	}
	return manifest, nil
}
func (h *ownedHistoricalFinalizationSourceV1) prepareAuditCertificateV1(e *Engine, snapshot *pdfadmission.ApplicationHistoricalCertificateSnapshotV1, manifest *pdfadmission.ApplicationHistoricalTerminalManifestV1) (*pdfadmission.ApplicationHistoricalAuditCertificateV1, error) {
	// Original signer guard precedes every recipient/signature SQL query.
	if e == nil || e.Signer == nil {
		return nil, errors.New("audit certificate: signer unavailable")
	}
	if h == nil || h.source == nil || h.operation == nil || h.css == nil || h.css.output == nil || snapshot == nil || e.WorkRuntime == nil || h.operation.factory != e.WorkRuntime.SessionsV1() {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	var cert *pdfadmission.ApplicationHistoricalAuditCertificateV1
	var ended *pdfadmission.ApplicationHTMLSendWorkV1
	err := h.operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationSourceV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		if _, err := h.source.NewHistoricalRenderContinuationV1(call, w); err != nil {
			return err
		}
		var err error
		cert, err = w.NewHistoricalAuditCertificateV1(call, h.source, snapshot, manifest, h.css.output, e.Signer.nativeAuditCertificatePrivateV1(), e.OrgName, e.BaseURL)
		if err == nil {
			ended = w
		}
		return err
	})
	if err != nil {
		h.certificateError = cert
		return nil, historicalFinalizationSourceErrorV1(err)
	}
	if ended != nil {
		ended.CloseConsumerV1()
	}
	return cert, nil
}
func nativeWithStoredCertificateV1(cert *pdfadmission.ApplicationHistoricalAuditCertificateV1, consume func(storedAuditCertificate) error) error {
	return cert.WithStoredV1(func(keys [3]string, sums [3][sha256.Size]byte, versions [3]string) error {
		artifacts := storedAuditCertificate{nativeReport: cert, CertKey: keys[0], CertSHA256: sums[0], CertVersionID: versions[0], PayloadKey: keys[1], PayloadSHA256: sums[1], PayloadVersionID: versions[1], SignatureKey: keys[2], SignatureSHA256: sums[2], SignatureVersionID: versions[2]}
		defer func() { artifacts = storedAuditCertificate{} }()
		return consume(artifacts)
	})
}
