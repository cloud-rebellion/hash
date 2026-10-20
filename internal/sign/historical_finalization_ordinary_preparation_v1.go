// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/jackc/pgx/v5"
)

// A failed provider observation and its actual source bytes remain owned until
// the original response/error consumer retires through the existing input lease.
type ordinaryFinalizationErrorV1 struct {
	preparation *pdfadmission.ApplicationHistoricalOrdinaryPreparationV1
	body        *pdfadmission.ApplicationHistoricalOrdinaryBodyV1
	rendered    *pdfadmission.ApplicationHistoricalOrdinaryRenderedV1
	put         *storage.EvidenceLocalPutV1
}

func (o *ordinaryFinalizationErrorV1) closeV1() {
	if o == nil {
		return
	}
	if o.put != nil {
		o.put.CloseConsumerV1()
	}
	if o.rendered != nil {
		o.rendered.CloseConsumerV1()
	}
	if o.body != nil {
		o.body.CloseConsumerV1()
	}
	if o.preparation != nil {
		o.preparation.CloseConsumerV1()
	}
}

func (e *Engine) ordinaryFinalizationPhaseV1(ctx context.Context, ref *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1, consume func(context.Context, *pdfadmission.ApplicationHTMLSendWorkV1) error) (failure error) {
	if e == nil || ctx == nil || ref == nil || consume == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return ErrSigningAdmissionUnavailableV1
	}
	factory := e.WorkRuntime.SessionsV1()
	org, document, err := ref.ScopeV1(ctx, factory)
	if err != nil {
		return err
	}
	native, err := factory.NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return err
	}
	operation := &ownedBlocksSignatureOperationV1{native: native, factory: factory, original: ctx}
	defer func() { failure = errors.Join(failure, operation.closeV1()) }()
	return operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationStageV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return fmt.Errorf("ordinary preparation phase: locked state: %w", err)
		}
		models, err := w.ReadModelsV1(call)
		if err != nil {
			return fmt.Errorf("ordinary preparation phase: locked models: %w", err)
		}
		if models.Document == nil || models.Document.Status != "finalizing" {
			return ErrDocumentRevisedDuringFinalize
		}
		if err = requireHistoricalSigningAdmissionV1(models.Document); err != nil {
			return err
		}
		if err = w.ValidateHistoricalFinalizationSigningPageV1(call); err != nil {
			return fmt.Errorf("ordinary preparation phase: signing page: %w", err)
		}
		if err = w.ValidateHistoricalFinalizationStageReferenceV1(call, ref); err != nil {
			return fmt.Errorf("ordinary preparation phase: stage reference: %w", err)
		}
		return consume(call, w)
	})
}
func (e *Engine) readOrdinaryPreparationV1(ctx context.Context, ref *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) (p *pdfadmission.ApplicationHistoricalOrdinaryPreparationV1, failure error) {
	failure = e.ordinaryFinalizationPhaseV1(ctx, ref, func(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		var err error
		p, err = w.ReadHistoricalOrdinaryPreparationV1(call, ref)
		return err
	})
	if failure != nil && p != nil {
		p.CloseConsumerV1()
		p = nil
	}
	return
}
func (e *Engine) readOrdinaryBodyV1(ctx context.Context, ref *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1, p *pdfadmission.ApplicationHistoricalOrdinaryPreparationV1, kind string) (b *pdfadmission.ApplicationHistoricalOrdinaryBodyV1, failure error) {
	failure = e.ordinaryFinalizationPhaseV1(ctx, ref, func(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		var err error
		b, err = w.ReadHistoricalOrdinaryBodyV1(call, ref, p, kind)
		return err
	})
	if failure != nil && b != nil {
		b.CloseConsumerV1()
		b = nil
	}
	return
}

func (e *Engine) ordinaryCertificateInputFrozenV1(ctx context.Context, ref *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) (bool, error) {
	p, err := e.readOrdinaryPreparationV1(ctx, ref)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer p.CloseConsumerV1()
	return p.HasCertificateInputV1(), nil
}

// An ordinary preparation is a frozen byte source, not a second publication
// engine. Once Stage commits, the existing M46 exact pins/retention/recovery and
// M108 outbox/report unit remain the sole completion owner.
func (e *Engine) prepareOrdinaryHistoricalFinalizationV1(ctx context.Context, ref *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1, source *ownedHistoricalFinalizationSourceV1, doc *generated.Document, manifest *pdfadmission.ApplicationHistoricalTerminalManifestV1) (retired bool, failure error) {
	client, ok := e.Storage.(*storage.Client)
	if !ok || client == nil || source == nil || source.source == nil || doc == nil {
		return false, ErrSigningAdmissionUnavailableV1
	}
	p, err := e.readOrdinaryPreparationV1(ctx, ref)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	keepPreparation := false
	defer func() {
		if p != nil && !keepPreparation {
			p.CloseConsumerV1()
		}
	}()
	refresh := func() error {
		next, err := e.readOrdinaryPreparationV1(ctx, ref)
		if err != nil {
			return err
		}
		if p != nil {
			p.CloseConsumerV1()
		}
		p = next
		return nil
	}
	if p == nil {
		capture := func(final *pdfadmission.ApplicationHistoricalFinalizationPDFV1) error {
			if _, err := final.CalculateSHA256V1(); err != nil {
				source.finalError = final
				return err
			}
			err := e.ordinaryFinalizationPhaseV1(ctx, ref, func(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
				return w.CaptureHistoricalOrdinaryFinalPDFV1(call, ref, final)
			})
			if err != nil {
				source.finalError = final
				return err
			}
			final.RetireBodyV1()
			final.RetireSourceConsumerV1()
			final.CloseConsumerV1()
			return nil
		}
		if !doc.RequiresSignature {
			err = source.source.WithAcknowledgementFinalPDFV1(capture)
		} else if doc.SourceKind == "blocks" {
			var final *pdfadmission.ApplicationHistoricalFinalizationPDFV1
			final, err = source.renderFinalBlocksPDFV1(e)
			if err == nil {
				err = capture(final)
			}
		} else {
			err = source.stampManualPDFV1(e, capture)
		}
		if err != nil {
			return false, fmt.Errorf("freeze ordinary final PDF: %w", err)
		}
		if err = refresh(); err != nil {
			return false, err
		}
	}
	if !p.HasCertificateInputV1() {
		snapshot, err := e.loadHistoricalCertificateSnapshotOwnedV1(ctx, ref)
		source.certificateDataError = snapshot
		if err != nil {
			return false, err
		}
		if err = snapshot.snapshot.PrepareOrdinaryClaimsV1(source.source, p); err != nil {
			return false, err
		}
		certificate, err := source.prepareAuditCertificateV1(e, snapshot.snapshot, manifest)
		if err != nil {
			return false, err
		}
		source.certificateError = certificate
		snapshot.retireClaimsV1()
		if err = e.ordinaryFinalizationPhaseV1(ctx, ref, func(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
			return w.FreezeHistoricalOrdinaryCertificateV1(call, ref, certificate)
		}); err != nil {
			return false, fmt.Errorf("freeze ordinary certificate inputs: %w", err)
		}
		certificate.CloseConsumerV1()
		source.certificateError = nil
		if err = snapshot.closeV1(); err != nil {
			return false, err
		}
		source.certificateDataError = nil
		if err = refresh(); err != nil {
			return false, err
		}
	}
	if !p.HasCertificatePDFV1() {
		body, err := e.readOrdinaryBodyV1(ctx, ref, p, "render_html")
		if err != nil {
			return false, err
		}
		rendered, err := body.RenderCertificateV1(e.PDF)
		retained := &ordinaryFinalizationErrorV1{preparation: p, body: body, rendered: rendered}
		if err != nil {
			source.ordinaryError = retained
			keepPreparation = true
			return false, fmt.Errorf("render frozen ordinary certificate: %w", err)
		}
		err = e.ordinaryFinalizationPhaseV1(ctx, ref, func(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
			return w.CaptureHistoricalOrdinaryCertificatePDFV1(call, ref, rendered)
		})
		if err != nil {
			source.ordinaryError = retained
			keepPreparation = true
			return false, err
		}
		rendered.CloseConsumerV1()
		body.CloseConsumerV1()
		if err = refresh(); err != nil {
			return false, err
		}
	}
	for _, kind := range []string{"final_pdf", "certificate_pdf", "certificate_payload", "certificate_signature"} {
		body, err := e.readOrdinaryBodyV1(ctx, ref, p, kind)
		if err != nil {
			return false, err
		}
		put, storeErr := body.StoreV1(client)
		retained := &ordinaryFinalizationErrorV1{preparation: p, body: body, put: put}
		// Even a late failed PUT can have a positive provider identity. Preserve
		// that observation separately; successful readback/retention is still a
		// different fact. Unknown identities remain pending with their frozen bytes.
		checkpointCtx := ctx
		stop := func() {}
		if storeErr != nil {
			checkpointCtx, stop = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		}
		checkpointErr := e.ordinaryFinalizationPhaseV1(checkpointCtx, ref, func(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
			return w.CheckpointHistoricalOrdinaryOutputV1(call, ref, body, put)
		})
		stop()
		if storeErr != nil || checkpointErr != nil {
			source.ordinaryError = retained
			keepPreparation = true
			return false, fmt.Errorf("store frozen ordinary %s: %w", kind, errors.Join(storeErr, checkpointErr))
		}
		put.CloseConsumerV1()
		body.CloseConsumerV1()
		if err = refresh(); err != nil {
			return false, err
		}
	}
	// All original bodies and provider consumers have joined. The new independent
	// preparation metadata owns Stage; the old full source ends at this last use.
	if err = source.closeV1(); err != nil {
		return false, err
	}
	retired = true
	err = e.ordinaryFinalizationPhaseV1(ctx, ref, func(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		return w.StageHistoricalOrdinaryPreparationV1(call, ref, p)
	})
	return retired, err
}
