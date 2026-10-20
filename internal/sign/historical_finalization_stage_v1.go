// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// The original render/store work has produced these values. This separate
// fixed native phase owns only actual locked source/intent reads, SQL argument
// copies and the durable INSERT through acknowledged Commit and physical join.
// It grants no credit or provenance for that earlier render/provider work.
func (e *Engine) stageHistoricalFinalizationOwnedV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1, staged stagedDocumentFinalization) (failure error) {
	if e == nil || ctx == nil || reference == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return ErrSigningAdmissionUnavailableV1
	}
	factory := e.WorkRuntime.SessionsV1()
	org, document, err := reference.ScopeV1(ctx, factory)
	if err != nil {
		return blockSignatureFailureV1(err)
	}
	native, err := factory.NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return blockSignatureFailureV1(err)
	}
	operation := &ownedBlocksSignatureOperationV1{native: native, factory: factory, original: ctx}
	defer func() { failure = blockSignatureFailureV1(errors.Join(failure, operation.closeV1())) }()
	return operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationStageV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return fmt.Errorf("stage finalization: lock document: %w", err)
		}
		models, err := w.ReadModelsV1(call)
		if err != nil {
			return fmt.Errorf("stage finalization: lock document: %w", err)
		}
		locked := models.Document
		if locked.Status != "finalizing" {
			return ErrDocumentRevisedDuringFinalize
		}
		if _, err = validateHistoricalFinalizationModeOwnedV1(call, w, locked, staged.Mode); err != nil {
			return err
		}
		if err = w.ValidateHistoricalFinalizationStageReferenceV1(call, reference); err != nil {
			return errors.Join(errors.New("stage finalization: document commitments changed before intent persistence"), err)
		}
		if _, err = finalizationRetentionDeadline(locked); err != nil {
			return fmt.Errorf("stage finalization: %w", err)
		}
		params := generated.CreateDocumentFinalizationIntentParams{
			DocumentID: locked.ID, OrgID: locked.OrgID, Mode: staged.Mode, CompletionEffectiveAt: locked.CompletionEffectiveAt, RetainUntil: locked.FinalizationRetainUntil,
			FinalPdfKey: staged.FinalKey, FinalPdfSha256: staged.FinalSHA256[:], FinalPdfVersionID: pgtype.Text{String: staged.FinalVersionID, Valid: true},
			AuditCertKey: staged.Certificate.CertKey, AuditCertSha256: staged.Certificate.CertSHA256[:], AuditCertVersionID: pgtype.Text{String: staged.Certificate.CertVersionID, Valid: true},
			AuditPayloadKey: staged.Certificate.PayloadKey, AuditPayloadSha256: staged.Certificate.PayloadSHA256[:], AuditPayloadVersionID: pgtype.Text{String: staged.Certificate.PayloadVersionID, Valid: true},
			AuditSignatureKey: staged.Certificate.SignatureKey, AuditSignatureSha256: staged.Certificate.SignatureSHA256[:], AuditSignatureVersionID: pgtype.Text{String: staged.Certificate.SignatureVersionID, Valid: true},
		}
		existing, getErr := w.ReadHistoricalFinalizationIntentV1(call)
		if getErr == nil {
			if err := finalizationIntentMatchesParams(existing, params); err != nil {
				return err
			}
			return w.PersistHistoricalParticipantReportV1(call, staged.Certificate.nativeReport)
		}
		if !errors.Is(getErr, pgx.ErrNoRows) {
			return fmt.Errorf("stage finalization: load intent: %w", getErr)
		}
		created, err := w.CreateHistoricalFinalizationIntentV1(call, params)
		if err != nil {
			return fmt.Errorf("stage finalization: persist intent: %w", err)
		}
		if err := finalizationIntentMatchesParams(created, params); err != nil {
			return err
		}
		return w.PersistHistoricalParticipantReportV1(call, staged.Certificate.nativeReport)
	})
}
