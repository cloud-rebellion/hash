// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Capture only the acknowledged actual Claim's scalar authority for the native
// certificate metadata phase. All original staged.validate/store ordering stays
// at the later validation gate before the Claim's real last-use retirement.
func (e *Engine) captureHistoricalFinalizationStageReferenceV1(ctx context.Context, doc *generated.Document, serialization *pdfadmission.ApplicationHistoricalFinalizationLockV1, claim *ownedHistoricalFinalizationClaimV1) (*pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1, error) {
	if e == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || serialization == nil || claim == nil || claim.operation == nil || claim.operation.native == nil || claim.operation.factory != e.WorkRuntime.SessionsV1() {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	reference, err := serialization.NewStageReferenceV1(ctx, claim.operation.native)
	if err != nil {
		return nil, blockSignatureFailureV1(err)
	}
	if err = reference.MatchesDocumentV1(ctx, claim.operation.factory, doc); err != nil {
		return nil, blockSignatureFailureV1(err)
	}
	return reference, nil
}
func (e *Engine) validateHistoricalFinalizationStageReferenceV1(ctx context.Context, conn *pgxpool.Conn, doc *generated.Document, staged stagedDocumentFinalization, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) error {
	if conn == nil || e == nil || e.Queries == nil {
		return errors.New("stage finalization: lifecycle store unavailable")
	}
	if err := staged.validate(doc); err != nil {
		return err
	}
	if e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || reference == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	return blockSignatureFailureV1(reference.MatchesDocumentV1(ctx, e.WorkRuntime.SessionsV1(), doc))
}

// The caller has synchronously ended the render/certificate/source consumers
// and cleared its last old root pointer before this exact-operation close.
// Existing physical/backend cleanup still gates every credit; unknown debt is
// retained by the genuine factory and the new Stage must independently admit.
func (o *ownedHistoricalFinalizationClaimV1) retireForStageV1(ctx context.Context, e *Engine, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) error {
	if o == nil || o.operation == nil || e == nil || e.WorkRuntime == nil || o.operation.factory != e.WorkRuntime.SessionsV1() || reference == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	org, document, err := reference.ScopeV1(ctx, o.operation.factory)
	if err != nil {
		return blockSignatureFailureV1(err)
	}
	if org != o.org || document != o.document {
		return ErrSigningAdmissionUnavailableV1
	}
	return o.operation.closeV1()
}

func (e *Engine) resumeDocumentFinalizationFromStageReferenceOwnedV1(ctx context.Context, conn *pgxpool.Conn, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1, capture *completionCredentialCapture) (*generated.Document, bool, error) {
	if e == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || reference == nil {
		return nil, false, ErrSigningAdmissionUnavailableV1
	}
	org, document, err := reference.ScopeV1(ctx, e.WorkRuntime.SessionsV1())
	if err != nil {
		return nil, false, blockSignatureFailureV1(err)
	}
	return e.resumeDocumentFinalizationScopeOwnedV1(ctx, conn, org, document, capture, nil, reference)
}

// Recovery with a pre-existing staged intent uses the same genuine advisory
// owner/acknowledged Claim reference as the newly rendered path.
func (e *Engine) resumeDocumentFinalizationAfterSerializedClaimOwnedV1(ctx context.Context, conn *pgxpool.Conn, doc *generated.Document, capture *completionCredentialCapture, claim *ownedHistoricalFinalizationClaimV1, serialization *pdfadmission.ApplicationHistoricalFinalizationLockV1) (*generated.Document, bool, error) {
	if doc == nil || doc.Status != "finalizing" {
		return nil, false, ErrDocumentRevisedDuringFinalize
	}
	if e == nil || e.WorkRuntime == nil || claim == nil || claim.operation == nil || claim.operation.factory != e.WorkRuntime.SessionsV1() || serialization == nil {
		return nil, false, ErrSigningAdmissionUnavailableV1
	}
	reference, err := serialization.NewStageReferenceV1(ctx, claim.operation.native)
	if err != nil {
		return nil, false, blockSignatureFailureV1(err)
	}
	if err = reference.MatchesDocumentV1(ctx, claim.operation.factory, doc); err != nil {
		return nil, false, blockSignatureFailureV1(err)
	}
	return e.resumeDocumentFinalizationScopeOwnedV1(ctx, conn, doc.OrgID, doc.ID, capture, claim, reference)
}
