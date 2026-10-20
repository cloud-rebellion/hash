// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/subtle"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
	"unsafe"
)

// Checkpoints have no source/body policy work: the original fixed parent state
// header and actual locked full intent are sufficient. This purpose cannot read
// models/parties/roles/signatures or become a Claim/Stage source.
func (w *ApplicationHTMLSendWorkV1) historicalFinalizationIntentStateV1(call context.Context) (*applicationHistoricalFinalizationV1, error) {
	if w.stage == nil || (w.stage.purpose != HTMLHistoricalFinalizationCheckpointV1 && w.stage.purpose != HTMLHistoricalFinalizationResumeV1 && w.stage.purpose != HTMLHistoricalFinalizationEvidenceV1 && w.stage.purpose != htmlHistoricalFinalizationPublicationPurposeV1) {
		return w.historicalFinalizationStateV1(call)
	}
	if !w.valid(call) || w.familyRoot != nil || w.state == nil || w.state.BoundedStatus != "finalizing" {
		return nil, ErrHTMLSendWorkV1
	}
	if w.finalization != nil {
		return w.finalization, nil
	}
	raw := 2*int64(unsafe.Sizeof(applicationHistoricalFinalizationV1{})) + 8*int64(unsafe.Sizeof(uintptr(0))) + 2*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationIntentReadHeaderV1Row{})) + 2*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationIntentReadHeaderV1Params{})) + 2*int64(unsafe.Sizeof(generated.MarkDocumentFinalizationRetentionStartedParams{})) + 2*int64(unsafe.Sizeof(generated.MarkDocumentFinalizationRetentionCompleteParams{})) + 2*int64(unsafe.Sizeof(generated.MarkDocumentFinalizationAttemptFailedParams{})) + 2*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationSignatureReadHeaderV1Row{})) + 2*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationSignatureReadHeaderV1Params{})) + 2*int64(unsafe.Sizeof(generated.LockHistoricalFinalizationSignatureRowsV1Params{})) + 2*int64(unsafe.Sizeof(generated.CreateDocumentFinalizationIntentParams{}))
	closeState, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeState)
	w.finalization = &applicationHistoricalFinalizationV1{}
	return w.finalization, nil
}
func historicalFinalizationSameIntentV1(a, b *generated.DocumentFinalizationIntent) bool {
	if a == nil || b == nil {
		return false
	}
	p := generated.CreateDocumentFinalizationIntentParams{DocumentID: b.DocumentID, OrgID: b.OrgID, Mode: b.Mode, CompletionEffectiveAt: b.CompletionEffectiveAt, RetainUntil: b.RetainUntil, FinalPdfKey: b.FinalPdfKey, FinalPdfSha256: b.FinalPdfSha256, FinalPdfVersionID: b.FinalPdfVersionID, AuditCertKey: b.AuditCertKey, AuditCertSha256: b.AuditCertSha256, AuditCertVersionID: b.AuditCertVersionID, AuditPayloadKey: b.AuditPayloadKey, AuditPayloadSha256: b.AuditPayloadSha256, AuditPayloadVersionID: b.AuditPayloadVersionID, AuditSignatureKey: b.AuditSignatureKey, AuditSignatureSha256: b.AuditSignatureSha256, AuditSignatureVersionID: b.AuditSignatureVersionID}
	return historicalFinalizationIntentMatchesV1(a, p) && a.EvidenceVersionPinsRequired == b.EvidenceVersionPinsRequired && a.FittedPreparationID == b.FittedPreparationID && a.FitsIndexStorageKey == b.FitsIndexStorageKey && a.FitsIndexVersionID == b.FitsIndexVersionID && subtle.ConstantTimeCompare(a.FitsIndexSha256, b.FitsIndexSha256) == 1 && a.FitsIndexBytes == b.FitsIndexBytes
}

// Each actual phase can dispatch one fixed checkpoint only. Counter/error and
// checkpoint timestamp changes are intentionally excluded from legal tuple
// comparison, matching the original retryable marker queries.
func (w *ApplicationHTMLSendWorkV1) historicalFinalizationCheckpointV1(call context.Context, expected *generated.DocumentFinalizationIntent, kind uint8, message string) (int64, error) {
	if w == nil || w.self != w {
		return 0, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state, err := w.historicalFinalizationIntentStateV1(call)
	if err != nil {
		return 0, err
	}
	if w.stage.purpose != HTMLHistoricalFinalizationCheckpointV1 || !state.intentRead || state.checkpointAttempted || !historicalFinalizationSameIntentV1(state.intent, expected) {
		return 0, ErrHTMLSendWorkV1
	}
	state.checkpointAttempted = true
	switch kind {
	case 1:
		return w.queries.MarkDocumentFinalizationRetentionStarted(call, generated.MarkDocumentFinalizationRetentionStartedParams{DocumentID: state.intent.DocumentID, OrgID: state.intent.OrgID})
	case 2:
		return w.queries.MarkDocumentFinalizationRetentionComplete(call, generated.MarkDocumentFinalizationRetentionCompleteParams{DocumentID: state.intent.DocumentID, OrgID: state.intent.OrgID})
	case 3:
		if len(message) > 2048 {
			return 0, ErrHTMLSendWorkV1
		}
		closeMessage, err := w.actor.acquireOwnedRetainedBodyV1(call, int64(len(message))+2*int64(unsafe.Sizeof(generated.MarkDocumentFinalizationAttemptFailedParams{})), int64(len(message)))
		if err != nil {
			return 0, err
		}
		w.closes = append(w.closes, closeMessage)
		return w.queries.MarkDocumentFinalizationAttemptFailed(call, generated.MarkDocumentFinalizationAttemptFailedParams{DocumentID: state.intent.DocumentID, OrgID: state.intent.OrgID, LastError: pgtype.Text{String: message, Valid: true}})
	default:
		return 0, ErrHTMLSendWorkV1
	}
}
func (w *ApplicationHTMLSendWorkV1) MarkHistoricalFinalizationRetentionStartedV1(call context.Context, expected *generated.DocumentFinalizationIntent) (int64, error) {
	return w.historicalFinalizationCheckpointV1(call, expected, 1, "")
}
func (w *ApplicationHTMLSendWorkV1) MarkHistoricalFinalizationRetentionCompleteV1(call context.Context, expected *generated.DocumentFinalizationIntent) (int64, error) {
	return w.historicalFinalizationCheckpointV1(call, expected, 2, "")
}
func (w *ApplicationHTMLSendWorkV1) MarkHistoricalFinalizationAttemptFailedV1(call context.Context, expected *generated.DocumentFinalizationIntent, message string) (int64, error) {
	return w.historicalFinalizationCheckpointV1(call, expected, 3, message)
}
