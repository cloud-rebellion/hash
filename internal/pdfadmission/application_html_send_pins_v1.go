// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// The full immutable legal/source tuple remains identical. Only the actual
// first-party evidence observations and the original SQL's pin/timestamp fields
// may change; concurrent idempotent pinning retains its original SQL semantics.
func htmlSendPinnedBytesEqualV1(a, b []byte) bool {
	return (a == nil) == (b == nil) && bytes.Equal(a, b)
}
func htmlSendEvidencePinnedTupleEqualV1(a, b *generated.Document) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.ID != b.ID {
		return false
	}
	if a.OrgID != b.OrgID {
		return false
	}
	if a.TemplateID != b.TemplateID {
		return false
	}
	if a.Name != b.Name {
		return false
	}
	if a.Status != b.Status {
		return false
	}
	if a.RoutingMode != b.RoutingMode {
		return false
	}
	if a.SourceKind != b.SourceKind {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.BlocksJson, b.BlocksJson) {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.VariablesJson, b.VariablesJson) {
		return false
	}
	if a.RenderedPdfKey != b.RenderedPdfKey {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.RenderedPdfSha, b.RenderedPdfSha) {
		return false
	}
	if a.PdfStorageKey != b.PdfStorageKey {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.PdfSha256, b.PdfSha256) {
		return false
	}
	if a.FinalPdfKey != b.FinalPdfKey {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.FinalPdfSha, b.FinalPdfSha) {
		return false
	}
	if a.AuditCertKey != b.AuditCertKey {
		return false
	}
	if a.ExpiresAt != b.ExpiresAt {
		return false
	}
	if a.SentAt != b.SentAt {
		return false
	}
	if a.CompletedAt != b.CompletedAt {
		return false
	}
	if a.SenderID != b.SenderID {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.Metadata, b.Metadata) {
		return false
	}
	if a.CreatedAt != b.CreatedAt {
		return false
	}
	if a.ParentEnvelopeID != b.ParentEnvelopeID {
		return false
	}
	if a.EnvelopePosition != b.EnvelopePosition {
		return false
	}
	if a.IsEnvelope != b.IsEnvelope {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.MetadataRedactionReport, b.MetadataRedactionReport) {
		return false
	}
	if a.RoutingTier != b.RoutingTier {
		return false
	}
	if a.NegotiationEnabled != b.NegotiationEnabled {
		return false
	}
	if a.BilingualTargetLang != b.BilingualTargetLang {
		return false
	}
	if a.LawfulBasis != b.LawfulBasis {
		return false
	}
	if a.DeletedAt != b.DeletedAt {
		return false
	}
	if a.DefaultLocale != b.DefaultLocale {
		return false
	}
	if a.RequiresSignature != b.RequiresSignature {
		return false
	}
	if a.AuditPayloadKey != b.AuditPayloadKey {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.AuditPayloadSha256, b.AuditPayloadSha256) {
		return false
	}
	if a.AuditSignatureKey != b.AuditSignatureKey {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.AuditSignatureSha256, b.AuditSignatureSha256) {
		return false
	}
	if a.FinalPdfVersionID != b.FinalPdfVersionID {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.AuditCertSha256, b.AuditCertSha256) {
		return false
	}
	if a.AuditCertVersionID != b.AuditCertVersionID {
		return false
	}
	if a.AuditPayloadVersionID != b.AuditPayloadVersionID {
		return false
	}
	if a.AuditSignatureVersionID != b.AuditSignatureVersionID {
		return false
	}
	if a.CompletionEffectiveAt != b.CompletionEffectiveAt {
		return false
	}
	if a.CompletionEffectiveAtBound != b.CompletionEffectiveAtBound {
		return false
	}
	if a.FinalizationRetainUntil != b.FinalizationRetainUntil {
		return false
	}
	if a.Article13NoticeEpochAt != b.Article13NoticeEpochAt {
		return false
	}
	if a.Article13NoticeSchema != b.Article13NoticeSchema {
		return false
	}
	if a.Article13NoticeEpochV61Committed != b.Article13NoticeEpochV61Committed {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.HtmlSourceJson, b.HtmlSourceJson) {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.HtmlReviewedPdfSha256, b.HtmlReviewedPdfSha256) {
		return false
	}
	if a.HtmlReviewedBy != b.HtmlReviewedBy {
		return false
	}
	if a.HtmlReviewedAt != b.HtmlReviewedAt {
		return false
	}
	if a.HtmlCurrentMaterializationID != b.HtmlCurrentMaterializationID {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.HtmlCurrentSourceJson, b.HtmlCurrentSourceJson) {
		return false
	}
	if a.HtmlCurrentPageCount != b.HtmlCurrentPageCount {
		return false
	}
	if a.HtmlCurrentMaterializationSequence != b.HtmlCurrentMaterializationSequence {
		return false
	}
	if a.HtmlReviewedMaterializationID != b.HtmlReviewedMaterializationID {
		return false
	}
	if a.HtmlEffectiveSourceCommitment != b.HtmlEffectiveSourceCommitment {
		return false
	}
	if a.SignatureFitReservedBytes != b.SignatureFitReservedBytes {
		return false
	}
	if a.FitsIndexRequired != b.FitsIndexRequired {
		return false
	}
	if a.FitsIndexPreparationID != b.FitsIndexPreparationID {
		return false
	}
	if a.FitsIndexStorageKey != b.FitsIndexStorageKey {
		return false
	}
	if a.FitsIndexVersionID != b.FitsIndexVersionID {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.FitsIndexSha256, b.FitsIndexSha256) {
		return false
	}
	if a.FitsIndexBytes != b.FitsIndexBytes {
		return false
	}
	if a.SignatureFitOriginalPayloadBytes != b.SignatureFitOriginalPayloadBytes {
		return false
	}
	if a.SignatureFitOriginalAuthorityBytes != b.SignatureFitOriginalAuthorityBytes {
		return false
	}
	if a.SignatureFitOriginalAuthorityCount != b.SignatureFitOriginalAuthorityCount {
		return false
	}
	if a.ParticipantReportSchema != b.ParticipantReportSchema {
		return false
	}
	if a.SigningAdmissionPolicy != b.SigningAdmissionPolicy {
		return false
	}
	if a.SigningAdmissionActiveID != b.SigningAdmissionActiveID {
		return false
	}
	if a.SigningAdmissionSealedID != b.SigningAdmissionSealedID {
		return false
	}
	if a.SigningAdmissionCount != b.SigningAdmissionCount {
		return false
	}
	if a.SigningAdmissionStaticBytes != b.SigningAdmissionStaticBytes {
		return false
	}
	if a.SigningAdmissionOrdinaryBytes != b.SigningAdmissionOrdinaryBytes {
		return false
	}
	if a.SigningAdmissionPlanBytes != b.SigningAdmissionPlanBytes {
		return false
	}
	if a.SignatureFitRequestBindingBytes != b.SignatureFitRequestBindingBytes {
		return false
	}
	if a.SignatureFitRequestBindingCount != b.SignatureFitRequestBindingCount {
		return false
	}
	return true
}

func (w *ApplicationHTMLSendWorkV1) PinEvidenceVersionsV1(call context.Context, evidence *ApplicationHTMLSendEvidenceV1) (*generated.Document, error) {
	if w == nil || w.self != w || evidence == nil {
		return nil, ErrHTMLSendWorkV1
	}
	pdfVersion, renderedVersion, err := evidence.pinsForWorkV1(w)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLSendPinV1 || (w.sourceStarted && (w.familyRoot == nil || w.priorPinnedSource != nil)) || w.sourceDocument == nil || w.models == nil || w.pinsAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	w.pinsAttempted = true
	extra, err := htmlAuthoringSumV1(int64(len(pdfVersion.String)), int64(len(renderedVersion.String)))
	if err != nil {
		return nil, err
	}
	raw, _, err := w.admitDocumentReturnV1(call, extra)
	if err != nil {
		return nil, err
	}
	s := w.session.state
	row, err := w.queries.PinDocumentSendEvidenceVersions(call, generated.PinDocumentSendEvidenceVersionsParams{PdfStorageVersionID: pdfVersion, RenderedPdfVersionID: renderedVersion, ID: w.logicalDocumentV1(), OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if !w.verifyDocumentReturnV1(row, raw) || !htmlSendEvidencePinnedTupleEqualV1(w.sourceDocument, row) || !row.EvidenceVersionPinsRequired || row.PdfStorageVersionID != pdfVersion || row.RenderedPdfVersionID != renderedVersion {
		return nil, ErrHTMLSendWorkV1
	}
	if w.sourceStarted {
		w.priorPinnedSource = w.sourceState
		w.sourceOwner = nil
		w.sourceState = nil
		w.sourceStarted = false
		w.reviewedOriginalValidated = false
		w.sourceCurrent = nil
		w.currentRead = false
		w.currentAttempted = false
	}
	w.sourceDocument = htmlSendCloneDocumentV1(row)
	w.models.Document = row
	w.state.UpdatedAt = row.UpdatedAt
	w.pinsCompleted = true
	return row, nil
}
