// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlsource

import (
	"bytes"
	"github.com/bright-interaction/hash/internal/db/generated"
	"strings"
)

// Explicit generated.Document inventory: all 39 variable fields are
// detached, and all 81 fields bind this exact native row representation.
// Timestamp location/monotonic representation is deliberately exact here;
// approval/review decision methods still use the original Time comparisons.
// The pure value supplies no native authority; native Current12 pins remain
// separately required. No reflection or JSON serialization forms these pins.
func cloneRevisionDocumentV1(in *generated.Document) *generated.Document {
	if in == nil {
		return nil
	}
	out := *in
	out.Name = strings.Clone(in.Name)
	out.Status = strings.Clone(in.Status)
	out.RoutingMode = strings.Clone(in.RoutingMode)
	out.SourceKind = strings.Clone(in.SourceKind)
	out.BlocksJson = bytes.Clone(in.BlocksJson)
	out.VariablesJson = bytes.Clone(in.VariablesJson)
	out.RenderedPdfKey.String = strings.Clone(in.RenderedPdfKey.String)
	out.RenderedPdfSha = bytes.Clone(in.RenderedPdfSha)
	out.PdfStorageKey.String = strings.Clone(in.PdfStorageKey.String)
	out.PdfSha256 = bytes.Clone(in.PdfSha256)
	out.FinalPdfKey.String = strings.Clone(in.FinalPdfKey.String)
	out.FinalPdfSha = bytes.Clone(in.FinalPdfSha)
	out.AuditCertKey.String = strings.Clone(in.AuditCertKey.String)
	out.Metadata = bytes.Clone(in.Metadata)
	out.MetadataRedactionReport = bytes.Clone(in.MetadataRedactionReport)
	out.RoutingTier = strings.Clone(in.RoutingTier)
	out.BilingualTargetLang = strings.Clone(in.BilingualTargetLang)
	out.LawfulBasis = strings.Clone(in.LawfulBasis)
	out.DefaultLocale = strings.Clone(in.DefaultLocale)
	out.AuditPayloadKey.String = strings.Clone(in.AuditPayloadKey.String)
	out.AuditPayloadSha256 = bytes.Clone(in.AuditPayloadSha256)
	out.AuditSignatureKey.String = strings.Clone(in.AuditSignatureKey.String)
	out.AuditSignatureSha256 = bytes.Clone(in.AuditSignatureSha256)
	out.PdfStorageVersionID.String = strings.Clone(in.PdfStorageVersionID.String)
	out.RenderedPdfVersionID.String = strings.Clone(in.RenderedPdfVersionID.String)
	out.FinalPdfVersionID.String = strings.Clone(in.FinalPdfVersionID.String)
	out.AuditCertSha256 = bytes.Clone(in.AuditCertSha256)
	out.AuditCertVersionID.String = strings.Clone(in.AuditCertVersionID.String)
	out.AuditPayloadVersionID.String = strings.Clone(in.AuditPayloadVersionID.String)
	out.AuditSignatureVersionID.String = strings.Clone(in.AuditSignatureVersionID.String)
	out.Article13NoticeSchema = strings.Clone(in.Article13NoticeSchema)
	out.HtmlSourceJson = bytes.Clone(in.HtmlSourceJson)
	out.HtmlReviewedPdfSha256 = bytes.Clone(in.HtmlReviewedPdfSha256)
	out.HtmlCurrentSourceJson = bytes.Clone(in.HtmlCurrentSourceJson)
	out.HtmlEffectiveSourceCommitment.String = strings.Clone(in.HtmlEffectiveSourceCommitment.String)
	out.FitsIndexStorageKey.String = strings.Clone(in.FitsIndexStorageKey.String)
	out.FitsIndexVersionID.String = strings.Clone(in.FitsIndexVersionID.String)
	out.FitsIndexSha256 = bytes.Clone(in.FitsIndexSha256)
	out.ParticipantReportSchema = strings.Clone(in.ParticipantReportSchema)
	out.SigningAdmissionPolicy = strings.Clone(in.SigningAdmissionPolicy)
	return &out
}
func revisionBytesEqualV1(a, b []byte) bool { return (a == nil) == (b == nil) && bytes.Equal(a, b) }
func revisionDocumentEqualV1(a, b *generated.Document) bool {
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
	if !revisionBytesEqualV1(a.BlocksJson, b.BlocksJson) {
		return false
	}
	if !revisionBytesEqualV1(a.VariablesJson, b.VariablesJson) {
		return false
	}
	if a.RenderedPdfKey != b.RenderedPdfKey {
		return false
	}
	if !revisionBytesEqualV1(a.RenderedPdfSha, b.RenderedPdfSha) {
		return false
	}
	if a.PdfStorageKey != b.PdfStorageKey {
		return false
	}
	if !revisionBytesEqualV1(a.PdfSha256, b.PdfSha256) {
		return false
	}
	if a.FinalPdfKey != b.FinalPdfKey {
		return false
	}
	if !revisionBytesEqualV1(a.FinalPdfSha, b.FinalPdfSha) {
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
	if !revisionBytesEqualV1(a.Metadata, b.Metadata) {
		return false
	}
	if a.CreatedAt != b.CreatedAt {
		return false
	}
	if a.UpdatedAt != b.UpdatedAt {
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
	if !revisionBytesEqualV1(a.MetadataRedactionReport, b.MetadataRedactionReport) {
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
	if !revisionBytesEqualV1(a.AuditPayloadSha256, b.AuditPayloadSha256) {
		return false
	}
	if a.AuditSignatureKey != b.AuditSignatureKey {
		return false
	}
	if !revisionBytesEqualV1(a.AuditSignatureSha256, b.AuditSignatureSha256) {
		return false
	}
	if a.PdfStorageVersionID != b.PdfStorageVersionID {
		return false
	}
	if a.RenderedPdfVersionID != b.RenderedPdfVersionID {
		return false
	}
	if a.FinalPdfVersionID != b.FinalPdfVersionID {
		return false
	}
	if !revisionBytesEqualV1(a.AuditCertSha256, b.AuditCertSha256) {
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
	if a.EvidenceVersionPinsRequired != b.EvidenceVersionPinsRequired {
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
	if !revisionBytesEqualV1(a.HtmlSourceJson, b.HtmlSourceJson) {
		return false
	}
	if !revisionBytesEqualV1(a.HtmlReviewedPdfSha256, b.HtmlReviewedPdfSha256) {
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
	if !revisionBytesEqualV1(a.HtmlCurrentSourceJson, b.HtmlCurrentSourceJson) {
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
	if !revisionBytesEqualV1(a.FitsIndexSha256, b.FitsIndexSha256) {
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
