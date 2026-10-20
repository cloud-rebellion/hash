// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Pure canonical original prepared Send comparison; this boolean creates no
// native source, SQL, body, provider or completion authority.
func HTMLSendPreparedDocumentEqualV1(prepared, locked *generated.Document) bool {
	if prepared == nil || locked == nil || prepared.ID != locked.ID || prepared.OrgID != locked.OrgID {
		return false
	}
	if prepared.Name != locked.Name || prepared.Status != locked.Status || prepared.SenderID != locked.SenderID ||
		prepared.SourceKind != locked.SourceKind || prepared.RoutingMode != locked.RoutingMode ||
		prepared.RoutingTier != locked.RoutingTier || prepared.RequiresSignature != locked.RequiresSignature ||
		prepared.IsEnvelope != locked.IsEnvelope || prepared.DefaultLocale != locked.DefaultLocale ||
		prepared.BilingualTargetLang != locked.BilingualTargetLang || prepared.LawfulBasis != locked.LawfulBasis ||
		prepared.NegotiationEnabled != locked.NegotiationEnabled ||
		prepared.RenderedPdfKey != locked.RenderedPdfKey || prepared.PdfStorageKey != locked.PdfStorageKey ||
		prepared.RenderedPdfVersionID != locked.RenderedPdfVersionID || prepared.PdfStorageVersionID != locked.PdfStorageVersionID ||
		prepared.EvidenceVersionPinsRequired != locked.EvidenceVersionPinsRequired ||
		prepared.ParentEnvelopeID != locked.ParentEnvelopeID || prepared.EnvelopePosition != locked.EnvelopePosition ||
		!bytes.Equal(prepared.BlocksJson, locked.BlocksJson) ||
		!bytes.Equal(prepared.VariablesJson, locked.VariablesJson) ||
		!bytes.Equal(prepared.Metadata, locked.Metadata) ||
		!bytes.Equal(prepared.HtmlSourceJson, locked.HtmlSourceJson) ||
		!bytes.Equal(prepared.HtmlCurrentSourceJson, locked.HtmlCurrentSourceJson) ||
		prepared.HtmlCurrentMaterializationID != locked.HtmlCurrentMaterializationID ||
		prepared.HtmlCurrentMaterializationSequence != locked.HtmlCurrentMaterializationSequence ||
		prepared.HtmlCurrentPageCount != locked.HtmlCurrentPageCount ||
		prepared.HtmlEffectiveSourceCommitment != locked.HtmlEffectiveSourceCommitment ||
		prepared.HtmlReviewedMaterializationID != locked.HtmlReviewedMaterializationID ||
		!bytes.Equal(prepared.HtmlReviewedPdfSha256, locked.HtmlReviewedPdfSha256) ||
		prepared.HtmlReviewedBy != locked.HtmlReviewedBy ||
		prepared.HtmlReviewedAt.Valid != locked.HtmlReviewedAt.Valid ||
		prepared.HtmlReviewedAt.InfinityModifier != locked.HtmlReviewedAt.InfinityModifier ||
		(prepared.HtmlReviewedAt.Valid && !prepared.HtmlReviewedAt.Time.Equal(locked.HtmlReviewedAt.Time)) ||
		!bytes.Equal(prepared.RenderedPdfSha, locked.RenderedPdfSha) ||
		!bytes.Equal(prepared.PdfSha256, locked.PdfSha256) ||
		prepared.ExpiresAt.Valid != locked.ExpiresAt.Valid ||
		(prepared.ExpiresAt.Valid && !prepared.ExpiresAt.Time.Equal(locked.ExpiresAt.Time)) {
		return false
	}
	return true
}
