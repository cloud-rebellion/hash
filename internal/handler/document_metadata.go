// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import "github.com/bright-interaction/hash/internal/db/generated"

// Metadata reads deliberately never load either embedded HTML design. Origin
// and review state must therefore come from the explicit SQL flags, rather
// than being inferred from missing source bytes in this response projection.
func toDocumentMetadataResponse(d *generated.ListDocumentMetadataForRESTRow) documentResponse {
	out := toDocumentResponse(&generated.Document{
		ID: d.ID, OrgID: d.OrgID, TemplateID: d.TemplateID, Name: d.Name,
		Status: d.Status, RoutingMode: d.RoutingMode, SourceKind: d.SourceKind,
		RequiresSignature: d.RequiresSignature, BlocksJson: d.BlocksJson,
		VariablesJson: d.VariablesJson, PdfStorageKey: d.PdfStorageKey,
		PdfSha256: d.PdfSha256, FinalPdfKey: d.FinalPdfKey, AuditCertKey: d.AuditCertKey,
		ExpiresAt: d.ExpiresAt, SentAt: d.SentAt, CompletedAt: d.CompletedAt,
		SenderID: d.SenderID, Metadata: d.Metadata, DefaultLocale: d.DefaultLocale,
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	})
	out.HasHTMLSource = d.HasHtmlSource
	out.HTMLReviewRequired = d.HtmlReviewRequired
	if out.HasHTMLSource {
		out.HTMLSourceCommitment = d.HtmlEffectiveSourceCommitment.String
		out.HTMLMaterializationRevision = 1
		if d.HtmlCurrentMaterializationSequence.Valid {
			out.HTMLMaterializationRevision = d.HtmlCurrentMaterializationSequence.Int32
		}
	}
	return out
}

func toEnvelopeChildMetadataResponse(d *generated.ListEnvelopeChildMetadataForReadRow) documentResponse {
	// sqlc's equal row layouts make this conversion fail at compile time if
	// the two read projections drift, instead of silently losing a column.
	return toDocumentMetadataResponse((*generated.ListDocumentMetadataForRESTRow)(d))
}
