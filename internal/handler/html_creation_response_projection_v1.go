// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/hex"
	"github.com/bright-interaction/hash/internal/db/generated"
	"time"
)

// Explicit response projection preserves every current public field while
// avoiding allocation of an origin/current approved HTML master during replay.
// No generated.Document with fabricated source or approval facts is constructed.
func htmlCreationDocumentProjectionV1(d *generated.ReadHTMLCreationResponseV1Row) documentResponse {
	out := documentResponse{ID: d.ID, OrgID: d.OrgID, Name: d.Name, Status: d.Status, RoutingMode: d.RoutingMode, SourceKind: d.SourceKind,
		RequiresSignature: d.RequiresSignature, BlocksJSON: d.BlocksJson, VariablesJSON: d.VariablesJson, SenderID: d.SenderID,
		Metadata: d.Metadata, DefaultLocale: d.DefaultLocale, CreatedAt: d.CreatedAt.Time.Format(time.RFC3339), UpdatedAt: d.UpdatedAt.Time.UTC().Format(time.RFC3339Nano),
		HasHTMLSource: d.HasHtmlSource, HTMLReviewRequired: d.HtmlReviewRequired}
	if d.HasHtmlSource {
		out.HTMLSourceCommitment = d.HtmlEffectiveSourceCommitment.String
		out.HTMLMaterializationRevision = 1
		if d.HtmlCurrentMaterializationSequence.Valid {
			out.HTMLMaterializationRevision = d.HtmlCurrentMaterializationSequence.Int32
		}
	}
	if d.TemplateID.Valid {
		out.TemplateID = uuidFromBytes(d.TemplateID.Bytes).String()
	}
	if d.PdfStorageKey.Valid {
		out.PDFStorageKey = d.PdfStorageKey.String
	}
	if len(d.PdfSha256) > 0 {
		out.PDFSHA256 = hex.EncodeToString(d.PdfSha256)
	}
	if d.FinalPdfKey.Valid {
		out.FinalPDFKey = d.FinalPdfKey.String
	}
	if d.AuditCertKey.Valid {
		out.AuditCertKey = d.AuditCertKey.String
	}
	if d.ExpiresAt.Valid {
		out.ExpiresAt = d.ExpiresAt.Time.Format(time.RFC3339)
	}
	if d.SentAt.Valid {
		out.SentAt = d.SentAt.Time.Format(time.RFC3339)
	}
	if d.CompletedAt.Valid {
		out.CompletedAt = d.CompletedAt.Time.Format(time.RFC3339)
	}
	return out
}
