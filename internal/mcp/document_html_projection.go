// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"bytes"
	"encoding/hex"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// HTML designs contain bounded but potentially large inline assets. Repeated
// document listings must not duplicate the origin/current masters per row.
// The document UI's declared-source/history APIs retain deliberate inspection.
func documentReadProjection(doc *generated.Document) *generated.Document {
	if doc == nil || len(doc.HtmlSourceJson) == 0 {
		return doc
	}
	copy := *doc
	copy.HtmlSourceJson = nil
	copy.HtmlCurrentSourceJson = nil
	return &copy
}

func documentListReadProjection(rows []*generated.Document) []*generated.Document {
	out := make([]*generated.Document, len(rows))
	for i, doc := range rows {
		out[i] = documentReadProjection(doc)
	}
	return out
}

func documentMCPListQueryProjection(rows []*generated.ListDocumentsForMCPRow) []*generated.Document {
	out := make([]*generated.Document, len(rows))
	for i, row := range rows {
		out[i] = (*generated.Document)(row)
	}
	return out
}

func documentMCPSearchQueryProjection(rows []*generated.SearchDocumentsByNameForMCPRow) []*generated.Document {
	out := make([]*generated.Document, len(rows))
	for i, row := range rows {
		out[i] = (*generated.Document)(row)
	}
	return out
}

type htmlDocumentReadResponse struct {
	*generated.Document
	HasHTMLSource                bool   `json:"has_html_source"`
	HTMLReviewRequired           bool   `json:"html_review_required"`
	ExpectedPDFSHA256            string `json:"expected_pdf_sha256"`
	ExpectedHTMLSourceCommitment string `json:"expected_html_source_commitment"`
}

func htmlDocumentReadProjection(doc *generated.Document, commitment string) htmlDocumentReadResponse {
	return htmlDocumentReadResponse{Document: documentReadProjection(doc), HasHTMLSource: true,
		HTMLReviewRequired: !bytes.Equal(doc.PdfSha256, doc.HtmlReviewedPdfSha256) || !doc.HtmlReviewedBy.Valid || !doc.HtmlReviewedAt.Valid ||
			(doc.HtmlCurrentMaterializationID.Valid && (!doc.HtmlReviewedMaterializationID.Valid || doc.HtmlCurrentMaterializationID != doc.HtmlReviewedMaterializationID)),
		ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment}
}
