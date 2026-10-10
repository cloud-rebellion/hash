// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import "github.com/bright-interaction/hash/internal/db/generated"

// Preserve the existing envelope metadata API without loading a child's
// embedded HTML source or changing the full-content lifecycle readers.
func envelopeMetadataRow(row *generated.ListEnvelopeChildMetadataForReadRow) map[string]any {
	return envelopeRow(&generated.Document{
		ID:               row.ID,
		Name:             row.Name,
		Status:           row.Status,
		SourceKind:       row.SourceKind,
		IsEnvelope:       row.IsEnvelope,
		CreatedAt:        row.CreatedAt,
		ParentEnvelopeID: row.ParentEnvelopeID,
		EnvelopePosition: row.EnvelopePosition,
		FinalPdfKey:      row.FinalPdfKey,
		FinalPdfSha:      row.FinalPdfSha,
		CompletedAt:      row.CompletedAt,
	})
}
