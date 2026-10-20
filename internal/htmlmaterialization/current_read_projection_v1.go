// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaterialization

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
)

// CurrentReadProjectionV1 contains every field used to validate the current
// normalized HTML source and exact PDF. Public reads do not decode unrelated
// history descriptions, changed-section arrays or attribution. This explicit
// type is a value projection, never an abbreviated full history model, source
// approval, work loan or current-signing permission.
type CurrentReadProjectionV1 struct {
	ID, DocumentID, OrgID                         uuid.UUID
	Sequence, PageCount                           int32
	PdfKey, PdfVersionID                          string
	PdfSha256, SourceCommitment, OriginCommitment []byte
	SourceJson, MetadataRedactionReport           json.RawMessage
}

func currentReadProjectionV1(row *generated.HtmlDocumentMaterialization) *CurrentReadProjectionV1 {
	if row == nil {
		return nil
	}
	return &CurrentReadProjectionV1{ID: row.ID, DocumentID: row.DocumentID, OrgID: row.OrgID, Sequence: row.Sequence, PageCount: row.PageCount, PdfKey: row.PdfKey, PdfVersionID: row.PdfVersionID, PdfSha256: row.PdfSha256, SourceCommitment: row.SourceCommitment, OriginCommitment: row.OriginCommitment, SourceJson: row.SourceJson, MetadataRedactionReport: row.MetadataRedactionReport}
}

// ValidateCurrentReadProjectionV1 shares the actual Current validation body.
// Callers first acquire a real body loan from locked actual M91/M93 headers;
// validation does not invent size bounds or attest SQL/actor/controller origin.
func ValidateCurrentReadProjectionV1(doc *generated.Document, row *CurrentReadProjectionV1) error {
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		return err
	}
	if !doc.HtmlCurrentMaterializationID.Valid {
		if row != nil {
			return ErrInvalid
		}
		return nil
	}
	return validateCurrentReadProjectionV1(doc, row, commitment)
}
func validateCurrentReadProjectionV1(doc *generated.Document, row *CurrentReadProjectionV1, commitment string) error {
	origin, err := htmlsource.OriginCommitment(doc)
	if err != nil || row == nil || row.ID != uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) || row.DocumentID != doc.ID || row.OrgID != doc.OrgID ||
		row.Sequence != doc.HtmlCurrentMaterializationSequence.Int32 || row.PageCount != doc.HtmlCurrentPageCount.Int32 ||
		row.PdfKey != doc.PdfStorageKey.String || row.PdfVersionID != doc.PdfStorageVersionID.String || !bytes.Equal(row.PdfSha256, doc.PdfSha256) ||
		hex.EncodeToString(row.SourceCommitment) != commitment || hex.EncodeToString(row.OriginCommitment) != origin {
		return ErrInvalid
	}
	// Rows predating persisted report provenance may be NULL. Preserve their
	// current legacy behavior, but a report retained on a row must be projected
	// with that exact PDF rather than independently replaced.
	if len(row.MetadataRedactionReport) > 0 && !bytes.Equal(row.MetadataRedactionReport, doc.MetadataRedactionReport) {
		return ErrInvalid
	}
	if err := validateMaterializationReport(row.MetadataRedactionReport, row.PdfSha256, row.PageCount); err != nil {
		return err
	}
	check := *doc
	check.HtmlCurrentSourceJson = bytes.Clone(row.SourceJson)
	rowCommitment, err := htmlsource.Commitment(&check)
	if err != nil || rowCommitment != commitment {
		return ErrInvalid
	}
	return nil
}
