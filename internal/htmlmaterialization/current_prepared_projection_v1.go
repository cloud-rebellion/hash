// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlmaterialization

import (
	"bytes"
	"encoding/hex"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
)

// ValidateCurrentReadProjectionPreparedV1 keeps the original complete Current
// tuple/report/source decisions while reusing only exact immutable validation
// operations. It grants no SQL, scope, cache, body, deadline or mutation authority.
// A transport-different row source needs its OWN original-document validation;
// a row's claimed commitment alone never substitutes that validation.
func ValidateCurrentReadProjectionPreparedV1(doc *generated.Document, row *CurrentReadProjectionV1, validated, rowValidated *htmlsource.RevisionValidationV1) error {
	if validated == nil || !validated.MatchesDocumentV1(doc) {
		return htmlsource.ErrInvalid
	}
	required, err := ValidateCurrentReadProjectionMetadataPreparedV1(doc, row, validated)
	if err != nil || !required {
		return err
	}
	commitment, err := validated.CommitmentV1()
	if err != nil {
		return err
	}
	check := *doc
	check.HtmlCurrentSourceJson = row.SourceJson
	if rowValidated == nil || !rowValidated.MatchesDocumentV1(&check) {
		return ErrInvalid
	}
	rowCommitment, err := rowValidated.CommitmentV1()
	if err != nil || rowCommitment != commitment {
		return ErrInvalid
	}
	return nil
}

// The native owner uses this exact original metadata/report prefix BEFORE
// separately validating a transport-different actual row source. The boolean
// only reports whether the original legacy Current path has a row source.
// It grants no source validity or work authority.
func ValidateCurrentReadProjectionMetadataPreparedV1(doc *generated.Document, row *CurrentReadProjectionV1, validated *htmlsource.RevisionValidationV1) (bool, error) {
	if validated == nil || !validated.MatchesDocumentV1(doc) {
		return false, htmlsource.ErrInvalid
	}
	commitment, err := validated.CommitmentV1()
	if err != nil {
		return false, err
	}
	if !doc.HtmlCurrentMaterializationID.Valid {
		if row != nil {
			return false, ErrInvalid
		}
		return false, nil
	}
	origin, err := validated.OriginCommitmentV1()
	if err != nil || row == nil || row.ID != uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) || row.DocumentID != doc.ID || row.OrgID != doc.OrgID ||
		row.Sequence != doc.HtmlCurrentMaterializationSequence.Int32 || row.PageCount != doc.HtmlCurrentPageCount.Int32 ||
		row.PdfKey != doc.PdfStorageKey.String || row.PdfVersionID != doc.PdfStorageVersionID.String || !bytes.Equal(row.PdfSha256, doc.PdfSha256) ||
		hex.EncodeToString(row.SourceCommitment) != commitment || hex.EncodeToString(row.OriginCommitment) != origin {
		return false, ErrInvalid
	}
	if len(row.MetadataRedactionReport) > 0 && !bytes.Equal(row.MetadataRedactionReport, doc.MetadataRedactionReport) {
		return false, ErrInvalid
	}
	if err := validateMaterializationReport(row.MetadataRedactionReport, row.PdfSha256, row.PageCount); err != nil {
		return false, err
	}
	return true, nil
}
