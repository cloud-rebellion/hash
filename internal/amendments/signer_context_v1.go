// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package amendments

import "github.com/google/uuid"

const SignerContextSchemaV1 = "hash-signer-amendment-context-v1"

// SignerContextV1 is a saved relation disclosure for this exact ordinary fresh
// ceremony. It grants no access to the original agreement's private artifacts,
// and records no consent, signature, acknowledgement or legal effectiveness.
type SignerContextV1 struct {
	Schema                 string    `json:"schema"`
	AmendmentID            uuid.UUID `json:"amendment_id"`
	Revision               string    `json:"revision"`
	DocumentID             uuid.UUID `json:"document_id"`
	OriginalDocumentID     uuid.UUID `json:"original_document_id"`
	OriginalName           string    `json:"original_name"`
	OriginalFinalPDFSHA256 string    `json:"original_final_pdf_sha256"`
	// Canonical mandatory participant-report digest, NOT its rendered PDF digest.
	OriginalReportSHA256    string `json:"original_report_sha256"`
	OriginalReportPDFSHA256 string `json:"original_report_pdf_sha256"`
	Mode                    ModeV1 `json:"mode"`
	FileCommitmentSHA256    string `json:"file_commitment_sha256"`
}
