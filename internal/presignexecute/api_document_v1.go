// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

// DocumentViewV1 is the staff document's optional `pre_sign` projection.
// Existing pdf_sha256/source/review fields remain the immutable original.
// The authenticated current PDF route uses this exact derivative when the
// relation exists and refuses sealing; it never falls back to the base PDF.
// Retained expired ceremonies remain visible to authorized staff, while the
// customer route separately enforces publication and its live token/status.
type DocumentViewV1 struct {
	SchemaVersion    int                  `json:"schema_version"`
	Execution        ExecutionReferenceV1 `json:"execution"`
	Publication      string               `json:"publication"` // sealing | published | expired | completed
	VisiblePDFSHA256 string               `json:"visible_pdf_sha256"`
	PageCount        int                  `json:"page_count"`
}
