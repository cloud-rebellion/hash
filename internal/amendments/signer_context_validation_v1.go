// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package amendments

import (
	"encoding/hex"
	"github.com/google/uuid"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidateV1 checks this saved disclosure against the SAME actual candidate
// model. It grants no original artifact access or participant-response authority.
func (c *SignerContextV1) ValidateV1(document uuid.UUID, requiresSignature bool) error {
	if c == nil {
		return nil
	} // An ordinary unlinked agreement stays ordinary.
	n, e := RevisionV1(c.Revision)
	if e != nil || n < 1 || c.Schema != SignerContextSchemaV1 || c.AmendmentID == uuid.Nil || document == uuid.Nil || c.DocumentID != document || c.OriginalDocumentID == uuid.Nil || c.OriginalDocumentID == document || !validOriginalNameV1(c.OriginalName) {
		return ErrUnavailableV1
	}
	if c.Mode != SignatureV1 && c.Mode != AcknowledgementV1 || requiresSignature != (c.Mode == SignatureV1) {
		return ErrUnavailableV1
	}
	for _, s := range []string{c.OriginalFinalPDFSHA256, c.OriginalReportSHA256, c.OriginalReportPDFSHA256, c.FileCommitmentSHA256} {
		b, e := hex.DecodeString(s)
		if e != nil || len(b) != 32 || hex.EncodeToString(b) != s {
			return ErrUnavailableV1
		}
	}
	return nil
}
func validOriginalNameV1(s string) bool {
	if len(s) < 1 || len(s) > 512 || !utf8.ValidString(s) || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func CloneSignerContextV1(c *SignerContextV1) *SignerContextV1 {
	if c == nil {
		return nil
	}
	v := *c
	return &v
}
func EqualSignerContextV1(a, b *SignerContextV1) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
