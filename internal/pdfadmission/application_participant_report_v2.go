// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import "github.com/bright-interaction/hash/internal/render"

// The participant-safe V2 assembler verifies its exact closed canonical HTML
// before signing. This is ADDITIONAL to the original output/prefix/field grant.
// Preflight limits arrays before typed decode. Funding covers all coexisting
// unescape/raw/decoder/canonical/HTML copies, token strings and validation maps,
// including prior passes not yet collected. No input cap or operator limit is
// increased, and no presumed GC retirement is used to justify a smaller grant.
func participantReportParserQuoteV2(total *int64, htmlBytes int, rows int64) bool {
	if total == nil || htmlBytes <= 0 || htmlBytes > render.MaxCertificatePayloadBytesV1 || rows < 0 || rows > render.MaxParticipantReportRowsV1 {
		return false
	}
	return htmlInputAddV1(total, 65536, 1) && htmlInputAddV1(total, int64(htmlBytes), 64) && htmlInputAddV1(total, rows, 8192)
}
