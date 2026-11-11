// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package render

import "github.com/bright-interaction/hash/internal/documentpackage"

// New Swedish receipts carry a new immutable statement version. Include its
// exact canonical text in new reports without changing any legacy EN HTML
// serialization or retrospectively relabelling an archived English report.
func participantReportSwedishIncorporationV128(response ParticipantReportResponseV1) string {
	if response.IncorporationVersion != documentpackage.IncorporationVersionSwedishV1 || response.IncorporationSHA256 != documentpackage.IncorporationSHA256SwedishV1 {
		return ""
	}
	return documentpackage.IncorporationTextSwedishV1
}
