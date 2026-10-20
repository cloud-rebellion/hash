// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"errors"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// ErrSigningAdmissionUnavailableV1 closes the legacy route while a document's
// immutable PDF admission driver is unavailable. No pending response or legacy
// signature/finalization fallback is authorized by installing the SQL policy.
var ErrSigningAdmissionUnavailableV1 = errors.New("document signing admission is unavailable")

// requireHistoricalSigningAdmissionV1 is temporary route closure, not admission
// to the future fitted driver. Only the exact database historical default may
// enter the legacy preparation, storage and finalization path. Missing/unknown
// policy is never permission. Mutation callers repeat this check on the actual
// locked row after an earlier magic-link lookup or read observation.
func requireHistoricalSigningAdmissionV1(doc *generated.Document) error {
	if doc == nil || doc.SigningAdmissionPolicy != "historical" {
		return ErrSigningAdmissionUnavailableV1
	}
	return nil
}
