// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package recipients

import "github.com/bright-interaction/hash/internal/db/generated"

// Existing completion eligibility is a pure shared predicate, never admission
// or a token grant. Callers retain their own genuine document/recipient source.
func ReceivesCompletedArtifactV1(requiresSignature bool, rec *generated.Recipient, requiredRoles map[string]struct{}) bool {
	if rec == nil {
		return false
	}
	if !requiresSignature {
		return rec.Role != "cc" && rec.Status == "accepted"
	}
	if rec.Status != "signed" {
		return false
	}
	_, required := requiredRoles[rec.Role]
	return required
}
