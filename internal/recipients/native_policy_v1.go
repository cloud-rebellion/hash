// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package recipients

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

// MutationDependenciesAvailableV1 preserves the original canonical typed-nil
// dependency decision for the fixed native leaf adapter. It grants no actor,
// transaction, source or permission authority.
func MutationDependenciesAvailableV1(engine *MutationEngine) bool {
	return engine != nil && !nilMutationDependency(engine.Pool) && !nilMutationDependency(engine.Audit)
}

// ValidateContractRecipientUpdateV1 shares the exact original printed-party
// policy with the native leaf adapter; no parser, grammar or policy is copied.
func ValidateContractRecipientUpdateV1(parties []htmlsource.ContractParty, existing *generated.Recipient, values Values) error {
	return validateContractRecipientUpdate(parties, existing, values)
}
