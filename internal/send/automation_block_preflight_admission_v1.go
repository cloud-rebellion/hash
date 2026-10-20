// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
)

var ErrAutomationBlockAdmissionV1 = errors.New("automation block preflight admission unavailable")

// This error preserves the original public preflight text/category and the
// genuine numeric-admission refusal identity across the original %v wrappers.
type automationBlockPreflightFailureV1 struct{ original, cause error }

func (e automationBlockPreflightFailureV1) Error() string   { return e.original.Error() }
func (e automationBlockPreflightFailureV1) Unwrap() []error { return []error{e.original, e.cause} }

// ValidateAutomationBlockRequestWithAdmissionV1 preserves the original plain
// blocks preflight order and grammar. It issues no Document/Tx/credential or
// native authority. The actual producer must independently own the original
// immutable raw input, parsed/result/party storage and this hook's real decimal
// high-water through final use before invoking this fixed pure operation.
func ValidateAutomationBlockRequestWithAdmissionV1(blockTree, variablesJSON []byte, values []recipients.Values, admission blocks.ConditionalSendAdmissionV1) error {
	if admission == nil {
		return ErrAutomationBlockAdmissionV1
	}
	tree, err := blocks.ParseCanonicalTreeForSendV1(blockTree, admission)
	if err != nil {
		return automationBlockPreflightFailureV1{fmt.Errorf("%w: invalid block tree", ErrUnresolvedVariables), err}
	}
	if withdrawnBuiltInLegalDraft(tree) {
		return ErrUnsafeBuiltInLegalDraft
	}
	if _, err = blocks.ValidateResolvedVariableValuesForSendV1(tree, variablesJSON, admission); err != nil {
		return automationBlockPreflightFailureV1{fmt.Errorf("%w: %v", ErrUnresolvedVariables, err), err}
	}
	persisted := make([]*generated.Recipient, 0, len(values))
	for _, value := range values {
		persisted = append(persisted, &generated.Recipient{Role: value.Role, Email: value.Email, Name: value.Name, OrderIndex: value.OrderIndex, Locale: value.Locale, Status: "pending"})
	}
	// The original constructed automation preflight has no HTML provenance or
	// envelope. Its two HTML-only checks are necessarily no-ops; no fake model
	// is used here to grant source, review or persistence authority.
	for _, rec := range persisted {
		if err = recipients.ValidatePersisted(recipients.Values{Email: rec.Email, Name: rec.Name, Role: rec.Role, OrderIndex: rec.OrderIndex, Locale: rec.Locale}); err != nil {
			return fmt.Errorf("%w: recipient %s: %v", ErrInvalidRecipient, rec.ID, err)
		}
		if rec.Role == "cc" || rec.Role == "viewer" {
			return fmt.Errorf("%w: recipient %s uses role %s", ErrUnsupportedRecipientRole, rec.ID, rec.Role)
		}
	}
	// Repeat the original separate recipient-stage canonical parse. Reusing an
	// earlier result could change its original guard/format/error ordering.
	tree, err = blocks.ParseCanonicalTreeForSendV1(blockTree, admission)
	if err != nil {
		return automationBlockPreflightFailureV1{fmt.Errorf("send document: parse blocks: %w", err), err}
	}
	if err = validateImmutableBlockEvidence(tree); err != nil {
		return fmt.Errorf("send document: %w", err)
	}
	resolved, err := blocks.ParseVariableValues(variablesJSON)
	if err != nil {
		return fmt.Errorf("send document: variables: %w", err)
	}
	roles, err := blocks.RequiredSignerRolesForVariablesForSendV1(tree, resolved, admission)
	if err != nil {
		return automationBlockPreflightFailureV1{fmt.Errorf("send document: signer roles: %w", err), err}
	}
	if len(roles) == 0 {
		return ErrNoSignatureFields
	}
	eligible := 0
	for _, rec := range persisted {
		if recipientEligibleForSend(rec) && rec.Role != "cc" {
			eligible++
		}
	}
	if eligible == 0 {
		return ErrNoSigners
	}
	return validateRequiredRoles(roles, persisted)
}
