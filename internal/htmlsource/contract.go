// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlsource

import (
	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
)

// PartyBinding pins a reviewed party slot to the fresh named recipient created
// for this document. It survives every text revision; changing an identity must
// update its printed values and that same recipient in one draft transaction.
type PartyBinding struct {
	Slot        string    `json:"slot"`
	RecipientID uuid.UUID `json:"recipient_id"`
}

// ContractParty is a declared representative from the current frozen source.
// These assertions are not independent proof of identity or legal authority.
type ContractParty struct {
	Slot        string    `json:"slot"`
	Role        string    `json:"role"`
	RecipientID uuid.UUID `json:"recipient_id"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	CompanyName string    `json:"company_name"`
	CompanyID   string    `json:"company_id"`
	Authority   string    `json:"representative_authority"`
}

func validatePartyBindings(s source, doc *generated.Document) error {
	if s.SchemaVersion == SchemaVersion {
		if len(s.PartyBindings) != 0 {
			return invalid("legacy source cannot carry contract party bindings")
		}
		return nil
	}
	if !doc.RequiresSignature || len(s.PartyBindings) != 2 ||
		s.PartyBindings[0].Slot != "customer" || s.PartyBindings[1].Slot != "provider" ||
		s.PartyBindings[0].RecipientID == uuid.Nil || s.PartyBindings[1].RecipientID == uuid.Nil ||
		s.PartyBindings[0].RecipientID == s.PartyBindings[1].RecipientID {
		return invalid("reviewed contract requires both pinned signing parties")
	}
	return nil
}

// ContractProfile returns the profile from the validated saved design, never
// from a later live-template revision. The returned value owns its data.
func ContractProfile(doc *generated.Document) (*htmlmaster.ContractProfile, error) {
	s, err := validatedSource(doc, false)
	if err != nil || (s.SchemaVersion != ContractSchemaVersion && s.SchemaVersion != SigningPageSchemaVersion) {
		return nil, err
	}
	master, err := htmlmaster.Decode(s.MasterJSON)
	if err != nil {
		return nil, invalid("contract master")
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return nil, invalid("contract master")
	}
	return compiled.ContractProfile(), nil
}

// ContractParties validates the complete current source before projecting its
// immutable recipient IDs and current printed identities. Missing/corrupt
// profile provenance never falls back to generic recipient-derived intention.
func ContractParties(doc *generated.Document) ([]ContractParty, error) {
	s, err := validatedSource(doc, false)
	if err != nil || (s.SchemaVersion != ContractSchemaVersion && s.SchemaVersion != SigningPageSchemaVersion) {
		return nil, err
	}
	master, err := htmlmaster.Decode(s.MasterJSON)
	if err != nil {
		return nil, invalid("contract master")
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return nil, invalid("contract master")
	}
	readiness, err := compiled.ContractReadiness(htmlmaster.Input{Values: s.Values, Sections: s.Sections})
	if err != nil || !readiness.Complete || len(readiness.Parties) != 2 {
		return nil, invalid("reviewed contract essentials are incomplete")
	}
	bySlot := make(map[string]uuid.UUID, 2)
	for _, binding := range s.PartyBindings {
		bySlot[binding.Slot] = binding.RecipientID
	}
	parties := make([]ContractParty, 0, 2)
	for _, party := range readiness.Parties {
		id := bySlot[party.Slot]
		if id == uuid.Nil {
			return nil, invalid("reviewed contract party binding is absent")
		}
		parties = append(parties, ContractParty{Slot: party.Slot, Role: party.Slot, RecipientID: id,
			Name: party.RepresentativeName, Email: party.RepresentativeEmail,
			CompanyName: party.CompanyName, CompanyID: party.CompanyID, Authority: party.RepresentativeAuthority})
	}
	return parties, nil
}

// ValidateContractParties is independent of the recipients and fields that
// happen to remain. Both approved slots must still name the exact recipients,
// roles and identities printed in the current artifact. Legacy sources retain
// their existing lifecycle validation at the caller.
func ValidateContractParties(doc *generated.Document, rows []*generated.Recipient) error {
	parties, err := ContractParties(doc)
	if err != nil || len(parties) == 0 {
		return err
	}
	if len(rows) != len(parties) {
		return invalid("reviewed contract requires exactly its two intended recipients")
	}
	byID := make(map[uuid.UUID]*generated.Recipient, len(rows))
	for _, row := range rows {
		if row == nil || row.ID == uuid.Nil || row.DocumentID != doc.ID || byID[row.ID] != nil {
			return invalid("invalid reviewed contract recipient")
		}
		byID[row.ID] = row
	}
	for _, party := range parties {
		row := byID[party.RecipientID]
		if row == nil || row.Role != party.Role || row.Name != party.Name || row.Email != party.Email {
			return invalid("intended party differs from the current printed contract; revise and review its PDF")
		}
	}
	return nil
}
