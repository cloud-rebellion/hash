// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaster

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ContractProfile declares the information a human-reviewed proposal or
// ordinary B2B services design must print. Template approval covers these
// declarations. This is an engineering completeness check, not independent
// identity, representative-authority, tax or legal validation.
type ContractProfile struct {
	ID      string          `json:"id"`
	Version int             `json:"version"`
	Kind    string          `json:"kind"`
	Parties []ContractParty `json:"parties"`
	Terms   []ContractTerm  `json:"terms"`
}

// ContractParty binds each intended party to required, printed value names.
// The source/signing lifecycle additionally binds the slot to a recipient UUID.
type ContractParty struct {
	Slot                    string `json:"slot"`
	CompanyName             string `json:"company_name"`
	CompanyID               string `json:"company_id"`
	RepresentativeName      string `json:"representative_name"`
	RepresentativeEmail     string `json:"representative_email"`
	RepresentativeAuthority string `json:"representative_authority"`
}

// ContractTerm maps an essential commercial term to exactly one printed value
// or editable text section. Additional reviewed terms may also be declared;
// every declared term must be nonblank when a document is materialized.
type ContractTerm struct {
	Name    string `json:"name"`
	Value   string `json:"value,omitempty"`
	Section string `json:"section,omitempty"`
}

type ContractPartyValues struct {
	Slot                    string `json:"slot"`
	CompanyName             string `json:"company_name"`
	CompanyID               string `json:"company_id"`
	RepresentativeName      string `json:"representative_name"`
	RepresentativeEmail     string `json:"representative_email"`
	RepresentativeAuthority string `json:"representative_authority"`
}

type ContractIssue struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

type ContractReadiness struct {
	ProfileID      string                `json:"profile_id"`
	ProfileVersion int                   `json:"profile_version"`
	ProfileKind    string                `json:"profile_kind"`
	ProfileDigest  string                `json:"profile_digest"`
	Complete       bool                  `json:"complete"`
	Parties        []ContractPartyValues `json:"parties"`
	Issues         []ContractIssue       `json:"issues"`
}

func versionedDomain(base string, schema int) string {
	if schema == ContractSchemaVersion {
		return base + ".v2"
	}
	return base + ".v1"
}

func cloneContractProfile(profile *ContractProfile) *ContractProfile {
	if profile == nil {
		return nil
	}
	clone := *profile
	clone.Parties = append([]ContractParty{}, profile.Parties...)
	clone.Terms = append([]ContractTerm{}, profile.Terms...)
	return &clone
}

func (c *Compiled) ContractProfile() *ContractProfile {
	if c == nil {
		return nil
	}
	return cloneContractProfile(c.master.ContractProfile)
}

func (c *Compiled) ProfileDigest() string {
	if c == nil || c.master.ContractProfile == nil {
		return ""
	}
	canonical, _ := json.Marshal(c.master.ContractProfile)
	return digest("hash.contract-profile.v1", canonical)
}

func (c *Compiled) compileContractProfile(master *Master) error {
	if master.SchemaVersion == SchemaVersion {
		if master.ContractProfile != nil {
			return invalid("contract profile requires schema version 2")
		}
		return nil
	}
	profile := cloneContractProfile(master.ContractProfile)
	if profile == nil || !namePattern.MatchString(profile.ID) || profile.Version < 1 || profile.Version > 1000000 {
		return invalid("contract profile identity/version")
	}
	var essential []string
	switch profile.Kind {
	case "proposal":
		essential = []string{"scope", "price", "currency", "tax", "payment_terms", "valid_until"}
	case "b2b_services":
		essential = []string{"scope", "price", "currency", "tax", "payment_terms", "effective_date", "duration", "termination"}
	default:
		return invalid("unsupported reviewed contract profile kind")
	}
	if len(profile.Parties) != 2 || len(profile.Terms) > 16 {
		return invalid("contract profile requires provider/customer and bounded terms")
	}
	used := map[string]bool{}
	requireValue := func(name string) error {
		definition, exists := c.values[name]
		key := "value:" + name
		if !exists || !definition.Required || used[key] {
			return invalid("contract profile value must be declared, required and uniquely bound")
		}
		used[key] = true
		return nil
	}
	slots := map[string]bool{}
	for _, party := range profile.Parties {
		if (party.Slot != "provider" && party.Slot != "customer") || slots[party.Slot] {
			return invalid("contract profile party slots")
		}
		slots[party.Slot] = true
		for _, name := range []string{party.CompanyName, party.CompanyID, party.RepresentativeName, party.RepresentativeEmail, party.RepresentativeAuthority} {
			if err := requireValue(name); err != nil {
				return err
			}
		}
	}
	terms := map[string]bool{}
	for _, term := range profile.Terms {
		if !namePattern.MatchString(term.Name) || terms[term.Name] || (term.Value == "") == (term.Section == "") {
			return invalid("contract profile term definition")
		}
		terms[term.Name] = true
		if term.Value != "" {
			if err := requireValue(term.Value); err != nil {
				return err
			}
		} else {
			key := "section:" + term.Section
			if _, exists := c.sections[term.Section]; !exists || used[key] {
				return invalid("contract profile section must be declared and uniquely bound")
			}
			used[key] = true
		}
	}
	for _, name := range essential {
		if !terms[name] {
			return invalid("contract profile omitted essential term: " + name)
		}
	}
	sort.Slice(profile.Parties, func(i, j int) bool { return profile.Parties[i].Slot < profile.Parties[j].Slot })
	sort.Slice(profile.Terms, func(i, j int) bool { return profile.Terms[i].Name < profile.Terms[j].Name })
	master.ContractProfile = profile
	return nil
}

// ContractReadiness returns structured missing/conflicting inputs before
// materialization. Unknown names and out-of-policy lengths remain errors. Its
// party values are exact printed strings, without silent identity correction.
func (c *Compiled) ContractReadiness(input Input) (ContractReadiness, error) {
	var result ContractReadiness
	if c == nil {
		return result, invalid("missing compiled master")
	}
	if err := c.validateValues(input.Values, false); err != nil {
		return result, err
	}
	if err := c.validateSections(input.Sections); err != nil {
		return result, err
	}
	profile := c.master.ContractProfile
	if profile == nil {
		return result, nil
	}
	result = ContractReadiness{ProfileID: profile.ID, ProfileVersion: profile.Version, ProfileKind: profile.Kind,
		ProfileDigest: c.ProfileDigest(), Parties: []ContractPartyValues{}, Issues: []ContractIssue{}}
	issue := func(code, path, message string) {
		result.Issues = append(result.Issues, ContractIssue{code, path, message})
	}
	for _, declaration := range profile.Parties {
		party := ContractPartyValues{Slot: declaration.Slot, CompanyName: input.Values[declaration.CompanyName], CompanyID: input.Values[declaration.CompanyID],
			RepresentativeName: input.Values[declaration.RepresentativeName], RepresentativeEmail: input.Values[declaration.RepresentativeEmail],
			RepresentativeAuthority: input.Values[declaration.RepresentativeAuthority]}
		base := "parties." + declaration.Slot + "."
		for _, field := range []struct{ name, text string }{
			{"company_name", party.CompanyName}, {"company_id", party.CompanyID}, {"representative_name", party.RepresentativeName},
			{"representative_email", party.RepresentativeEmail}, {"representative_authority", party.RepresentativeAuthority},
		} {
			if isBlank(field.text) {
				issue("missing", base+field.name, "Required printed party information is missing.")
			}
		}
		if !isBlank(party.RepresentativeEmail) && !canonicalRepresentativeEmail(party.RepresentativeEmail) {
			issue("invalid_email", base+"representative_email", "Representative email must be a canonical simple email address.")
		}
		if !isBlank(party.RepresentativeName) && !canonicalRepresentativeName(party.RepresentativeName) {
			issue("invalid_representative_name", base+"representative_name", "Representative name must match canonical recipient name limits.")
		}
		// Recipient storage preserves these exact canonical printed identities,
		// including email casing. Never silently change a mailbox local part.
		result.Parties = append(result.Parties, party)
	}
	for _, term := range profile.Terms {
		text := input.Values[term.Value]
		if term.Section != "" {
			var overridden bool
			text, overridden = input.Sections[term.Section]
			if !overridden {
				text = c.sections[term.Section].DefaultText
			}
		}
		if isBlank(text) {
			issue("missing", "terms."+term.Name, "Required printed commercial information is missing.")
		}
	}
	if len(result.Parties) == 2 {
		left, right := result.Parties[0], result.Parties[1]
		if sameNonblankIdentity(left.RepresentativeEmail, right.RepresentativeEmail) {
			issue("duplicate_email", "parties", "Provider and customer must have distinct representative email addresses.")
		}
		if sameNonblankIdentity(left.CompanyID, right.CompanyID) {
			issue("duplicate_company_id", "parties", "Provider and customer company identifiers conflict.")
		}
	}
	result.Complete = len(result.Issues) == 0
	return result, nil
}

func sameNonblankIdentity(a, b string) bool {
	return !isBlank(a) && !isBlank(b) && strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func canonicalRepresentativeEmail(value string) bool {
	if len(value) > 254 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value
}

func canonicalRepresentativeName(value string) bool {
	if strings.TrimSpace(value) != value || len(value) > 800 || utf8.RuneCountInString(value) > 200 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (c *Compiled) requireContractComplete(input Input) error {
	if c.master.ContractProfile == nil {
		return nil
	}
	readiness, err := c.ContractReadiness(input)
	if err != nil {
		return err
	}
	if readiness.ProfileID != "" && !readiness.Complete {
		paths := make([]string, len(readiness.Issues))
		for i, issue := range readiness.Issues {
			paths[i] = issue.Path
		}
		return fmt.Errorf("%w: %s", ErrContractIncomplete, strings.Join(paths, ", "))
	}
	return nil
}
