// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlsource

import (
	"bytes"
	"maps"
	"slices"
	"strings"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
)

// IsOptionalEmptyAddition reports the narrow input-presence change that can
// legitimately have the same rendered content digest as the current source:
// one or more omitted, declared optional values become explicitly empty.
// Every existing value, section, approval, design and party UUID must remain
// unchanged. Invalid current provenance or malformed design inputs fail closed.
//
// This is only a revision admission check. It performs no I/O or mutation and
// grants no authority to reuse a PDF, review or field layout. Callers must still
// render/intake a fresh artifact and run the complete materialization pipeline.
// A schema3 SigningArtifact is validated separately against that fresh PDF by
// New and Append; it is not part of the immutable approved design comparison.
func IsOptionalEmptyAddition(previous *generated.Document, candidate Input) (bool, error) {
	current, err := validatedSource(previous, false)
	if err != nil {
		return false, err
	}
	if current.Commitment == "" {
		return false, invalid("missing current HTML source")
	}
	if candidate.Values == nil || candidate.Sections == nil ||
		len(candidate.Values) > htmlmaster.MaxDefinitions || len(candidate.Sections) > htmlmaster.MaxDefinitions {
		return false, invalid("revision input maps or limits")
	}
	if candidate.TemplateID != current.TemplateID || candidate.TemplateVersion != current.TemplateVersion ||
		candidate.TemplateContentSHA256 != current.TemplateContentSHA256 ||
		candidate.TemplateApprovedBy != current.TemplateApprovedBy || !candidate.TemplateApprovedAt.Equal(current.TemplateApprovedAt) {
		return false, nil
	}
	bindings := slices.Clone(candidate.PartyBindings)
	slices.SortFunc(bindings, func(a, b PartyBinding) int { return strings.Compare(a.Slot, b.Slot) })
	if !slices.Equal(bindings, current.PartyBindings) {
		return false, nil
	}
	canonical, err := htmlmaster.CanonicalTemplate(candidate.MasterJSON, candidate.DefaultVarsJSON)
	if err != nil {
		return false, invalid("revision master or approved defaults")
	}
	approved, err := htmlmaster.CanonicalTemplate(current.MasterJSON, current.DefaultVarsJSON)
	if err != nil {
		return false, invalid("current master or approved defaults")
	}
	if canonical.SHA256 != current.TemplateContentSHA256 ||
		!bytes.Equal(canonical.MasterJSON, approved.MasterJSON) || !bytes.Equal(canonical.DefaultsJSON, approved.DefaultsJSON) {
		return false, nil
	}
	if !maps.Equal(current.Sections, candidate.Sections) || len(candidate.Values) <= len(current.Values) {
		return false, nil
	}
	for name, value := range current.Values {
		if next, present := candidate.Values[name]; !present || next != value {
			return false, nil
		}
	}
	master, err := htmlmaster.Decode(canonical.MasterJSON)
	if err != nil {
		return false, invalid("canonical revision master")
	}
	optional := make(map[string]bool, len(master.Values))
	for _, value := range master.Values {
		optional[value.Name] = !value.Required
	}
	for name, value := range candidate.Values {
		if _, present := current.Values[name]; !present && (value != "" || !optional[name]) {
			return false, nil
		}
	}
	return true, nil
}
