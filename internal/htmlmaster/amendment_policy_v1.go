// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlmaster

import (
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxAmendmentClauseBytesV1 = 8192
const MaxAmendmentReferenceBytesV1 = 512
const MaxAmendmentConditionBytesV1 = 2048

// AmendmentPolicyV1 is an owner's explicit mapping of an existing printed
// contract term. Approval and document PDF review remain mandatory. It is not
// a legal interpretation of the clause, nor permission inferred from a title.
type AmendmentPolicyV1 struct {
	Term               string   `json:"term"`
	ClauseReference    string   `json:"clause_reference"`
	AllowedModes       []string `json:"allowed_modes"`
	AllowedChannels    []string `json:"allowed_channels"`
	EffectiveCondition string   `json:"effective_condition"`
}

type PresentedAmendmentPolicyV1 struct {
	AmendmentPolicyV1
	ReviewedClause string
}

func CloneAmendmentPolicyV1(p *AmendmentPolicyV1) *AmendmentPolicyV1 {
	if p == nil {
		return nil
	}
	c := *p
	c.AllowedModes = slices.Clone(p.AllowedModes)
	c.AllowedChannels = slices.Clone(p.AllowedChannels)
	return &c
}

func amendmentPolicyTextV1(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) || strings.TrimSpace(s) != s || !hasContractText(s) {
		return false
	}
	for _, r := range s {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// AmendmentPolicyShapeV1 is allocation-free so native input/clone ownership
// can reject an oversized declaration before copying any variable-length list.
func AmendmentPolicyShapeV1(p *AmendmentPolicyV1) bool {
	if p == nil {
		return true
	}
	if len(p.Term) < 1 || len(p.Term) > 64 || p.Term[0] < 'a' || p.Term[0] > 'z' {
		return false
	}
	for _, b := range []byte(p.Term) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_') {
			return false
		}
	}
	if !amendmentPolicyTextV1(p.ClauseReference, MaxAmendmentReferenceBytesV1) || !amendmentPolicyTextV1(p.EffectiveCondition, MaxAmendmentConditionBytesV1) || len(p.AllowedModes) < 1 || len(p.AllowedModes) > 3 || p.AllowedChannels == nil || len(p.AllowedChannels) > 1 {
		return false
	}
	notice := false
	for i, m := range p.AllowedModes {
		if m != "signature" && m != "acknowledgement" && m != "agreed_notice" {
			return false
		}
		if slices.Contains(p.AllowedModes[:i], m) {
			return false
		}
		notice = notice || m == "agreed_notice"
	}
	return (notice && len(p.AllowedChannels) == 1 && p.AllowedChannels[0] == "email") || (!notice && len(p.AllowedChannels) == 0)
}

func validateAmendmentPolicyV1(profile *ContractProfile) error {
	p := profile.AmendmentPolicy
	if !AmendmentPolicyShapeV1(p) {
		return invalid("amendment policy declaration")
	}
	if p == nil {
		return nil
	}
	found := false
	for _, t := range profile.Terms {
		found = found || t.Name == p.Term
	}
	if !found {
		return invalid("amendment policy requires a declared printed contract term")
	}
	sort.Strings(p.AllowedModes)
	return nil
}

// PresentedAmendmentPolicyV1 projects only the actual materialized value or
// section, including its approved default. Reference and condition are exact
// quotations from that same printed clause. No additional wording is generated.
func (c *Compiled) PresentedAmendmentPolicyV1(input Input) (*PresentedAmendmentPolicyV1, error) {
	if c == nil {
		return nil, invalid("missing compiled master")
	}
	if c.master.ContractProfile == nil || c.master.ContractProfile.AmendmentPolicy == nil {
		return nil, nil
	}
	p := c.master.ContractProfile.AmendmentPolicy
	for _, term := range c.master.ContractProfile.Terms {
		if term.Name != p.Term {
			continue
		}
		text := input.Values[term.Value]
		if term.Section != "" {
			var present bool
			text, present = input.Sections[term.Section]
			if !present {
				text = c.sections[term.Section].DefaultText
			}
		}
		if !amendmentPolicyTextV1(text, MaxAmendmentClauseBytesV1) || !strings.Contains(text, p.ClauseReference) || !strings.Contains(text, p.EffectiveCondition) {
			return nil, invalid("amendment policy differs from printed clause")
		}
		return &PresentedAmendmentPolicyV1{AmendmentPolicyV1: *CloneAmendmentPolicyV1(p), ReviewedClause: text}, nil
	}
	return nil, invalid("amendment policy printed term missing")
}
