// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlmaster

import (
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"
)

func amendmentPolicyFixture483(t *testing.T) (Master, Input) {
	t.Helper()
	m, in := testContractMaster("b2b_services")
	m.ContractProfile.AmendmentPolicy = &AmendmentPolicyV1{Term: "termination", ClauseReference: "Section 12", AllowedModes: []string{"signature", "agreed_notice", "acknowledgement"}, AllowedChannels: []string{"email"}, EffectiveCondition: "after 30 days"}
	for i := range m.Sections {
		if m.Sections[i].Name == "termination" {
			m.Sections[i].DefaultText = "Section 12: Changes may be signed, acknowledged, or notified by email as agreed, effective after 30 days."
		}
	}
	return m, in
}

func TestAmendmentPolicyBindsActualPrintedTerm483(t *testing.T) {
	m, in := amendmentPolicyFixture483(t)
	before, _ := json.Marshal(m)
	c := mustCompile(t, m)
	got, err := c.PresentedAmendmentPolicyV1(in)
	if err != nil || got == nil || !strings.Contains(got.ReviewedClause, "Section 12") || !strings.Contains(got.ReviewedClause, "after 30 days") {
		t.Fatalf("actual default clause unavailable: %+v %v", got, err)
	}
	if strings.Join(got.AllowedModes, ",") != "acknowledgement,agreed_notice,signature" {
		t.Fatal("policy modes not canonical")
	}
	pdfHTML, err := c.Materialize(in)
	if err != nil || !strings.Contains(pdfHTML.HTML, got.ReviewedClause) {
		t.Fatal("projected clause differs from actual rendering", err)
	}
	got.AllowedModes[0] = "forged"
	got.AllowedChannels[0] = "sms"
	profile := c.ContractProfile()
	profile.AmendmentPolicy.EffectiveCondition = "forged"
	profile.AmendmentPolicy.AllowedModes[0] = "forged"
	again, err := c.PresentedAmendmentPolicyV1(in)
	if err != nil || again.AllowedChannels[0] != "email" || again.AllowedModes[0] != "acknowledgement" || again.EffectiveCondition != "after 30 days" {
		t.Fatal("caller mutated approved compiled policy", err)
	}
	after, _ := json.Marshal(m)
	if string(before) != string(after) {
		t.Fatal("compilation mutated authored source")
	}
	override := Input{Values: maps.Clone(in.Values), Sections: maps.Clone(in.Sections)}
	override.Sections["termination"] = "Section 12: the changed actual term says after 60 days."
	readiness, err := c.ContractReadiness(override)
	if err != nil || readiness.Complete {
		t.Fatal("changed printed condition accepted", err)
	}
	if _, err := c.Materialize(override); !errors.Is(err, ErrContractIncomplete) {
		t.Fatal("materialization bypassed policy text mismatch", err)
	}
	override.Sections["termination"] = "Section 12: a newly reviewed term takes effect after 30 days."
	actual, err := c.PresentedAmendmentPolicyV1(override)
	if err != nil || actual.ReviewedClause != override.Sections["termination"] {
		t.Fatal("stale default substituted for actual current section", err)
	}
}

func TestAmendmentPolicyDeclarationRefusesInventedAuthority483(t *testing.T) {
	for name, change := range map[string]func(*AmendmentPolicyV1){
		"undeclared printed term": func(p *AmendmentPolicyV1) { p.Term = "invisible" },
		"empty modes":             func(p *AmendmentPolicyV1) { p.AllowedModes = nil },
		"duplicate mode": func(p *AmendmentPolicyV1) {
			p.AllowedModes = []string{"signature", "signature"}
			p.AllowedChannels = nil
		},
		"unknown mode":              func(p *AmendmentPolicyV1) { p.AllowedModes = []string{"automatic_acceptance"} },
		"notice without email":      func(p *AmendmentPolicyV1) { p.AllowedChannels = nil },
		"hidden extra channel":      func(p *AmendmentPolicyV1) { p.AllowedChannels = []string{"email", "sms"} },
		"channel without notice":    func(p *AmendmentPolicyV1) { p.AllowedModes = []string{"signature"} },
		"format-only reference":     func(p *AmendmentPolicyV1) { p.ClauseReference = "\u200b" },
		"condition over byte bound": func(p *AmendmentPolicyV1) { p.EffectiveCondition = strings.Repeat("å", 1025) },
		"outer whitespace":          func(p *AmendmentPolicyV1) { p.ClauseReference = " Section 12" },
	} {
		t.Run(name, func(t *testing.T) {
			m, _ := amendmentPolicyFixture483(t)
			change(m.ContractProfile.AmendmentPolicy)
			if _, err := Compile(m); err == nil {
				t.Fatal("invalid policy declaration accepted")
			}
		})
	}
	m, in := amendmentPolicyFixture483(t)
	m.ContractProfile.AmendmentPolicy = nil
	c := mustCompile(t, m)
	if p, err := c.PresentedAmendmentPolicyV1(in); err != nil || p != nil {
		t.Fatal("absence generated policy", err)
	}
	if strings.Contains(string(c.CanonicalJSON()), "amendment_policy") {
		t.Fatal("absent policy changed legacy canonical shape")
	}
	m, in = amendmentPolicyFixture483(t)
	for i := range m.Sections {
		if m.Sections[i].Name == "termination" {
			m.Sections[i].DefaultText = "Section 12 " + strings.Repeat("x", 8192) + " after 30 days"
			m.Sections[i].MaxChars = 20000
		}
	}
	if p, err := mustCompile(t, m).PresentedAmendmentPolicyV1(in); err == nil || p != nil {
		t.Fatal("oversized printed clause accepted")
	}
}

func TestAmendmentPolicyRequiresExplicitEmptyChannels483(t *testing.T) {
	m, in := amendmentPolicyFixture483(t)
	m.ContractProfile.AmendmentPolicy.AllowedModes = []string{"signature"}
	m.ContractProfile.AmendmentPolicy.AllowedChannels = []string{}
	c := mustCompile(t, m)
	if _, err := c.Materialize(in); err != nil {
		t.Fatal("explicit signature-only policy failed", err)
	}
	raw := c.CanonicalJSON()
	if !strings.Contains(string(raw), `"allowed_channels":[]`) {
		t.Fatal("explicit empty channels not preserved")
	}
	for _, replacement := range []string{`"allowed_channels":null`, `"omitted_channels":[]`} {
		changed := strings.Replace(string(raw), `"allowed_channels":[]`, replacement, 1)
		d, err := Decode([]byte(changed))
		if err == nil {
			_, err = Compile(d)
		}
		if err == nil {
			t.Fatal("missing/null explicit channel declaration accepted")
		}
	}
}
