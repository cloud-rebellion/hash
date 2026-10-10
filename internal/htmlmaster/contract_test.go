// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaster

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"sync"
	"testing"
)

func testContractMaster(kind string) (Master, Input) {
	master := Master{SchemaVersion: ContractSchemaVersion, HTML: "<main>",
		ContractProfile: &ContractProfile{ID: "reviewed_services", Version: 1, Kind: kind}}
	input := Input{Values: map[string]string{}, Sections: map[string]string{}}
	for _, slot := range []string{"provider", "customer"} {
		master.ContractProfile.Parties = append(master.ContractProfile.Parties, ContractParty{Slot: slot,
			CompanyName: slot + "_company_name", CompanyID: slot + "_company_id", RepresentativeName: slot + "_name",
			RepresentativeEmail: slot + "_email", RepresentativeAuthority: slot + "_authority"})
		for _, field := range []string{"company_name", "company_id", "name", "email", "authority"} {
			name := slot + "_" + field
			master.Values = append(master.Values, Value{Name: name, Required: true, MaxChars: 1024})
			master.HTML += `<p><span data-hash-value="` + name + `"></span></p>`
			input.Values[name] = slot + " " + field
		}
		input.Values[slot+"_email"] = slot + "@example.invalid"
	}
	terms := []string{"scope", "price", "currency", "tax", "payment_terms", "valid_until"}
	if kind == "b2b_services" {
		terms = []string{"scope", "price", "currency", "tax", "payment_terms", "effective_date", "duration", "termination"}
	}
	for _, name := range terms {
		if name == "scope" || name == "termination" {
			master.ContractProfile.Terms = append(master.ContractProfile.Terms, ContractTerm{Name: name, Section: name})
			master.Sections = append(master.Sections, Section{Name: name, DefaultText: "Human reviewed " + name, MaxChars: 1024})
			master.HTML += `<div data-hash-section="` + name + `"></div>`
		} else {
			master.ContractProfile.Terms = append(master.ContractProfile.Terms, ContractTerm{Name: name, Value: name})
			master.Values = append(master.Values, Value{Name: name, Required: true, MaxChars: 1024})
			master.HTML += `<p><span data-hash-value="` + name + `"></span></p>`
			input.Values[name] = "Reviewed " + name
		}
	}
	master.HTML += "</main>"
	return master, input
}

func TestContractProfileLeavesLegacyCommitmentsByteIdentical(t *testing.T) {
	master := Master{SchemaVersion: SchemaVersion, HTML: "<p>Approved</p>"}
	compiled := mustCompile(t, master)
	// These independent golden commitments bind the pre-profile canonical
	// master, template envelope and materialization domains/bytes.
	wantJSON := `{"schema_version":1,"html":"\u003cp\u003eApproved\u003c/p\u003e","css":""}`
	if string(compiled.CanonicalJSON()) != wantJSON || compiled.Digest() != "244247086b1240735f81190f04fca86816af8008eaca25dccd6a7854c41ac05d" {
		t.Fatal("legacy canonical bytes or master digest changed")
	}
	canonical, err := CanonicalTemplate(compiled.CanonicalJSON(), []byte(`{}`))
	if err != nil || canonical.SHA256 != "5bb90a031aa39c13e5716c7825b973c338b4fbb27c4e88834e89b50dcd38bbe8" {
		t.Fatalf("legacy approved-template commitment changed: %v", err)
	}
	result, err := compiled.Materialize(Input{})
	if err != nil || result.ContentDigest != "3f9e616bb443f5ea7f99446d52332e7befeabeba04a094f5c4f1858d8b3fd1d7" {
		t.Fatalf("legacy materialization changed: %v", err)
	}
	ready, err := compiled.ContractReadiness(Input{})
	if err != nil || ready.ProfileID != "" || ready.Complete || compiled.ContractProfile() != nil || compiled.ProfileDigest() != "" {
		t.Fatal("historical unprofiled master received a completeness claim")
	}
}

func TestContractProfileCompileRejectsUndeclaredOrOmittedEssentials(t *testing.T) {
	for name, change := range map[string]func(*Master){
		"legacy-with-profile": func(m *Master) { m.SchemaVersion = SchemaVersion },
		"profile-absent":      func(m *Master) { m.ContractProfile = nil },
		"kind":                func(m *Master) { m.ContractProfile.Kind = "unreviewed" },
		"invalid-id":          func(m *Master) { m.ContractProfile.ID = "Reviewed" },
		"missing-version":     func(m *Master) { m.ContractProfile.Version = 0 },
		"version-bound":       func(m *Master) { m.ContractProfile.Version = 1000001 },
		"missing-customer":    func(m *Master) { m.ContractProfile.Parties = m.ContractProfile.Parties[:1] },
		"same-slot":           func(m *Master) { m.ContractProfile.Parties[1].Slot = "provider" },
		"wrong-slot":          func(m *Master) { m.ContractProfile.Parties[1].Slot = "observer" },
		"undeclared-party":    func(m *Master) { m.ContractProfile.Parties[1].RepresentativeAuthority = "omitted" },
		"optional-party":      func(m *Master) { m.Values[0].Required = false },
		"same-party-binding":  func(m *Master) { m.ContractProfile.Parties[1].CompanyName = m.ContractProfile.Parties[0].CompanyName },
		"missing-termination": func(m *Master) { m.ContractProfile.Terms = m.ContractProfile.Terms[:len(m.ContractProfile.Terms)-1] },
		"missing-price":       func(m *Master) { m.ContractProfile.Terms[1].Name = "custom_note" },
		"undeclared-term":     func(m *Master) { m.ContractProfile.Terms[1].Value = "omitted" },
		"optional-term": func(m *Master) {
			for i := range m.Values {
				if m.Values[i].Name == "price" {
					m.Values[i].Required = false
				}
			}
		},
		"shared-value-binding":   func(m *Master) { m.ContractProfile.Terms[2].Value = m.ContractProfile.Terms[1].Value },
		"shared-section-binding": func(m *Master) { m.ContractProfile.Terms[len(m.ContractProfile.Terms)-1].Section = "scope" },
		"both-term-bindings":     func(m *Master) { m.ContractProfile.Terms[0].Value = "price" },
		"missing-term-binding":   func(m *Master) { m.ContractProfile.Terms[0].Section = "" },
		"duplicate-term":         func(m *Master) { m.ContractProfile.Terms[1].Name = "scope" },
		"too-many-terms":         func(m *Master) { m.ContractProfile.Terms = append(m.ContractProfile.Terms, make([]ContractTerm, 9)...) },
	} {
		t.Run(name, func(t *testing.T) {
			master, _ := testContractMaster("b2b_services")
			change(&master)
			if _, err := Compile(master); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid contract profile accepted: %v", err)
			}
		})
	}
}

func TestContractProfileStrictJSONRejectsNullUnknownDuplicateAndWrongShapes(t *testing.T) {
	master, _ := testContractMaster("proposal")
	raw, _ := json.Marshal(master)
	if _, err := Decode(raw); err != nil {
		t.Fatalf("typed profile pointer failed strict decode: %v", err)
	}
	for name, input := range map[string][]byte{
		"null-profile":        []byte(`{"schema_version":2,"contract_profile":null}`),
		"null-parties":        []byte(`{"schema_version":2,"contract_profile":{"parties":null}}`),
		"null-party-name":     []byte(`{"schema_version":2,"contract_profile":{"parties":[{"company_name":null}]}}`),
		"unknown-profile":     []byte(`{"schema_version":2,"contract_profile":{"unknown":true}}`),
		"unknown-party":       []byte(`{"schema_version":2,"contract_profile":{"parties":[{"unknown":true}]}}`),
		"case-profile":        []byte(`{"schema_version":2,"Contract_Profile":{}}`),
		"duplicate-profile":   []byte(`{"schema_version":2,"contract_profile":{},"contract_profile":{}}`),
		"duplicate-id":        []byte(`{"schema_version":2,"contract_profile":{"id":"a","id":"b"}}`),
		"duplicate-term-name": []byte(`{"schema_version":2,"contract_profile":{"terms":[{"name":"scope","name":"price"}]}}`),
		"wrong-profile-shape": []byte(`{"schema_version":2,"contract_profile":[]}`),
		"wrong-field-shape":   []byte(`{"schema_version":2,"contract_profile":{"id":1}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(input); err == nil {
				t.Fatal("ambiguous profile JSON accepted")
			}
		})
	}
}

func TestContractReadinessChecksPrintedPartyAndCommercialInputs(t *testing.T) {
	for _, kind := range []string{"proposal", "b2b_services"} {
		t.Run(kind, func(t *testing.T) {
			master, input := testContractMaster(kind)
			compiled := mustCompile(t, master)
			ready, err := compiled.ContractReadiness(input)
			if err != nil || !ready.Complete || len(ready.Parties) != 2 || len(ready.Issues) != 0 || ready.ProfileDigest == "" {
				t.Fatalf("complete reviewed inputs rejected: %#v %v", ready, err)
			}
			if _, err := compiled.Materialize(input); err != nil {
				t.Fatal(err)
			}
			for name, change := range map[string]func(*Input){
				"company-name":             func(i *Input) { delete(i.Values, "customer_company_name") },
				"company-id":               func(i *Input) { i.Values["customer_company_id"] = " \t" },
				"representative-authority": func(i *Input) { i.Values["provider_authority"] = "" },
				"scope":                    func(i *Input) { i.Sections["scope"] = " \n " },
				"price":                    func(i *Input) { delete(i.Values, "price") },
				"email-display-name":       func(i *Input) { i.Values["customer_email"] = "Person <person@example.invalid>" },
				"email-controls":           func(i *Input) { i.Values["customer_email"] = "customer@example.invalid\n" },
				"email-boundary":           func(i *Input) { i.Values["customer_email"] = " customer@example.invalid" },
				"email-conflict":           func(i *Input) { i.Values["customer_email"] = "PROVIDER@example.invalid" },
				"company-id-conflict":      func(i *Input) { i.Values["customer_company_id"] = "  PROVIDER COMPANY_ID  " },
				"name-controls":            func(i *Input) { i.Values["provider_name"] = "Person\n" },
				"name-length":              func(i *Input) { i.Values["provider_name"] = strings.Repeat("a", 201) },
			} {
				t.Run(name, func(t *testing.T) {
					changed := Input{Values: maps.Clone(input.Values), Sections: maps.Clone(input.Sections)}
					change(&changed)
					ready, err := compiled.ContractReadiness(changed)
					if err != nil || ready.Complete || len(ready.Issues) == 0 {
						t.Fatalf("incomplete/conflicting input accepted: %#v %v", ready, err)
					}
					if _, err := compiled.Materialize(changed); !errors.Is(err, ErrContractIncomplete) {
						t.Fatalf("materialization did not stop: %v", err)
					}
					for _, issue := range ready.Issues {
						if issue.Code == "" || issue.Path == "" || issue.Message == "" || strings.Contains(issue.Message, "@") {
							t.Fatal("issue lacks safe structured guidance")
						}
					}
				})
			}
		})
	}
}

func TestContractProfilePinsOwnershipOrderAndConcurrentReadiness(t *testing.T) {
	master, input := testContractMaster("b2b_services")
	input.Values["provider_email"] = "PROVIDER@example.invalid"
	compiled := mustCompile(t, master)
	raw := compiled.CanonicalJSON()
	canonical, err := CanonicalTemplate(raw, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	result, err := compiled.Materialize(input)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := compiled.ContractReadiness(input)
	if err != nil || ready.Parties[1].RepresentativeEmail != "PROVIDER@example.invalid" || !strings.Contains(result.HTML, "PROVIDER@example.invalid") {
		t.Fatal("routing identity changed printed values")
	}
	master.ContractProfile.Parties[0], master.ContractProfile.Parties[1] = master.ContractProfile.Parties[1], master.ContractProfile.Parties[0]
	for i, j := 0, len(master.ContractProfile.Terms)-1; i < j; i, j = i+1, j-1 {
		master.ContractProfile.Terms[i], master.ContractProfile.Terms[j] = master.ContractProfile.Terms[j], master.ContractProfile.Terms[i]
	}
	reordered := mustCompile(t, master)
	if !bytes.Equal(raw, reordered.CanonicalJSON()) || compiled.ProfileDigest() != reordered.ProfileDigest() {
		t.Fatal("irrelevant profile order changed approved pins")
	}
	master.ContractProfile.Version++
	changed := mustCompile(t, master)
	changedCanonical, err := CanonicalTemplate(changed.CanonicalJSON(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	changedResult, err := changed.Materialize(input)
	if err != nil || changed.ProfileDigest() == compiled.ProfileDigest() || changedCanonical.SHA256 == canonical.SHA256 || changedResult.ContentDigest == result.ContentDigest {
		t.Fatal("profile revision did not change every approval/materialization pin")
	}
	copy := compiled.ContractProfile()
	copy.ID = "mutated"
	copy.Parties[0].CompanyName = "mutated"
	copy.Terms[0].Name = "mutated"
	master.ContractProfile.ID = "mutated"
	if compiled.ContractProfile().ID != "reviewed_services" || !bytes.Equal(raw, compiled.CanonicalJSON()) {
		t.Fatal("caller mutated compiled profile")
	}
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Go(func() {
			next, err := compiled.ContractReadiness(input)
			if err != nil || !next.Complete || next.ProfileDigest != ready.ProfileDigest {
				t.Error("concurrent readiness changed")
			}
			next.Parties[0].CompanyID = "mutated"
			next.Issues = append(next.Issues, ContractIssue{Code: "mutated"})
			other, err := compiled.Materialize(input)
			if err != nil || other.ContentDigest != result.ContentDigest {
				t.Error("concurrent profile materialization changed")
			}
		})
	}
	group.Wait()
}
