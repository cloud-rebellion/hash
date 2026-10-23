// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
)

func sourceInputFixtureV1() preSignAPISourceInputV1 {
	return preSignAPISourceInputV1{RequestID: uuid.New(), ExpectedOrgID: uuid.New(), ExpectedUserID: uuid.New(),
		Policy: presign.Reference{ID: uuid.New(), Revision: 1, SHA256: strings.Repeat("a", 64)}, Grant: presign.Reference{ID: uuid.New(), Revision: 1, SHA256: strings.Repeat("b", 64)}, DocumentName: "Original approved contract"}
}
func TestPreSignSourceOriginalCommandBindsCredentialAndEveryInputV1(t *testing.T) {
	in := sourceInputFixtureV1()
	credential := uuid.New()
	binding := strings.Repeat("c", 64)
	digest, err := preSignSourceInputDigestV1(in, in.ExpectedOrgID, in.ExpectedUserID, credential, binding)
	if err != nil {
		t.Fatal(err)
	}
	same, err := preSignSourceInputDigestV1(in, in.ExpectedOrgID, in.ExpectedUserID, credential, binding)
	if err != nil || digest != same {
		t.Fatal("original canonical request changed")
	}
	for name, change := range map[string]func(*preSignAPISourceInputV1){
		"request": func(v *preSignAPISourceInputV1) { v.RequestID = uuid.New() }, "name": func(v *preSignAPISourceInputV1) { v.DocumentName += " changed" },
		"policy": func(v *preSignAPISourceInputV1) { v.Policy.ID = uuid.New() }, "policy revision": func(v *preSignAPISourceInputV1) { v.Policy.Revision++ },
		"policy hash": func(v *preSignAPISourceInputV1) { v.Policy.SHA256 = strings.Repeat("d", 64) }, "grant": func(v *preSignAPISourceInputV1) { v.Grant.ID = uuid.New() },
		"grant revision": func(v *preSignAPISourceInputV1) { v.Grant.Revision++ }, "grant hash": func(v *preSignAPISourceInputV1) { v.Grant.SHA256 = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			v := in
			change(&v)
			got, err := preSignSourceInputDigestV1(v, in.ExpectedOrgID, in.ExpectedUserID, credential, binding)
			if err != nil || got == digest {
				t.Fatal("changed source command kept original identity", err)
			}
		})
	}
	for _, c := range []struct {
		id   uuid.UUID
		hash string
	}{{uuid.New(), binding}, {credential, strings.Repeat("d", 64)}} {
		got, err := preSignSourceInputDigestV1(in, in.ExpectedOrgID, in.ExpectedUserID, c.id, c.hash)
		if err != nil || got == digest {
			t.Fatal("replacement credential adopted source request", err)
		}
	}
	for name, change := range map[string]func(*preSignAPISourceInputV1){
		"foreign org": func(v *preSignAPISourceInputV1) { v.ExpectedOrgID = uuid.New() }, "foreign user": func(v *preSignAPISourceInputV1) { v.ExpectedUserID = uuid.New() },
		"zero request": func(v *preSignAPISourceInputV1) { v.RequestID = uuid.Nil }, "large name": func(v *preSignAPISourceInputV1) { v.DocumentName = strings.Repeat("x", 201) },
		"NUL": func(v *preSignAPISourceInputV1) { v.DocumentName = "a\x00b" }, "bad hash": func(v *preSignAPISourceInputV1) { v.Grant.SHA256 = strings.Repeat("A", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			v := in
			change(&v)
			if _, err := preSignSourceInputDigestV1(v, in.ExpectedOrgID, in.ExpectedUserID, credential, binding); err == nil {
				t.Fatal("invalid actor or source command accepted")
			}
		})
	}
}

func TestPreSignSourceClosedWireRejectsCallerSourceAndIdentityAliasesV1(t *testing.T) {
	in := sourceInputFixtureV1()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, err := json.Marshal(in.Policy)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"source":     strings.Replace(string(raw), `"document_name":`, `"html_source":{},"document_name":`, 1),
		"values":     strings.Replace(string(raw), `"document_name":`, `"values":{"provider_name":"attacker"},"document_name":`, 1),
		"review":     strings.Replace(string(raw), `"document_name":`, `"reviewed":true,"document_name":`, 1),
		"duplicate":  strings.Replace(string(raw), `"document_name":`, `"document_name":"first","document_name":`, 1),
		"case alias": strings.Replace(string(raw), `"document_name":`, `"DocumentName":"alias","document_name":`, 1),
		"null":       strings.Replace(string(raw), string(policyRaw), `null`, 1),
		"trailing":   string(raw) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", strings.NewReader(bad))
			var value preSignAPISourceInputV1
			if decodeCRMTemplateJSON(r, &value) == nil {
				t.Fatal("ambiguous/source-bearing command accepted")
			}
		})
	}
	var actual preSignAPISourceInputV1
	if err := decodeCRMTemplateJSON(httptest.NewRequest("POST", "/", strings.NewReader(string(raw))), &actual); err != nil || !reflect.DeepEqual(actual, in) {
		t.Fatal("closed source command did not roundtrip", err)
	}
}

func TestPreSignSourceUsesRealApprovedMasterAndOnlyFrozenRulesV1(t *testing.T) {
	raw, err := os.ReadFile("../presignregistry/testdata/workflow-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := presignregistry.DecodeDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	input, _, _ := testfixture.HTMLContract(t)
	m, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	m.SchemaVersion = 3
	m.SigningPage = testfixture.BrandedSigningPolicy()
	master, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := json.Marshal(input.Values)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := htmlmaster.CanonicalTemplate(master, defaults)
	if err != nil {
		t.Fatal(err)
	}
	d.Kind = presignregistry.KindApprovedData
	d.Template.ContentSHA256 = pin.SHA256
	grantor := presign.NamedRepresentative{UserID: d.Executor.UserID, Name: "Exact Provider", Email: "provider@example.test", CompanyName: d.RecipientRules.ProviderCompanyName, CompanyID: d.RecipientRules.ProviderCompanyID, AuthorityBasis: d.RecipientRules.ProviderAuthorityBasis}
	provider := map[string]string{}
	for _, p := range m.ContractProfile.Parties {
		if p.Slot == "provider" {
			provider = map[string]string{p.RepresentativeName: "name", p.RepresentativeEmail: "email", p.CompanyName: "company_name", p.CompanyID: "company_id", p.RepresentativeAuthority: "authority_basis"}
		}
	}
	for _, v := range m.Values {
		rule := presignregistry.ValueRule{Variable: v.Name, Mode: presignregistry.ModeDefault}
		if field := provider[v.Name]; field != "" {
			rule.Mode = presignregistry.ModeGrantor
			rule.GrantorField = field
		}
		d.DataRules.Values = append(d.DataRules.Values, rule)
	}
	for _, s := range m.Sections {
		d.DataRules.Sections = append(d.DataRules.Sections, presignregistry.SectionRule{Section: s.Name, Mode: presignregistry.ModeDefault})
	}
	values, sections, err := preSignSourceFrozenDataV1(d, grantor, pin.MasterJSON, pin.DefaultsJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = compiled.Materialize(htmlmaster.Input{Values: values, Sections: sections}); err != nil {
		t.Fatal("actual approved master did not materialize", err)
	}
	if _, err = compiled.SigningPageHTML(htmlmaster.Input{Values: values, Sections: sections}); err != nil {
		t.Fatal("actual protected signing page did not materialize", err)
	}
	for variable, field := range provider {
		want := map[string]string{"name": grantor.Name, "email": grantor.Email, "company_name": grantor.CompanyName, "company_id": grantor.CompanyID, "authority_basis": grantor.AuthorityBasis}[field]
		if values[variable] != want {
			t.Fatal("provider source differs from actual named grantor")
		}
	}
	for i, rule := range d.DataRules.Values {
		if provider[rule.Variable] == "" {
			literal := "Exact policy literal"
			d.DataRules.Values[i] = presignregistry.ValueRule{Variable: rule.Variable, Mode: presignregistry.ModeLiteral, Literal: &literal}
			next, _, err := preSignSourceFrozenDataV1(d, grantor, pin.MasterJSON, pin.DefaultsJSON)
			if err != nil || next[rule.Variable] != literal {
				t.Fatal("stored literal not selected", err)
			}
			break
		}
	}
	d.DataRules.CRM = &presignregistry.CRMScope{}
	if _, _, err := preSignSourceFrozenDataV1(d, grantor, pin.MasterJSON, pin.DefaultsJSON); err == nil {
		t.Fatal("malformed CRM policy was accepted")
	}
	d.DataRules.CRM = nil
	d.Kind = presignregistry.KindReviewedDocument
	if _, _, err := preSignSourceFrozenDataV1(d, grantor, pin.MasterJSON, pin.DefaultsJSON); !errors.Is(err, errPreSignSourceUnsupportedV1) {
		t.Fatal("reviewed/manual workflow silently became approved data")
	}
}
