// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func definitionFixture(t testing.TB) WorkflowDefinition {
	t.Helper()
	raw, err := os.ReadFile("testdata/workflow-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestWorkflowDefinitionCanonicalIndependentVector(t *testing.T) {
	d := definitionFixture(t)
	raw, hash, rules, err := CanonicalDefinition(d)
	want, readErr := os.ReadFile("testdata/workflow-v1.sha256")
	fixture, _ := os.ReadFile("testdata/workflow-v1.json")
	if err != nil || readErr != nil || hash != strings.TrimSpace(string(want)) || !bytes.Equal(raw, bytes.TrimSpace(fixture)) {
		t.Fatal("independently declared canonical vector changed")
	}
	if rules.InputRulesSHA256 == rules.DataRulesSHA256 || rules.DataRulesSHA256 == hash || rules.RecipientRulesSHA256 == hash {
		t.Fatal("purpose domains collided")
	}
	changed := d
	changed.Executor.UserID = uuid.New()
	_, other, _, err := CanonicalDefinition(changed)
	if err != nil || hash == other {
		t.Fatal("executor substitution retained commitment")
	}
}

func TestWorkflowDefinitionStrictJSON(t *testing.T) {
	raw, _ := os.ReadFile("testdata/workflow-v1.json")
	cases := map[string]string{"duplicate": strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1), "case_alias": strings.Replace(string(raw), `"name":"Synthetic workflow"`, `"name":"Synthetic workflow","Name":"Synthetic workflow"`, 1), "null": strings.Replace(string(raw), `"values":[]`, `"values":null`, 1), "UUID_alias": strings.Replace(string(raw), `"11111111-1111-4111-8111-111111111111"`, `"{11111111-1111-4111-8111-111111111111}"`, 1), "trailing": string(raw) + `{}`, "unknown": strings.Replace(string(raw), `"version":1`, `"unexpected":true,"version":1`, 1), "NUL": strings.Replace(string(raw), `Synthetic workflow`, `Synthetic\u0000workflow`, 1)}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDefinition([]byte(bad)); err == nil {
				t.Fatal("ambiguous definition accepted")
			}
		})
	}
}

func masterDefinitionFixture(t testing.TB) (WorkflowDefinition, []byte, []byte) {
	t.Helper()
	in, _, _ := testfixture.HTMLContract(t)
	m, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	m.SchemaVersion = 3
	m.SigningPage = testfixture.BrandedSigningPolicy()
	m.Sections = []htmlmaster.Section{{Name: "manual_scope", DefaultText: "Approved initial scope", MaxChars: 1000}}
	m.HTML += `<p data-hash-section="manual_scope"></p>`
	raw, _ := json.Marshal(m)
	pin, err := htmlmaster.CanonicalTemplate(raw, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	d := definitionFixture(t)
	d.Template.ContentSHA256 = pin.SHA256
	for _, v := range m.Values {
		d.DataRules.Values = append(d.DataRules.Values, ValueRule{Variable: v.Name, Mode: ModeReviewedValue})
	}
	d.DataRules.Sections = []SectionRule{{Section: "manual_scope", Mode: ModeReviewedValue}}
	return d, pin.MasterJSON, pin.DefaultsJSON
}

func TestWorkflowRulesPreserveReviewedManualValuesAndSections(t *testing.T) {
	d, m, defaults := masterDefinitionFixture(t)
	if err := ValidateDefinitionAgainstTemplate(d, m, defaults); err != nil {
		t.Fatal(err)
	}
	d.Kind = KindApprovedData
	if ValidateDefinitionAgainstTemplate(d, m, defaults) == nil {
		t.Fatal("unattended workflow accepted newly supplied manual prose")
	}
	d.Kind = KindReviewedDocument
	d.DataRules.Values = append(d.DataRules.Values, ValueRule{Variable: "undeclared", Mode: ModeReviewedValue})
	if ValidateDefinitionAgainstTemplate(d, m, defaults) == nil {
		t.Fatal("undeclared mapping accepted")
	}
}

func approvedDataRules(t testing.TB, d WorkflowDefinition, raw []byte) WorkflowDefinition {
	t.Helper()
	m, err := htmlmaster.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	in, _, _ := testfixture.HTMLContract(t)
	provider := map[string]string{}
	for _, p := range m.ContractProfile.Parties {
		if p.Slot == "provider" {
			provider = map[string]string{p.CompanyName: "company_name", p.CompanyID: "company_id", p.RepresentativeName: "name", p.RepresentativeEmail: "email", p.RepresentativeAuthority: "authority_basis"}
		}
	}
	d.Kind = KindApprovedData
	d.DataRules.Values = []ValueRule{}
	for _, v := range m.Values {
		if field := provider[v.Name]; field != "" {
			d.DataRules.Values = append(d.DataRules.Values, ValueRule{Variable: v.Name, Mode: ModeGrantor, GrantorField: field})
		} else {
			value := in.Values[v.Name]
			d.DataRules.Values = append(d.DataRules.Values, ValueRule{Variable: v.Name, Mode: ModeLiteral, Literal: &value})
		}
	}
	d.DataRules.Sections = []SectionRule{}
	for _, s := range m.Sections {
		d.DataRules.Sections = append(d.DataRules.Sections, SectionRule{Section: s.Name, Mode: ModeDefault})
	}
	return d
}

func TestApprovedDataWorkflowHasRealBoundedRules(t *testing.T) {
	d, m, defaults := masterDefinitionFixture(t)
	d = approvedDataRules(t, d, m)
	if err := ValidateDefinitionAgainstTemplate(d, m, defaults); err != nil {
		t.Fatal(err)
	}
	_, _, rules, err := CanonicalDefinition(d)
	if err != nil || rules.InputMode != presign.InputApprovedData {
		t.Fatal("approved-data path lacks distinct real rule commitment")
	}
	d.DataRules.Sections[0] = SectionRule{Section: "manual_scope", Mode: ModeReviewedValue}
	if ValidateDefinitionAgainstTemplate(d, m, defaults) == nil {
		t.Fatal("unattended prose admitted")
	}
}

func TestWorkflowRulesRejectWrongCRMFieldAndAmbiguousModes(t *testing.T) {
	d := definitionFixture(t)
	value := "fixed"
	for name, r := range map[string]ValueRule{"arbitrary_nested": {Variable: "price", Mode: ModeCRM, SourceKind: "crm.deal", SourcePath: "secret.body"}, "literal_absent": {Variable: "price", Mode: ModeLiteral}, "mixed": {Variable: "price", Mode: ModeReviewedValue, Literal: &value}} {
		t.Run(name, func(t *testing.T) {
			d.DataRules.Values = []ValueRule{r}
			if ValidateDefinition(d) == nil {
				t.Fatal("unapproved or ambiguous rule accepted")
			}
		})
	}
}

func TestSessionActorRequiresActualOriginalSignedCookie(t *testing.T) {
	cookies, err := auth.NewSignedCookie(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	org, user := uuid.New(), uuid.New()
	raw, _ := json.Marshal(auth.SessionPayload{UserID: user, Generation: 3})
	one := cookies.Mint(raw, time.Minute)
	two := cookies.Mint(raw, 2*time.Minute)
	a, err := NewSessionActor(cookies, one, org, user)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSessionActor(cookies, two, org, user)
	if err != nil {
		t.Fatal(err)
	}
	if a.credentialSHA256 == b.credentialSHA256 || a.authorize == nil {
		t.Fatal("original credential not pinned")
	}
	if _, err := NewSessionActor(cookies, one, org, uuid.New()); err == nil {
		t.Fatal("another member substituted")
	}
	if _, err := NewSessionActor(cookies, "API credential", org, user); err == nil {
		t.Fatal("API token fabricated named consent")
	}
	purpose, _ := cookies.MintPurpose("presign.self-grant.confirm.v1", raw, time.Minute)
	if _, err := NewSessionActor(cookies, purpose, org, user); err == nil {
		t.Fatal("purpose receipt became login authority")
	}
}

func TestRegistrySignatureAndDisclosureAreServerOwned(t *testing.T) {
	styles, err := SignatureStyles()
	if err != nil || len(styles) != 5 {
		t.Fatal("missing embedded font catalog")
	}
	for _, style := range styles {
		h, err := render.SignatureFontSHA256(style.Font)
		if err != nil || style.FontSHA256 != h {
			t.Fatal("font proof not actual asset")
		}
	}
	copy := Disclosure()
	if copy.Version != 1 || copy.SHA256 != domainSHA("hash:presign-disclosure:v1", []byte(copy.Text)) || copy.Text == "" {
		t.Fatal("copy pin not app-owned text")
	}
}

func TestRegistryErrorAndDependencyBoundaries(t *testing.T) {
	if ErrorCode(errors.Join(ErrAudit, pgx.ErrNoRows)) != 500 || ErrorCode(ErrConflict) != 409 {
		t.Fatal("audit no-row disguised as client conflict")
	}
	e := NewEngine(nil, nil, nil)
	if _, err := e.GetOwnRequest(context.Background(), SessionActor{}, uuid.New()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing session/database admitted")
	}
	d := definitionFixture(t)
	d.DataRules.Values = []ValueRule{{Variable: "optional", Mode: ModeLiteral, Literal: new(string)}}
	raw, _, _, err := CanonicalDefinition(d)
	if err != nil || !bytes.Contains(raw, []byte(`"literal":""`)) {
		t.Fatal("explicit empty lost presence")
	}
	d.DataRules.Values[0].Mode = ModeAbsent
	d.DataRules.Values[0].Literal = nil
	_, _, rules, err := CanonicalDefinition(d)
	if err != nil || rules.InputMode != presign.InputReviewedDocument {
		t.Fatal("explicit absence rule refused")
	}
}
