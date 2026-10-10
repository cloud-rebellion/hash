// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlsource_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// All PDF and composition hashes here are synthetic; these tests prove source
// commitments and admission only, not rendering, storage or field replacement.
func optionalEmptyFixture(t *testing.T, schema int) (htmlsource.Input, *generated.Document) {
	t.Helper()
	input, doc, _ := testfixture.HTMLContract(t)
	if schema == htmlsource.SigningPageSchemaVersion {
		input, doc, _ = testfixture.BrandedHTMLContract(t)
	}
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	master.SchemaVersion = schema
	if schema == htmlsource.SchemaVersion {
		master.ContractProfile = nil
		input.PartyBindings = nil
	}
	master.HTML += `<p><span data-hash-value="note"></span><span data-hash-value="memo"></span></p><div data-hash-section="details"></div>`
	master.Values = append(master.Values, htmlmaster.Value{Name: "note", MaxChars: 100}, htmlmaster.Value{Name: "memo", MaxChars: 100})
	master.Sections = append(master.Sections, htmlmaster.Section{Name: "details", DefaultText: "Approved unchanged details", MaxChars: 100})
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, input.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	input.MasterJSON, input.DefaultVarsJSON, input.TemplateContentSHA256 = canonical.MasterJSON, canonical.DefaultsJSON, canonical.SHA256
	if input.SigningArtifact != nil {
		compiled, err := htmlmaster.Compile(master)
		if err != nil {
			t.Fatal(err)
		}
		input.SigningArtifact, err = htmlsource.NewSigningArtifact(compiled, htmlmaster.Input{Values: input.Values, Sections: input.Sections}, input.PartyBindings, input.SigningArtifact.Composition)
		if err != nil {
			t.Fatal(err)
		}
	}
	doc.HtmlSourceJson, err = htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	input, err = htmlsource.InputForCurrent(doc)
	if err != nil {
		t.Fatal(err)
	}
	return input, doc
}

func TestOptionalEmptyAdditionPreservesAllHistoricalSourceDomains(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("schema%d", schema), func(t *testing.T) {
			input, doc := optionalEmptyFixture(t, schema)
			original := bytes.Clone(doc.HtmlSourceJson)
			before, err := htmlsource.Commitment(doc)
			if err != nil {
				t.Fatal(err)
			}
			beforeDigest, err := htmlsource.MaterializationDigest(doc)
			if err != nil {
				t.Fatal(err)
			}
			input.Values["note"], input.Values["memo"] = "", ""
			ok, err := htmlsource.IsOptionalEmptyAddition(doc, input)
			if err != nil || !ok || !bytes.Equal(doc.HtmlSourceJson, original) {
				t.Fatalf("optional presence change rejected or mutated origin: %v %v", ok, err)
			}
			candidate := *doc
			candidate.VariablesJson, err = json.Marshal(input.Values)
			if err != nil {
				t.Fatal(err)
			}
			candidate.HtmlSourceJson, err = htmlsource.New(input, &candidate)
			if err != nil {
				t.Fatal(err)
			}
			after, err := htmlsource.Commitment(&candidate)
			if err != nil {
				t.Fatal(err)
			}
			afterDigest, err := htmlsource.MaterializationDigest(&candidate)
			if err != nil || before == after || beforeDigest != afterDigest {
				t.Fatal("exact input presence did not change source while preserving rendered digest", err)
			}
			var wire struct {
				SchemaVersion int `json:"schema_version"`
			}
			if err := json.Unmarshal(candidate.HtmlSourceJson, &wire); err != nil || wire.SchemaVersion != schema {
				t.Fatal("source schema changed", err)
			}
			if ok, err := htmlsource.IsOptionalEmptyAddition(&candidate, input); ok || err != nil {
				t.Fatal("already materialized empty values became a revision", err)
			}
		})
	}
}

func TestOptionalEmptyAdditionRejectsOtherInputAndAuthorityChanges(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*htmlsource.Input)
	}{
		{"no_addition", func(i *htmlsource.Input) {}},
		{"nonempty_addition", func(i *htmlsource.Input) { i.Values["note"] = "new" }},
		{"whitespace_is_not_empty", func(i *htmlsource.Input) { i.Values["note"] = " " }},
		{"unknown_empty", func(i *htmlsource.Input) { i.Values["unknown"] = "" }},
		{"required_blank", func(i *htmlsource.Input) { i.Values["note"] = ""; i.Values["price"] = "" }},
		{"existing_rewrite", func(i *htmlsource.Input) { i.Values["note"] = ""; i.Values["price"] = "2000" }},
		{"existing_drop", func(i *htmlsource.Input) { i.Values["note"], i.Values["memo"] = "", ""; delete(i.Values, "price") }},
		{"section_presence", func(i *htmlsource.Input) { i.Values["note"] = ""; i.Sections["details"] = "Approved unchanged details" }},
		{"section_rewrite", func(i *htmlsource.Input) { i.Values["note"] = ""; i.Sections["details"] = "Changed wording" }},
		{"template_id", func(i *htmlsource.Input) { i.Values["note"] = ""; i.TemplateID = uuid.New() }},
		{"template_version", func(i *htmlsource.Input) { i.Values["note"] = ""; i.TemplateVersion++ }},
		{"template_digest", func(i *htmlsource.Input) { i.Values["note"] = ""; i.TemplateContentSHA256 = "" }},
		{"approver", func(i *htmlsource.Input) { i.Values["note"] = ""; i.TemplateApprovedBy = uuid.New() }},
		{"approval_time", func(i *htmlsource.Input) {
			i.Values["note"] = ""
			i.TemplateApprovedAt = i.TemplateApprovedAt.Add(time.Second)
		}},
		{"master", func(i *htmlsource.Input) {
			i.Values["note"] = ""
			i.MasterJSON = bytes.Replace(i.MasterJSON, []byte("Approved unchanged details"), []byte("Changed approved details"), 1)
		}},
		{"defaults", func(i *htmlsource.Input) { i.Values["note"] = ""; i.DefaultVarsJSON = []byte(`{"note":""}`) }},
		{"null_defaults", func(i *htmlsource.Input) { i.Values["note"] = ""; i.DefaultVarsJSON = []byte(`null`) }},
		{"nil_values", func(i *htmlsource.Input) { i.Values = nil }},
		{"nil_sections", func(i *htmlsource.Input) { i.Values["note"] = ""; i.Sections = nil }},
	}
	for _, schema := range []int{1, 2, 3} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("schema%d/%s", schema, tc.name), func(t *testing.T) {
				input, doc := optionalEmptyFixture(t, schema)
				tc.mutate(&input)
				if ok, _ := htmlsource.IsOptionalEmptyAddition(doc, input); ok {
					t.Fatal("non-presence-only change accepted")
				}
			})
		}
		if schema > 1 {
			t.Run(fmt.Sprintf("schema%d/party_identity", schema), func(t *testing.T) {
				input, doc := optionalEmptyFixture(t, schema)
				input.Values["note"] = ""
				input.PartyBindings[0].RecipientID = uuid.New()
				if ok, _ := htmlsource.IsOptionalEmptyAddition(doc, input); ok {
					t.Fatal("party substitution accepted")
				}
			})
		}
	}
	input, doc := optionalEmptyFixture(t, 3)
	input.Values["note"] = ""
	input.MasterJSON = bytes.Replace(input.MasterJSON, []byte(`"primary_hex":"#102038"`), []byte(`"primary_hex":"#112039"`), 1)
	if ok, _ := htmlsource.IsOptionalEmptyAddition(doc, input); ok {
		t.Fatal("signing policy change accepted")
	}
}

func TestOptionalEmptyAdditionUsesValidatedCurrentSourceAndCanonicalDesign(t *testing.T) {
	input, doc := optionalEmptyFixture(t, 3)
	origin := bytes.Clone(doc.HtmlSourceJson)
	input.Values["note"] = ""
	doc.VariablesJson, _ = json.Marshal(input.Values)
	current, err := htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson = origin
	doc.HtmlCurrentSourceJson = current
	doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.HtmlCurrentPageCount = pgtype.Int4{Int32: 2, Valid: true}
	doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 2, Valid: true}
	input, err = htmlsource.InputForCurrent(doc)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := htmlsource.IsOptionalEmptyAddition(doc, input); ok || err != nil {
		t.Fatal("origin omission overrode current presence", err)
	}
	input.Values["memo"] = ""
	var transported bytes.Buffer
	if err := json.Indent(&transported, doc.HtmlCurrentSourceJson, "", "  "); err != nil {
		t.Fatal(err)
	}
	doc.HtmlCurrentSourceJson = transported.Bytes()
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, input.MasterJSON, "", "  "); err != nil {
		t.Fatal(err)
	}
	input.MasterJSON = pretty.Bytes()
	input.PartyBindings[0], input.PartyBindings[1] = input.PartyBindings[1], input.PartyBindings[0]
	if ok, err := htmlsource.IsOptionalEmptyAddition(doc, input); !ok || err != nil {
		t.Fatal("equivalent JSONB design or bindings rejected", err)
	}
	for _, raw := range [][]byte{[]byte(`null`), bytes.Replace(current, []byte(`"values":{`), []byte(`"values":{"memo":null,`), 1)} {
		copy := *doc
		copy.HtmlCurrentSourceJson = raw
		if ok, err := htmlsource.IsOptionalEmptyAddition(&copy, input); ok || err == nil {
			t.Fatal("invalid/null current source accepted")
		}
	}
	if ok, err := htmlsource.IsOptionalEmptyAddition(nil, input); ok || err == nil {
		t.Fatal("nil previous source accepted")
	}
}
