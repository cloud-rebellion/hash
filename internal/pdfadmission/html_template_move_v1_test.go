// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

func moveMasterV1(t *testing.T, html string, values []htmlmaster.Value, sections []htmlmaster.Section, defaults string) htmlmaster.TemplateCommitment {
	t.Helper()
	raw, err := json.Marshal(htmlmaster.Master{SchemaVersion: 1, HTML: html, Values: values, Sections: sections})
	if err != nil {
		t.Fatal(err)
	}
	c, err := htmlmaster.CanonicalTemplate(raw, []byte(defaults))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func moveFixtureV1(t *testing.T) (htmlsource.Input, *HTMLTemplateMoveTargetV1) {
	t.Helper()
	tid := uuid.New()
	old := moveMasterV1(t, `<p><span data-hash-value="customer"></span> <span data-hash-value="ref"></span></p><div data-hash-section="scope"></div>`,
		[]htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 100}, {Name: "ref", MaxChars: 50}},
		[]htmlmaster.Section{{Name: "scope", DefaultText: "old scope", MaxChars: 500}}, `{"customer":"Old default","ref":"R-1"}`)
	next := moveMasterV1(t, `<p><span data-hash-value="customer"></span> <span data-hash-value="ref"></span> <span data-hash-value="extra"></span></p><div data-hash-section="scope"></div>`,
		[]htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 100}, {Name: "ref", MaxChars: 50}, {Name: "extra", MaxChars: 50}},
		[]htmlmaster.Section{{Name: "scope", DefaultText: "new scope", MaxChars: 500}}, `{"customer":"New default","ref":"R-2","extra":"E"}`)
	current := htmlsource.Input{TemplateID: tid, TemplateVersion: 1, TemplateContentSHA256: old.SHA256, MasterJSON: old.MasterJSON, DefaultVarsJSON: old.DefaultsJSON,
		Values:   map[string]string{"customer": "Old default", "ref": "Mine"},
		Sections: map[string]string{"scope": "old scope"}, TemplateApprovedBy: uuid.New(), TemplateApprovedAt: time.Now()}
	return current, &HTMLTemplateMoveTargetV1{TemplateID: tid, Version: 2, Content: next, ApprovedBy: uuid.New(), ApprovedAt: time.Now()}
}

func TestPlanHTMLTemplateMoveCarriesTypedValuesAndAdoptsOnlyNewDefaults(t *testing.T) {
	current, target := moveFixtureV1(t)
	got, diff, err := PlanHTMLTemplateMoveV1(current, target, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.TemplateVersion != 2 || got.TemplateContentSHA256 != target.Content.SHA256 || got.TemplateApprovedBy != target.ApprovedBy {
		t.Fatal("design pins not moved", got.TemplateVersion)
	}
	// "customer" equals the old default but is still carried exactly.
	if got.Values["customer"] != "Old default" || got.Values["ref"] != "Mine" || got.Values["extra"] != "E" {
		t.Fatalf("typed values must be kept, new names take defaults: %v", got.Values)
	}
	if got.Sections["scope"] != "old scope" {
		t.Fatalf("section override must be carried exactly: %v", got.Sections)
	}
	if !slices.Equal(diff.AdoptedDefaultValues, []string{"extra"}) || len(diff.DroppedValues) != 0 {
		t.Fatalf("diff: %+v", diff)
	}
	if current.Values["customer"] != "Old default" {
		t.Fatal("plan mutated the current input")
	}
	got, diff, err = PlanHTMLTemplateMoveV1(current, target, map[string]string{"extra": "Supplied"}, map[string]string{"scope": "mine"})
	if err != nil || got.Values["extra"] != "Supplied" || got.Sections["scope"] != "mine" || len(diff.AdoptedDefaultValues) != 0 {
		t.Fatalf("requests win and are not reported as adopted: %v %+v %v", got.Values, diff, err)
	}
}

func TestPlanHTMLTemplateMoveDropsRemovedFieldsOnlyWhenUntouched(t *testing.T) {
	for name, tc := range map[string]struct {
		value   string
		dropped bool
	}{"old default": {"R-1", true}, "empty": {"", true}, "typed": {"Mine", false}} {
		t.Run(name, func(t *testing.T) {
			current, target := moveFixtureV1(t)
			target.Content = moveMasterV1(t, `<p><span data-hash-value="customer"></span></p><div data-hash-section="scope"></div>`,
				[]htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 100}},
				[]htmlmaster.Section{{Name: "scope", DefaultText: "new scope", MaxChars: 500}}, `{"customer":"New default"}`)
			current.Values["ref"] = tc.value
			got, diff, err := PlanHTMLTemplateMoveV1(current, target, nil, nil)
			if tc.dropped {
				if err != nil || !slices.Equal(diff.DroppedValues, []string{"ref"}) {
					t.Fatalf("%v %+v", err, diff)
				}
				if _, kept := got.Values["ref"]; kept {
					t.Fatal("removed field kept")
				}
			} else if !errors.Is(err, ErrHTMLTemplateMoveUndeclaredV1) {
				t.Fatalf("typed value of a removed field must refuse: %v", err)
			}
		})
	}
	// Sections follow the same rule.
	current, target := moveFixtureV1(t)
	target.Content = moveMasterV1(t, `<p><span data-hash-value="customer"></span> <span data-hash-value="ref"></span></p>`,
		[]htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 100}, {Name: "ref", MaxChars: 50}}, nil, `{"customer":"N","ref":"R"}`)
	if got, diff, err := PlanHTMLTemplateMoveV1(current, target, nil, nil); err != nil || !slices.Equal(diff.DroppedSections, []string{"scope"}) || len(got.Sections) != 0 {
		t.Fatalf("untouched removed section: %v %+v", err, diff)
	}
	current.Sections["scope"] = "typed"
	if _, _, err := PlanHTMLTemplateMoveV1(current, target, nil, nil); !errors.Is(err, ErrHTMLTemplateMoveUndeclaredV1) {
		t.Fatalf("typed removed section must refuse: %v", err)
	}
}

func TestPlanHTMLTemplateMoveSectionsAreFilteredToDeclared(t *testing.T) {
	current, target := moveFixtureV1(t)
	current.Sections["scope"] = "kept"
	got, _, err := PlanHTMLTemplateMoveV1(current, target, nil, nil)
	if err != nil || got.Sections["scope"] != "kept" || len(got.Sections) != 1 {
		t.Fatalf("%v %v", err, got.Sections)
	}
	if _, _, err = PlanHTMLTemplateMoveV1(current, target, nil, map[string]string{"ghost": "x"}); !errors.Is(err, ErrHTMLTemplateMoveUndeclaredV1) || !strings.Contains(err.Error(), "section ghost") {
		t.Fatalf("undeclared section request: %v", err)
	}
}

func moveContractV1(t *testing.T, kind string, slots ...string) htmlmaster.TemplateCommitment {
	t.Helper()
	master := htmlmaster.Master{SchemaVersion: htmlmaster.ContractSchemaVersion, HTML: "<main>",
		ContractProfile: &htmlmaster.ContractProfile{ID: "reviewed_services", Version: 1, Kind: kind}}
	defaults := map[string]string{}
	for _, slot := range slots {
		master.ContractProfile.Parties = append(master.ContractProfile.Parties, htmlmaster.ContractParty{Slot: slot,
			CompanyName: slot + "_company_name", CompanyID: slot + "_company_id", RepresentativeName: slot + "_name",
			RepresentativeEmail: slot + "_email", RepresentativeAuthority: slot + "_authority"})
		for _, f := range []string{"company_name", "company_id", "name", "email", "authority"} {
			n := slot + "_" + f
			master.Values = append(master.Values, htmlmaster.Value{Name: n, Required: true, MaxChars: 1024})
			master.HTML += `<p><span data-hash-value="` + n + `"></span></p>`
			defaults[n] = "Default " + n
		}
	}
	terms := []string{"scope", "price", "currency", "tax", "payment_terms", "valid_until"}
	if kind == "b2b_services" {
		terms = []string{"scope", "price", "currency", "tax", "payment_terms", "effective_date", "duration", "termination"}
	}
	for _, n := range terms {
		if n == "scope" || n == "termination" {
			master.ContractProfile.Terms = append(master.ContractProfile.Terms, htmlmaster.ContractTerm{Name: n, Section: n})
			master.Sections = append(master.Sections, htmlmaster.Section{Name: n, DefaultText: "Reviewed " + n, MaxChars: 1024})
			master.HTML += `<div data-hash-section="` + n + `"></div>`
			continue
		}
		master.ContractProfile.Terms = append(master.ContractProfile.Terms, htmlmaster.ContractTerm{Name: n, Value: n})
		master.Values = append(master.Values, htmlmaster.Value{Name: n, Required: true, MaxChars: 1024})
		master.HTML += `<p><span data-hash-value="` + n + `"></span></p>`
		defaults[n] = "Default " + n
	}
	master.HTML += "</main>"
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	dj, _ := json.Marshal(defaults)
	c, err := htmlmaster.CanonicalTemplate(raw, dj)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func moveContractCurrentV1(t *testing.T, old htmlmaster.TemplateCommitment, tid uuid.UUID, slots ...string) htmlsource.Input {
	t.Helper()
	var defaults map[string]string
	if err := json.Unmarshal(old.DefaultsJSON, &defaults); err != nil {
		t.Fatal(err)
	}
	in := htmlsource.Input{TemplateID: tid, TemplateVersion: 1, TemplateContentSHA256: old.SHA256, MasterJSON: old.MasterJSON, DefaultVarsJSON: old.DefaultsJSON,
		Values: defaults, Sections: map[string]string{}}
	for _, s := range slots {
		in.PartyBindings = append(in.PartyBindings, htmlsource.PartyBinding{Slot: s, RecipientID: uuid.New()})
	}
	return in
}

func TestPlanHTMLTemplateMoveContractProfiles(t *testing.T) {
	tid := uuid.New()
	old := moveContractV1(t, "proposal", "provider", "customer")
	current := moveContractCurrentV1(t, old, tid, "provider", "customer")
	target := func(c htmlmaster.TemplateCommitment) *HTMLTemplateMoveTargetV1 {
		return &HTMLTemplateMoveTargetV1{TemplateID: tid, Version: 2, Content: c, ApprovedBy: uuid.New(), ApprovedAt: time.Now()}
	}
	// Same kind and slots: allowed, party identity values are carried.
	current.Values["customer_email"] = "me@example.invalid"
	got, _, err := PlanHTMLTemplateMoveV1(current, target(moveContractV1(t, "proposal", "provider", "customer")), nil, nil)
	if err != nil || got.Values["customer_email"] != "me@example.invalid" {
		t.Fatalf("same-shape contract move: %v %v", err, got.Values["customer_email"])
	}
	for name, c := range map[string]htmlmaster.TemplateCommitment{
		"kind change (U2)": moveContractV1(t, "b2b_services", "provider", "customer"),
	} {
		if _, _, err := PlanHTMLTemplateMoveV1(current, target(c), nil, nil); !errors.Is(err, ErrHTMLTemplateMoveSchemaV1) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Bindings that do not match the slots are refused even if old and new agree.
	bad := current
	bad.PartyBindings = bad.PartyBindings[:1]
	if _, _, err := PlanHTMLTemplateMoveV1(bad, target(moveContractV1(t, "proposal", "provider", "customer")), nil, nil); !errors.Is(err, ErrHTMLTemplateMoveSchemaV1) {
		t.Fatalf("binding mismatch: %v", err)
	}
	// A party field newly declared by the target never takes a default.
	newer := moveContractV1(t, "proposal", "provider", "customer")
	var m htmlmaster.Master
	if err := json.Unmarshal(newer.MasterJSON, &m); err != nil {
		t.Fatal(err)
	}
	cur := current
	delete(cur.Values, "customer_email")
	got, diff, err := PlanHTMLTemplateMoveV1(cur, target(newer), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, set := got.Values["customer_email"]; set || slices.Contains(diff.AdoptedDefaultValues, "customer_email") {
		t.Fatalf("party email must never come from a default: %v %+v", got.Values["customer_email"], diff)
	}
}

func TestPlanHTMLTemplateMoveRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*htmlsource.Input, *HTMLTemplateMoveTargetV1)
		values map[string]string
		want   error
	}{
		"same version":       {func(c *htmlsource.Input, _ *HTMLTemplateMoveTargetV1) { c.TemplateVersion = 2 }, nil, ErrHTMLTemplateMoveNotForwardV1},
		"older version":      {func(c *htmlsource.Input, _ *HTMLTemplateMoveTargetV1) { c.TemplateVersion = 3 }, nil, ErrHTMLTemplateMoveNotForwardV1},
		"other template":     {func(_ *htmlsource.Input, g *HTMLTemplateMoveTargetV1) { g.TemplateID = uuid.New() }, nil, ErrHTMLTemplateMoveStaleV1},
		"undeclared request": {nil, map[string]string{"nope": "x"}, ErrHTMLTemplateMoveUndeclaredV1},
		"undeclared carried": {func(c *htmlsource.Input, _ *HTMLTemplateMoveTargetV1) { c.Values["dropped"] = "x" }, nil, ErrHTMLTemplateMoveUndeclaredV1},
		"party slots": {func(c *htmlsource.Input, _ *HTMLTemplateMoveTargetV1) {
			c.PartyBindings = []htmlsource.PartyBinding{{Slot: "provider", RecipientID: uuid.New()}}
		}, nil, ErrHTMLTemplateMoveSchemaV1},
	} {
		t.Run(name, func(t *testing.T) {
			current, target := moveFixtureV1(t)
			if tc.mutate != nil {
				tc.mutate(&current, target)
			}
			if _, _, err := PlanHTMLTemplateMoveV1(current, target, tc.values, nil); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
	current, _ := moveFixtureV1(t)
	if _, _, err := PlanHTMLTemplateMoveV1(current, nil, nil, nil); !errors.Is(err, ErrHTMLTemplateMoveStaleV1) {
		t.Fatal("nil target accepted")
	}
}

func TestHTMLTemplateMoveInputShape(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ok := []string{"{}", `{"expected_updated_at":"x","expected_html_source_commitment":"y","template_version":3,"expected_template_content_sha256":"z","values":{"a":"b"},"sections":{},"summary":"s"}`}
	for _, raw := range ok {
		if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLDocumentTemplateMoveInputV1, []byte(raw)); err != nil {
			t.Fatalf("typed pin authority must stay with the decoder: %s %v", raw, err)
		}
	}
	for _, raw := range []string{`{"extra":1}`, `{"values":{"x":{"n":1}}}`, `{"sections":["a"]}`, `[]`} {
		if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLDocumentTemplateMoveInputV1, []byte(raw)); err == nil {
			t.Fatalf("admitted: %s", raw)
		}
	}
	if limit, err := htmlAuthoringInputLimitV1(HTMLDocumentTemplateMoveInputV1); err != nil || limit != 1<<20 {
		t.Fatal("profile limit", limit, err)
	}
}
