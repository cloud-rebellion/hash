// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlsource_test

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestBrandedSourceArtifactBindsCurrentPDFPartiesAndProtectsCopies(t *testing.T) {
	input, doc, rows := testfixture.BrandedHTMLContract(t)
	fields := testfixture.BrandedSignatureFields(t, doc)
	if err := htmlsource.Validate(doc, true); err != nil {
		t.Fatal(err)
	}
	if err := htmlsource.ValidateContractParties(doc, rows); err != nil {
		t.Fatal(err)
	}
	if err := htmlsource.ValidateSigningFields(doc, fields, 2); err != nil {
		t.Fatal(err)
	}
	policy, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || policy == nil || artifact == nil {
		t.Fatal("missing policy", err)
	}
	policy.Branding.TextHex = "#000000"
	artifact.Fields[0].X = 0
	input.SigningArtifact.Fields[0].X = 0
	if err := htmlsource.ValidateSigningFields(doc, fields, 2); err != nil {
		t.Fatal("caller changed saved artifact", err)
	}
	recovered, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		t.Fatal(err)
	}
	recovered.SigningArtifact.Fields[0].X = 0
	if err := htmlsource.Validate(doc, false); err != nil {
		t.Fatal("recovered copy changed saved artifact", err)
	}
	fields[0], fields[1] = fields[1], fields[0]
	if err := htmlsource.ValidateSigningFields(doc, fields, 2); err != nil {
		t.Fatal("query row order became authority", err)
	}
}

func TestBrandedSourceRefusesFieldOwnershipGeometryAndBindingDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]*generated.DocumentField) []*generated.DocumentField
	}{
		{"missing", func(f []*generated.DocumentField) []*generated.DocumentField { return f[:1] }},
		{"extra", func(f []*generated.DocumentField) []*generated.DocumentField { return append(f, f[0]) }},
		{"id", func(f []*generated.DocumentField) []*generated.DocumentField { f[0].ID = uuid.Nil; return f }},
		{"recipient", func(f []*generated.DocumentField) []*generated.DocumentField {
			f[0].RecipientID = f[1].RecipientID
			return f
		}},
		{"page", func(f []*generated.DocumentField) []*generated.DocumentField { f[0].Page = 1; return f }},
		{"geometry", func(f []*generated.DocumentField) []*generated.DocumentField {
			f[0].YPct = pgtype.Numeric{Int: big.NewInt(420001), Exp: -4, Valid: true}
			return f
		}},
		{"required", func(f []*generated.DocumentField) []*generated.DocumentField { f[0].Required = false; return f }},
		{"label", func(f []*generated.DocumentField) []*generated.DocumentField {
			f[0].Label.String = "Other party"
			return f
		}},
		{"source", func(f []*generated.DocumentField) []*generated.DocumentField {
			f[0].OptionsJson = []byte(`{}`)
			return f
		}},
		{"case", func(f []*generated.DocumentField) []*generated.DocumentField {
			f[0].OptionsJson = bytes.Replace(f[0].OptionsJson, []byte(`"slot"`), []byte(`"Slot"`), 1)
			return f
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, doc, _ := testfixture.BrandedHTMLContract(t)
			fields := testfixture.BrandedSignatureFields(t, doc)
			if htmlsource.ValidateSigningFields(doc, test.mutate(fields), 2) == nil {
				t.Fatal("field drift accepted")
			}
		})
	}
	_, doc, _ := testfixture.BrandedHTMLContract(t)
	if htmlsource.ValidateSigningFields(doc, testfixture.BrandedSignatureFields(t, doc), 1) == nil {
		t.Fatal("wrong actual PDF page count accepted")
	}
}

func TestBrandedSourceRefusesMalformedManifestAndPrintedPlanReuse(t *testing.T) {
	input, doc, _ := testfixture.BrandedHTMLContract(t)
	original := bytes.Clone(doc.HtmlSourceJson)
	for _, raw := range []string{
		strings.Replace(string(original), `"signing_artifact":`, `"Signing_Artifact":`, 1),
		strings.Replace(string(original), `"plan_sha256":`, `"Plan_SHA256":`, 1),
		strings.Replace(string(original), `"rotation":0`, `"Rotation":0`, 1),
		strings.Replace(string(original), `[0,0,594960,841920]`, `[0,0,594960]`, 1),
		strings.Replace(string(original), `"x":100000`, `"x":100001`, 1),
		strings.Replace(string(original), `"final_pages":2`, `"final_pages":3`, 1),
	} {
		copy := *doc
		copy.HtmlSourceJson = []byte(raw)
		if htmlsource.Validate(&copy, false) == nil {
			t.Fatal("malformed manifest accepted")
		}
	}
	input.Values["customer_name"] = "New Synthetic Customer"
	doc.VariablesJson, _ = json.Marshal(input.Values)
	if _, err := htmlsource.New(input, doc); err == nil {
		t.Fatal("old printed signing plan reused for changed identity")
	}
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	input.SigningArtifact, err = htmlsource.NewSigningArtifact(compiled, htmlmaster.Input{Values: input.Values, Sections: input.Sections}, input.PartyBindings, input.SigningArtifact.Composition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := htmlsource.New(input, doc); err != nil {
		t.Fatal("fresh plan refused", err)
	}
}

func TestBrandedSourceRequiresCompleteExactApprovedBrandingIncludingEmptyLogo(t *testing.T) {
	_, doc, _ := testfixture.BrandedHTMLContract(t)
	policy, _, err := htmlsource.SigningPage(doc)
	if err != nil {
		t.Fatal(err)
	}
	b := policy.Branding
	text := func(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }
	row := &generated.DocumentBrandingOverride{DocumentID: doc.ID, PrimaryHex: text(b.PrimaryHex), AccentHex: text(b.AccentHex), SurfaceHex: text(b.SurfaceHex), TextHex: text(b.TextHex), MutedHex: text(b.MutedHex),
		LogoUrl: text(""), LogoAlt: text(""), FontHeading: text(b.FontHeading), FontBody: text(b.FontBody), SignatureColor: text(b.SignatureColor)}
	if err := htmlsource.ValidateSigningBranding(doc, row); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*generated.DocumentBrandingOverride){func(r *generated.DocumentBrandingOverride) { r.LogoUrl.Valid = false }, func(r *generated.DocumentBrandingOverride) { r.LogoUrl.String = "/org/logo.png" }, func(r *generated.DocumentBrandingOverride) { r.TextHex.String = "#000000" }, func(r *generated.DocumentBrandingOverride) { r.DocumentID = uuid.New() }} {
		copy := *row
		mutate(&copy)
		if htmlsource.ValidateSigningBranding(doc, &copy) == nil {
			t.Fatal("approved branding drift accepted")
		}
	}
	_, legacy, _ := testfixture.HTMLContract(t)
	if htmlsource.ValidateSigningFields(legacy, nil, 0) != nil || htmlsource.ValidateSigningBranding(legacy, nil) != nil {
		t.Fatal("legacy profile acquired schema3 state requirements")
	}
}
