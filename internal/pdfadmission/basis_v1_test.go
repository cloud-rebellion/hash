// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
)

// Synthetic snapshots qualify canonical identity and bounded field/party
// consistency only. No worker/render/SQL/provider/signing/legal proof is inferred.
func basisInputV1(t *testing.T, ordinary bool) InputV1 {
	t.Helper()
	org := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	doc := uuid.MustParse("20000000-0000-0000-0000-000000000001")
	signer := uuid.MustParse("30000000-0000-0000-0000-000000000001")
	source := manualfit.SourceTupleV1{Key: "opaque/source.pdf", VersionID: " original+/opaque= ", SHA256: strings.Repeat("a", 64), Bytes: 100}
	page := sanitize.PDFManualPage{UserUnit: 1}
	for i := range page.Boxes {
		page.Boxes[i] = [4]float64{0, 0, 600, 800}
	}
	geom := sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: source.SHA256, SourceBytes: source.Bytes, Pages: []sanitize.PDFManualPage{page, page}}
	raw, err := json.Marshal(geom.Pages)
	if err != nil {
		t.Fatal(err)
	}
	geom.GeometrySHA256 = testSHA256V1(raw)
	in := InputV1{OrgID: org, DocumentID: doc, OriginalDocumentName: "  Avtal – 李 & Co  ", CeremonyEpoch: time.Date(2026, 10, 12, 11, 22, 33, 123456000, time.UTC), SourceKind: "pdf", RequiresSignature: true,
		Source: source, Geometry: geom, RoutingMode: "parallel",
		RenderRecipe: RenderRecipeV1{Schema: OrdinaryRecipeSchemaV1, RecipeID: OrdinaryRecipeIDV1, HTMLTemplateSHA256: strings.Repeat("b", 64), CoreCSSSHA256: strings.Repeat("c", 64),
			MeasurementSHA256: strings.Repeat("d", 64), SnapshotSHA256: strings.Repeat("e", 64), PrintRecipeSHA256: strings.Repeat("f", 64), BrandingCSS: "/* original context only */\n.brand { color: #123456; }",
			Fonts: []FontAssetV1{{File: OrdinaryFontFileV1, Family: OrdinaryFontFamilyV1, SHA256: OrdinaryFontSHA256V1, Bytes: OrdinaryFontBytesV1}}}}
	role := "signer"
	if !ordinary {
		role = "customer"
	}
	in.Parties = []PartyV1{{OrgID: org, DocumentID: doc, ID: signer, Role: role, Name: "Åsa 李 & Co", Email: "asa@example.test", OrderIndex: 1, Locale: "en"}}
	in.RequiredRoles = []string{role}
	in.Fields = []FieldV1{{OrgID: org, DocumentID: doc, ID: uuid.MustParse("40000000-0000-0000-0000-000000000001"), RecipientID: signer, RecipientValid: true, Type: "signature", Page: 1, Required: true, X: "05.0000", Y: "70.0000", W: "90.0000", H: "20.0000"}}
	if ordinary {
		in.Fields = append(in.Fields, FieldV1{OrgID: org, DocumentID: doc, ID: uuid.MustParse("40000000-0000-0000-0000-000000000002"), RecipientID: signer, RecipientValid: true, Type: "text", Page: 2, Required: true, X: "5.0000", Y: "10.0000", W: "90.0000", H: "20.0000", ValueValid: true, Value: "  Åsa & 李\r\n<approved text>\t  "})
	} else {
		provider := uuid.MustParse("30000000-0000-0000-0000-000000000002")
		in.Parties = append(in.Parties, PartyV1{OrgID: org, DocumentID: doc, ID: provider, Role: "provider", Name: "Bright Company", Email: "provider@example.test", OrderIndex: 0, Locale: "sv"})
		in.RequiredRoles = append(in.RequiredRoles, "provider")
		in.Fields = append(in.Fields, FieldV1{OrgID: org, DocumentID: doc, ID: uuid.MustParse("40000000-0000-0000-0000-000000000002"), RecipientID: provider, RecipientValid: true, Type: "signature", Page: 2, Required: true, X: "5.0000", Y: "70.0000", W: "90.0000", H: "20.0000"})
	}
	return in
}

func testSHA256V1(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func refreshGeometryV1(t *testing.T, in *InputV1) {
	t.Helper()
	raw, err := json.Marshal(in.Geometry.Pages)
	if err != nil {
		t.Fatal(err)
	}
	in.Geometry.GeometrySHA256 = testSHA256V1(raw)
}

func TestBasisV1CanonicalScopeOriginalsAndFinalFields(t *testing.T) {
	in := basisInputV1(t, true)
	b, err := BuildV1(in)
	if err != nil {
		t.Fatal(err)
	}
	raw := b.CanonicalJSON()
	expected := sha256.New()
	_, _ = expected.Write([]byte(DomainV1))
	_, _ = expected.Write(raw)
	if b.SHA256() != hex.EncodeToString(expected.Sum(nil)) || b.CanonicalSHA256() != testSHA256V1(raw) || b.SHA256() == b.CanonicalSHA256() {
		t.Fatal("static domain/plain object commitments confused")
	}
	restored, err := DecodeV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := restored.Input()
	if !bytes.Equal(raw, restored.CanonicalJSON()) || got.OriginalDocumentName != in.OriginalDocumentName || got.Fields[1].Value != in.Fields[1].Value || got.Fields[0].X != "05.0000" || got.Source.VersionID != in.Source.VersionID || got.Parties[0].Name != in.Parties[0].Name || got.Parties[0].OrgID != in.OrgID || got.Fields[0].DocumentID != in.DocumentID {
		t.Fatal("original literal/scope bytes changed")
	}
	fields, err := json.Marshal(in.Fields)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fields, b.FieldsJSON()) || b.FieldsSHA256() != testSHA256V1(fields) || bytes.Contains(b.FieldsJSON(), []byte("OrgID")) || bytes.Contains(raw, []byte("typed_name")) || bytes.Contains(raw, []byte("signed_at")) || bytes.Contains(raw, []byte("retain_until")) {
		t.Fatal("static fields changed final-wire shape or invented future adoption")
	}
	if pages := b.OrdinaryPages(); len(pages) != 1 || pages[0] != 2 {
		t.Fatal("ordinary painting page set wrong")
	}
	targets, err := b.SignatureTargets(in.Parties[0].ID)
	if err != nil || len(targets) != 1 || targets[0].X != "05.0000" || targets[0].OrgID != in.OrgID || targets[0].DocumentID != in.DocumentID {
		t.Fatal("exact all-target binding missing")
	}
	if _, err := b.SignatureTargets(uuid.New()); !errors.Is(err, ErrBasisV1) {
		t.Fatal("foreign target party accepted")
	}
}

func TestBasisV1SortingAndImmutableAccessors(t *testing.T) {
	in := basisInputV1(t, false)
	b, err := BuildV1(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Fields[0], in.Fields[1] = in.Fields[1], in.Fields[0]
	in.Parties[0], in.Parties[1] = in.Parties[1], in.Parties[0]
	in.RequiredRoles[0], in.RequiredRoles[1] = in.RequiredRoles[1], in.RequiredRoles[0]
	same, err := BuildV1(in)
	if err != nil || b.SHA256() != same.SHA256() {
		t.Fatal("input enumeration order changed canonical identity")
	}
	raw := b.CanonicalJSON()
	original := bytes.Clone(raw)
	raw[0] = '['
	got := b.Input()
	got.Fields[0].X = "99"
	got.Parties[0].Name = "changed"
	got.Geometry.Pages[0].Boxes[0][0] = 999
	got.RequiredRoles[0] = "changed"
	got.RenderRecipe.Fonts[0].SHA256 = strings.Repeat("1", 64)
	parts := [][]byte{b.FieldsJSON(), b.PartiesJSON(), b.GeometryJSON(), b.GeometryPagesJSON(), b.RenderRecipeJSON(), b.OrdinaryRecipeJSON()}
	for _, part := range parts {
		part[0] = '!'
	}
	targets, err := b.SignatureTargets(b.Parties()[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	targets[0].X = "99"
	if !bytes.Equal(b.CanonicalJSON(), original) || b.Input().Fields[0].X != "05.0000" || b.Input().Parties[0].Name == "changed" || b.Geometry().Pages[0].Boxes[0][0] != 0 || b.RenderRecipe().Fonts[0].SHA256 != OrdinaryFontSHA256V1 {
		t.Fatal("mutable accessor changed sealed candidate bytes")
	}
}

func TestBasisV1NamedPartiesAndOrdinaryScope(t *testing.T) {
	in := basisInputV1(t, false)
	in.RoutingMode = "sequential" // Recorded order is not proof of eligibility enforcement.
	b, err := BuildV1(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.OrdinaryPages()) != 0 || b.Parties()[0].Role != "customer" || b.Parties()[1].Role != "provider" || b.Parties()[0].OrderIndex != 1 || b.Parties()[1].OrderIndex != 0 || b.Input().RoutingMode != "sequential" {
		t.Fatal("actual named roles/order/routing were repaired or narrowed")
	}
	for _, mode := range []string{"named-ordinary", "missing-party-target", "role-set", "duplicate-role", "unassigned", "optional-signature", "field-party", "cross-field-org", "cross-party-doc", "future-signature-value", "blocks", "envelope", "child", "response-role"} {
		t.Run(mode, func(t *testing.T) {
			candidate := basisInputV1(t, false)
			switch mode {
			case "named-ordinary":
				candidate.Fields[0].Type = "text"
				candidate.Fields[0].ValueValid = true
				candidate.Fields[0].Value = "value"
			case "missing-party-target":
				candidate.Fields = candidate.Fields[:1]
			case "role-set":
				candidate.RequiredRoles[1] = "signer"
			case "duplicate-role":
				candidate.Parties[1].Role = candidate.Parties[0].Role
				candidate.RequiredRoles[1] = candidate.RequiredRoles[0]
			case "unassigned":
				candidate.Fields[0].RecipientValid = false
				candidate.Fields[0].RecipientID = uuid.Nil
			case "optional-signature":
				candidate.Fields[0].Required = false
			case "field-party":
				candidate.Fields[0].RecipientID = uuid.New()
			case "cross-field-org":
				candidate.Fields[0].OrgID = uuid.New()
			case "cross-party-doc":
				candidate.Parties[0].DocumentID = uuid.New()
			case "future-signature-value":
				candidate.Fields[0].ValueValid = true
				candidate.Fields[0].Value = "not a declared future name"
			case "blocks":
				candidate.SourceKind = "blocks"
			case "envelope":
				candidate.IsEnvelope = true
			case "child":
				candidate.ParentEnvelopeID = uuid.New()
			case "response-role":
				candidate.Parties[1].Role = "viewer"
				candidate.RequiredRoles[1] = "viewer"
			}
			if _, err := BuildV1(candidate); !errors.Is(err, ErrBasisV1) {
				t.Fatalf("invalid static membership accepted: %v", err)
			}
		})
	}
}

func TestBasisV1ExactDecimalRectangleAndFullGeometry(t *testing.T) {
	for _, mode := range []string{"overflow", "zero-width", "exponent", "unicode", "overlong", "source-hash", "source-bytes", "geometry-hash", "unoccupied-page", "rotation", "user-unit", "nonfinite", "empty-box", "nanosecond", "null-version", "development-version"} {
		t.Run(mode, func(t *testing.T) {
			in := basisInputV1(t, false)
			switch mode {
			case "overflow":
				in.Fields[0].X = "90.0001"
				in.Fields[0].W = "10.0000"
			case "zero-width":
				in.Fields[0].W = "0.0000"
			case "exponent":
				in.Fields[0].X = "5e0"
			case "unicode":
				in.Fields[0].X = "５.0000"
			case "overlong":
				in.Fields[0].X = strings.Repeat("0", 129)
			case "source-hash":
				in.Source.SHA256 = strings.Repeat("b", 64)
			case "source-bytes":
				in.Source.Bytes++
			case "geometry-hash":
				in.Geometry.GeometrySHA256 = strings.Repeat("b", 64)
			case "unoccupied-page":
				in.Fields = in.Fields[:1]
				in.Parties = in.Parties[:1]
				in.RequiredRoles = in.RequiredRoles[:1]
				in.Geometry.Pages[1].Boxes[4][2]--
			case "rotation":
				in.Geometry.Pages[1].Rotation = 45
			case "user-unit":
				in.Geometry.Pages[0].UserUnit = 0
			case "nonfinite":
				in.Geometry.Pages[0].Boxes[4][0] = math.Inf(1)
			case "empty-box":
				in.Geometry.Pages[1].Boxes[4][2] = 0
			case "nanosecond":
				in.CeremonyEpoch = in.CeremonyEpoch.Add(time.Nanosecond)
			case "null-version":
				in.Source.VersionID = "null"
			case "development-version":
				in.Source.VersionID = "hash:unversioned-development"
			}
			if _, err := BuildV1(in); !errors.Is(err, ErrBasisV1) {
				t.Fatalf("invalid geometry/source/decimal accepted: %v", err)
			}
		})
	}
	original := basisInputV1(t, false)
	a, err := BuildV1(original)
	if err != nil {
		t.Fatal(err)
	}
	changed := basisInputV1(t, false)
	changed.Geometry.Pages[1].Rotation = -270
	changed.Geometry.Pages[1].UserUnit = 2
	refreshGeometryV1(t, &changed)
	b, err := BuildV1(changed)
	if err != nil || b.SHA256() == a.SHA256() || b.FieldsSHA256() != a.FieldsSHA256() || b.Geometry().Pages[1].Rotation != -270 || b.Geometry().Pages[1].UserUnit != 2 {
		t.Fatal("full worker geometry was rounded, omitted or rebound")
	}
}

func TestBasisV1ClosedCanonicalDecode(t *testing.T) {
	b, err := BuildV1(basisInputV1(t, true))
	if err != nil {
		t.Fatal(err)
	}
	raw := b.CanonicalJSON()
	for _, mode := range []string{"space", "trailing", "duplicate", "unknown", "nested", "font-extra", "field-case", "version-null", "raw-newline", "noncanonical-epoch", "geometry-number"} {
		t.Run(mode, func(t *testing.T) {
			candidate := bytes.Clone(raw)
			switch mode {
			case "space":
				candidate = append([]byte(" "), candidate...)
			case "trailing":
				candidate = append(candidate, []byte("{}")...)
			case "duplicate":
				candidate = bytes.Replace(candidate, []byte(`"schema":"`+SchemaV1+`"`), []byte(`"schema":"`+SchemaV1+`","schema":"`+SchemaV1+`"`), 1)
			case "unknown":
				candidate = append(candidate[:len(candidate)-1], []byte(`,"future_signature":true}`)...)
			case "nested":
				candidate = bytes.Replace(candidate, []byte(`"geometry":{"schema_version":1,`), []byte(`"geometry":{"hidden":true,"schema_version":1,`), 1)
			case "font-extra":
				candidate = bytes.Replace(candidate, []byte(`"file":"Inter.woff2",`), []byte(`"file":"Inter.woff2","script":"private",`), 1)
			case "field-case":
				candidate = bytes.Replace(candidate, []byte(`"RecipientValid":true`), []byte(`"recipientvalid":true`), 1)
			case "version-null":
				candidate = bytes.Replace(candidate, []byte(`"version_id":" original+/opaque= "`), []byte(`"version_id":"null"`), 1)
			case "raw-newline":
				candidate = bytes.Replace(candidate, []byte(`\r\n`), []byte("\n"), 1)
			case "noncanonical-epoch":
				candidate = bytes.Replace(candidate, []byte("2026-10-12T11:22:33.123456Z"), []byte("2026-10-12T11:22:33.123456+00:00"), 1)
			case "geometry-number":
				candidate = bytes.Replace(candidate, []byte(`"user_unit":1`), []byte(`"user_unit":1.0`), 1)
			}
			if bytes.Equal(candidate, raw) {
				t.Fatal("test mutation did not change wire")
			}
			if _, err := DecodeV1(candidate); !errors.Is(err, ErrBasisV1) {
				t.Fatalf("noncanonical/unknown wire accepted: %v", err)
			}
		})
	}
}

func TestBasisV1OrdinaryValuesAndCheckboxClassification(t *testing.T) {
	for _, raw := range []string{"true", "1", "yes", "on", "checked", "x", "\u2003TRUE\r\n"} {
		if !CheckboxTruthyV1(raw) {
			t.Fatal("existing truthy class changed")
		}
	}
	for _, raw := range []string{"false", "0", "off", "", " \t ", "maybe", "checked x"} {
		if CheckboxTruthyV1(raw) {
			t.Fatal("false value became a visible mark")
		}
	}
	in := basisInputV1(t, true)
	in.Fields[1].Type = "checkbox"
	in.Fields[1].Value = " \r\nFALSE\u2003"
	b, err := BuildV1(in)
	if err != nil || len(b.OrdinaryPages()) != 0 || b.Fields()[1].Value != in.Fields[1].Value {
		t.Fatal("false checkbox was coerced/painted")
	}
	in.Fields[1].Value = " \r\nX\u2003"
	b, err = BuildV1(in)
	if err != nil || len(b.OrdinaryPages()) != 1 || b.Fields()[1].Value != in.Fields[1].Value {
		t.Fatal("literal truthy value lost")
	}
	in.Fields[1].Value = ""
	in.Fields[1].ValueValid = false
	b, err = BuildV1(in)
	if err != nil || len(b.OrdinaryPages()) != 0 {
		t.Fatal("provisional required empty value must be representable")
	}
	in.Fields[1].Value = "hidden"
	if _, err := BuildV1(in); !errors.Is(err, ErrBasisV1) {
		t.Fatal("invalid NULL/value contradiction accepted")
	}
}

func TestBasisV1OwnedRecipeVersusOriginalBrandingContext(t *testing.T) {
	in := basisInputV1(t, true)
	a, err := BuildV1(in)
	if err != nil {
		t.Fatal(err)
	}
	in.RenderRecipe.BrandingCSS += "\n/* different original provenance */"
	b, err := BuildV1(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.SHA256() == b.SHA256() || a.BrandingCSSSHA256() == b.BrandingCSSSHA256() || a.RenderRecipeSHA256() == b.RenderRecipeSHA256() || a.OrdinaryRecipeSHA256() != b.OrdinaryRecipeSHA256() || a.FieldsSHA256() != b.FieldsSHA256() {
		t.Fatal("ignored branding was claimed as actual ordinary recipe")
	}
	for _, mode := range []string{"font-hash", "font-file", "font-size", "recipe", "measurement", "snapshot", "print", "css-nul", "css-size", "css-escape-size"} {
		t.Run(mode, func(t *testing.T) {
			v := basisInputV1(t, true)
			switch mode {
			case "font-hash":
				v.RenderRecipe.Fonts[0].SHA256 = strings.Repeat("b", 64)
			case "font-file":
				v.RenderRecipe.Fonts[0].File = "Caveat.woff2"
			case "font-size":
				v.RenderRecipe.Fonts[0].Bytes++
			case "recipe":
				v.RenderRecipe.RecipeID = "unknown"
			case "measurement":
				v.RenderRecipe.MeasurementSHA256 = ""
			case "snapshot":
				v.RenderRecipe.SnapshotSHA256 = ""
			case "print":
				v.RenderRecipe.PrintRecipeSHA256 = ""
			case "css-nul":
				v.RenderRecipe.BrandingCSS = "bad\x00context"
			case "css-size":
				v.RenderRecipe.BrandingCSS = strings.Repeat("a", MaxBrandingCSSBytesV1+1)
			case "css-escape-size":
				v.RenderRecipe.BrandingCSS = strings.Repeat("<", MaxBrandingCSSBytesV1)
			}
			if _, err := BuildV1(v); !errors.Is(err, ErrBasisV1) {
				t.Fatal("unbounded or undeclared ordinary recipe accepted")
			}
		})
	}
}

func TestBasisV1CountsAndEncodingExpansionLimits(t *testing.T) {
	in := basisInputV1(t, true)
	in.Fields[1].Value = strings.Repeat("<&>\n\\\"Å\u2028\u2029", 2000)
	actual, err := json.Marshal(in.Fields)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildV1(in)
	if err != nil || !bytes.Equal(actual, b.FieldsJSON()) {
		t.Fatalf("exact encoding admission rejected valid original: %v", err)
	}
	in.Fields[1].Value = strings.Repeat("<", 180000)
	expanded, err := json.Marshal(in.Fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Fields[1].Value) >= MaxComponentBytesV1 || len(expanded) <= MaxComponentBytesV1 {
		t.Fatal("escape-expansion fixture does not cross the actual cap")
	}
	if _, err := BuildV1(in); !errors.Is(err, ErrBasisV1) {
		t.Fatal("raw-size-only field admission accepted encoding expansion")
	}
	for _, mode := range []string{"fields", "parties", "pages", "decode-fields", "decode-pages", "decode-static", "target-page"} {
		t.Run(mode, func(t *testing.T) {
			v := basisInputV1(t, false)
			if strings.HasPrefix(mode, "decode") {
				base, err := BuildV1(v)
				if err != nil {
					t.Fatal(err)
				}
				var env map[string]json.RawMessage
				if json.Unmarshal(base.CanonicalJSON(), &env) != nil {
					t.Fatal("envelope")
				}
				switch mode {
				case "decode-fields":
					field, _ := json.Marshal(v.Fields[0])
					env["fields"] = []byte("[" + strings.TrimSuffix(strings.Repeat(string(field)+",", pdflayout.MaxFields+1), ",") + "]")
				case "decode-pages":
					var geom map[string]json.RawMessage
					if json.Unmarshal(env["geometry"], &geom) != nil {
						t.Fatal("geometry")
					}
					page, _ := json.Marshal(v.Geometry.Pages[0])
					geom["pages"] = []byte("[" + strings.TrimSuffix(strings.Repeat(string(page)+",", sanitize.MaxPDFPages+1), ",") + "]")
					env["geometry"], _ = json.Marshal(geom)
				case "decode-static":
					if _, err := DecodeV1(bytes.Repeat([]byte(" "), MaxCanonicalBytesV1+1)); !errors.Is(err, ErrBasisV1) {
						t.Fatal("oversize canonical input accepted")
					}
					return
				}
				raw, _ := json.Marshal(env)
				if _, err := DecodeV1(raw); !errors.Is(err, ErrBasisV1) {
					t.Fatal("unbounded decoded array accepted")
				}
				return
			}
			switch mode {
			case "fields":
				v.Fields = make([]FieldV1, pdflayout.MaxFields+1)
			case "parties":
				v.Parties = make([]PartyV1, pdflayout.MaxParties+1)
				v.RequiredRoles = make([]string, pdflayout.MaxParties+1)
			case "pages":
				v.Geometry.Pages = make([]sanitize.PDFManualPage, sanitize.MaxPDFPages+1)
			case "target-page":
				first := v.Fields[0]
				v.Fields = v.Fields[1:]
				for i := 0; i < manualfit.MaxAuthorityTargetsPerPageV1+1; i++ {
					f := first
					f.ID = uuid.New()
					v.Fields = append(v.Fields, f)
				}
			}
			if _, err := BuildV1(v); !errors.Is(err, ErrBasisV1) {
				t.Fatal("unbounded snapshot/target count accepted")
			}
		})
	}
}
