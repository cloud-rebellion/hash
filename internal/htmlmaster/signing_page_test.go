// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaster

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"unicode"

	"golang.org/x/net/html"
)

func testSigningPageMaster() (Master, Input) {
	master, input := testContractMaster("proposal")
	master.SchemaVersion = SigningPageSchemaVersion
	master.SigningPage = &SigningPagePolicy{Version: SigningPagePolicyVersion, Policy: SigningPagePolicyName, FontSHA256: SigningPageFontSHA256,
		Branding: SigningPageBranding{PrimaryHex: "#141414", AccentHex: "#2563EB", SurfaceHex: "#FFFFFF", TextHex: "#141414", MutedHex: "#475569", FontHeading: "Inter", FontBody: "Inter", SignatureColor: "#1E293B"}}
	return master, input
}

func TestSigningPagePolicyStrictSchemaAndExplicitMembers(t *testing.T) {
	master, _ := testSigningPageMaster()
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	compiled := mustCompile(t, decoded)
	if next := mustCompile(t, mustDecodeSigningPage(t, compiled.CanonicalJSON())); !bytes.Equal(next.CanonicalJSON(), compiled.CanonicalJSON()) {
		t.Fatal("schema3 canonical round trip changed")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var policy map[string]json.RawMessage
	if err := json.Unmarshal(envelope["signing_page"], &policy); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "policy", "branding", "logo_asset", "logo_sha256", "logo_alt", "font_sha256"} {
		t.Run("missing-policy-"+key, func(t *testing.T) {
			var copy map[string]json.RawMessage
			_ = json.Unmarshal(envelope["signing_page"], &copy)
			delete(copy, key)
			value, _ := json.Marshal(copy)
			candidate := bytes.Replace(raw, envelope["signing_page"], value, 1)
			if _, err := Decode(candidate); err == nil {
				t.Fatal("missing explicit policy member accepted")
			}
		})
	}
	for _, key := range []string{"primary_hex", "accent_hex", "surface_hex", "text_hex", "muted_hex", "logo_url", "logo_alt", "font_heading", "font_body", "signature_color"} {
		t.Run("missing-branding-"+key, func(t *testing.T) {
			var copy map[string]json.RawMessage
			_ = json.Unmarshal(policy["branding"], &copy)
			delete(copy, key)
			value, _ := json.Marshal(copy)
			candidate := bytes.Replace(raw, policy["branding"], value, 1)
			if _, err := Decode(candidate); err == nil {
				t.Fatal("missing explicit branding member accepted")
			}
		})
	}
	for name, replacement := range map[string]string{
		"null-policy":   `"signing_page":null`,
		"null-branding": `"signing_page":{"version":1,"policy":"hash-branded-signing-page-a4-v1","branding":null,"logo_asset":"","logo_sha256":"","logo_alt":""}`,
		"unknown":       `"signing_page":{"version":1,"unexpected":true}`,
		"case-alias":    `"Signing_Page":{}`,
		"duplicate":     `"signing_page":{},"signing_page":{}`,
		"wrong-shape":   `"signing_page":[]`,
	} {
		t.Run(name, func(t *testing.T) {
			candidate := []byte(`{"schema_version":3,` + replacement + `}`)
			if _, err := Decode(candidate); err == nil {
				t.Fatal("ambiguous policy JSON accepted")
			}
		})
	}
	for _, schema := range []int{SchemaVersion, ContractSchemaVersion} {
		legacy := master
		legacy.SchemaVersion = schema
		encoded, _ := json.Marshal(legacy)
		if _, err := Decode(encoded); err == nil {
			t.Fatal("legacy policy declaration accepted by decode")
		}
		if _, err := Compile(legacy); err == nil {
			t.Fatal("legacy policy declaration accepted by compile")
		}
	}
	master.SigningPage = nil
	encoded, _ := json.Marshal(master)
	if _, err := Decode(encoded); err == nil {
		t.Fatal("schema3 without policy accepted")
	}
	if _, err := Compile(master); err == nil {
		t.Fatal("schema3 without policy compiled")
	}
}

func mustDecodeSigningPage(t *testing.T, raw []byte) Master {
	t.Helper()
	master, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return master
}

func TestSigningPagePolicyRejectsMutableOrIncompleteBrandingAndLogo(t *testing.T) {
	for name, change := range map[string]func(*Master){
		"profile-absent":    func(m *Master) { m.ContractProfile = nil },
		"version":           func(m *Master) { m.SigningPage.Version = 2 },
		"policy":            func(m *Master) { m.SigningPage.Policy = "future-policy" },
		"font-digest":       func(m *Master) { m.SigningPage.FontSHA256 = strings.Repeat("0", 64) },
		"empty-font-digest": func(m *Master) { m.SigningPage.FontSHA256 = "" },
		"missing-color":     func(m *Master) { m.SigningPage.Branding.PrimaryHex = "" },
		"shorthand-color":   func(m *Master) { m.SigningPage.Branding.PrimaryHex = "#fff" },
		"color-css":         func(m *Master) { m.SigningPage.Branding.PrimaryHex = "#FFFFFF;background:url(https://example.invalid)" },
		"heading-font":      func(m *Master) { m.SigningPage.Branding.FontHeading = "Different" },
		"body-font":         func(m *Master) { m.SigningPage.Branding.FontBody = "Inter, Arial" },
		"remote-logo":       func(m *Master) { m.SigningPage.Branding.LogoURL = "https://example.invalid/logo.png" },
		"public-logo":       func(m *Master) { m.SigningPage.Branding.LogoURL = "/branding/logo/mutable.png" },
		"branding-alt":      func(m *Master) { m.SigningPage.Branding.LogoAlt = "mutable" },
		"empty-logo-digest": func(m *Master) { m.SigningPage.LogoSHA256 = strings.Repeat("0", 64) },
		"empty-logo-alt":    func(m *Master) { m.SigningPage.LogoAlt = "logo" },
		"undeclared-logo":   func(m *Master) { m.SigningPage.LogoAsset = "undeclared" },
		"digest-mismatch": func(m *Master) {
			m.Assets = []Asset{pngAsset(t)}
			m.SigningPage.LogoAsset = "logo"
			m.SigningPage.LogoSHA256 = strings.Repeat("0", 64)
			m.SigningPage.LogoAlt = "Approved logo"
		},
		"font-as-logo": func(m *Master) {
			font, err := os.ReadFile("../render/assets/Inter.woff2")
			if err != nil {
				t.Fatal(err)
			}
			m.Assets = []Asset{fixtureAsset(t, "inter", "font/woff2", font)}
			m.SigningPage.LogoAsset = "inter"
			m.SigningPage.LogoSHA256 = m.Assets[0].SHA256
			m.SigningPage.LogoAlt = "Font"
		},
		"blank-alt": func(m *Master) {
			m.Assets = []Asset{pngAsset(t)}
			m.SigningPage.LogoAsset = "logo"
			m.SigningPage.LogoSHA256 = m.Assets[0].SHA256
		},
	} {
		t.Run(name, func(t *testing.T) {
			master, _ := testSigningPageMaster()
			change(&master)
			if _, err := Compile(master); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid page policy accepted: %v", err)
			}
		})
	}
	master, input := testSigningPageMaster()
	master.Assets = []Asset{pngAsset(t)}
	master.SigningPage.LogoAsset = "logo"
	master.SigningPage.LogoSHA256 = master.Assets[0].SHA256
	master.SigningPage.LogoAlt = `Approved "logo" & image`
	compiled := mustCompile(t, master)
	page, err := compiled.SigningPageHTML(input)
	if err != nil || !strings.Contains(page, "data:image/png;base64,") || !strings.Contains(page, `alt="Approved &#34;logo&#34; &amp; image"`) {
		t.Fatalf("exact approved image missing/unsafe: %v", err)
	}
}

func TestSigningPageFontCoverageIsPinnedAndUnsupportedIdentitiesRefused(t *testing.T) {
	raw, err := os.ReadFile("../render/assets/Inter.woff2")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != SigningPageFontSHA256 {
		t.Fatal("bundled font changed without a reviewed signing-page policy")
	}
	covered := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if signingPageFontSupports(r) {
			covered++
		}
	}
	if covered != 230 {
		t.Fatal("approved font cmap point count drifted")
	}
	for _, glyph := range []rune{'Ω', 'Ж', '界', '★', '😀', '\u0302'} {
		if signingPageFontSupports(glyph) {
			t.Fatal("unmapped glyph declared supported")
		}
		for field, key := range map[string]string{"company_name": "customer_company_name", "company_id": "customer_company_id", "representative_name": "customer_name", "representative_email": "customer_email", "representative_authority": "customer_authority"} {
			t.Run(field+"-"+string(glyph), func(t *testing.T) {
				master, input := testSigningPageMaster()
				input.Values[key] = "Visible" + string(glyph)
				compiled := mustCompile(t, master)
				ready, err := compiled.ContractReadiness(input)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, issue := range ready.Issues {
					if issue.Code == "signing_page_text" && issue.Path == "parties.customer."+field && strings.Contains(issue.Message, "approved bundled Inter font") {
						found = true
					}
				}
				if ready.Complete || !found {
					t.Fatal("unsupported font glyph did not produce a field-specific readiness issue")
				}
				if _, err := compiled.Materialize(input); !errors.Is(err, ErrContractIncomplete) {
					t.Fatal("unsupported signing identity reached body render", err)
				}
				if _, err := compiled.SigningPageHTML(input); !errors.Is(err, ErrContractIncomplete) {
					t.Fatal("unsupported signing identity reached suffix render", err)
				}
			})
		}
	}
	for _, text := range []string{"Åsa Öberg", "Élodie François", "Øresund Œuvre", "e\u0301 A\u0308 à ñ a\u0304 a\u0323"} {
		master, input := testSigningPageMaster()
		input.Values["customer_name"] = text
		page, err := mustCompile(t, master).SigningPageHTML(input)
		if err != nil || !strings.Contains(page, text) || !strings.Contains(page, "font-family:Inter;") || strings.Contains(page, "Arial") || strings.Contains(page, "sans-serif") {
			t.Fatal("approved Swedish/Latin/combining glyphs were not rendered with the pinned font", err)
		}
	}
}

func TestSigningPagePaletteRejectsInvisibleAndInsufficientContrast(t *testing.T) {
	for name, set := range map[string]func(*SigningPageBranding){
		"text-invisible":      func(b *SigningPageBranding) { b.TextHex = b.SurfaceHex },
		"muted-invisible":     func(b *SigningPageBranding) { b.MutedHex = b.SurfaceHex },
		"primary-invisible":   func(b *SigningPageBranding) { b.PrimaryHex = b.SurfaceHex },
		"signature-invisible": func(b *SigningPageBranding) { b.SignatureColor = b.SurfaceHex },
		"text-below-4.5":      func(b *SigningPageBranding) { b.TextHex = "#777777" },
		"muted-below-4.5":     func(b *SigningPageBranding) { b.MutedHex = "#777777" },
		"primary-below-3":     func(b *SigningPageBranding) { b.PrimaryHex = "#959595" },
		"signature-below-3":   func(b *SigningPageBranding) { b.SignatureColor = "#959595" },
	} {
		t.Run(name, func(t *testing.T) {
			master, _ := testSigningPageMaster()
			set(&master.SigningPage.Branding)
			if _, err := Compile(master); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "signing_page.branding.") || !strings.Contains(err.Error(), "contrast with surface_hex") {
				t.Fatal("unreadable reviewed palette accepted or error lacks exact palette path", err)
			}
		})
	}
	master, input := testSigningPageMaster()
	master.SigningPage.Branding.TextHex, master.SigningPage.Branding.MutedHex = "#767676", "#767676"
	master.SigningPage.Branding.PrimaryHex, master.SigningPage.Branding.SignatureColor = "#949494", "#949494"
	master.SigningPage.Branding.AccentHex = "#FFFFFF" // Decorative, carries no identity text.
	if _, err := mustCompile(t, master).SigningPageHTML(input); err != nil {
		t.Fatal("readable near-threshold palette refused", err)
	}
	master, input = testSigningPageMaster()
	b := &master.SigningPage.Branding
	b.SurfaceHex = "#141414"
	b.TextHex, b.MutedHex, b.PrimaryHex, b.SignatureColor = "#FFFFFF", "#FFFFFF", "#FFFFFF", "#FFFFFF"
	if _, err := mustCompile(t, master).SigningPageHTML(input); err != nil {
		t.Fatal("readable reversed palette refused", err)
	}
	if signingPageContrast("#000000", "#FFFFFF") != 21 || signingPageContrast("#FFFFFF", "#000000") != 21 || signingPageContrast("#777777", "#777777") != 1 {
		t.Fatal("contrast calculation does not preserve black/white and equal-color controls")
	}
}

func TestSigningPageHTMLIsSeparateEscapedAndImmutable(t *testing.T) {
	master, input := testSigningPageMaster()
	master.CSS = `main {display:none; color:red;}`
	input.Values["customer_company_name"] = `Company <script>x</script> & co`
	input.Values["customer_name"] = "Åsa Östergård"
	compiled := mustCompile(t, master)
	digest, canonical := compiled.SigningPagePolicyDigest(), compiled.CanonicalJSON()
	page, err := compiled.SigningPageHTML(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page, master.CSS) || strings.Contains(page, "<script>") || !strings.Contains(page, "&lt;script&gt;") || !strings.Contains(page, "Åsa Östergård") {
		t.Fatal("master CSS/dynamic markup leaked or identity changed")
	}
	if strings.Count(page, `data-hash-signing-slot=`) != 2 || !strings.Contains(page, `.customer-signature{top:42%;}`) || !strings.Contains(page, `.provider-signature{top:79%;}`) || !strings.Contains(page, `left:10%;width:80%;height:7%;`) {
		t.Fatal("fixed slot policy missing")
	}
	if strings.Contains(page, "overflow:hidden") || strings.Contains(page, "text-overflow") || !strings.Contains(page, "@page{size:A4;margin:0;}") || !strings.Contains(page, "./Inter.woff2") {
		t.Fatal("page policy hides identity or lacks exact owned page/font")
	}
	parsed, err := html.Parse(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "iframe" || n.Data == "img") {
			t.Fatal("dynamic identity created a resource/executable node")
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(parsed)
	master.SigningPage.Branding.PrimaryHex = "#FFFFFF"
	copy := compiled.SigningPagePolicy()
	copy.Policy = "changed"
	copy.Branding.TextHex = "#000000"
	if compiled.SigningPagePolicyDigest() != digest || !bytes.Equal(compiled.CanonicalJSON(), canonical) || compiled.SigningPagePolicy().Policy != SigningPagePolicyName {
		t.Fatal("caller changed immutable policy")
	}
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next, err := compiled.SigningPageHTML(input)
			if err != nil || next != page {
				t.Error("concurrent page changed")
			}
		}()
	}
	wg.Wait()
}

func TestSigningPageIdentityBoundsAndCombiningMarks(t *testing.T) {
	for field, key := range map[string]string{"company_name": "customer_company_name", "company_id": "customer_company_id", "representative_name": "customer_name", "representative_email": "customer_email", "representative_authority": "customer_authority"} {
		for name, value := range map[string]string{"overlength": strings.Repeat("a", signingPageTextLimit(field)+1), "wide": strings.Repeat("界", signingPageTextLimit(field)/2+1), "newline": "First\nSecond", "bidi": "First\u202eSecond", "leading-mark": "\u0308First", "outer-space": " First"} {
			t.Run(field+"-"+name, func(t *testing.T) {
				master, input := testSigningPageMaster()
				input.Values[key] = value
				compiled := mustCompile(t, master)
				ready, err := compiled.ContractReadiness(input)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, issue := range ready.Issues {
					if issue.Code == "signing_page_text" && issue.Path == "parties.customer."+field {
						found = true
					}
				}
				if ready.Complete || !found {
					t.Fatal("page-layout issue missing at exact field path")
				}
				if _, err := compiled.Materialize(input); !errors.Is(err, ErrContractIncomplete) {
					t.Fatalf("body accepted unrenderable signing identity: %v", err)
				}
				if _, err := compiled.SigningPageHTML(input); !errors.Is(err, ErrContractIncomplete) {
					t.Fatalf("suffix accepted unrenderable identity: %v", err)
				}
			})
		}
	}
	text := strings.Repeat("A", signingPageLineUnits) + "\u0308" + "B"
	lines := signingPageLines(text)
	if strings.Count(lines, `class="identity-line"`) != 2 || !strings.Contains(lines, strings.Repeat("A", signingPageLineUnits)+"\u0308</span>") || strings.Contains(lines, ">\u0308") {
		t.Fatal("combining mark detached from original base")
	}
	master, input := testSigningPageMaster()
	input.Values["customer_name"] = strings.Repeat("A", MaxSigningPageRepresentativeNameChars)
	if _, err := mustCompile(t, master).SigningPageHTML(input); err != nil {
		t.Fatalf("exact readable name bound rejected: %v", err)
	}
}

func TestSigningPageDomainsPreserveLegacyMasterAndTemplateBytes(t *testing.T) {
	master, input := testContractMaster("proposal")
	compiled := mustCompile(t, master)
	if compiled.Digest() != "b2734936e83e3f70ddfc73ec49cf9ce0514abf066e4788083572576a8a1b7bc7" {
		t.Fatal("schema2 master golden changed")
	}
	canonical, err := CanonicalTemplate(compiled.CanonicalJSON(), []byte(`{}`))
	if err != nil || canonical.SHA256 != "06e3dda52f4d4cc7a1d79cbecdd7558d3e9fae39ecf62f60248880f2866d2aed" {
		t.Fatalf("schema2 template golden changed: %v", err)
	}
	if compiled.SigningPagePolicy() != nil || compiled.SigningPagePolicyDigest() != "" || strings.Contains(string(compiled.CanonicalJSON()), "signing_page") {
		t.Fatal("schema2 acquired a policy")
	}
	if _, err := compiled.SigningPageHTML(input); err == nil {
		t.Fatal("schema2 silently acquired a suffix")
	}
	for _, schema := range []int{SchemaVersion, ContractSchemaVersion, SigningPageSchemaVersion} {
		want := "hash.html-master.v1"
		if schema == 2 {
			want = "hash.html-master.v2"
		}
		if schema == 3 {
			want = "hash.html-master.v3"
		}
		if versionedDomain("hash.html-master", schema) != want {
			t.Fatal("schema domain mismatch")
		}
	}
	pageMaster, pageInput := testSigningPageMaster()
	pageCompiled := mustCompile(t, pageMaster)
	first, err := pageCompiled.Materialize(pageInput)
	if err != nil {
		t.Fatal(err)
	}
	pageMaster.SigningPage.Branding.AccentHex = "#7C3AED"
	changed := mustCompile(t, pageMaster)
	second, err := changed.Materialize(pageInput)
	if err != nil || changed.Digest() == pageCompiled.Digest() || changed.SigningPagePolicyDigest() == pageCompiled.SigningPagePolicyDigest() || second.ContentDigest == first.ContentDigest {
		t.Fatal("approved page policy is absent from materialization commitment")
	}
}
