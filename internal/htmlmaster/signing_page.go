// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaster

import (
	"encoding/json"
	"fmt"
	"html"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	SigningPagePolicyVersion              = 1
	SigningPagePolicyName                 = "hash-branded-signing-page-a4-v1"
	SigningPagePolicyDomain               = "hash.html-signing-page-policy.v1"
	SigningPageFontSHA256                 = "3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62"
	MaxSigningPageCompanyNameChars        = 80
	MaxSigningPageCompanyIDChars          = 40
	MaxSigningPageRepresentativeNameChars = 80
	// This is an application page-layout limit, not an email protocol limit.
	MaxSigningPageRepresentativeEmailChars = 128
	MaxSigningPageAuthorityChars           = 80
	MaxSigningPageLogoAltChars             = 80
	signingPageLineUnits                   = 40
)

// SigningPageBranding is a complete approval snapshot. The separate, baked-in
// logo uses LogoAsset below; URLs are deliberately empty and never fetched.
type SigningPageBranding struct {
	PrimaryHex     string `json:"primary_hex"`
	AccentHex      string `json:"accent_hex"`
	SurfaceHex     string `json:"surface_hex"`
	TextHex        string `json:"text_hex"`
	MutedHex       string `json:"muted_hex"`
	LogoURL        string `json:"logo_url"`
	LogoAlt        string `json:"logo_alt"`
	FontHeading    string `json:"font_heading"`
	FontBody       string `json:"font_body"`
	SignatureColor string `json:"signature_color"`
}

// Every policy member is explicit, including all three empty logo members.
// Changing the approved snapshot requires a new template revision and preview.
type SigningPagePolicy struct {
	Version    int                 `json:"version"`
	Policy     string              `json:"policy"`
	Branding   SigningPageBranding `json:"branding"`
	LogoAsset  string              `json:"logo_asset"`
	LogoSHA256 string              `json:"logo_sha256"`
	LogoAlt    string              `json:"logo_alt"`
	FontSHA256 string              `json:"font_sha256"`
}

var signingPageHex = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func cloneSigningPagePolicy(policy *SigningPagePolicy) *SigningPagePolicy {
	if policy == nil {
		return nil
	}
	copy := *policy
	return &copy
}

// SigningPagePolicy returns an independent copy of the exact approved policy.
// Schema1/2 masters do not gain a page declaration or a branding snapshot.
func (c *Compiled) SigningPagePolicy() *SigningPagePolicy {
	if c == nil {
		return nil
	}
	return cloneSigningPagePolicy(c.master.SigningPage)
}

func (c *Compiled) SigningPagePolicyDigest() string {
	if c == nil || c.master.SigningPage == nil {
		return ""
	}
	raw, _ := json.Marshal(c.master.SigningPage)
	return digest(SigningPagePolicyDomain, raw)
}

func validateSigningPageJSON(raw []byte, master Master) error {
	if master.SchemaVersion != SigningPageSchemaVersion {
		if master.SigningPage != nil {
			return invalid("signing page requires schema version 3")
		}
		return nil
	}
	if master.SigningPage == nil {
		return invalid("schema version 3 requires an explicit signing page")
	}
	var envelope map[string]json.RawMessage
	var policy, branding map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || json.Unmarshal(envelope["signing_page"], &policy) != nil || len(policy) != 7 {
		return invalid("signing page requires every explicit policy member")
	}
	for _, key := range []string{"version", "policy", "branding", "logo_asset", "logo_sha256", "logo_alt", "font_sha256"} {
		if policy[key] == nil {
			return invalid("missing signing page member: " + key)
		}
	}
	if json.Unmarshal(policy["branding"], &branding) != nil || len(branding) != 10 {
		return invalid("signing page requires every explicit branding member")
	}
	for _, key := range []string{"primary_hex", "accent_hex", "surface_hex", "text_hex", "muted_hex", "logo_url", "logo_alt", "font_heading", "font_body", "signature_color"} {
		if branding[key] == nil {
			return invalid("missing signing page branding member: " + key)
		}
	}
	return nil
}

func (c *Compiled) compileSigningPage(master *Master) error {
	if master.SchemaVersion != SigningPageSchemaVersion {
		if master.SigningPage != nil {
			return invalid("signing page requires schema version 3")
		}
		return nil
	}
	policy := cloneSigningPagePolicy(master.SigningPage)
	if master.ContractProfile == nil || policy == nil || policy.Version != SigningPagePolicyVersion || policy.Policy != SigningPagePolicyName {
		return invalid("schema version 3 requires the reviewed signing page policy")
	}
	if policy.FontSHA256 != SigningPageFontSHA256 {
		return invalid("signing_page.font_sha256 must pin the approved bundled Inter font")
	}
	b := policy.Branding
	for _, color := range []string{b.PrimaryHex, b.AccentHex, b.SurfaceHex, b.TextHex, b.MutedHex, b.SignatureColor} {
		if !signingPageHex.MatchString(color) {
			return invalid("signing page requires complete six-digit branding colors")
		}
	}
	for _, color := range []struct {
		name, value string
		minimum     float64
	}{{"text_hex", b.TextHex, 4.5}, {"muted_hex", b.MutedHex, 4.5}, {"primary_hex", b.PrimaryHex, 3}, {"signature_color", b.SignatureColor, 3}} {
		if signingPageContrast(color.value, b.SurfaceHex) < color.minimum {
			return invalid(fmt.Sprintf("signing_page.branding.%s must contrast with surface_hex by at least %.1f:1", color.name, color.minimum))
		}
	}
	if b.FontHeading != "Inter" || b.FontBody != "Inter" || b.LogoURL != "" || b.LogoAlt != "" {
		return invalid("signing page requires bundled Inter and explicitly empty branding logo URL/alt")
	}
	if policy.LogoAsset == "" {
		if policy.LogoSHA256 != "" || policy.LogoAlt != "" {
			return invalid("absent signing page logo requires all three empty members")
		}
	} else {
		asset, exists := c.assets[policy.LogoAsset]
		if !namePattern.MatchString(policy.LogoAsset) || !exists || !asset.image {
			return invalid("signing page logo must be a declared PNG/JPEG image")
		}
		matched := false
		for _, declared := range master.Assets {
			if declared.Name == policy.LogoAsset && declared.SHA256 == policy.LogoSHA256 {
				matched = true
			}
		}
		if !matched || !signingPagePlainText(policy.LogoAlt, MaxSigningPageLogoAltChars) {
			return invalid("signing page logo digest or bounded plain alt text")
		}
	}
	master.SigningPage = policy
	return nil
}

// Only validated #RRGGBB values reach this calculation. Relative luminance uses
// linearized sRGB; text/labels need 4.5:1, large headings and signature borders
// need 3:1. Decorative accent rules do not carry identity information.
func signingPageContrast(a, b string) float64 {
	luminance := func(color string) float64 {
		value, _ := strconv.ParseUint(color[1:], 16, 24)
		channel := func(n uint64) float64 {
			c := float64(n) / 255
			if c <= 0.04045 {
				return c / 12.92
			}
			return math.Pow((c+0.055)/1.055, 2.4)
		}
		return 0.2126*channel((value>>16)&255) + 0.7152*channel((value>>8)&255) + 0.0722*channel(value&255)
	}
	x, y := luminance(a), luminance(b)
	if x < y {
		x, y = y, x
	}
	return (x + 0.05) / (y + 0.05)
}

// The cmap of the SHA-pinned Inter Latin subset has exactly these 230 points.
// This pure allowlist avoids platform fallback fonts and unrenderable identity
// glyphs. Mapped controls/format characters are still rejected by plainText.
func signingPageFontSupports(r rune) bool {
	switch {
	case r == 0, r >= 0x20 && r <= 0x7e, r >= 0xa0 && r <= 0xac, r >= 0xae && r <= 0xff,
		r == 0x131, r >= 0x152 && r <= 0x153, r >= 0x2bb && r <= 0x2bc,
		r == 0x2c6, r == 0x2da, r == 0x2dc, r >= 0x300 && r <= 0x301,
		r >= 0x303 && r <= 0x304, r >= 0x308 && r <= 0x309, r == 0x323,
		r == 0x2002, r == 0x2009, r == 0x200b, r >= 0x2013 && r <= 0x2014,
		r >= 0x2018 && r <= 0x201a, r >= 0x201c && r <= 0x201e,
		r == 0x2022, r == 0x2026, r >= 0x2032 && r <= 0x2033,
		r >= 0x2039 && r <= 0x203a, r == 0x2044, r == 0x20ac,
		r == 0x2122, r == 0x2191, r == 0x2193, r == 0x2212, r == 0xfeff:
		return true
	}
	return false
}

func signingPageTextLimit(field string) int {
	switch field {
	case "company_name":
		return MaxSigningPageCompanyNameChars
	case "company_id":
		return MaxSigningPageCompanyIDChars
	case "representative_name":
		return MaxSigningPageRepresentativeNameChars
	case "representative_email":
		return MaxSigningPageRepresentativeEmailChars
	case "representative_authority":
		return MaxSigningPageAuthorityChars
	default:
		return 0
	}
}

// Latin characters use one display unit; other base characters use two as a
// conservative width bound. Marks stay with their base. Invisible format and
// direction controls are refused rather than silently changing printed text.
func signingPageRuneUnits(r rune) int {
	if unicode.IsMark(r) {
		return 0
	}
	if r <= 0x024f {
		return 1
	}
	return 2
}

func signingPagePlainText(text string, limit int) bool {
	if limit < 1 || text == "" || strings.TrimSpace(text) != text || !utf8.ValidString(text) || utf8.RuneCountInString(text) > limit {
		return false
	}
	units, first := 0, true
	for _, r := range text {
		if !unicode.IsGraphic(r) || unicode.Is(unicode.Cf, r) || first && unicode.IsMark(r) || !signingPageFontSupports(r) {
			return false
		}
		first = false
		units += signingPageRuneUnits(r)
	}
	return units <= limit
}

func signingPageTextProblem(field, text string) string {
	limit := signingPageTextLimit(field)
	if !signingPagePlainText(text, limit) {
		for _, r := range text {
			if unicode.IsGraphic(r) && !unicode.Is(unicode.Cf, r) && !signingPageFontSupports(r) {
				return "Signing page requires characters supported by its approved bundled Inter font."
			}
		}
		return fmt.Sprintf("Signing page requires a single printable line of at most %d characters and display units; wide characters use two units. Controls and outer whitespace are unavailable.", limit)
	}
	return ""
}

func signingPageLines(text string) string {
	var out, line strings.Builder
	units := 0
	flush := func() {
		out.WriteString(`<span class="identity-line">`)
		out.WriteString(html.EscapeString(line.String()))
		out.WriteString(`</span>`)
		line.Reset()
		units = 0
	}
	for _, r := range text {
		n := signingPageRuneUnits(r)
		if n > 0 && units+n > signingPageLineUnits {
			flush()
		}
		line.WriteRune(r)
		units += n
	}
	if line.Len() > 0 {
		flush()
	}
	return out.String()
}

// SigningPageHTML renders only the app-owned suffix, independently of the
// master's HTML/CSS. The caller attaches the bundled Inter.woff2 bytes and
// renders/composes/inspects the exact PDF in the isolated worker. A4 is the
// approved raw Chromium policy (currently 594.959960 x 841.919980pt); a rounded
// milli-point manifest is descriptive and must never normalize those bytes.
func (c *Compiled) SigningPageHTML(input Input) (string, error) {
	if c == nil || c.master.SigningPage == nil {
		return "", invalid("approved signing page is absent")
	}
	if err := c.requireContractComplete(input); err != nil {
		return "", err
	}
	if err := c.validateValues(input.Values, true); err != nil {
		return "", err
	}
	ready, err := c.ContractReadiness(input)
	if err != nil || !ready.Complete || len(ready.Parties) != 2 {
		return "", ErrContractIncomplete
	}
	b := c.master.SigningPage.Branding
	css := fmt.Sprintf(`@font-face{font-family:Inter;src:url('./Inter.woff2') format('woff2');font-weight:100 900;font-style:normal;}@page{size:A4;margin:0;}*{box-sizing:border-box;}html,body{margin:0;padding:0;width:210mm;height:297mm;}body{font-family:Inter;background:%s;color:%s;-webkit-print-color-adjust:exact;print-color-adjust:exact;}.sheet{position:relative;width:100%%;height:100%%;}.brand{position:absolute;left:10%%;top:5%%;width:80%%;height:32pt;}.brand img{display:block;max-width:160pt;max-height:32pt;object-fit:contain;}.brand-rule{position:absolute;left:10%%;right:10%%;top:9%%;height:2pt;background:%s;}h1{position:absolute;left:10%%;top:10%%;margin:0;font-size:22pt;line-height:27pt;font-weight:700;color:%s;}.intro{position:absolute;left:10%%;right:10%%;top:15%%;margin:0;font-size:8.5pt;line-height:11pt;}.party-heading{position:absolute;left:10%%;margin:0;font-size:14pt;line-height:18pt;font-weight:700;color:%s;}.customer-heading{top:20%%;}.provider-heading{top:57%%;}.party-body{position:absolute;left:10%%;right:10%%;font-size:8.5pt;line-height:11pt;}.customer-body{top:23%%;}.provider-body{top:60%%;}.identity-row{display:grid;grid-template-columns:75pt minmax(0,1fr);column-gap:8pt;margin:0 0 3pt;}.identity-label{color:%s;}.identity-line{display:block;white-space:pre;}.signature-slot{position:absolute;left:10%%;width:80%%;height:7%%;border:1pt solid %s;background:transparent;}.customer-signature{top:42%%;}.provider-signature{top:79%%;}.signature-caption{position:absolute;left:10%%;right:10%%;margin:0;font-size:8pt;line-height:10pt;color:%s;}.customer-caption{top:50%%;}.provider-caption{top:87%%;}.footer{position:absolute;left:10%%;right:10%%;top:93%%;margin:0;font-size:7.5pt;line-height:10pt;color:%s;}`, b.SurfaceHex, b.TextHex, b.AccentHex, b.PrimaryHex, b.PrimaryHex, b.MutedHex, b.SignatureColor, b.MutedHex, b.MutedHex)
	var out strings.Builder
	out.WriteString(`<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; font-src 'self' file:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><style>`)
	out.WriteString(css)
	out.WriteString(`</style></head><body><main class="sheet"><div class="brand">`)
	if c.master.SigningPage.LogoAsset != "" {
		out.WriteString(`<img src="` + html.EscapeString(c.assets[c.master.SigningPage.LogoAsset].dataURL) + `" alt="` + html.EscapeString(c.master.SigningPage.LogoAlt) + `">`)
	}
	out.WriteString(`</div><div class="brand-rule"></div><h1>Signing parties</h1><p class="intro">Each representative signs for the party listed below. The agreement on the preceding pages remains part of this document.</p>`)
	for _, party := range ready.Parties {
		label := "Customer"
		if party.Slot == "provider" {
			label = "Provider"
		}
		out.WriteString(`<h2 class="party-heading ` + party.Slot + `-heading">` + label + `</h2><div class="party-body ` + party.Slot + `-body">`)
		for _, row := range []struct{ label, value string }{{"Company", party.CompanyName}, {"Company ID", party.CompanyID}, {"Representative", party.RepresentativeName}, {"Email", party.RepresentativeEmail}, {"Authority", party.RepresentativeAuthority}} {
			out.WriteString(`<div class="identity-row"><div class="identity-label">` + row.label + `</div><div class="identity-value">` + signingPageLines(row.value) + `</div></div>`)
		}
		out.WriteString(`</div><div class="signature-slot ` + party.Slot + `-signature" data-hash-signing-slot="` + party.Slot + `"></div><p class="signature-caption ` + party.Slot + `-caption">Signature of the ` + strings.ToLower(label) + ` representative</p>`)
	}
	out.WriteString(`<p class="footer">The completed document records the signatures and supporting evidence. Review the complete agreement before signing.</p></main></body></html>`)
	if out.Len() > MaxMaterializedBytes {
		return "", limited("signing page HTML bytes")
	}
	return out.String(), nil
}
