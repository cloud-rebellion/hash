// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaster

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"image"
	"image/png"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/html"
)

func testMaster() Master {
	return Master{SchemaVersion: 1, HTML: `<main class="design"><h1>Agreement with <span data-hash-value="company"></span></h1><div class="terms" data-hash-section="scope"></div></main>`, CSS: `@page {size:A4; margin:20mm;} .terms {white-space:pre-wrap;}`, Values: []Value{{Name: "company", Required: true, MaxChars: 256}}, Sections: []Section{{Name: "scope", DefaultText: "Approved scope\nSecond line", MaxChars: 1024}}, Assets: []Asset{}}
}

func mustCompile(t *testing.T, master Master) *Compiled {
	t.Helper()
	c, err := Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMaterializeEscapesEveryDynamicTextContextAndSignalsReview(t *testing.T) {
	c := mustCompile(t, testMaster())
	attack := `</div><script>alert(1)</script><img src="https://example.invalid/"> & "quoted" {{.Secret}}`
	result, err := c.Materialize(Input{Values: map[string]string{"company": attack}, Sections: map[string]string{"scope": attack}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ChangedSections) != 1 || result.ChangedSections[0] != "scope" {
		t.Fatalf("missing prose review: %#v", result.ChangedSections)
	}
	if strings.Contains(result.HTML, `<script>`) || strings.Contains(result.HTML, `<img src=`) || !strings.Contains(result.HTML, `&lt;script&gt;`) || !strings.Contains(result.HTML, `{{.Secret}}`) {
		t.Fatal("text evaluated or inserted as markup")
	}
	parsed, err := html.Parse(strings.NewReader(result.HTML))
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			text.WriteString(n.Data)
		}
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "img") {
			t.Fatal("dynamic text created executable/resource element")
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(parsed)
	if strings.Count(text.String(), attack) != 2 {
		t.Fatal("materialized text did not preserve both exact Unicode strings")
	}
	defaults, err := c.Materialize(Input{Values: map[string]string{"company": "Example AB"}, Sections: map[string]string{"scope": "Approved scope\nSecond line"}})
	if err != nil || len(defaults.ChangedSections) != 0 {
		t.Fatalf("unchanged approved section requires review: %v %#v", err, defaults.ChangedSections)
	}
}

func TestMasterCompletenessAndUnknownInputsFailClosed(t *testing.T) {
	c := mustCompile(t, testMaster())
	for _, input := range []Input{{}, {Values: map[string]string{"company": " \t\n"}}} {
		if _, err := c.Materialize(input); !errors.Is(err, ErrMissingValues) {
			t.Fatalf("missing required value: %v", err)
		}
	}
	for _, input := range []Input{
		{Values: map[string]string{"company": "Example", "unknown": "secret"}},
		{Values: map[string]string{"company": "Example"}, Sections: map[string]string{"unknown": "prose"}},
		{Values: map[string]string{"company": strings.Repeat("å", 257)}},
		{Values: map[string]string{"company": "bad\x00text"}},
		{Values: map[string]string{"company": "Example"}, Sections: map[string]string{"scope": strings.Repeat("x", 1025)}},
	} {
		if _, err := c.Materialize(input); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	master := testMaster()
	master.Values[0].Required = false
	if _, err := mustCompile(t, master).Materialize(Input{}); err != nil {
		t.Fatal("optional value without input must become empty text")
	}
}

func TestMasterRejectsActiveHTMLResourcesAndParserRepair(t *testing.T) {
	for name, source := range map[string]string{
		"script": `<script>alert(1)</script>`, "events": `<div onclick="x">x</div>`, "mixed-event": `<DIV onLoad="x">x</DIV>`,
		"form": `<form><div>x</div></form>`, "base": `<base href="https://example.invalid/">`, "iframe": `<iframe></iframe>`, "svg": `<svg></svg>`,
		"style": `<div style="background:url(file:///etc/passwd)"></div>`, "remote": `<img src="https://example.invalid/a">`, "relative": `<img src="../a">`, "data": `<img src="data:image/svg+xml,x">`,
		"namespace": `<div xlink:href="file:///a"></div>`, "duplicate": `<span data-hash-value="company" DATA-HASH-VALUE="company"></span>`,
		"unknown": `<span data-hash-value="unknown"></span>`, "both-markers": `<span data-hash-value="company" data-hash-section="scope"></span>`,
		"nested": `<span data-hash-value="company"><b>x</b></span>`, "nonempty": `<span data-hash-value="company">x</span>`, "selfclosing": `<span data-hash-value="company"/>`,
		"foster-parent":    `<table><span data-hash-value="company"></span><tbody><tr><td>x</td></tr></tbody></table>`,
		"paragraph-repair": `<p><div data-hash-value="company"></div></p>`, "comment": `<!-- template --><div>x</div>`, "unclosed": `<div>`,
	} {
		t.Run(name, func(t *testing.T) {
			master := testMaster()
			master.HTML = source
			if _, err := Compile(master); err == nil {
				t.Fatal("unsafe or ambiguous HTML accepted")
			}
		})
	}
	master := Master{SchemaVersion: 1, HTML: `<table><tbody><tr><td><span data-hash-value="company"></span></td></tr></tbody></table>`, Values: []Value{{Name: "company", Required: true, MaxChars: 256}}}
	mustCompile(t, master)
}

func TestMasterRejectsCSSExecutionFetchAndAmbiguity(t *testing.T) {
	for name, style := range map[string]string{
		"import": `@import "https://example.invalid/a";`, "remote": `div {background:url(https://example.invalid/a);}`,
		"relative": `div {background:url(a.png);}`, "data": `div {background:url("data:image/svg+xml,x");}`, "escape": `div {background:u\72l("https://example.invalid");}`,
		"split": `div {background:u/**/rl("https://example.invalid");}`, "local-font": `@font-face {font-family:test;src:local("Inter");}`,
		"image-set": `div {background-image:image-set("https://example.invalid/a" 1x);}`, "image-function": `div {background:image("https://example.invalid/a");}`,
		"attr": `div {content:attr(data-url);}`, "variable": `div {background:var(--remote);}`, "custom-prop": `div {--remote:url("https://example.invalid/a");}`,
		"expression": `div {width:expression(alert(1));}`, "behavior": `div {behavior:url("hash-asset:x");}`, "style-close": `div {content:"</style><script>x</script>";}`,
		"font-no-source": `@font-face {font-family:test;}`, "supports": `@supports (display:grid) {div {display:grid;}}`, "unknown-at": `@document url("https://example.invalid") {}`,
		"broken": `div { color: red;`, "broken-function": `div {color:rgb(1,2,3;}`,
	} {
		t.Run(name, func(t *testing.T) {
			master := testMaster()
			master.CSS = style
			if _, err := Compile(master); err == nil {
				t.Fatal("unsafe CSS accepted")
			}
		})
	}
	master := testMaster()
	master.CSS = `@media print {main {display:grid;grid-template-columns:1fr 2fr;color:rgba(1,2,3,0.5);}} @page :first {margin:12mm;}`
	mustCompile(t, master)
}

func TestMasterRefusesCSSParserRepairBeforeApproval(t *testing.T) {
	for name, source := range map[string]string{
		"hidden-remote":            `div {color:url(https://example.invalid/x):background:red;}`,
		"hidden-function":          `div {color:expression(alert(1)):background:red;}`,
		"hidden-local-font":        `div {font:local("Inter"):background:red;}`,
		"multiple-colon":           `div {color:blue:background:red;}`,
		"missing-separator":        `div {color:blue background:red;}`,
		"missing-property":         `div {:red;}`,
		"missing-value":            `div {color:;}`,
		"missing-colon":            `div {color red;}`,
		"naked-selector":           `div`,
		"trailing-selector":        `div {color:red;} span`,
		"semicolon-rule":           `div;`,
		"empty-rule":               `div {}`,
		"empty-media":              `@media print {}`,
		"nested-declaration":       `div {color:blue {background:red;}}`,
		"important-repair":         `div {color:red !important!important;}`,
		"unterminated-declaration": `div {color:red`,
	} {
		t.Run(name, func(t *testing.T) {
			master := Master{SchemaVersion: 1, HTML: `<div>Approved</div>`, CSS: source}
			if _, err := Compile(master); !errors.Is(err, ErrInvalid) {
				t.Fatalf("source requiring parser repair was accepted: %v", err)
			}
		})
	}
	master := Master{SchemaVersion: 1, HTML: `<div>Approved</div>`, CSS: `div {color:blue !IMPORTANT;content:"a:b;c";} div {color:red}`}
	compiled := mustCompile(t, master)
	decoded, err := Decode(compiled.CanonicalJSON())
	if err != nil {
		t.Fatal(err)
	}
	recompiled := mustCompile(t, decoded)
	if compiled.Digest() != recompiled.Digest() || !strings.Contains(decoded.CSS, `color: blue !important;`) || strings.Index(decoded.CSS, `color: blue`) > strings.Index(decoded.CSS, `color: red`) {
		t.Fatal("valid whole declarations lost important, literal punctuation or cascade order")
	}
}

func fixtureAsset(t *testing.T, name, media string, raw []byte) Asset {
	t.Helper()
	sum := sha256.Sum256(raw)
	return Asset{Name: name, MediaType: media, DataBase64: base64.StdEncoding.EncodeToString(raw), SHA256: hex.EncodeToString(sum[:])}
}
func pngAsset(t *testing.T) Asset {
	t.Helper()
	var out bytes.Buffer
	if err := png.Encode(&out, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	return fixtureAsset(t, "logo", "image/png", out.Bytes())
}

func TestMasterEmbeddedAssetsAreTypedDigestBoundAndBounded(t *testing.T) {
	font, err := os.ReadFile("../render/assets/Inter.woff2")
	if err != nil {
		t.Fatal(err)
	}
	master := testMaster()
	master.HTML += `<img alt="Logo" src="hash-asset:logo"/>`
	master.Assets = []Asset{pngAsset(t), fixtureAsset(t, "inter", "font/woff2", font)}
	master.CSS += ` @font-face {font-family:"Inter";src:url("hash-asset:inter") format("woff2");font-weight:300 700;} main {font-family:"Inter";background-image:url('hash-asset:logo');}`
	c := mustCompile(t, master)
	result, err := c.Materialize(Input{Values: map[string]string{"company": "Example"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.HTML, "data:image/png;base64,") || !strings.Contains(result.HTML, "data:font/woff2;base64,") || strings.Contains(result.HTML, "hash-asset:") {
		t.Fatal("approved asset references were not fully embedded")
	}
	for name, change := range map[string]func(*Master){
		"digest": func(m *Master) { m.Assets[0].SHA256 = strings.Repeat("0", 64) }, "wrong-media": func(m *Master) { m.Assets[0].MediaType = "image/jpeg" },
		"svg": func(m *Master) {
			m.Assets[0] = fixtureAsset(t, "logo", "image/svg+xml", []byte(`<svg><script/></svg>`))
		},
		"invalid-font": func(m *Master) { m.Assets[1] = fixtureAsset(t, "inter", "font/woff2", []byte("wOF2bad")) },
		"oversized":    func(m *Master) { m.Assets[0] = fixtureAsset(t, "logo", "image/png", make([]byte, MaxAssetBytes+1)) },
		"duplicate":    func(m *Master) { m.Assets = append(m.Assets, m.Assets[0]) }, "missing": func(m *Master) { m.Assets = m.Assets[1:] },
		"font-as-image": func(m *Master) { m.HTML = strings.ReplaceAll(m.HTML, "hash-asset:logo", "hash-asset:inter") },
		"image-as-font": func(m *Master) { m.CSS = strings.ReplaceAll(m.CSS, "hash-asset:inter", "hash-asset:logo") },
	} {
		t.Run(name, func(t *testing.T) {
			modified := master
			modified.Assets = append([]Asset{}, master.Assets...)
			change(&modified)
			if _, err := Compile(modified); err == nil {
				t.Fatal("invalid asset accepted")
			}
		})
	}
}

func TestCanonicalTemplatePinsAllDefaultsAndMasterBytes(t *testing.T) {
	master := testMaster()
	raw, _ := json.Marshal(master)
	first, err := CanonicalTemplate(raw, []byte(`{"company":"Approved AB"}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalTemplate(first.MasterJSON, first.DefaultsJSON)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 != second.SHA256 || !bytes.Equal(first.MasterJSON, second.MasterJSON) {
		t.Fatal("canonical commitment is not stable")
	}
	for name, change := range map[string]func(*Master){
		"html": func(m *Master) { m.HTML = strings.ReplaceAll(m.HTML, "Agreement", "Reviewed agreement") },
		"css":  func(m *Master) { m.CSS += ` main {color:#123456;}` }, "section": func(m *Master) { m.Sections[0].DefaultText = "Different approved terms" },
		"required": func(m *Master) { m.Values[0].Required = false }, "bound": func(m *Master) { m.Values[0].MaxChars = 255 },
	} {
		t.Run(name, func(t *testing.T) {
			modified := master
			modified.Values = append([]Value{}, master.Values...)
			modified.Sections = append([]Section{}, master.Sections...)
			change(&modified)
			raw, _ := json.Marshal(modified)
			other, err := CanonicalTemplate(raw, first.DefaultsJSON)
			if err != nil {
				t.Fatal(err)
			}
			if other.SHA256 == first.SHA256 {
				t.Fatal("changed approved content did not change pin")
			}
		})
	}
	other, err := CanonicalTemplate(raw, []byte(`{"company":"Changed AB"}`))
	if err != nil || other.SHA256 == first.SHA256 {
		t.Fatal("printed default value is not committed")
	}
	if _, err := CanonicalTemplate(raw, []byte(`{"company":""}`)); err != nil {
		t.Fatal("required default may remain blank until instantiation")
	}
	for _, defaults := range []string{`{"unknown":"x"}`, `{"company":1}`, `{"company":null}`, `null`, `{"company":"a","company":"b"}`, `{"company":"a"} {}`, `{"company":"\ud800"}`} {
		if _, err := CanonicalTemplate(raw, []byte(defaults)); err == nil {
			t.Fatalf("malformed defaults accepted: %s", defaults)
		}
	}
}

func TestDecodeStrictSchemaAndUnicode(t *testing.T) {
	master := testMaster()
	raw, _ := json.Marshal(master)
	for name, input := range map[string][]byte{
		"unknown": []byte(`{"schema_version":1,"unknown":true}`), "case": []byte(`{"schema_version":1,"HTML":"x"}`), "duplicate": []byte(`{"schema_version":1,"schema_version":1}`),
		"surrogate": []byte(`{"schema_version":1,"html":"\ud800"}`), "lone-low": []byte(`{"schema_version":1,"html":"\udc00"}`), "invalid-utf8": append([]byte(`{"html":"`), 0xff),
		"trailing": append(bytes.Clone(raw), []byte(` {}`)...), "null": []byte(`null`), "null-list": []byte(`{"schema_version":1,"values":null}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(input); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
	decoded, err := Decode([]byte(`{"schema_version":1,"html":"<p>\ud83d\ude00</p>","css":"","values":[],"sections":[],"assets":[]}`))
	if err != nil || !strings.Contains(decoded.HTML, "😀") {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
	// Callers may marshal a master without any optional declarations/assets.
	// Omitted lists are canonicalized; explicitly null lists remain refused.
	raw, err = json.Marshal(Master{SchemaVersion: 1, HTML: `<p>Approved</p>`})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = Decode(raw)
	if err != nil {
		t.Fatalf("omitted unused definitions rejected: %v", err)
	}
	mustCompile(t, decoded)
}

func TestCanonicalDefinitionOrderAndSnapshotOwnership(t *testing.T) {
	master := testMaster()
	master.HTML += `<span title="Second" class="optional" data-hash-value="optional"></span>`
	master.Values = append(master.Values, Value{Name: "optional", MaxChars: 64})
	first := mustCompile(t, master)
	master.Values[0], master.Values[1] = master.Values[1], master.Values[0]
	master.HTML = strings.ReplaceAll(master.HTML, `title="Second" class="optional"`, `class="optional" title="Second"`)
	second := mustCompile(t, master)
	if first.Digest() != second.Digest() {
		t.Fatal("irrelevant definition/attribute order changed canonical digest")
	}
	canonical := first.CanonicalJSON()
	canonical[0] = 'x'
	master.Values[0].Name = "changed"
	master.Sections[0].DefaultText = "changed"
	result, err := first.Materialize(Input{Values: map[string]string{"company": "Example"}})
	if err != nil || !strings.Contains(result.HTML, "Approved scope") {
		t.Fatal("caller mutated compiled snapshot")
	}
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Go(func() {
			other, err := first.Materialize(Input{Values: map[string]string{"company": "Example"}})
			if err != nil || other.ContentDigest != result.ContentDigest {
				t.Error("concurrent materialization changed digest")
			}
		})
	}
	group.Wait()
}

func TestMaterializationBoundsRepeatedDeclaredValues(t *testing.T) {
	master := Master{SchemaVersion: 1, HTML: strings.Repeat(`<span data-hash-value="value"></span>`, 4000), Values: []Value{{Name: "value", Required: true, MaxChars: MaxValueChars}}}
	c := mustCompile(t, master)
	if _, err := c.Materialize(Input{Values: map[string]string{"value": strings.Repeat("x", MaxValueChars)}}); !errors.Is(err, ErrLimit) {
		t.Fatalf("HTML amplification was not refused: %v", err)
	}
}

func TestMasterRejectsRasterExpansionAndFontExpansionHeaders(t *testing.T) {
	asset := pngAsset(t)
	raw, _ := base64.StdEncoding.DecodeString(asset.DataBase64)
	binary.BigEndian.PutUint32(raw[16:20], 4096)
	binary.BigEndian.PutUint32(raw[20:24], 4096)
	binary.BigEndian.PutUint32(raw[29:33], crc32.ChecksumIEEE(raw[12:29]))
	master := Master{SchemaVersion: 1, HTML: `<img src="hash-asset:logo"/>`, Assets: []Asset{fixtureAsset(t, "logo", "image/png", raw)}}
	if _, err := Compile(master); err == nil {
		t.Fatal("raster pixel amplification accepted")
	}
	font, err := os.ReadFile("../render/assets/Inter.woff2")
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(font[16:20], (16<<20)+1)
	master = Master{SchemaVersion: 1, HTML: `<p>Approved</p>`, Assets: []Asset{fixtureAsset(t, "inter", "font/woff2", font)}}
	if _, err := Compile(master); err == nil {
		t.Fatal("font expansion header accepted")
	}
}

func TestCanonicalizationRefusesOutputThatCannotBeRecompiled(t *testing.T) {
	// Tokenizer decodes the entity, so canonical rendering expands it. The
	// canonical master must itself remain within the same source limits.
	master := Master{SchemaVersion: 1, HTML: `<p>` + strings.Repeat("&", MaxHTMLBytes/2) + `</p>`}
	if _, err := Compile(master); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized canonical HTML accepted: %v", err)
	}
	master = testMaster()
	master.CSS = `main {color:` + strings.Repeat(" ", MaxCSSBytes-40) + `red;}`
	c := mustCompile(t, master)
	decoded, err := Decode(c.CanonicalJSON())
	if err != nil {
		t.Fatal(err)
	}
	other := mustCompile(t, decoded)
	if other.Digest() != c.Digest() {
		t.Fatal("canonical CSS did not compile identically")
	}
}

func TestMasterRefusesUnconsumedHTMLAtEOF(t *testing.T) {
	for _, source := range []string{`<div></div><script`, `<div></div></script`, `<img src="hash-asset:logo"`, `<div title="unfinished`, `<div></div><span data-hash-value="`} {
		master := Master{SchemaVersion: 1, HTML: source, Assets: []Asset{pngAsset(t)}}
		if _, err := Compile(master); err == nil {
			t.Fatal("unfinished trailing markup was silently discarded")
		}
	}
}
