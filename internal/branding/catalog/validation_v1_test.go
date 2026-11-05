// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package catalog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"math"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
)

func TestBrandProfileCompletePaletteAndCatalogAssetsV1(t *testing.T) {
	p := DefaultProfileDataV1()
	p.Palette.Colors["additional_swath"] = "#0a0b0c"
	p.Guidance = "Keep the original mark proportions."
	for i := 0; i < 49; i++ {
		p.Assets = append(p.Assets, AssetRefV1{Slot: "variant_" + string(rune('a'+i/26)) + string(rune('a'+i%26)), AssetID: uuid.New(), Revision: 1, Alt: "Original variant"})
	}
	if e := validateProfileV1(&p); e != nil {
		t.Fatal(e)
	}
	if p.Palette.Colors["additional_swath"] != "#0A0B0C" || len(p.Assets) != 49 {
		t.Fatal("full palette/catalog lost")
	}
	if _, e := selectedSlotsV1(p, nil); e == nil {
		t.Fatal("large catalog silently expanded beyond renderer limit")
	}
	chosen := []string{p.Assets[0].Slot, p.Assets[1].Slot}
	if slots, e := selectedSlotsV1(p, chosen); e != nil || len(slots) != 2 {
		t.Fatalf("explicit bounded selection: %v", e)
	}
	if slots, e := selectedSlotsV1(p, []string{}); e != nil || len(slots) != 0 {
		t.Fatal("palette-only explicit selection refused")
	}
	if _, e := selectedSlotsV1(p, []string{chosen[0], chosen[0]}); e == nil {
		t.Fatal("duplicate selection allowed")
	}
	if _, e := selectedSlotsV1(p, []string{"missing"}); e == nil {
		t.Fatal("unknown asset slot allowed")
	}
}
func TestBrandProfileValidationRejectsUnsafeOrAmbiguousInputV1(t *testing.T) {
	tests := map[string]func(*ProfileDataV1){"contrast": func(p *ProfileDataV1) { p.Palette.Colors[p.Palette.Roles.AccentText] = "#FFFFFF" }, "external_font": func(p *ProfileDataV1) { p.Typography.Body = "url(https://example.invalid/font)" }, "nonfinite_spacing": func(p *ProfileDataV1) { p.SpacingPX = []float64{0, math.Inf(1)} }, "unsorted_scale": func(p *ProfileDataV1) { p.Typography.ScalePX = []float64{16, 12} }, "unknown_background": func(p *ProfileDataV1) {
		p.Assets = []AssetRefV1{{Slot: "logo", AssetID: uuid.New(), Revision: 1, Alt: "Logo", Usage: LogoUsageV1{AllowedBackgrounds: []string{"missing"}}}}
	}, "nil_asset": func(p *ProfileDataV1) { p.Assets = []AssetRefV1{{Slot: "logo", Revision: 1, Alt: "Logo"}} }}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p := DefaultProfileDataV1()
			change(&p)
			if validateProfileV1(&p) == nil {
				t.Fatal("invalid profile admitted")
			}
		})
	}
}
func TestBrandProfileCanonicalAndStrictJSONV1(t *testing.T) {
	p := DefaultProfileDataV1()
	if e := validateProfileV1(&p); e != nil {
		t.Fatal(e)
	}
	raw, e := canonicalV1(p)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := decodeProfileV1(raw)
	if e != nil {
		t.Fatal(e)
	}
	again, e := canonicalV1(decoded)
	if e != nil || !bytes.Equal(raw, again) {
		t.Fatal("canonical round trip changed profile")
	}
	for _, raw := range []string{`{"schema_version":1,"schema_version":2}`, `{"unrecognized":true}`, `{} {}`, `{"x":{"nested":1,"nested":2}}`} {
		var p ProfileDataV1
		if strictJSONV1([]byte(raw), &p, MaxProfileBytesV1) == nil {
			t.Fatalf("ambiguous input admitted: %s", raw)
		}
	}
	if math.Abs(ContrastRatioV1("#000", "#fff")-21) > 0.00001 || ContrastRatioV1("not-a-color", "#fff") != 0 {
		t.Fatal("contrast calculation differs")
	}
	// Bare three-digit hex is an existing branding input, including "bad".
	if ContrastRatioV1("bad", "#fff") != ContrastRatioV1("#BBAADD", "#fff") {
		t.Fatal("contrast calculation changed the existing shorthand color contract")
	}
}
func tinyPNGV1(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	img.SetNRGBA(0, 0, color.NRGBA{R: 30, G: 60, B: 90, A: 255})
	var out bytes.Buffer
	if e := png.Encode(&out, img); e != nil {
		t.Fatal(e)
	}
	return out.Bytes()
}
func TestBrandAssetPreservesLargePNGOriginalAndExplicitVariantV1(t *testing.T) {
	original, variant := tinyPNGV1(t, 4800, 1), tinyPNGV1(t, 20, 5)
	in := AssetUploadV1{RequestID: uuid.New(), Name: "Generic original", MediaType: "image/png", OriginalBase64: base64.StdEncoding.EncodeToString(original), RenderPNGBase64: base64.StdEncoding.EncodeToString(variant)}
	p, e := decodeAssetV1(in)
	if e != nil {
		t.Fatal(e)
	}
	if e = validateAssetV1(context.Background(), in, &p); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(p.original, original) || !bytes.Equal(p.render, variant) || p.width != 4800 || p.renderWidth != 20 || p.method != "provided_png_v1" {
		t.Fatal("original/explicit variant changed")
	}
	in.RenderPNGBase64 = ""
	p, e = decodeAssetV1(in)
	if e != nil {
		t.Fatal(e)
	}
	if validateAssetV1(context.Background(), in, &p) == nil {
		t.Fatal("oversized original used as renderer input")
	}
	corrupt := append([]byte{}, original...)
	corrupt[len(corrupt)-1] ^= 1
	if _, _, e = validateOriginalPNGV1(context.Background(), corrupt); e == nil {
		t.Fatal("CRC-corrupt original admitted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e = validateOriginalPNGV1(cancelled, original); e == nil {
		t.Fatal("cancelled original parser continued")
	}
}
func TestBrandSVGOriginalPreservedAndActiveResourcesRefusedV1(t *testing.T) {
	valid := `<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 30"><path fill="#123456" d="M0 0L120 0L120 30Z"/></svg>`
	if w, h, e := validateOriginalSVGV1([]byte(valid)); e != nil || w != 120 || h != 30 {
		t.Fatalf("inert vector: %d %d %v", w, h, e)
	}
	for _, inner := range []string{`<script>alert(1)</script>`, `<image href="https://example.invalid/p.png"/>`, `<path onload="alert(1)"/>`, `<foreignObject/>`, `<style>@import url(https://example.invalid/a)</style>`, `<use href="#id"/>`} {
		if _, _, e := validateOriginalSVGV1([]byte(`<svg width="10" height="10">` + inner + `</svg>`)); e == nil {
			t.Fatalf("active/unknown vector accepted: %s", inner)
		}
	}
	if _, _, e := validateOriginalSVGV1([]byte(`<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg width="10" height="10">&x;</svg>`)); e == nil {
		t.Fatal("DTD allowed")
	}
	in := AssetUploadV1{RequestID: uuid.New(), Name: "Original vector", MediaType: "image/svg+xml", OriginalBase64: base64.StdEncoding.EncodeToString([]byte(valid)), RenderPNGBase64: base64.StdEncoding.EncodeToString(tinyPNGV1(t, 20, 5))}
	p, e := decodeAssetV1(in)
	if e != nil {
		t.Fatal(e)
	}
	if e = validateAssetV1(context.Background(), in, &p); e != nil || string(p.original) != valid {
		t.Fatal("vector original was rewritten")
	}
}
func TestBrandUploadIdentityAndBodyBoundV1(t *testing.T) {
	in := AssetUploadV1{RequestID: uuid.New(), Name: "Logo", MediaType: "image/png", OriginalBase64: base64.StdEncoding.EncodeToString(tinyPNGV1(t, 2, 2))}
	p, e := decodeAssetV1(in)
	if e != nil {
		t.Fatal(e)
	}
	first := uploadFingerprintV1(in, p)
	in.Name = "Another owner label"
	if first == uploadFingerprintV1(in, p) {
		t.Fatal("request fingerprint omitted identity")
	}
	in.OriginalBase64 = strings.Repeat("a", base64.StdEncoding.EncodedLen(MaxOriginalBytesV1)+1)
	if _, e = decodeAssetV1(in); e == nil {
		t.Fatal("oversized base64 decoded")
	}
}
func TestBrandBundleRetiresBeforeReleaseAndOnlyOnceV1(t *testing.T) {
	calls := 0
	b := &DesignBundleV1{Assets: []htmlmaster.Asset{{Name: "brand_logo", DataBase64: "owned"}}}
	b.release = func() {
		calls++
		if b.Assets != nil || !b.closed.Load() {
			t.Error("allowance released before borrowed data retired")
		}
	}
	b.Close()
	b.Close()
	if calls != 1 {
		t.Fatal(calls)
	}
	if _, e := json.Marshal(DefaultProfileDataV1()); e != nil {
		t.Fatal(e)
	}
}
