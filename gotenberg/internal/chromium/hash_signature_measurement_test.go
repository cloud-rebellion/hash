// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hashTestMeasurePlan() *hashSignatureMeasurePlan {
	return &hashSignatureMeasurePlan{Text: "Anna Åström", Font: "Caveat", SourceSHA256: strings.Repeat("1", 64), GeometrySHA256: strings.Repeat("2", 64), SpanSHA256: strings.Repeat("3", 64), Page: 1, WidthPoints: "600", HeightPoints: "400", Targets: []hashMeasureTarget{{ID: "11111111-1111-4111-8111-111111111111", X: "0.05", Y: "0.05", W: "0.9", H: "0.35"}}}
}

func TestHashSignatureMeasurementRejectsUnboundedOrAmbiguousInputs(t *testing.T) {
	if !hashTestMeasurePlan().valid() {
		t.Fatal("valid plan refused")
	}
	maximum := hashTestMeasurePlan()
	maximum.Targets = nil
	for i := 1; i <= 128; i++ {
		maximum.Targets = append(maximum.Targets, hashMeasureTarget{ID: fmt.Sprintf("%08x-1111-4111-8111-111111111111", i), X: ".05", Y: ".05", W: ".9", H: ".35"})
	}
	if !maximum.valid() {
		t.Fatal("maximum bounded target count refused")
	}
	cases := []struct {
		name   string
		change func(*hashSignatureMeasurePlan)
	}{
		{"zero-source", func(p *hashSignatureMeasurePlan) { p.SourceSHA256 = strings.Repeat("0", 64) }},
		{"uppercase-digest", func(p *hashSignatureMeasurePlan) { p.GeometrySHA256 = strings.Repeat("A", 64) }},
		{"missing-span", func(p *hashSignatureMeasurePlan) { p.SpanSHA256 = "" }},
		{"outside-page-exact", func(p *hashSignatureMeasurePlan) {
			p.Targets[0].X = "0.10000000000000000000000000000001"
			p.Targets[0].W = "0.9"
		}},
		{"zero-width", func(p *hashSignatureMeasurePlan) { p.Targets[0].W = "0" }},
		{"rational-syntax", func(p *hashSignatureMeasurePlan) { p.Targets[0].W = "1/2" }},
		{"hex-syntax", func(p *hashSignatureMeasurePlan) { p.Targets[0].W = "0x1p-1" }},
		{"exponent-bomb", func(p *hashSignatureMeasurePlan) { p.Targets[0].W = "0e99999999999999999" }},
		{"exponent-over-policy", func(p *hashSignatureMeasurePlan) { p.Targets[0].W = "1e-33" }},
		{"oversize-page", func(p *hashSignatureMeasurePlan) { p.WidthPoints = "14401" }},
		{"empty-targets", func(p *hashSignatureMeasurePlan) { p.Targets = nil }},
		{"duplicate-target", func(p *hashSignatureMeasurePlan) { p.Targets = append(p.Targets, p.Targets[0]) }},
		{"unsorted-targets", func(p *hashSignatureMeasurePlan) {
			first := p.Targets[0]
			first.ID = "22222222-2222-4222-8222-222222222222"
			p.Targets = append([]hashMeasureTarget{first}, p.Targets...)
		}},
		{"too-many-targets", func(p *hashSignatureMeasurePlan) { p.Targets = make([]hashMeasureTarget, 129) }},
		{"long-name", func(p *hashSignatureMeasurePlan) { p.Text = strings.Repeat("Å", 201) }},
		{"unknown-font", func(p *hashSignatureMeasurePlan) { p.Font = "Helvetica" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := hashTestMeasurePlan()
			c.change(p)
			if p.valid() {
				t.Fatal("invalid plan admitted")
			}
		})
	}
	for _, name := range []string{strings.Repeat("Å", 200), strings.Repeat("𝔸", 200), "A\u0301 B\u00a0 C\r\nD", `O'Neill <script> ${name} " backslash\`} {
		p := hashTestMeasurePlan()
		p.Text = name
		if !p.valid() {
			t.Fatal("full-name input policy narrowed")
		}
	}
}

func hashTestMeasureDOM(p *hashSignatureMeasurePlan) hashMeasureDOMReport {
	return hashMeasureDOMReport{Schema: 1, TextPreserved: true, PrintMedia: true, DocumentScriptsBlocked: true, Targets: []hashMeasuredTarget{{ID: p.Targets[0].ID, FontSizePoints: 12, WidthPX: 720, HeightPX: 400 * 0.35 * 4 / 3, ViewportBBox: hashMeasureBBox{40, 400 * 0.05 * 4 / 3, 720, 400 * 0.35 * 4 / 3}, Lines: []hashMeasureLine{{Text: p.Text, X: 3, Y: 23, Advance: 100, InkLeft: 0, InkRight: 100, InkAscent: 20, InkDescent: 4, FontAscent: 20, FontDescent: 4, BBox: hashMeasureBBox{3, 3, 100, 24}}}}}}
}

func TestHashSignatureMeasurementClosedReportBindsEveryTargetAndFullText(t *testing.T) {
	p := hashTestMeasurePlan()
	raw, err := json.Marshal(hashTestMeasureDOM(p))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeHashMeasurement(raw, p); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(string) string
	}{
		{"duplicate-root", func(s string) string { return strings.Replace(s, `"schema":1`, `"schema":1,"schema":1`, 1) }},
		{"duplicate-line", func(s string) string { return strings.Replace(s, `"x":3`, `"x":3,"x":3`, 1) }},
		{"missing-line-origin", func(s string) string { return strings.Replace(s, `"x":3,`, "", 1) }},
		{"unknown-bbox", func(s string) string { return strings.Replace(s, `"bbox":{`, `"bbox":{"unexpected":1,`, 1) }},
		{"null-metric", func(s string) string { return strings.Replace(s, `"advance":100`, `"advance":null`, 1) }},
		{"forged-fonts", func(s string) string { return strings.Replace(s, `"hardBreak":""`, `"hardBreak":"","fonts":[]`, 1) }},
		{"below-minimum", func(s string) string { return strings.Replace(s, `"fontSizePoints":12`, `"fontSizePoints":11`, 1) }},
		{"undeclared-size", func(s string) string { return strings.Replace(s, `"fontSizePoints":12`, `"fontSizePoints":13`, 1) }},
		{"changed-text", func(s string) string { return strings.Replace(s, p.Text, "Anna", 1) }},
		{"wrong-target", func(s string) string {
			return strings.Replace(s, p.Targets[0].ID, "22222222-2222-4222-8222-222222222222", 1)
		}},
		{"wrong-geometry", func(s string) string { return strings.Replace(s, `"widthPx":720`, `"widthPx":721`, 1) }},
		{"clipped-ink", func(s string) string { return strings.Replace(s, `"inkRight":100`, `"inkRight":800`, 1) }},
		{"clipped-bbox", func(s string) string { return strings.Replace(s, `"width":100`, `"width":800`, 1) }},
		{"displaced-viewport", func(s string) string { return strings.Replace(s, `"x":40`, `"x":41`, 1) }},
		{"resized-viewport", func(s string) string { return strings.Replace(s, `"width":720`, `"width":721`, 1) }},
		{"disabled-script-false", func(s string) string {
			return strings.Replace(s, `"documentScriptsBlocked":true`, `"documentScriptsBlocked":false`, 1)
		}},
		{"trailing-value", func(s string) string { return s + " {}" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := decodeHashMeasurement([]byte(c.change(string(raw))), p); !errors.Is(err, errHashSignatureMeasure) {
				t.Fatalf("ambiguous report admitted: %v", err)
			}
		})
	}
	p.Targets = append(p.Targets, hashMeasureTarget{ID: "22222222-2222-4222-8222-222222222222", X: ".1", Y: ".5", W: ".4", H: ".4"})
	if _, err := decodeHashMeasurement(raw, p); !errors.Is(err, errHashSignatureMeasure) {
		t.Fatal("missing assigned target admitted")
	}
}

func TestHashSignatureMeasurementGeneratedDocumentPinsExactFont(t *testing.T) {
	if _, err := hashSignatureMeasureHTML(nil, nil); !errors.Is(err, errHashSignatureMeasure) {
		t.Fatal("nil plan did not refuse")
	}
	for _, name := range []string{"Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple"} {
		t.Run(name, func(t *testing.T) {
			p := hashTestMeasurePlan()
			p.Font = name
			p.Text = `<script>alert("test")</script> ${name}`
			f, _ := hashPinnedMeasureFont(name)
			font, err := os.ReadFile(filepath.Join("..", "..", "..", "internal", "render", "assets", f.file))
			if err != nil {
				t.Fatal(err)
			}
			html, err := hashSignatureMeasureHTML(p, font)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(html, "<script") || strings.Contains(html, p.Text) || !strings.Contains(html, p.inputSHA()) || !strings.Contains(html, "data:font/woff2;base64,") {
				t.Fatal("generated document escaped closed recipe")
			}
			font[0] ^= 1
			if _, err := hashSignatureMeasureHTML(p, font); !errors.Is(err, errHashSignatureMeasure) {
				t.Fatal("changed font accepted")
			}
		})
	}
	p := hashTestMeasurePlan()
	first := p.inputSHA()
	p.Targets[0].X = ".05"
	if p.inputSHA() == first {
		t.Fatal("exact decimal commitment lost")
	}
}

func TestHashSignatureMeasurementCannotPrintWithoutPrivateIsolation(t *testing.T) {
	var public PdfOptions
	if json.Unmarshal([]byte(`{"hashSignatureMeasure":{"text":"Anna"},"HashSignatureMeasure":{"text":"Anna"}}`), &public) != nil || public.hashSignatureMeasure != nil {
		t.Fatal("public input armed hook")
	}
	if err := hashSignatureMeasurementAction(nil).Do(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := hashTestMeasurePlan()
	p.report = &hashSignatureMeasurement{Policy: "stale"}
	b := &chromiumBrowser{}
	err := b.pdf(context.Background(), slog.New(slog.DiscardHandler), "unused", "unused", PdfOptions{hashSignatureMeasure: p}, nil)
	if !errors.Is(err, errHashFitIsolation) || p.report != nil {
		t.Fatal("isolation refusal or stale measurement")
	}
	b.arguments.disableJavaScript = true
	err = b.pdf(context.Background(), slog.New(slog.DiscardHandler), "unused", "unused", PdfOptions{hashSignatureMeasure: p}, nil)
	if !errors.Is(err, errHashSignatureMeasure) {
		t.Fatal("missing print media admitted")
	}
}
