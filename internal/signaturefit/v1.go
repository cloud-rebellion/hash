// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package signaturefit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// This file is a frozen reader recipe. Do not replace these constants or
// validators when introducing another renderer version: add a new dispatched
// version instead. No browser, current render helper or current font asset is
// consulted when an archived package is decoded.
const htmlRecipeV1 = `<!doctype html><html data-hash-measure-policy="%s" data-hash-measure-input="%s"><meta charset="utf-8"><style>@font-face{font-family:"%s";src:url("data:font/woff2;base64,%s") format("woff2");font-weight:400;font-style:normal;font-display:block} @page{size:%spt %spt;margin:0}html,body{margin:0;padding:0;width:%spt;height:%spt;background:transparent}svg{position:absolute;overflow:visible}text{white-space:pre;font-kerning:normal;font-variant-ligatures:normal;font-variant-caps:normal;letter-spacing:0;word-spacing:0;direction:ltr;unicode-bidi:isolate;fill:#111827}</style><body></body></html>`
const sealCSSV1 = "html{-webkit-print-color-adjust:exact;print-color-adjust:exact}"
const printRecipeV1 = "all-pages;scale=1;zero-margins;css-page-size;transparent;background;no-headers;no-tags;no-outline"

func inputSHAUncheckedV1(p Plan) string { b, _ := json.Marshal(p); return sha(b) }

func sealHTMLV1(p Plan, font []byte) ([]byte, error) {
	if ValidatePlan(p) != nil {
		return nil, ErrInvalid
	}
	f, ok := Font(p.Font)
	if !ok || len(font) == 0 || len(font) > maxFontBytes || sha(font) != f.SHA256 {
		return nil, ErrInvalid
	}
	_, width, _ := decimalV1(p.WidthPoints)
	_, height, _ := decimalV1(p.HeightPoints)
	raw := fmt.Sprintf(htmlRecipeV1, measurementPolicyV1, inputSHAUncheckedV1(p), f.Family, base64.StdEncoding.EncodeToString(font), strconv.FormatFloat(width, 'g', -1, 64), strconv.FormatFloat(height, 'g', -1, 64), strconv.FormatFloat(width, 'g', -1, 64), strconv.FormatFloat(height, 'g', -1, 64))
	raw = strings.Replace(raw, "<style>", "<style>"+sealCSSV1, 1)
	if len(raw) > maxHTMLBytes {
		return nil, ErrInvalid
	}
	return []byte(raw), nil
}

type fontUsageV1 struct {
	FamilyName     string  `json:"familyName"`
	PostScriptName string  `json:"postScriptName"`
	IsCustomFont   bool    `json:"isCustomFont"`
	GlyphCount     float64 `json:"glyphCount"`
}

type bboxV1 struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}
type lineV1 struct {
	Text        string         `json:"text"`
	HardBreak   string         `json:"hardBreak"`
	X           float64        `json:"x"`
	Y           float64        `json:"y"`
	Advance     float64        `json:"advance"`
	InkLeft     float64        `json:"inkLeft"`
	InkRight    float64        `json:"inkRight"`
	InkAscent   float64        `json:"inkAscent"`
	InkDescent  float64        `json:"inkDescent"`
	FontAscent  float64        `json:"fontAscent"`
	FontDescent float64        `json:"fontDescent"`
	BBox        bboxV1         `json:"bbox"`
	Fonts       []*fontUsageV1 `json:"fonts,omitempty"`
}
type measuredTargetV1 struct {
	ID             string   `json:"id"`
	FontSizePoints float64  `json:"fontSizePoints"`
	WidthPX        float64  `json:"widthPx"`
	HeightPX       float64  `json:"heightPx"`
	ViewportBBox   bboxV1   `json:"viewportBBox"`
	Lines          []lineV1 `json:"lines"`
}
type domReportV1 struct {
	Schema                 int                `json:"schema"`
	TextPreserved          bool               `json:"textPreserved"`
	PrintMedia             bool               `json:"printMedia"`
	DocumentScriptsBlocked bool               `json:"documentScriptsBlocked"`
	Targets                []measuredTargetV1 `json:"targets"`
}
type measurementV1 struct {
	Policy      string      `json:"policy"`
	InputSHA256 string      `json:"inputSha256"`
	FontSHA256  string      `json:"fontSha256"`
	DOM         domReportV1 `json:"dom"`
}

func jsonTokenV1(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrInvalid
	}
	t, err := d.Token()
	if err != nil || t == nil {
		return ErrInvalid
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			s, ok := key.(string)
			if err != nil || !ok || seen[s] {
				return ErrInvalid
			}
			seen[s] = true
			if err = jsonTokenV1(d, depth+1); err != nil {
				return err
			}
		}
		if t, err = d.Token(); err != nil || t != json.Delim('}') {
			return ErrInvalid
		}
	case json.Delim('['):
		for d.More() {
			if err = jsonTokenV1(d, depth+1); err != nil {
				return err
			}
		}
		if t, err = d.Token(); err != nil || t != json.Delim(']') {
			return ErrInvalid
		}
	}
	return nil
}

func closeV1(a, b float64) bool { return math.Abs(a-b) <= 0.001 }
func closedKeysV1(raw []byte, keys ...string) bool {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := values[key]; !ok {
			return false
		}
	}
	return true
}
func decodeMeasurementV1(raw []byte, p *Plan) (*domReportV1, error) {
	if (p == nil || ValidatePlan(*p) != nil) || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if jsonTokenV1(d, 0) != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	if !closedKeysV1(raw, "schema", "textPreserved", "printMedia", "documentScriptsBlocked", "targets") {
		return nil, ErrInvalid
	}
	var top map[string]json.RawMessage
	_ = json.Unmarshal(raw, &top)
	var targets []json.RawMessage
	_ = json.Unmarshal(top["targets"], &targets)
	for _, target := range targets {
		if !closedKeysV1(target, "id", "fontSizePoints", "widthPx", "heightPx", "viewportBBox", "lines") {
			return nil, ErrInvalid
		}
		var t map[string]json.RawMessage
		_ = json.Unmarshal(target, &t)
		if !closedKeysV1(t["viewportBBox"], "x", "y", "width", "height") {
			return nil, ErrInvalid
		}
		var lines []json.RawMessage
		_ = json.Unmarshal(t["lines"], &lines)
		for _, line := range lines {
			if !closedKeysV1(line, "text", "hardBreak", "x", "y", "advance", "inkLeft", "inkRight", "inkAscent", "inkDescent", "fontAscent", "fontDescent", "bbox") {
				return nil, ErrInvalid
			}
			var l map[string]json.RawMessage
			_ = json.Unmarshal(line, &l)
			if !closedKeysV1(l["bbox"], "x", "y", "width", "height") {
				return nil, ErrInvalid
			}
		}
	}
	var r domReportV1
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || r.Schema != 1 || !r.TextPreserved || !r.PrintMedia || !r.DocumentScriptsBlocked || len(r.Targets) != len(p.Targets) {
		return nil, ErrInvalid
	}
	_, pw, _ := decimalV1(p.WidthPoints)
	_, ph, _ := decimalV1(p.HeightPoints)
	for i, t := range r.Targets {
		_, x, _ := decimalV1(p.Targets[i].X)
		_, y, _ := decimalV1(p.Targets[i].Y)
		_, w, _ := decimalV1(p.Targets[i].W)
		_, h, _ := decimalV1(p.Targets[i].H)
		if t.ID != p.Targets[i].ID || !closeV1(t.WidthPX, w*pw*4/3) || !closeV1(t.HeightPX, h*ph*4/3) || len(t.Lines) < 1 || len(t.Lines) > 4 {
			return nil, ErrInvalid
		}
		for _, pair := range [][2]float64{{t.ViewportBBox.X, x * pw * 4 / 3}, {t.ViewportBBox.Y, y * ph * 4 / 3}, {t.ViewportBBox.Width, w * pw * 4 / 3}, {t.ViewportBBox.Height, h * ph * 4 / 3}} {
			if math.IsNaN(pair[0]) || math.IsInf(pair[0], 0) || math.Abs(pair[0]-pair[1]) > 1.0/32 {
				return nil, ErrInvalid
			}
		}
		validSize := false
		for _, s := range []float64{48, 44, 40, 36, 32, 28, 24, 20, 18, 16, 14, 12} {
			if t.FontSizePoints == s {
				validSize = true
			}
		}
		if !validSize {
			return nil, ErrInvalid
		}
		text := ""
		for _, line := range t.Lines {
			if line.Fonts != nil || !(line.HardBreak == "" || line.HardBreak == "\r" || line.HardBreak == "\n" || line.HardBreak == "\r\n") {
				return nil, ErrInvalid
			}
			text += line.Text + line.HardBreak
			for _, v := range []float64{line.X, line.Y, line.Advance, line.InkLeft, line.InkRight, line.InkAscent, line.InkDescent, line.FontAscent, line.FontDescent, line.BBox.X, line.BBox.Y, line.BBox.Width, line.BBox.Height} {
				if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 100000 {
					return nil, ErrInvalid
				}
			}
			if line.Advance < 0 || line.FontAscent < 0 || line.FontDescent < 0 || line.BBox.Width < 0 || line.BBox.Height < 0 || line.X-line.InkLeft < 8.0/3-0.25 || line.X+line.InkRight > t.WidthPX-8.0/3+0.25 || line.Y-line.InkAscent < 8.0/3-0.25 || line.Y+line.InkDescent > t.HeightPX-8.0/3+0.25 {
				return nil, ErrInvalid
			}
			if line.Text != "" && (line.BBox.X < 8.0/3-0.25 || line.BBox.Y < 8.0/3-0.25 || line.BBox.X+line.BBox.Width > t.WidthPX-8.0/3+0.25 || line.BBox.Y+line.BBox.Height > t.HeightPX-8.0/3+0.25) {
				return nil, ErrInvalid
			}
		}
		if text != p.Text {
			return nil, ErrInvalid
		}
	}
	return &r, nil
}

func validSealedMeasurementV1(p *Plan, m *measurementV1) bool {
	if p == nil || ValidatePlan(*p) != nil {
		return false
	}
	f, ok := Font(p.Font)
	if !ok || m == nil || m.Policy != measurementPolicyV1 || m.InputSHA256 != inputSHAUncheckedV1(*p) || m.FontSHA256 != f.SHA256 {
		return false
	}
	raw, err := json.Marshal(m.DOM)
	if err != nil {
		return false
	}
	var observed domReportV1
	if json.Unmarshal(raw, &observed) != nil {
		return false
	}
	for i := range observed.Targets {
		for j := range observed.Targets[i].Lines {
			l := &observed.Targets[i].Lines[j]
			if strings.TrimSpace(l.Text) == "" {
				if len(l.Fonts) != 0 {
					return false
				}
			} else {
				if len(l.Fonts) != 1 || l.Fonts[0] == nil {
					return false
				}
				v := l.Fonts[0]
				if !v.IsCustomFont || v.FamilyName != f.Family || v.PostScriptName != f.PostScript || v.GlyphCount <= 0 || v.GlyphCount > 800 || math.Trunc(v.GlyphCount) != v.GlyphCount {
					return false
				}
			}
			l.Fonts = nil
		}
	}
	raw, err = json.Marshal(observed)
	if err != nil {
		return false
	}
	_, err = decodeMeasurementV1(raw, p)
	return err == nil
}
