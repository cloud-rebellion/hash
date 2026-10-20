// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ordinarypage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"
	"unicode/utf8"
)

type BBoxV1 struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}
type FontUsageV1 struct {
	FamilyName     string  `json:"familyName"`
	PostScriptName string  `json:"postScriptName"`
	IsCustomFont   bool    `json:"isCustomFont"`
	GlyphCount     float64 `json:"glyphCount"`
}
type LineV1 struct {
	Text        string        `json:"text"`
	HardBreak   string        `json:"hardBreak"`
	X           float64       `json:"x"`
	Y           float64       `json:"y"`
	Advance     float64       `json:"advance"`
	InkLeft     float64       `json:"inkLeft"`
	InkRight    float64       `json:"inkRight"`
	InkAscent   float64       `json:"inkAscent"`
	InkDescent  float64       `json:"inkDescent"`
	FontAscent  float64       `json:"fontAscent"`
	FontDescent float64       `json:"fontDescent"`
	BBox        BBoxV1        `json:"bbox"`
	Fonts       []FontUsageV1 `json:"fonts"`
}
type FieldMeasurementV1 struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	NoInk        bool     `json:"noInk"`
	Checked      bool     `json:"checked"`
	FontSizePX   float64  `json:"fontSizePx"`
	MarkSizePX   float64  `json:"markSizePx"`
	ViewportBBox BBoxV1   `json:"viewportBBox"`
	Lines        []LineV1 `json:"lines"`
	MarkBBox     BBoxV1   `json:"markBBox"`
	MarkPath     string   `json:"markPath"`
}
type MeasurementV1 struct {
	Schema                 int                  `json:"schema"`
	Policy                 string               `json:"policy"`
	InputSHA256            string               `json:"inputSha256"`
	FontSHA256             string               `json:"fontSha256"`
	TextPreserved          bool                 `json:"textPreserved"`
	Unobscured             bool                 `json:"unobscured"`
	PrintMedia             bool                 `json:"printMedia"`
	DocumentScriptsBlocked bool                 `json:"documentScriptsBlocked"`
	Fields                 []FieldMeasurementV1 `json:"fields"`
}
type SnapshotLineV1 struct {
	BBox  BBoxV1        `json:"bbox"`
	Fonts []FontUsageV1 `json:"fonts"`
}
type SnapshotFieldV1 struct {
	ID           string           `json:"id"`
	ViewportBBox BBoxV1           `json:"viewportBBox"`
	Lines        []SnapshotLineV1 `json:"lines"`
	MarkBBox     BBoxV1           `json:"markBBox"`
}
type SnapshotReportV1 struct {
	Schema               int               `json:"schema"`
	InputSHA256          string            `json:"inputSha256"`
	RecipeSHA256         string            `json:"recipeSha256"`
	DOMSHA256            string            `json:"domSha256"`
	ComputedStylesSHA256 string            `json:"computedStylesSha256"`
	BodyTextSHA256       string            `json:"bodyTextSha256"`
	Fields               []SnapshotFieldV1 `json:"fields"`
}
type ChromiumVersionV1 struct {
	Product  string `json:"product"`
	Revision string `json:"revision"`
	Protocol string `json:"protocol"`
}
type ReportV1 struct {
	Schema         int               `json:"schema"`
	Policy         string            `json:"policy"`
	Plan           PlanV1            `json:"plan"`
	InputSHA256    string            `json:"inputSha256"`
	RecipeSHA256   string            `json:"recipeSha256"`
	HTMLSHA256     string            `json:"htmlSha256"`
	FontSHA256     string            `json:"fontSha256"`
	PDFSHA256      string            `json:"pdfSha256"`
	PDFBytes       int               `json:"pdfBytes"`
	FragmentPage   int               `json:"fragmentPage"`
	SnapshotSHA256 string            `json:"snapshotSha256"`
	Chromium       ChromiumVersionV1 `json:"chromium"`
	Measurement    MeasurementV1     `json:"measurement"`
}

// Archived originals are immutable through accessors. Decoder success is
// integrity/layout consistency only; the private genuine renderer and isolated
// strict PDF fragment/source inspection are mandatory before Sign admission.
type PackageV1 struct {
	parts  [5][]byte
	report ReportV1
}

func (p *PackageV1) PDF() []byte {
	if p == nil {
		return nil
	}
	return bytes.Clone(p.parts[1])
}
func (p *PackageV1) PDFByteCount() int {
	if p == nil {
		return 0
	}
	return len(p.parts[1])
}
func (p *PackageV1) ReportBytes() []byte {
	if p == nil {
		return nil
	}
	return bytes.Clone(p.parts[0])
}
func (p *PackageV1) SnapshotBytes() []byte {
	if p == nil {
		return nil
	}
	return bytes.Clone(p.parts[4])
}
func (p *PackageV1) Plan() (PlanV1, error) {
	if p == nil {
		return PlanV1{}, ErrInvalidV1
	}
	return ClonePlanV1(p.report.Plan)
}
func (p *PackageV1) Report() (ReportV1, error) {
	if p == nil {
		return ReportV1{}, ErrInvalidV1
	}
	var r ReportV1
	if json.Unmarshal(p.parts[0], &r) != nil {
		return ReportV1{}, ErrInvalidV1
	}
	return r, nil
}
func (p *PackageV1) Bytes() []byte {
	if p == nil {
		return nil
	}
	n := PackageHeaderBytesV1
	for _, part := range p.parts {
		n += len(part)
	}
	raw := make([]byte, PackageHeaderBytesV1, n)
	copy(raw, "HSHORD01")
	for i, part := range p.parts {
		binary.BigEndian.PutUint32(raw[8+i*4:], uint32(len(part)))
	}
	h := sha256.Sum256(p.parts[0])
	copy(raw[28:], h[:])
	for _, part := range p.parts {
		raw = append(raw, part...)
	}
	return raw
}
func DecodeV1(raw []byte, expected PlanV1) (*PackageV1, error) {
	return DecodeWithContextV1(context.Background(), raw, expected)
}
func DecodeWithContextV1(ctx context.Context, raw []byte, expected PlanV1) (*PackageV1, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ContextErrorV1(ctx)
	}
	if ValidatePlanV1(expected) != nil || len(raw) < PackageHeaderBytesV1 || len(raw) > MaxPackageBytesV1 || string(raw[:8]) != "HSHORD01" {
		return nil, ErrInvalidV1
	}
	limits := [5]int{MaxReportBytesV1, MaxPDFBytesV1, MaxHTMLBytesV1, MaxFontBytesV1, MaxSnapshotBytesV1}
	var parts [5][]byte
	at := PackageHeaderBytesV1
	for i, limit := range limits {
		n := uint64(binary.BigEndian.Uint32(raw[8+i*4:]))
		if n < 1 || n > uint64(limit) || n > uint64(len(raw)-at) {
			return nil, ErrInvalidV1
		}
		parts[i] = raw[at : at+int(n)]
		at += int(n)
	}
	if at != len(raw) {
		return nil, ErrInvalidV1
	}
	h := sha256.Sum256(parts[0])
	if !bytes.Equal(h[:], raw[28:60]) {
		return nil, ErrInvalidV1
	}
	var report ReportV1
	if closedDecodeV1(ctx, parts[0], MaxReportBytesV1, &report) != nil {
		return nil, ContextErrorV1(ctx)
	}
	inputSHA, err := PlanSHA256V1(expected)
	if err != nil {
		return nil, ErrInvalidV1
	}
	actualSHA, err := PlanSHA256V1(report.Plan)
	if err != nil || actualSHA != inputSHA || report.Schema != 1 || report.Policy != PolicyV1 || report.InputSHA256 != inputSHA ||
		report.RecipeSHA256 != RecipeSHA256V1() || report.HTMLSHA256 != digestV1(parts[2]) || report.FontSHA256 != FontSHA256V1 ||
		len(parts[3]) != FontBytesV1 || digestV1(parts[3]) != FontSHA256V1 || report.PDFSHA256 != digestV1(parts[1]) ||
		report.PDFBytes != len(parts[1]) || report.FragmentPage != 1 || !bytes.HasPrefix(parts[1], []byte("%PDF-")) ||
		report.SnapshotSHA256 != digestV1(parts[4]) || !validRuntimeTextV1(report.Chromium.Product, 256) ||
		!validRuntimeTextV1(report.Chromium.Revision, 256) || !validRuntimeTextV1(report.Chromium.Protocol, 32) {
		return nil, ErrInvalidV1
	}
	html, err := GeneratedHTMLV1(expected, parts[3])
	if err != nil || !bytes.Equal(html, parts[2]) {
		return nil, ErrInvalidV1
	}
	if ValidateMeasurementV1(ctx, expected, report.Measurement) != nil {
		return nil, ContextErrorV1(ctx)
	}
	var snapshot SnapshotReportV1
	if closedDecodeV1(ctx, parts[4], MaxSnapshotBytesV1, &snapshot) != nil || validateSnapshotV1(expected, report.Measurement, snapshot) != nil {
		return nil, ContextErrorV1(ctx)
	}
	if ctx.Err() != nil {
		return nil, ContextErrorV1(ctx)
	}
	p := &PackageV1{report: report}
	for i, part := range parts {
		if ctx.Err() != nil {
			return nil, ContextErrorV1(ctx)
		}
		p.parts[i] = bytes.Clone(part)
	}
	return p, nil
}
func ValidateMeasurementV1(ctx context.Context, p PlanV1, m MeasurementV1) error {
	if ctx == nil || ctx.Err() != nil {
		return ContextErrorV1(ctx)
	}
	inputSHA, err := PlanSHA256V1(p)
	if err != nil || m.Schema != 1 || m.Policy != PolicyV1 || m.InputSHA256 != inputSHA || m.FontSHA256 != FontSHA256V1 ||
		!m.TextPreserved || !m.Unobscured || !m.PrintMedia || !m.DocumentScriptsBlocked || len(m.Fields) != len(p.Fields) {
		return ErrInvalidV1
	}
	lineCount := 0
	collision := newInkGridV1()
	for i, f := range m.Fields {
		if ctx.Err() != nil {
			return ContextErrorV1(ctx)
		}
		expected := p.Fields[i]
		rect := fieldRectV1(p, expected)
		checked := expected.Type == "checkbox" && expected.ValueValid && CheckedV1(expected.Value)
		visual := visibleValueV1(expected)
		noInk := !checked && visual == ""
		fontSize := float64(FontSizePXV1)
		if expected.Type == "checkbox" {
			fontSize = 0
		}
		markSize := float64(0)
		if checked {
			markSize = 11
		}
		if f.ID != expected.ID || f.Type != expected.Type || f.NoInk != noInk || f.Checked != checked || f.FontSizePX != fontSize || f.MarkSizePX != markSize ||
			!boxNearV1(f.ViewportBBox, rect, 1.0/32.0) || len(f.Lines) > 1000 || !validBoxV1(f.MarkBBox) {
			return ErrInvalidV1
		}
		if checked {
			if rect.Width < 15 || rect.Height < 15 || len(f.Lines) != 0 || f.MarkPath != CheckboxPathV1 ||
				!boxNearV1(f.MarkBBox, BBoxV1{3, (rect.Height-11)/2 + 1, 9, 7}, 0.001) ||
				f.MarkBBox.Width <= 0 || f.MarkBBox.Height <= 0 || f.MarkBBox.X-0.75 < 2-0.001 || f.MarkBBox.Y-0.75 < 2-0.001 ||
				f.MarkBBox.X+f.MarkBBox.Width+0.75 > rect.Width-2+0.001 || f.MarkBBox.Y+f.MarkBBox.Height+0.75 > rect.Height-2+0.001 {
				return ErrInvalidV1
			}
			ink := BBoxV1{rect.X + f.MarkBBox.X - 0.75, rect.Y + f.MarkBBox.Y - 0.75, f.MarkBBox.Width + 1.5, f.MarkBBox.Height + 1.5}
			if collision.add(ctx, f.ID, ink) != nil {
				return ErrInvalidV1
			}
		} else if f.MarkPath != "" || f.MarkBBox != (BBoxV1{}) {
			return ErrInvalidV1
		}
		if noInk {
			if len(f.Lines) != 0 {
				return ErrInvalidV1
			}
			continue
		}
		if expected.Type == "checkbox" {
			continue
		}
		if len(f.Lines) < 1 {
			return ErrInvalidV1
		}
		var raw strings.Builder
		raw.Grow(len(visual))
		for _, line := range f.Lines {
			lineCount++
			if lineCount > MaxLinesV1 {
				return ErrInvalidV1
			}
			if ctx.Err() != nil {
				return ContextErrorV1(ctx)
			}
			if len(line.Text) > len(visual) || !utf8.ValidString(line.Text) || len(line.Fonts) > 1 || !validBoxV1(line.BBox) {
				return ErrInvalidV1
			}
			switch line.HardBreak {
			case "", "\r", "\n", "\r\n":
			default:
				return ErrInvalidV1
			}
			values := []float64{line.X, line.Y, line.Advance, line.InkLeft, line.InkRight, line.InkAscent, line.InkDescent, line.FontAscent, line.FontDescent}
			for _, v := range values {
				if !finiteV1(v) || math.Abs(v) > 100000 {
					return ErrInvalidV1
				}
			}
			if line.Advance < 0 || line.FontAscent < 0 || line.FontDescent < 0 ||
				line.X-line.InkLeft < 2-0.25 || line.X+line.InkRight > rect.Width-2+0.25 ||
				line.Y-line.InkAscent < 2-0.25 || line.Y+line.InkDescent > rect.Height-2+0.25 {
				return ErrInvalidV1
			}
			empty := strings.TrimSpace(line.Text) == ""
			if empty {
				if len(line.Fonts) != 0 {
					return ErrInvalidV1
				}
			} else {
				if len(line.Fonts) != 1 || !validFontUsageV1(line.Fonts[0]) || line.BBox.Width <= 0 || line.BBox.Height <= 0 ||
					line.BBox.X < 2-0.25 || line.BBox.Y < 2-0.25 || line.BBox.X+line.BBox.Width > rect.Width-2+0.25 ||
					line.BBox.Y+line.BBox.Height > rect.Height-2+0.25 {
					return ErrInvalidV1
				}
				if collision.add(ctx, f.ID, BBoxV1{rect.X + line.BBox.X, rect.Y + line.BBox.Y, line.BBox.Width, line.BBox.Height}) != nil {
					return ErrInvalidV1
				}
			}
			if len(line.Text)+len(line.HardBreak) > len(visual)-raw.Len() {
				return ErrInvalidV1
			}
			raw.WriteString(line.Text)
			raw.WriteString(line.HardBreak)
		}
		if raw.String() != visual {
			return ErrInvalidV1
		}
	}
	return nil
}
func validateSnapshotV1(p PlanV1, m MeasurementV1, s SnapshotReportV1) error {
	sha, err := PlanSHA256V1(p)
	if err != nil || s.Schema != 1 || s.InputSHA256 != sha || s.RecipeSHA256 != RecipeSHA256V1() || !validDigestV1(s.DOMSHA256) ||
		!validDigestV1(s.ComputedStylesSHA256) || !validDigestV1(s.BodyTextSHA256) || len(s.Fields) != len(m.Fields) {
		return ErrInvalidV1
	}
	var body strings.Builder
	for _, f := range p.Fields {
		body.WriteString(visibleValueV1(f))
	}
	if s.BodyTextSHA256 != digestV1([]byte(body.String())) {
		return ErrInvalidV1
	}
	for i, f := range s.Fields {
		before := m.Fields[i]
		if f.ID != before.ID || !boxNearV1(f.ViewportBBox, before.ViewportBBox, 0.001) || !boxNearV1(f.MarkBBox, before.MarkBBox, 0.001) || len(f.Lines) != len(before.Lines) {
			return ErrInvalidV1
		}
		for j, line := range f.Lines {
			if !boxNearV1(line.BBox, before.Lines[j].BBox, 0.001) {
				return ErrInvalidV1
			}
			a, _ := json.Marshal(line.Fonts)
			b, _ := json.Marshal(before.Lines[j].Fonts)
			if !bytes.Equal(a, b) {
				return ErrInvalidV1
			}
		}
	}
	return nil
}
func validRuntimeTextV1(s string, max int) bool {
	if len(s) < 1 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func validFontUsageV1(f FontUsageV1) bool {
	return f.IsCustomFont && f.FamilyName == FontFamilyV1 && validRuntimeTextV1(f.PostScriptName, 256) && finiteV1(f.GlyphCount) &&
		f.GlyphCount > 0 && f.GlyphCount <= MaxValueBytesV1 && math.Trunc(f.GlyphCount) == f.GlyphCount
}
func validBoxV1(b BBoxV1) bool {
	return finiteV1(b.X) && finiteV1(b.Y) && finiteV1(b.Width) && finiteV1(b.Height) && math.Abs(b.X) <= 100000 && math.Abs(b.Y) <= 100000 && b.Width >= 0 && b.Width <= 100000 && b.Height >= 0 && b.Height <= 100000
}
func boxNearV1(a, b BBoxV1, tolerance float64) bool {
	return validBoxV1(a) && validBoxV1(b) && math.Abs(a.X-b.X) <= tolerance && math.Abs(a.Y-b.Y) <= tolerance && math.Abs(a.Width-b.Width) <= tolerance && math.Abs(a.Height-b.Height) <= tolerance
}
func fieldRectV1(p PlanV1, f FieldV1) BBoxV1 {
	_, w, _ := decimalV1(p.WidthPoints)
	_, h, _ := decimalV1(p.HeightPoints)
	_, x, _ := decimalV1(f.XPct)
	_, y, _ := decimalV1(f.YPct)
	_, fw, _ := decimalV1(f.WPct)
	_, fh, _ := decimalV1(f.HPct)
	return BBoxV1{x * w * 4 / 300, y * h * 4 / 300, fw * w * 4 / 300, fh * h * 4 / 300}
}

type inkEntryV1 struct {
	id  string
	box BBoxV1
}
type inkGridV1 struct {
	cells   map[[2]int][]int
	entries []inkEntryV1
	work    int
}

func newInkGridV1() *inkGridV1 { return &inkGridV1{cells: make(map[[2]int][]int)} }
func (g *inkGridV1) add(ctx context.Context, id string, b BBoxV1) error {
	if !validBoxV1(b) {
		return ErrInvalidV1
	}
	x0, x1, y0, y1 := int(math.Floor(b.X/64)), int(math.Floor((b.X+b.Width)/64)), int(math.Floor(b.Y/64)), int(math.Floor((b.Y+b.Height)/64))
	if (x1-x0+1)*(y1-y0+1) > 10000 {
		return ErrInvalidV1
	}
	seen := make(map[int]bool)
	for x := x0; x <= x1; x++ {
		for y := y0; y <= y1; y++ {
			if ctx.Err() != nil {
				return ContextErrorV1(ctx)
			}
			g.work++
			if g.work > 100000 {
				return ErrInvalidV1
			}
			for _, index := range g.cells[[2]int{x, y}] {
				if seen[index] {
					continue
				}
				seen[index] = true
				g.work++
				if g.work > 100000 {
					return ErrInvalidV1
				}
				other := g.entries[index]
				if other.id != id && math.Min(b.X+b.Width, other.box.X+other.box.Width)-math.Max(b.X, other.box.X) > 0.001 &&
					math.Min(b.Y+b.Height, other.box.Y+other.box.Height)-math.Max(b.Y, other.box.Y) > 0.001 {
					return ErrInvalidV1
				}
			}
		}
	}
	index := len(g.entries)
	g.entries = append(g.entries, inkEntryV1{id, b})
	for x := x0; x <= x1; x++ {
		for y := y0; y <= y1; y++ {
			g.work++
			if g.work > 100000 || len(g.cells) > 100000 {
				return ErrInvalidV1
			}
			key := [2]int{x, y}
			g.cells[key] = append(g.cells[key], index)
		}
	}
	return nil
}
