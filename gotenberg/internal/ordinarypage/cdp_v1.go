// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ordinarypage

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/css"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
)

// A seal belongs to exactly one owned browser target. Shared supervisor,
// navigation/network barriers, native print stream ownership, target registry
// cleanup and publication AFTER cleanup remain in Chromium's production bridge.
type SealV1 struct {
	plan          PlanV1
	font, html    []byte
	measurement   *MeasurementV1
	before        []byte
	afterVerified bool
	finished      bool
	busy          atomic.Bool
}

func NewSealV1(p PlanV1, font []byte) (*SealV1, error) {
	own, err := ClonePlanV1(p)
	if err != nil || len(font) != FontBytesV1 || digestV1(font) != FontSHA256V1 {
		return nil, ErrInvalidV1
	}
	html, err := GeneratedHTMLV1(own, font)
	if err != nil {
		return nil, err
	}
	return &SealV1{plan: own, font: bytes.Clone(font), html: html}, nil
}
func (s *SealV1) HTML() []byte {
	if s == nil {
		return nil
	}
	return bytes.Clone(s.html)
}
func (s *SealV1) Plan() (PlanV1, error) {
	if s == nil {
		return PlanV1{}, ErrInvalidV1
	}
	return ClonePlanV1(s.plan)
}
func (s *SealV1) begin(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ContextErrorV1(ctx)
	}
	if s == nil || !s.busy.CompareAndSwap(false, true) {
		return ErrUnavailableV1
	}
	return nil
}

type measureFieldArgV1 struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	VisibleValue string  `json:"visibleValue"`
	Checked      bool    `json:"checked"`
	LeftPX       float64 `json:"leftPx"`
	TopPX        float64 `json:"topPx"`
	WidthPX      float64 `json:"widthPx"`
	HeightPX     float64 `json:"heightPx"`
}
type measureArgV1 struct {
	Policy       string              `json:"policy"`
	InputSHA     string              `json:"inputSha"`
	FontSHA      string              `json:"fontSha"`
	FontSize     int                 `json:"fontSize"`
	Padding      int                 `json:"padding"`
	CheckboxPath string              `json:"checkboxPath"`
	Fields       []measureFieldArgV1 `json:"fields"`
}

func MeasureV1(ctx context.Context, s *SealV1) error {
	if err := s.begin(ctx); err != nil {
		return err
	}
	defer s.busy.Store(false)
	if s.measurement != nil || s.finished {
		return ErrUnavailableV1
	}
	inputSHA, err := PlanSHA256V1(s.plan)
	if err != nil {
		return ErrUnavailableV1
	}
	args := measureArgV1{Policy: PolicyV1, InputSHA: inputSHA, FontSHA: FontSHA256V1, FontSize: 11, Padding: 2, CheckboxPath: CheckboxPathV1, Fields: make([]measureFieldArgV1, 0, len(s.plan.Fields))}
	for _, f := range s.plan.Fields {
		if ctx.Err() != nil {
			return ContextErrorV1(ctx)
		}
		r := fieldRectV1(s.plan, f)
		args.Fields = append(args.Fields, measureFieldArgV1{f.ID, f.Type, visibleValueV1(f), f.Type == "checkbox" && f.ValueValid && CheckedV1(f.Value), r.X, r.Y, r.Width, r.Height})
	}
	raw, err := json.Marshal(args)
	if err != nil || len(raw) > MaxRequestBytesV1 {
		return ErrUnavailableV1
	}
	value, err := callOwnedFunctionV1(ctx, MeasurementFunctionV1, raw, MaxReportBytesV1)
	if err != nil {
		return err
	}
	var m MeasurementV1
	if decodeRuntimeV1(ctx, value, MaxReportBytesV1, &m) != nil || len(m.Fields) != len(s.plan.Fields) {
		return ContextErrorV1(ctx)
	}
	root, err := dom.GetDocument().Do(ctx)
	// chromedp already enables CSS while attaching this target, before navigation.
	// Re-enabling it here preloads document resources; file origins can reject
	// that inspection-only self-fetch. Keep the enabled agent and font getters.
	if err != nil || root == nil || dom.Enable().Do(ctx) != nil {
		return ContextErrorV1(ctx)
	}
	for i := range m.Fields {
		for j := range m.Fields[i].Lines {
			if ctx.Err() != nil {
				return ContextErrorV1(ctx)
			}
			line := &m.Fields[i].Lines[j]
			fonts, err := readFontsV1(ctx, root.NodeID, i, j, line.Text)
			if err != nil {
				return err
			}
			line.Fonts = fonts
		}
	}
	if ValidateMeasurementV1(ctx, s.plan, m) != nil || ctx.Err() != nil {
		return ContextErrorV1(ctx)
	}
	s.measurement = &m
	return nil
}
func SnapshotV1(ctx context.Context, s *SealV1) ([]byte, error) {
	if err := s.begin(ctx); err != nil {
		return nil, err
	}
	defer s.busy.Store(false)
	if s.measurement == nil || s.finished || s.afterVerified {
		return nil, ErrUnavailableV1
	}
	args := struct {
		Policy    string               `json:"policy"`
		InputSHA  string               `json:"inputSha"`
		RecipeSHA string               `json:"recipeSha"`
		Fields    []FieldMeasurementV1 `json:"fields"`
	}{PolicyV1, s.measurement.InputSHA256, RecipeSHA256V1(), s.measurement.Fields}
	arg, err := json.Marshal(args)
	if err != nil || len(arg) > MaxReportBytesV1 {
		return nil, ErrUnavailableV1
	}
	value, err := callOwnedFunctionV1(ctx, SnapshotFunctionV1, arg, MaxSnapshotBytesV1)
	if err != nil {
		return nil, err
	}
	var snapshot SnapshotReportV1
	if decodeRuntimeV1(ctx, value, MaxSnapshotBytesV1, &snapshot) != nil || len(snapshot.Fields) != len(s.measurement.Fields) {
		return nil, ContextErrorV1(ctx)
	}
	root, err := dom.GetDocument().Do(ctx)
	if err != nil || root == nil {
		return nil, ContextErrorV1(ctx)
	}
	for i := range snapshot.Fields {
		if len(snapshot.Fields[i].Lines) != len(s.measurement.Fields[i].Lines) {
			return nil, ErrUnavailableV1
		}
		for j := range snapshot.Fields[i].Lines {
			if ctx.Err() != nil {
				return nil, ContextErrorV1(ctx)
			}
			fonts, err := readFontsV1(ctx, root.NodeID, i, j, s.measurement.Fields[i].Lines[j].Text)
			if err != nil {
				return nil, err
			}
			snapshot.Fields[i].Lines[j].Fonts = fonts
		}
	}
	if validateSnapshotV1(s.plan, *s.measurement, snapshot) != nil {
		return nil, ErrUnavailableV1
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil || len(canonical) > MaxSnapshotBytesV1 || ctx.Err() != nil {
		return nil, ContextErrorV1(ctx)
	}
	if s.before == nil {
		s.before = bytes.Clone(canonical)
	} else {
		if !bytes.Equal(canonical, s.before) {
			return nil, ErrUnavailableV1
		}
		s.afterVerified = true
	}
	return canonical, nil
}

// Finish can consume only real measurement+two actual matching CDP snapshots.
// The bridge supplies the sole bounded native PDF stream and observed runtime.
// It must retain the candidate until b.do and supervisor physically join cleanup.
func (s *SealV1) FinishV1(ctx context.Context, pdf, afterSnapshot []byte, version ChromiumVersionV1) (*PackageV1, error) {
	if err := s.begin(ctx); err != nil {
		return nil, err
	}
	defer s.busy.Store(false)
	if s.measurement == nil || s.before == nil || !s.afterVerified || s.finished || !bytes.Equal(afterSnapshot, s.before) ||
		len(pdf) < 1 || len(pdf) > MaxPDFBytesV1 || !bytes.HasPrefix(pdf, []byte("%PDF-")) ||
		!validRuntimeTextV1(version.Product, 256) || !validRuntimeTextV1(version.Revision, 256) || !validRuntimeTextV1(version.Protocol, 32) {
		return nil, ErrUnavailableV1
	}
	if ValidateMeasurementV1(ctx, s.plan, *s.measurement) != nil {
		return nil, ContextErrorV1(ctx)
	}
	inputSHA, _ := PlanSHA256V1(s.plan)
	report := ReportV1{Schema: 1, Policy: PolicyV1, Plan: s.plan, InputSHA256: inputSHA, RecipeSHA256: RecipeSHA256V1(),
		HTMLSHA256: digestV1(s.html), FontSHA256: FontSHA256V1, PDFSHA256: digestV1(pdf), PDFBytes: len(pdf), FragmentPage: 1,
		SnapshotSHA256: digestV1(s.before), Chromium: version, Measurement: *s.measurement}
	raw, err := json.Marshal(report)
	if err != nil || len(raw) > MaxReportBytesV1 || ctx.Err() != nil {
		return nil, ContextErrorV1(ctx)
	}
	candidate := &PackageV1{parts: [5][]byte{raw, pdf, s.html, s.font, s.before}, report: report}
	result, err := DecodeWithContextV1(ctx, candidate.Bytes(), s.plan)
	if err != nil {
		return nil, ContextErrorV1(ctx)
	}
	s.finished = true
	return result, nil
}
func callOwnedFunctionV1(ctx context.Context, function string, arg []byte, maxBytes int) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ContextErrorV1(ctx)
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	frame, err := page.GetFrameTree().Do(call)
	if err != nil || frame == nil || frame.Frame == nil {
		return nil, ContextErrorV1(ctx)
	}
	world, err := page.CreateIsolatedWorld(frame.Frame.ID).WithWorldName(PolicyV1).WithGrantUniveralAccess(false).Do(call)
	if err != nil || world == 0 {
		return nil, ContextErrorV1(ctx)
	}
	value, exception, err := runtime.CallFunctionOn(function).WithExecutionContextID(world).
		WithArguments([]*runtime.CallArgument{{Value: arg}}).WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true).WithUserGesture(false).Do(call)
	if err != nil || exception != nil || value == nil || value.Type != runtime.TypeObject || len(value.Value) < 1 || len(value.Value) > maxBytes || ctx.Err() != nil || call.Err() != nil {
		return nil, ContextErrorV1(ctx)
	}
	return bytes.Clone(value.Value), nil
}
func decodeRuntimeV1(ctx context.Context, raw []byte, max int, dst any) error {
	if ctx == nil || ctx.Err() != nil || len(raw) < 1 || len(raw) > max || !utf8.Valid(raw) {
		return ContextErrorV1(ctx)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	budget := &jsonBudgetV1{}
	if closedTokenV1(ctx, d, 0, "", budget) != nil {
		return ErrUnavailableV1
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrUnavailableV1
	}
	// Chrome's raw HTML strings/numeric spellings need not use Go's canonical
	// JSON encoding. Stored package/snapshot encodings are canonicalized once
	// before original reservation; the runtime reader still closes keys/tokens.
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrUnavailableV1
	}
	return nil
}
func readFontsV1(ctx context.Context, root cdp.NodeID, i, j int, text string) ([]FontUsageV1, error) {
	if strings.TrimSpace(text) == "" {
		return []FontUsageV1{}, nil
	}
	if ctx.Err() != nil {
		return nil, ContextErrorV1(ctx)
	}
	selector := "#ordinary-line-" + itoaV1(i) + "-" + itoaV1(j)
	node, err := dom.QuerySelector(root, selector).Do(ctx)
	if err != nil || node == 0 {
		return nil, ContextErrorV1(ctx)
	}
	fonts, err := css.GetPlatformFontsForNode(node).Do(ctx)
	if err != nil || len(fonts) != 1 || fonts[0] == nil {
		return nil, ContextErrorV1(ctx)
	}
	font := fonts[0]
	result := FontUsageV1{FamilyName: font.FamilyName, PostScriptName: font.PostScriptName, IsCustomFont: font.IsCustomFont, GlyphCount: font.GlyphCount}
	if !validFontUsageV1(result) {
		return nil, ErrUnavailableV1
	}
	return []FontUsageV1{result}, nil
}
func itoaV1(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	at := len(buf)
	for n > 0 {
		at--
		buf[at] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[at:])
}
