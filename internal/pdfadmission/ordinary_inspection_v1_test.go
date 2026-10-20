// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ordinarypage"
	"github.com/bright-interaction/hash/internal/sanitize"
)

// These private worker oracles qualify dispatch, exact binding, refusal and
// consumer/physical-join accounting only. Their PDFs/semantic metadata are
// synthetic and do NOT qualify production worker or genuine producer acceptance.
// Synthetic permission only; shared physical capacity is qualified separately.
func ordinaryInspectionTestWorkerAdmissionV1(context.Context, OrdinaryInspectionWorkerBudgetV1) (func(), error) {
	return func() {}, nil
}

type ordinaryInspectionTestAdmissionV1 struct {
	mu               sync.Mutex
	active, releases int
	budgets          []OrdinaryInspectionBudgetV1
}

func (a *ordinaryInspectionTestAdmissionV1) admit(_ context.Context, b OrdinaryInspectionBudgetV1) (func(), error) {
	a.mu.Lock()
	a.active++
	a.budgets = append(a.budgets, b)
	a.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { a.mu.Lock(); a.active--; a.releases++; a.mu.Unlock() }) }, nil
}
func (a *ordinaryInspectionTestAdmissionV1) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.active
}
func ordinaryInspectionTestBasisV1(t *testing.T) (*BasisV1, []byte) {
	t.Helper()
	in := basisInputV1(t, true)
	ownOrdinaryRecipeV1(&in)
	in.Fields[1].Value = "Owned ordinary bytes"
	source := []byte("%PDF-synthetic-source-shape-only-not-a-genuine-document")
	in.Source.SHA256 = plainSHA256V1(source)
	in.Source.Bytes = int64(len(source))
	in.Geometry.SourceSHA256 = in.Source.SHA256
	in.Geometry.SourceBytes = in.Source.Bytes
	b, err := BuildV1(in)
	if err != nil {
		t.Fatal(err)
	}
	return b, source
}
func ordinaryInspectionTestFragmentV1(pdf []byte, w, h float64) sanitize.PDFManualFragmentAdmission {
	p := sanitize.PDFManualPage{UserUnit: 1}
	for j := range p.Boxes {
		p.Boxes[j] = [4]float64{0, 0, w, h}
	}
	raw, _ := json.Marshal([]sanitize.PDFManualPage{p})
	pin := plainSHA256V1([]byte("synthetic content/resource/group oracle"))
	return sanitize.PDFManualFragmentAdmission{SchemaVersion: 1, Policy: sanitize.PDFManualFragmentPolicy, PDFSHA256: plainSHA256V1(pdf), PDFBytes: int64(len(pdf)),
		WidthPoints: w, HeightPoints: h, ObservedWidthPoints: w, ObservedHeightPoints: h, GeometrySHA256: plainSHA256V1(raw), ContentSHA256: pin, ResourcesSHA256: pin, GroupSHA256: pin}
}
func ordinaryInspectionTestInspectorV1(t *testing.T, b *BasisV1, a *ordinaryInspectionTestAdmissionV1) (*OrdinaryInspectorV1, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	i, err := NewOrdinaryInspectorV1(a.admit, ordinaryInspectionTestWorkerAdmissionV1)
	if err != nil {
		t.Fatal(err)
	}
	sourceCalls, fragmentCalls := &atomic.Int64{}, &atomic.Int64{}
	i.worker = ordinaryInspectionWorkerV1{source: func(_ context.Context, _ []byte) (sanitize.PDFManualGeometry, error) {
		sourceCalls.Add(1)
		return b.Geometry(), nil
	},
		fragment: func(_ context.Context, pdf []byte, w, h float64) (sanitize.PDFManualFragmentAdmission, error) {
			fragmentCalls.Add(1)
			return ordinaryInspectionTestFragmentV1(pdf, w, h), nil
		}}
	return i, sourceCalls, fragmentCalls
}
func ordinaryInspectionTestFrameV1(t *testing.T, parts [5][]byte) []byte {
	t.Helper()
	raw := make([]byte, ordinarypage.PackageHeaderBytesV1)
	copy(raw, "HSHORD01")
	for j, part := range parts {
		if len(part) < 1 {
			t.Fatal("empty integrity fixture section")
		}
		binary.BigEndian.PutUint32(raw[8+j*4:], uint32(len(part)))
	}
	h := sha256.Sum256(parts[0])
	copy(raw[28:], h[:])
	for _, part := range parts {
		raw = append(raw, part...)
	}
	return raw
}
func ordinaryInspectionTestEnvelopeV1(t *testing.T, b *BasisV1, page int, pdf []byte) []byte {
	t.Helper()
	plans, err := OrdinaryPlansV1(b)
	if err != nil {
		t.Fatal(err)
	}
	var p ordinarypage.PlanV1
	for _, candidate := range plans {
		if candidate.Page == page {
			p = candidate
		}
	}
	if p.Schema != 1 {
		t.Fatal("ordinary fixture page absent")
	}
	font, err := os.ReadFile("../render/assets/Inter.woff2")
	if err != nil || len(font) != ordinarypage.FontBytesV1 || plainSHA256V1(font) != ordinarypage.FontSHA256V1 {
		t.Fatal("exact owned Inter fixture required")
	}
	html, err := ordinarypage.GeneratedHTMLV1(p, font)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := ordinarypage.PlanSHA256V1(p)
	m := ordinarypage.MeasurementV1{Schema: 1, Policy: ordinarypage.PolicyV1, InputSHA256: input, FontSHA256: ordinarypage.FontSHA256V1, TextPreserved: true, Unobscured: true, PrintMedia: true, DocumentScriptsBlocked: true, Fields: []ordinarypage.FieldMeasurementV1{}}
	snapshot := ordinarypage.SnapshotReportV1{Schema: 1, InputSHA256: input, RecipeSHA256: ordinarypage.RecipeSHA256V1(), DOMSHA256: plainSHA256V1([]byte("synthetic DOM")), ComputedStylesSHA256: plainSHA256V1([]byte("synthetic style")), Fields: []ordinarypage.SnapshotFieldV1{}}
	var body strings.Builder
	width, _ := strconv.ParseFloat(p.WidthPoints, 64)
	height, _ := strconv.ParseFloat(p.HeightPoints, 64)
	for _, f := range p.Fields {
		x, _ := strconv.ParseFloat(f.XPct, 64)
		y, _ := strconv.ParseFloat(f.YPct, 64)
		w, _ := strconv.ParseFloat(f.WPct, 64)
		h, _ := strconv.ParseFloat(f.HPct, 64)
		rect := ordinarypage.BBoxV1{X: x * width * 4 / 300, Y: y * height * 4 / 300, Width: w * width * 4 / 300, Height: h * height * 4 / 300}
		measured := ordinarypage.FieldMeasurementV1{ID: f.ID, Type: f.Type, FontSizePX: 11, ViewportBBox: rect, Lines: []ordinarypage.LineV1{}}
		if f.ValueValid && strings.TrimSpace(f.Value) != "" {
			measured.Lines = []ordinarypage.LineV1{{Text: f.Value, X: 2, Y: 14, Advance: 8, InkRight: 8, InkAscent: 9, InkDescent: 3, FontAscent: 9, FontDescent: 3,
				BBox: ordinarypage.BBoxV1{X: 2, Y: 5, Width: 8, Height: 12}, Fonts: []ordinarypage.FontUsageV1{{FamilyName: "Inter", PostScriptName: "synthetic-oracle-only", IsCustomFont: true, GlyphCount: 1}}}}
			body.WriteString(f.Value)
		} else {
			measured.NoInk = true
		}
		m.Fields = append(m.Fields, measured)
		sf := ordinarypage.SnapshotFieldV1{ID: f.ID, ViewportBBox: rect, Lines: []ordinarypage.SnapshotLineV1{}}
		for _, line := range measured.Lines {
			sf.Lines = append(sf.Lines, ordinarypage.SnapshotLineV1{BBox: line.BBox, Fonts: line.Fonts})
		}
		snapshot.Fields = append(snapshot.Fields, sf)
	}
	snapshot.BodyTextSHA256 = plainSHA256V1([]byte(body.String()))
	snap, _ := json.Marshal(snapshot)
	report := ordinarypage.ReportV1{Schema: 1, Policy: ordinarypage.PolicyV1, Plan: p, InputSHA256: input, RecipeSHA256: ordinarypage.RecipeSHA256V1(), HTMLSHA256: plainSHA256V1(html), FontSHA256: ordinarypage.FontSHA256V1,
		PDFSHA256: plainSHA256V1(pdf), PDFBytes: len(pdf), FragmentPage: 1, SnapshotSHA256: plainSHA256V1(snap), Chromium: ordinarypage.ChromiumVersionV1{Product: "synthetic-integrity-only", Revision: "synthetic", Protocol: "synthetic"}, Measurement: m}
	reportRaw, _ := json.Marshal(report)
	raw := ordinaryInspectionTestFrameV1(t, [5][]byte{reportRaw, pdf, html, font, snap})
	if _, err := ordinarypage.DecodeV1(raw, p); err != nil {
		t.Fatal("synthetic integrity-only package shape", err)
	}
	return raw
}
func ordinaryInspectionTestContextV1(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestOrdinaryInspectionConstructorAndZeroReceiptsV1(t *testing.T) {
	if i, err := NewOrdinaryInspectorV1(nil, ordinaryInspectionTestWorkerAdmissionV1); i != nil || !errors.Is(err, ErrOrdinaryInspectionV1) {
		t.Fatal("missing shared admission admitted")
	}
	i, err := NewOrdinaryInspectorV1(func(context.Context, OrdinaryInspectionBudgetV1) (func(), error) { return func() {}, nil }, ordinaryInspectionTestWorkerAdmissionV1)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.ValueOf(i.worker.source).Pointer() != reflect.ValueOf(sanitize.InspectManualPDFWithContext).Pointer() || reflect.ValueOf(i.worker.fragment).Pointer() != reflect.ValueOf(sanitize.InspectManualPDFFragmentWithContext).Pointer() {
		t.Fatal("public constructor does not fix production worker")
	}
	b, source := ordinaryInspectionTestBasisV1(t)
	ctx := ordinaryInspectionTestContextV1(t)
	if r, err := (&OrdinaryInspectorV1{}).InspectSourceV1(ctx, b, source); r != nil || err == nil {
		t.Fatal("zero inspector minted authority")
	}
	zeroSource := &OrdinarySourceInspectionV1{}
	if zeroSource.MatchesBasisV1(b) {
		t.Fatal("zero source became authority")
	}
	zeroSource.Close()
	if _, err := zeroSource.GeometryV1(); err == nil {
		t.Fatal("zero geometry accepted")
	}
	if r, err := i.InspectPageV1(ctx, zeroSource, 2, make([]byte, ordinarypage.PackageHeaderBytesV1)); r != nil || err == nil {
		t.Fatal("zero source minted page receipt")
	}
	zeroPage := &OrdinaryPageInspectionV1{}
	zeroPage.Close()
	if zeroPage.MatchesOriginalV1(b, 2, nil) {
		t.Fatal("zero page became authority")
	}
	if _, err := zeroPage.MetadataV1(); err == nil {
		t.Fatal("zero metadata accepted")
	}
}
func TestOrdinaryInspectionOwnedBodiesScopeAndConsumerCloseV1(t *testing.T) {
	b, source := ordinaryInspectionTestBasisV1(t)
	ctx := ordinaryInspectionTestContextV1(t)
	a := &ordinaryInspectionTestAdmissionV1{}
	i, sourceCalls, fragmentCalls := ordinaryInspectionTestInspectorV1(t, b, a)
	sourceReceipt, err := i.InspectSourceV1(ctx, b, source)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceReceipt.Close()
	if !sourceReceipt.MatchesBasisV1(b) || a.count() != 1 || sourceCalls.Load() != 1 {
		t.Fatal("source exact binding/admission missing")
	}
	source[0] ^= 1
	if sourceReceipt.state.source[0] == source[0] {
		t.Fatal("source body borrowed mutable caller bytes")
	}
	g, err := sourceReceipt.GeometryV1()
	if err != nil {
		t.Fatal(err)
	}
	g.Pages[0].Boxes[0][0] = -999
	original := ordinaryInspectionTestEnvelopeV1(t, b, 2, []byte("%PDF-synthetic-fragment-shape-only"))
	saved := bytes.Clone(original)
	page, err := i.InspectPageV1(ctx, sourceReceipt, 2, original)
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()
	if a.count() != 2 || fragmentCalls.Load() != 1 || !page.MatchesOriginalV1(b, 2, saved) {
		t.Fatal("page body/resource binding missing")
	}
	original[len(original)-1] ^= 1
	if page.MatchesOriginalV1(b, 2, original) {
		t.Fatal("altered original accepted")
	}
	metadata, err := page.MetadataV1()
	if err != nil || metadata.StaticBasisSHA256 != b.SHA256() || metadata.StaticCanonicalSHA256 != b.CanonicalSHA256() || metadata.Source != b.Source() || metadata.PackageSHA256 != plainSHA256V1(saved) || metadata.PackageBytes != int64(len(saved)) || metadata.Page != 2 {
		t.Fatal("receipt archived wrong identity")
	}
	plan, err := page.PlanV1()
	if err != nil {
		t.Fatal(err)
	}
	plan.Fields[0].Value = "changed"
	again, _ := page.PlanV1()
	if again.Fields[0].Value == "changed" {
		t.Fatal("receipt lent fields")
	}
	foreign := b.Input()
	foreign.DocumentID[0] ^= 1
	for j := range foreign.Fields {
		foreign.Fields[j].DocumentID = foreign.DocumentID
	}
	for j := range foreign.Parties {
		foreign.Parties[j].DocumentID = foreign.DocumentID
	}
	other, err := BuildV1(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if page.MatchesOriginalV1(other, 2, saved) || sourceReceipt.MatchesBasisV1(other) {
		t.Fatal("foreign document receipt admitted")
	}
	sourceReceipt.Close()
	if a.count() != 2 || sourceReceipt.MatchesBasisV1(b) {
		t.Fatal("source Close released live page loan or allowed new consumer")
	}
	if _, err := sourceReceipt.GeometryV1(); err == nil {
		t.Fatal("closed source lends geometry")
	}
	if _, err := page.MetadataV1(); err != nil {
		t.Fatal("source Close invalidated already admitted page consumer")
	}
	page.Close()
	page.Close()
	sourceReceipt.Close()
	if a.count() != 0 || a.releases != 2 || sourceReceipt.state.source != nil || sourceReceipt.state.basis != nil || page.state.original != nil || page.state.pdf != nil {
		t.Fatal("consumer body/quota release incomplete")
	}
	if page.MatchesOriginalV1(b, 2, saved) {
		t.Fatal("closed receipt still authoritative")
	}
}
func TestOrdinaryInspectionSourceFullGeometryRefusalsV1(t *testing.T) {
	for _, mode := range []string{"wrong-pin", "wrong-source-sha", "wrong-size", "wrong-page-count", "changed-one-box", "changed-rotation", "changed-user-unit", "wrong-schema"} {
		t.Run(mode, func(t *testing.T) {
			b, source := ordinaryInspectionTestBasisV1(t)
			ctx := ordinaryInspectionTestContextV1(t)
			a := &ordinaryInspectionTestAdmissionV1{}
			i, calls, _ := ordinaryInspectionTestInspectorV1(t, b, a)
			g := b.Geometry()
			switch mode {
			case "wrong-pin":
				source[0] ^= 1
			case "wrong-source-sha":
				g.SourceSHA256 = strings.Repeat("b", 64)
			case "wrong-size":
				g.SourceBytes++
			case "wrong-page-count":
				g.Pages = g.Pages[:1]
			case "changed-one-box":
				g.Pages[1].Boxes[4][2] -= 1
			case "changed-rotation":
				g.Pages[1].Rotation = 90
			case "changed-user-unit":
				g.Pages[1].UserUnit = 2
			case "wrong-schema":
				g.SchemaVersion = 2
			}
			raw, _ := json.Marshal(g.Pages)
			g.GeometrySHA256 = plainSHA256V1(raw)
			i.worker.source = func(context.Context, []byte) (sanitize.PDFManualGeometry, error) { calls.Add(1); return g, nil }
			r, err := i.InspectSourceV1(ctx, b, source)
			if err == nil || r != nil || a.count() != 0 {
				t.Fatal("source mismatch admitted or quota leaked")
			}
			if mode == "wrong-pin" && calls.Load() != 0 {
				t.Fatal("wrong original reached worker")
			}
		})
	}
}
func TestOrdinaryInspectionPageRefusalsAndQuantizationV1(t *testing.T) {
	for _, mode := range []string{"wrong-page", "corrupt-package", "foreign-issuer", "wrong-pdf-sha", "wrong-pdf-size", "wrong-expected-width", "outside-quantization", "wrong-fragment-geometry", "wrong-policy", "invalid-content-digest"} {
		t.Run(mode, func(t *testing.T) {
			b, source := ordinaryInspectionTestBasisV1(t)
			ctx := ordinaryInspectionTestContextV1(t)
			a := &ordinaryInspectionTestAdmissionV1{}
			i, _, calls := ordinaryInspectionTestInspectorV1(t, b, a)
			sr, err := i.InspectSourceV1(ctx, b, source)
			if err != nil {
				t.Fatal(err)
			}
			defer sr.Close()
			original := ordinaryInspectionTestEnvelopeV1(t, b, 2, []byte("%PDF-synthetic-fragment"))
			targetPage := 2
			switch mode {
			case "wrong-page":
				targetPage = 1
			case "corrupt-package":
				original[len(original)-1] ^= 1
			case "foreign-issuer":
				other, _, _ := ordinaryInspectionTestInspectorV1(t, b, a)
				i = other
			}
			i.worker.fragment = func(_ context.Context, pdf []byte, w, h float64) (sanitize.PDFManualFragmentAdmission, error) {
				calls.Add(1)
				v := ordinaryInspectionTestFragmentV1(pdf, w, h)
				switch mode {
				case "wrong-pdf-sha":
					v.PDFSHA256 = strings.Repeat("b", 64)
				case "wrong-pdf-size":
					v.PDFBytes++
				case "wrong-expected-width":
					v.WidthPoints += .1
				case "outside-quantization":
					v.ObservedWidthPoints += .751
				case "wrong-fragment-geometry":
					v.GeometrySHA256 = strings.Repeat("c", 64)
				case "wrong-policy":
					v.Policy = "future"
				case "invalid-content-digest":
					v.ContentSHA256 = "not-a-digest"
				}
				return v, nil
			}
			r, err := i.InspectPageV1(ctx, sr, targetPage, original)
			if err == nil || r != nil || a.count() != 1 {
				t.Fatal("page mismatch admitted or live source quota altered")
			}
			if (mode == "wrong-page" || mode == "corrupt-package" || mode == "foreign-issuer") && calls.Load() != 0 {
				t.Fatal("invalid authority/package reached semantic worker")
			}
		})
	}
	pdf := []byte("%PDF-shape")
	v := ordinaryInspectionTestFragmentV1(pdf, 600, 800)
	v.ObservedWidthPoints += .75
	p := sanitize.PDFManualPage{UserUnit: 1}
	for j := range p.Boxes {
		p.Boxes[j] = [4]float64{0, 0, v.ObservedWidthPoints, v.ObservedHeightPoints}
	}
	raw, _ := json.Marshal([]sanitize.PDFManualPage{p})
	v.GeometrySHA256 = plainSHA256V1(raw)
	if ordinaryInspectionFragmentV1(v, pdf, 600, 800) != nil {
		t.Fatal("existing exact quantization boundary refused")
	}
}
func TestOrdinaryInspectionAdmissionAndContextBeforeWorkerV1(t *testing.T) {
	b, source := ordinaryInspectionTestBasisV1(t)
	for _, mode := range []string{"nil-context", "no-deadline", "cancelled", "admission-refusal", "nil-release", "late-release-error"} {
		t.Run(mode, func(t *testing.T) {
			a := &ordinaryInspectionTestAdmissionV1{}
			i, calls, _ := ordinaryInspectionTestInspectorV1(t, b, a)
			ctx := ordinaryInspectionTestContextV1(t)
			switch mode {
			case "nil-context":
				ctx = nil
			case "no-deadline":
				ctx = context.Background()
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "admission-refusal":
				i.admission = func(context.Context, OrdinaryInspectionBudgetV1) (func(), error) {
					return nil, errors.New("private capacity details")
				}
			case "nil-release":
				i.admission = func(context.Context, OrdinaryInspectionBudgetV1) (func(), error) { return nil, nil }
			case "late-release-error":
				i.admission = func(c context.Context, b OrdinaryInspectionBudgetV1) (func(), error) {
					release, _ := a.admit(c, b)
					return release, errors.New("private admission error")
				}
			}
			r, err := i.InspectSourceV1(ctx, b, source)
			if r != nil || err == nil || calls.Load() != 0 || a.count() != 0 || strings.Contains(err.Error(), "private") {
				t.Fatal("pre-I/O refusal/late-release sanitization failed")
			}
		})
	}
}
func TestOrdinaryInspectionCancellationHoldsPhysicalWorkerAndConsumerV1(t *testing.T) {
	b, source := ordinaryInspectionTestBasisV1(t)
	a := &ordinaryInspectionTestAdmissionV1{}
	i, _, _ := ordinaryInspectionTestInspectorV1(t, b, a)
	var sourceAlias, pdfAlias []byte
	var orderFault atomic.Bool
	i.admission = func(ctx context.Context, budget OrdinaryInspectionBudgetV1) (func(), error) {
		release, err := a.admit(ctx, budget)
		return func() {
			if budget.Phase == "source" && !ordinaryInspectionTestPrivateZeroV1(sourceAlias) {
				orderFault.Store(true)
			}
			if budget.Phase == "fragment" && !ordinaryInspectionTestPrivateZeroV1(pdfAlias) {
				orderFault.Store(true)
			}
			release()
		}, err
	}
	parent := ordinaryInspectionTestContextV1(t)
	sr, err := i.InspectSourceV1(parent, b, source)
	if err != nil {
		t.Fatal(err)
	}
	sourceAlias = sr.state.source
	sourceSaved := bytes.Clone(sourceAlias)
	ctx, cancel := context.WithCancelCause(parent)
	cause := errors.New("private caller cancellation marker")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	result := make(chan struct {
		r   *OrdinaryPageInspectionV1
		err error
	}, 1)
	i.worker.fragment = func(_ context.Context, pdf []byte, w, h float64) (sanitize.PDFManualFragmentAdmission, error) {
		pdfAlias = pdf
		close(entered)
		select {
		case <-release:
		case <-time.After(2 * time.Second):
			return sanitize.PDFManualFragmentAdmission{}, errors.New("owned physical gate expired")
		}
		return ordinaryInspectionTestFragmentV1(pdf, w, h), nil
	}
	original := ordinaryInspectionTestEnvelopeV1(t, b, 2, []byte("%PDF-synthetic-gated-worker"))
	t.Cleanup(func() {
		cancel(cause)
		unblock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("owned inspection caller failed to join")
		}
		sr.Close()
	})
	go func() {
		defer close(done)
		r, err := i.InspectPageV1(ctx, sr, 2, original)
		result <- struct {
			r   *OrdinaryPageInspectionV1
			err error
		}{r, err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("physical worker gate not reached")
	}
	cancel(cause)
	sr.Close()
	if a.count() != 2 || !bytes.Equal(sourceAlias, sourceSaved) || !bytes.Equal(pdfAlias, []byte("%PDF-synthetic-gated-worker")) {
		t.Fatal("cancel/Close erased or released in-flight source or fragment resources")
	}
	select {
	case <-done:
		t.Fatal("inspection returned before physical worker joined")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("inspection failed to join")
	}
	got := <-result
	if got.r != nil || !errors.Is(got.err, context.Canceled) || !errors.Is(got.err, cause) || strings.Contains(got.err.Error(), cause.Error()) || a.count() != 0 || orderFault.Load() || !ordinaryInspectionTestPrivateZeroV1(sourceAlias) || !ordinaryInspectionTestPrivateZeroV1(pdfAlias) {
		t.Fatal("cancelled physical cleanup/body/cause accounting failed")
	}
}

// Saved aliases belong only to private test oracles/receipt state. They never
// expose production bodies. These checks cover explicit []byte buffers only;
// no erasure of immutable Go strings or general GC/RSS bound is claimed.
func ordinaryInspectionTestPrivateZeroV1(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}
func TestOrdinaryInspectionClearPrivateConsumerBuffersBeforeReleaseV1(t *testing.T) {
	b, source := ordinaryInspectionTestBasisV1(t)
	sourceSaved := bytes.Clone(source)
	ctx := ordinaryInspectionTestContextV1(t)
	a := &ordinaryInspectionTestAdmissionV1{}
	i, _, _ := ordinaryInspectionTestInspectorV1(t, b, a)
	var sourceAlias, originalAlias, pdfAlias []byte
	var orderFault atomic.Bool
	i.admission = func(ctx context.Context, budget OrdinaryInspectionBudgetV1) (func(), error) {
		release, err := a.admit(ctx, budget)
		return func() {
			if budget.Phase == "source" && !ordinaryInspectionTestPrivateZeroV1(sourceAlias) {
				orderFault.Store(true)
			}
			if budget.Phase == "fragment" && (!ordinaryInspectionTestPrivateZeroV1(originalAlias) || !ordinaryInspectionTestPrivateZeroV1(pdfAlias)) {
				orderFault.Store(true)
			}
			release()
		}, err
	}
	sr, err := i.InspectSourceV1(ctx, b, source)
	if err != nil {
		t.Fatal(err)
	}
	defer sr.Close()
	sourceAlias = sr.state.source
	pdf := []byte("%PDF-synthetic-private-buffer-lifecycle")
	original := ordinaryInspectionTestEnvelopeV1(t, b, 2, pdf)
	originalSaved := bytes.Clone(original)
	page, err := i.InspectPageV1(ctx, sr, 2, original)
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()
	originalAlias, pdfAlias = page.state.original, page.state.pdf
	sr.Close()
	if a.count() != 2 || !bytes.Equal(sourceAlias, sourceSaved) || !bytes.Equal(originalAlias, originalSaved) || !bytes.Equal(pdfAlias, pdf) {
		t.Fatal("source Close erased or released a live admitted page body loan")
	}
	page.Close()
	if a.count() != 0 || orderFault.Load() || !ordinaryInspectionTestPrivateZeroV1(sourceAlias) || !ordinaryInspectionTestPrivateZeroV1(originalAlias) || !ordinaryInspectionTestPrivateZeroV1(pdfAlias) {
		t.Fatal("private consumer buffers were not erased before their permits released")
	}
	if !bytes.Equal(source, sourceSaved) || !bytes.Equal(original, originalSaved) || !bytes.Equal(pdf, []byte("%PDF-synthetic-private-buffer-lifecycle")) {
		t.Fatal("consumer Close erased caller-owned bytes")
	}
	sr.Close()
	page.Close()
	if a.releases != 2 {
		t.Fatal("consumer Close released a permit more than once")
	}
}
func TestOrdinaryInspectionClearsFailedDispatchPrivateBuffersV1(t *testing.T) {
	for _, phase := range []string{"source", "fragment"} {
		t.Run(phase, func(t *testing.T) {
			b, source := ordinaryInspectionTestBasisV1(t)
			sourceSaved := bytes.Clone(source)
			ctx := ordinaryInspectionTestContextV1(t)
			a := &ordinaryInspectionTestAdmissionV1{}
			i, _, _ := ordinaryInspectionTestInspectorV1(t, b, a)
			var sourceAlias, pdfAlias []byte
			var orderFault atomic.Bool
			i.admission = func(ctx context.Context, budget OrdinaryInspectionBudgetV1) (func(), error) {
				release, err := a.admit(ctx, budget)
				return func() {
					if budget.Phase == "source" && !ordinaryInspectionTestPrivateZeroV1(sourceAlias) {
						orderFault.Store(true)
					}
					if budget.Phase == "fragment" && !ordinaryInspectionTestPrivateZeroV1(pdfAlias) {
						orderFault.Store(true)
					}
					release()
				}, err
			}
			i.worker.source = func(_ context.Context, owned []byte) (sanitize.PDFManualGeometry, error) {
				sourceAlias = owned
				if phase == "source" {
					return sanitize.PDFManualGeometry{}, errors.New("private source worker refusal")
				}
				return b.Geometry(), nil
			}
			sr, err := i.InspectSourceV1(ctx, b, source)
			if phase == "source" {
				if sr != nil || err == nil || a.count() != 0 || orderFault.Load() || !ordinaryInspectionTestPrivateZeroV1(sourceAlias) || !bytes.Equal(source, sourceSaved) {
					t.Fatal("failed source dispatch did not erase private bytes before release, or erased caller")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer sr.Close()
			original := ordinaryInspectionTestEnvelopeV1(t, b, 2, []byte("%PDF-synthetic-private-worker-refusal"))
			originalSaved := bytes.Clone(original)
			i.worker.fragment = func(_ context.Context, pdf []byte, _, _ float64) (sanitize.PDFManualFragmentAdmission, error) {
				pdfAlias = pdf
				return sanitize.PDFManualFragmentAdmission{}, errors.New("private fragment worker refusal")
			}
			page, err := i.InspectPageV1(ctx, sr, 2, original)
			if page != nil || err == nil || a.count() != 1 || orderFault.Load() || !ordinaryInspectionTestPrivateZeroV1(pdfAlias) || !bytes.Equal(sourceAlias, sourceSaved) {
				t.Fatal("failed page dispatch did not clear private PDF before release or damaged retained source")
			}
			if !bytes.Equal(source, sourceSaved) || !bytes.Equal(original, originalSaved) {
				t.Fatal("failed dispatch erased caller source/package")
			}
			sr.Close()
			if a.count() != 0 || orderFault.Load() || !ordinaryInspectionTestPrivateZeroV1(sourceAlias) {
				t.Fatal("failed-page source consumer did not clear before final release")
			}
		})
	}
}
