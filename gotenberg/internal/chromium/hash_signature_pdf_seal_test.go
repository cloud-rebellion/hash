// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/css"
	cdpio "github.com/chromedp/cdproto/io"
	"github.com/chromedp/cdproto/page"
)

type hashSealReader struct {
	reader          io.Reader
	closeErr        error
	closes, maxRead int
	cancel          context.CancelFunc
}

func (r *hashSealReader) Read(b []byte) (int, error) {
	r.maxRead = max(r.maxRead, len(b))
	n, err := r.reader.Read(b)
	if r.cancel != nil {
		r.cancel()
	}
	return n, err
}
func (r *hashSealReader) Close() error { r.closes++; return r.closeErr }

type hashSealNoProgress struct{}

func (hashSealNoProgress) Read([]byte) (int, error) { return 0, nil }

func TestHashSignaturePDFBoundedStreamRefusesReadCloseAndCancellationFailures(t *testing.T) {
	for _, c := range []struct {
		name     string
		reader   io.Reader
		closeErr error
		cancel   bool
		success  bool
	}{
		{"exact-pdf", strings.NewReader("%PDF-fixture"), nil, false, true},
		{"empty", strings.NewReader(""), nil, false, false},
		{"non-pdf", strings.NewReader("private-name-must-not-leak"), nil, false, false},
		{"close-failure", strings.NewReader("%PDF-fixture"), errors.New("private-close-data"), false, false},
		{"over-limit", io.MultiReader(strings.NewReader("%PDF-"), io.LimitReader(hashZeroReader{}, hashSignaturePDFLimit)), nil, false, false},
		{"no-progress", hashSealNoProgress{}, nil, false, false},
		{"cancel-after-read", strings.NewReader("%PDF-fixture"), nil, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := &hashSealReader{reader: c.reader, closeErr: c.closeErr}
			if c.cancel {
				r.cancel = cancel
			}
			pdf, err, closed := hashReadSignaturePDF(ctx, r)
			if c.success {
				if err != nil || string(pdf) != "%PDF-fixture" || !closed {
					t.Fatal("valid closed stream refused")
				}
			} else if err == nil || pdf != nil {
				t.Fatal("partial output published")
			}
			if r.closes != 1 || r.maxRead > 64<<10 || closed != (c.closeErr == nil) {
				t.Fatal("read/close ownership contract")
			}
			if err != nil && strings.Contains(err.Error(), "private-") {
				t.Fatal("stream error leaked private data")
			}
		})
	}
}

type hashZeroReader struct{}

func (hashZeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type hashSealProtocolFault struct {
	mode                  string
	prints, reads, closes int
	t                     *testing.T
}

func (f *hashSealProtocolFault) Execute(_ context.Context, method string, params, result any) error {
	switch method {
	case page.CommandPrintToPDF:
		f.prints++
		p := params.(*page.PrintToPDFParams)
		if p.Scale != 1 || p.Landscape || p.DisplayHeaderFooter || !p.PrintBackground || !p.PreferCSSPageSize || p.GenerateTaggedPDF || p.GenerateDocumentOutline || p.MarginTop != 0 || p.MarginBottom != 0 || p.MarginLeft != 0 || p.MarginRight != 0 || p.PageRanges != "" || p.TransferMode != page.PrintToPDFTransferModeReturnAsStream || p.PaperWidth != 600.0/72 || p.PaperHeight != 400.0/72 {
			f.t.Fatal("fixed print recipe changed")
		}
		if f.mode == "unknown-print" {
			return errors.New("lost print result")
		}
		if f.mode != "empty-handle" {
			result.(*page.PrintToPDFReturns).Stream = "fixture"
		}
		return nil
	case cdpio.CommandRead:
		f.reads++
		if f.mode == "read-failure" {
			return errors.New("private-read-data")
		}
		r := result.(*cdpio.ReadReturns)
		r.EOF = true
		r.Data = "%PDF-fixture"
		return nil
	case cdpio.CommandClose:
		f.closes++
		if f.mode == "close-failure" {
			return errors.New("private-close-data")
		}
		return nil
	default:
		return errors.New("unexpected private protocol command")
	}
}
func TestHashSignaturePDFProtocolFaultsQuarantineUnknownStreamOwnership(t *testing.T) {
	for _, mode := range []string{"valid", "unknown-print", "empty-handle", "read-failure", "close-failure"} {
		t.Run(mode, func(t *testing.T) {
			f := &hashSealProtocolFault{mode: mode, t: t}
			b := &chromiumBrowser{}
			pdf, err := b.hashPrintSignaturePDF(cdp.WithExecutor(context.Background(), f), 600, 400)
			if mode == "valid" {
				if err != nil || string(pdf) != "%PDF-fixture" {
					t.Fatal("valid protocol")
				}
			} else if err == nil || pdf != nil {
				t.Fatal("fault published PDF")
			}
			unknown := mode == "unknown-print" || mode == "empty-handle" || mode == "close-failure"
			if b.hashCleanupUnconfirmed.Load() != unknown || f.prints != 1 || (mode != "unknown-print" && mode != "empty-handle" && f.closes != 1) {
				t.Fatal("stream ownership not retained")
			}
		})
	}
}

func TestHashSignaturePDFRecipeV1IdentityRequiresExplicitVersionChange(t *testing.T) {
	// This active-generation decoder is not a historical recovery API. Archive
	// consumption must dispatch frozen recipe versions and consume retained PDF
	// bytes without regenerating or depending on current renderer/font assets.
	const approvedV1 = "ed5a53b65dfe42099002721a6453fe2a2b9aef26fd97a8ae0dcc7fd6cad2c6da"
	if hashSignatureRecipeSHA() != approvedV1 {
		t.Fatal("V1 recipe changed; preserve V1 and introduce an explicitly reviewed version")
	}
}

func hashSealTestPackage(t *testing.T) (*hashSignatureMeasurePlan, *hashSignaturePDFPackage) {
	t.Helper()
	p := hashTestMeasurePlan()
	f, _ := hashPinnedMeasureFont(p.Font)
	font, err := os.ReadFile(filepath.Join("..", "..", "..", "internal", "render", "assets", f.file))
	if err != nil {
		t.Fatal(err)
	}
	s, err := newHashSignatureSeal(p, font)
	if err != nil {
		t.Fatal(err)
	}
	m := hashSignatureMeasurement{Policy: hashMeasurePolicy, InputSHA256: p.inputSHA(), FontSHA256: f.sha, DOM: hashTestMeasureDOM(p)}
	m.DOM.Targets[0].Lines[0].Fonts = []*css.PlatformFontUsage{{FamilyName: f.family, PostScriptName: f.postscript, IsCustomFont: true, GlyphCount: 12}}
	pdf := []byte("%PDF-native-integrity-fixture-not-a-parsed-PDF")
	r := hashSignaturePDFReport{Schema: 1, Policy: hashSignatureSealPolicy, Plan: *p, InputSHA256: p.inputSHA(), RecipeSHA256: hashSignatureRecipeSHA(), HTMLSHA256: hashSealSHA(s.html), FontFile: f.file, FontSHA256: f.sha, PDFSHA256: hashSealSHA(pdf), PDFBytes: len(pdf), FragmentPage: 1, SnapshotSHA256: hashSealSHA([]byte("{}")), ChromiumProduct: "Chrome/native-fixture", ChromiumRevision: "native-fixture", ChromiumProtocol: "1.3", Measurement: m}
	report, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return p, &hashSignaturePDFPackage{report, pdf, s.html, s.font, []byte("{}")}
}

func TestHashSignaturePDFPackageFreezesInputsAndReturnedBuffers(t *testing.T) {
	p, pack := hashSealTestPackage(t)
	raw := pack.Bytes()
	decoded, err := decodeHashSignaturePDFPackage(raw, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{decoded.Bytes(), decoded.PDF(), decoded.Report()} {
		b[len(b)-1] ^= 1
	}
	if !bytes.Equal(decoded.Bytes(), raw) {
		t.Fatal("accessor exposes mutable package")
	}
	raw[len(raw)-1] ^= 1
	if _, err = decodeHashSignaturePDFPackage(raw, p); err == nil {
		t.Fatal("tampered retained snapshot admitted")
	}
	f, _ := hashPinnedMeasureFont(p.Font)
	font, err := os.ReadFile(filepath.Join("..", "..", "..", "internal", "render", "assets", f.file))
	if err != nil {
		t.Fatal(err)
	}
	s, err := newHashSignatureSeal(p, font)
	if err != nil {
		t.Fatal(err)
	}
	before := s.inputSHA
	p.Text = "Changed"
	p.Targets[0].W = ".1"
	font[0] ^= 1
	if s.plan.inputSHA() != before || s.plan.Text == p.Text || hashSealSHA(s.font) != f.sha {
		t.Fatal("caller mutation changes prepared inputs")
	}
}

func TestHashSignaturePDFPackageRejectsStaleSwappedIncompleteAndAmbiguousBindings(t *testing.T) {
	p, pack := hashSealTestPackage(t)
	for _, c := range []struct {
		name   string
		change func(*hashSignaturePDFPackage)
	}{
		{"pdf-byte", func(p *hashSignaturePDFPackage) { p.pdf[6] ^= 1 }},
		{"html-byte", func(p *hashSignaturePDFPackage) { p.html[0] ^= 1 }},
		{"font-byte", func(p *hashSignaturePDFPackage) { p.font[0] ^= 1 }},
		{"snapshot-byte", func(p *hashSignaturePDFPackage) { p.snapshot[0] ^= 1 }},
		{"duplicate-schema", func(p *hashSignaturePDFPackage) {
			p.report = bytes.Replace(p.report, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
		}},
		{"unknown-key", func(p *hashSignaturePDFPackage) { p.report = append([]byte(`{"unexpected":true,`), p.report[1:]...) }},
		{"missing-schema", func(p *hashSignaturePDFPackage) { p.report = bytes.Replace(p.report, []byte(`"schema":1,`), nil, 1) }},
		{"wrong-case", func(p *hashSignaturePDFPackage) {
			p.report = bytes.Replace(p.report, []byte(`"schema"`), []byte(`"Schema"`), 1)
		}},
		{"null-schema", func(p *hashSignaturePDFPackage) {
			p.report = bytes.Replace(p.report, []byte(`"schema":1`), []byte(`"schema":null`), 1)
		}},
		{"trailing-json", func(p *hashSignaturePDFPackage) { p.report = append(p.report, []byte(" {}")...) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			copy := &hashSignaturePDFPackage{bytes.Clone(pack.report), bytes.Clone(pack.pdf), bytes.Clone(pack.html), bytes.Clone(pack.font), bytes.Clone(pack.snapshot)}
			c.change(copy)
			if _, err := decodeHashSignaturePDFPackage(copy.Bytes(), p); err == nil {
				t.Fatal("invalid package admitted")
			}
		})
	}
	for _, c := range []struct {
		name   string
		change func(*hashSignaturePDFReport)
	}{
		{"source", func(r *hashSignaturePDFReport) { r.Plan.SourceSHA256 = strings.Repeat("5", 64) }},
		{"span", func(r *hashSignaturePDFReport) { r.Plan.SpanSHA256 = strings.Repeat("5", 64) }},
		{"exact-decimal", func(r *hashSignaturePDFReport) { r.Plan.Targets[0].X = "0.050" }},
		{"recipe", func(r *hashSignaturePDFReport) { r.RecipeSHA256 = strings.Repeat("5", 64) }},
		{"font", func(r *hashSignaturePDFReport) { r.FontFile = "Other.woff2" }},
		{"missing-target", func(r *hashSignaturePDFReport) { r.Measurement.DOM.Targets = nil }},
		{"unattributed-font", func(r *hashSignaturePDFReport) { r.Measurement.DOM.Targets[0].Lines[0].Fonts = nil }},
		{"fractional-glyph-count", func(r *hashSignaturePDFReport) { r.Measurement.DOM.Targets[0].Lines[0].Fonts[0].GlyphCount = 1.5 }},
		{"wrong-observed-font", func(r *hashSignaturePDFReport) { r.Measurement.DOM.Targets[0].Lines[0].Fonts[0].FamilyName = "Other" }},
		{"missing-name-part", func(r *hashSignaturePDFReport) { r.Measurement.DOM.Targets[0].Lines[0].Text = "Anna" }},
		{"wrong-fragment-page", func(r *hashSignaturePDFReport) { r.FragmentPage = 2 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			var r hashSignaturePDFReport
			if json.Unmarshal(pack.report, &r) != nil {
				t.Fatal("fixture")
			}
			c.change(&r)
			report, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			copy := &hashSignaturePDFPackage{report, pack.pdf, pack.html, pack.font, pack.snapshot}
			if _, err = decodeHashSignaturePDFPackage(copy.Bytes(), p); err == nil {
				t.Fatal("stale/incomplete binding admitted")
			}
		})
	}
	for _, mode := range []string{"length-overrun", "length-cap", "report-digest", "trailing", "short", "wrong-request"} {
		t.Run(mode, func(t *testing.T) {
			raw := pack.Bytes()
			expected := hashTestMeasurePlan()
			switch mode {
			case "length-overrun":
				binary.BigEndian.PutUint32(raw[12:], uint32(len(raw)))
			case "length-cap":
				binary.BigEndian.PutUint32(raw[12:], hashSignaturePDFLimit+1)
			case "report-digest":
				raw[28] ^= 1
			case "trailing":
				raw = append(raw, 0)
			case "short":
				raw = raw[:59]
			case "wrong-request":
				expected.Text = "Another signer"
			}
			if _, err := decodeHashSignaturePDFPackage(raw, expected); err == nil {
				t.Fatal("framing/request mismatch admitted")
			}
		})
	}
	// Outer framing and SHA are integrity bindings, not cryptographic authority.
	// Updating the outer digest cannot bless a report with an undeclared target.
	raw := pack.Bytes()
	raw[hashSignaturePackageHeader+1] ^= 1
	h := sha256.Sum256(raw[hashSignaturePackageHeader : hashSignaturePackageHeader+len(pack.report)])
	copy(raw[28:60], h[:])
	if _, err := decodeHashSignaturePDFPackage(raw, p); err == nil {
		t.Fatal("rehashed corrupt report admitted")
	}
}
