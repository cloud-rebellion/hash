// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sanitize

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

func manualLayersTestSource() []byte {
	return metadataTestPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [-30 -40 150 300] /CropBox [10 20 110 220] /Rotate 90 /UserUnit 2 /Group << /S /Transparency /CS /DeviceRGB >> /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		metadataTestStream("", "BT /F1 12 Tf 20 30 Td (ORIGINAL_APPROVED_BODY) Tj ET"),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>",
		metadataTestStream("", "BT /F1 12 Tf 10 20 Td (UNCHANGED_SECOND_PAGE) Tj ET"),
	}, "")
}

func manualLayersTestInputs() []PDFManualLayerV1 {
	return []PDFManualLayerV1{
		{1, 1, PDFManualLayerBaseV1, "document-base", manualTestPDF("", "0 0 400 200", "BT /F1 11 Tf 10 20 Td (FILLED_NON_SIGNATURE_TEXT) Tj ET")},
		{1, 2, PDFManualLayerSignatureV1, "party-alpha", manualTestPDF("/Group << /S /Transparency /CS /DeviceRGB >>", "0 0 400 200", "BT /F1 12 Tf 20 40 Td (PARTY_ALPHA) Tj ET")},
		{1, 3, PDFManualLayerSignatureV1, "party-beta", manualTestPDF("/Group << /S /Transparency /CS /DeviceRGB /I true >>", "0 0 400 200", "BT /F1 12 Tf 100 40 Td (PARTY_BETA) Tj ET")},
	}
}

func manualLayersTestFrame(t *testing.T, source []byte, layers []PDFManualLayerV1) ([]byte, int) {
	t.Helper()
	g, err := manualGeometryInProcess(source)
	if err != nil {
		t.Fatal(err)
	}
	b := manualLayersBatchV1{1, g.SourceSHA256, g.SourceBytes, g.GeometrySHA256, len(g.Pages), make([]manualLayerDescriptorV1, len(layers))}
	for i, l := range layers {
		b.Layers[i] = manualLayerDescriptorV1{l.Page, l.Order, l.Kind, l.Identity, len(l.PDF), pdfSHA(l.PDF)}
	}
	metadata, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(bytes.Clone(metadata), source...)
	for _, l := range layers {
		raw = append(raw, l.PDF...)
	}
	return raw, len(metadata)
}

func manualLayersTestRewriteFrame(t *testing.T, raw []byte, n int, change func(*manualLayersBatchV1)) ([]byte, int) {
	t.Helper()
	var b manualLayersBatchV1
	if json.Unmarshal(raw[:n], &b) != nil {
		t.Fatal("fixture metadata")
	}
	change(&b)
	metadata, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return append(metadata, raw[n:]...), len(metadata)
}

func TestManualLayersMultipartyPaintOrderAndOriginalPage(t *testing.T) {
	source, layers := manualLayersTestSource(), manualLayersTestInputs()
	raw, n := manualLayersTestFrame(t, source, layers)
	r, err := manualLayersInProcess(raw, n)
	if err != nil || ValidatePDFManualLayersResult(r) != nil {
		t.Fatalf("ordered composition: %v", err)
	}
	ctx, _, geometry, err := observePDF(r.Bytes)
	g, ge := manualGeometryInProcess(source)
	if err != nil || ge != nil || geometry != g.GeometrySHA256 || ctx.PageCount != 2 || r.Layers.Layers != 3 || r.Layers.DescriptorSHA256 != pdfSHA(raw[:n]) {
		t.Fatal("source/order/geometry commitment lost")
	}
	page, _, attrs, err := ctx.PageDict(1, false)
	if err != nil {
		t.Fatal(err)
	}
	content, err := manualPageContent(ctx, page, &manualResourceUsage{})
	if err != nil {
		t.Fatal(err)
	}
	// Literal independent expected order/matrix: original first, then base text,
	// then both parties; no source re-wrapping between fragments.
	expected := "q /HashManualLayersSourceV1 Do Q\n" +
		"q 0.000000000000 0.500000000000 -0.500000000000 0.000000000000 110.000000000000 20.000000000000 cm /HashManualLayersFragmentV1_1 Do Q\n" +
		"q 0.000000000000 0.500000000000 -0.500000000000 0.000000000000 110.000000000000 20.000000000000 cm /HashManualLayersFragmentV1_2 Do Q\n" +
		"q 0.000000000000 0.500000000000 -0.500000000000 0.000000000000 110.000000000000 20.000000000000 cm /HashManualLayersFragmentV1_3 Do Q\n"
	if string(content) != expected {
		t.Fatalf("paint order changed: %q", content)
	}
	x, err := ctx.DereferenceDict(attrs.Resources["XObject"])
	if err != nil || len(x) != 4 {
		t.Fatal("unexpected callable source or fragment")
	}
	expectedTexts := []string{"ORIGINAL_APPROVED_BODY", "FILLED_NON_SIGNATURE_TEXT", "PARTY_ALPHA", "PARTY_BETA"}
	for i, name := range []string{"HashManualLayersSourceV1", "HashManualLayersFragmentV1_1", "HashManualLayersFragmentV1_2", "HashManualLayersFragmentV1_3"} {
		sd, _, err := ctx.DereferenceStreamDict(x[name])
		if err != nil {
			t.Fatal(err)
		}
		c, err := manualContentStream(ctx, sd, 1<<20)
		if err != nil || !bytes.Contains(c, []byte(expectedTexts[i])) {
			t.Fatal("painted Form content substituted")
		}
		if i == 0 {
			if _, duplicate := sd.Dict["Group"]; duplicate {
				t.Fatal("original transparency Group duplicated on source Form")
			}
		}
	}
	sourceCtx, _, err := observePDFCompositionInput(source)
	if err != nil {
		t.Fatal(err)
	}
	p0, _, _, err := sourceCtx.PageDict(1, false)
	if err != nil {
		t.Fatal(err)
	}
	originalGroup, _ := manualResourceHash(sourceCtx, p0["Group"])
	actualGroup, _ := manualResourceHash(ctx, page["Group"])
	if originalGroup != actualGroup {
		t.Fatal("source page Group changed")
	}
	p2, _, attrs2, err := ctx.PageDict(2, false)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := manualPageContent(ctx, p2, &manualResourceUsage{})
	if err != nil || string(c2) != "BT /F1 12 Tf 10 20 Td (UNCHANGED_SECOND_PAGE) Tj ET" {
		t.Fatal("unassigned page painting changed")
	}
	orig2, _, origAttrs2, err := sourceCtx.PageDict(2, false)
	if err != nil {
		t.Fatal(err)
	}
	rh0, _ := manualResourceHash(sourceCtx, origAttrs2.Resources)
	rh2, _ := manualResourceHash(ctx, attrs2.Resources)
	gh0, _ := manualResourceHash(sourceCtx, orig2["Group"])
	gh2, _ := manualResourceHash(ctx, p2["Group"])
	if rh0 != rh2 || gh0 != gh2 {
		t.Fatal("unassigned page resources changed")
	}
	swapped := manualLayersTestInputs()
	swapped[1].PDF, swapped[2].PDF = swapped[2].PDF, swapped[1].PDF
	swapped[1].Identity, swapped[2].Identity = swapped[2].Identity, swapped[1].Identity
	changed, m := manualLayersTestFrame(t, source, swapped)
	r2, err := manualLayersInProcess(changed, m)
	if err != nil || r2.Layers.DescriptorSHA256 == r.Layers.DescriptorSHA256 || r2.Layers.OrderedPaintingSHA256 == r.Layers.OrderedPaintingSHA256 {
		t.Fatal("party order was not committed")
	}
}

func TestManualLayersViewportVectorsAndQuantization(t *testing.T) {
	for _, v := range []struct {
		rotation      int
		width, height float64
		matrix        string
	}{
		{0, 200, 400, "0.500000000000 0.000000000000 0.000000000000 0.500000000000 10.000000000000 20.000000000000"},
		{90, 400, 200, "0.000000000000 0.500000000000 -0.500000000000 0.000000000000 110.000000000000 20.000000000000"},
		{180, 200, 400, "-0.500000000000 0.000000000000 0.000000000000 -0.500000000000 110.000000000000 220.000000000000"},
		{270, 400, 200, "0.000000000000 -0.500000000000 0.500000000000 0.000000000000 10.000000000000 220.000000000000"},
		{-90, 400, 200, "0.000000000000 -0.500000000000 0.500000000000 0.000000000000 10.000000000000 220.000000000000"},
	} {
		t.Run(fmt.Sprint(v.rotation), func(t *testing.T) {
			source := manualTestPDF(fmt.Sprintf("/CropBox [10 20 110 220] /Rotate %d /UserUnit 2", v.rotation), "-30 -40 150 300", "BT /F1 12 Tf 20 30 Td (APPROVED_BODY) Tj ET")
			fragment := manualTestPDF("", fmt.Sprintf("0 0 %g %g", v.width, v.height), "BT /F1 12 Tf 10 15 Td (PARTY) Tj ET")
			raw, n := manualLayersTestFrame(t, source, []PDFManualLayerV1{{1, 1, PDFManualLayerSignatureV1, "first", fragment}, {1, 2, PDFManualLayerSignatureV1, "second", fragment}})
			result, err := manualLayersInProcess(raw, n)
			if err != nil {
				t.Fatal(err)
			}
			ctx, _, _, err := observePDF(result.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			page, _, _, err := ctx.PageDict(1, false)
			if err != nil {
				t.Fatal(err)
			}
			c, err := manualPageContent(ctx, page, &manualResourceUsage{})
			if err != nil {
				t.Fatal(err)
			}
			expected := "q /HashManualLayersSourceV1 Do Q\nq " + v.matrix + " cm /HashManualLayersFragmentV1_1 Do Q\nq " + v.matrix + " cm /HashManualLayersFragmentV1_2 Do Q\n"
			if string(c) != expected {
				t.Fatal("crop/rotation/UserUnit placement drift")
			}
		})
	}
	for _, v := range []struct {
		delta   float64
		allowed bool
	}{{.74, true}, {.76, false}} {
		pdf := manualTestPDF("", fmt.Sprintf("0 0 %g 300", 200+v.delta), "BT /F1 12 Tf 10 15 Td (FULL_NAME) Tj ET")
		descriptor := manualFragmentRequestV1{1, pdfSHA(pdf), int64(len(pdf)), 200, 300}
		metadata, _ := json.Marshal(descriptor)
		r, err := manualFragmentInProcess(append(metadata, pdf...), len(metadata))
		if (err == nil) != v.allowed {
			t.Fatalf("quantization %.2f: %v", v.delta, err)
		}
		if v.allowed && (r.ObservedWidthPoints == r.WidthPoints || r.PDFSHA256 != pdfSHA(pdf)) {
			t.Fatal("observed geometry silently normalized")
		}
	}
}

func TestManualLayersRejectClosedFrameDriftAndInvalidOrder(t *testing.T) {
	source, layers := manualLayersTestSource(), manualLayersTestInputs()
	raw, n := manualLayersTestFrame(t, source, layers)
	for _, kind := range []string{"source-swap", "fragment-swap", "trailing", "duplicate-key", "unknown-key", "missing-key", "null-layer", "wrong-source", "wrong-geometry", "wrong-bytes", "wrong-page", "page-regression", "order-gap", "duplicate-order", "base-after-signature", "second-base", "duplicate-party", "unknown-kind", "unsafe-identity", "empty-identity"} {
		t.Run(kind, func(t *testing.T) {
			changed := bytes.Clone(raw)
			m := n
			switch kind {
			case "source-swap":
				changed[n+10] ^= 1
			case "fragment-swap":
				changed[len(changed)-10] ^= 1
			case "trailing":
				changed = append(changed, 'x')
			case "duplicate-key", "unknown-key", "missing-key", "null-layer":
				metadata := string(raw[:n])
				switch kind {
				case "duplicate-key":
					metadata = strings.Replace(metadata, `"order":2`, `"order":2,"order":2`, 1)
				case "unknown-key":
					metadata = strings.Replace(metadata, `"kind":"base_text_v1"`, `"kind":"base_text_v1","caller_html":"private"`, 1)
				case "missing-key":
					metadata = strings.Replace(metadata, `"identity":"document-base",`, "", 1)
				case "null-layer":
					metadata = strings.Replace(metadata, string(raw[:n])[strings.Index(string(raw[:n]), "{\"page\""):strings.Index(string(raw[:n]), "},")+1], "null", 1)
				}
				changed = append([]byte(metadata), raw[n:]...)
				m = len(metadata)
			default:
				changed, m = manualLayersTestRewriteFrame(t, raw, n, func(b *manualLayersBatchV1) {
					switch kind {
					case "wrong-source":
						b.SourceSHA256 = pdfSHA([]byte("other"))
					case "wrong-geometry":
						b.GeometrySHA256 = pdfSHA([]byte("other"))
					case "wrong-bytes":
						b.Layers[2].Bytes++
					case "wrong-page":
						b.Layers[1].Page = 3
					case "page-regression":
						b.Layers[0].Page = 2
					case "order-gap":
						b.Layers[1].Order = 3
					case "duplicate-order":
						b.Layers[1].Order = 1
					case "base-after-signature":
						b.Layers[0].Kind = PDFManualLayerSignatureV1
						b.Layers[1].Kind = PDFManualLayerBaseV1
					case "second-base":
						b.Layers[1].Kind = PDFManualLayerBaseV1
					case "duplicate-party":
						b.Layers[2].Identity = b.Layers[1].Identity
					case "unknown-kind":
						b.Layers[2].Kind = "renderer_html"
					case "unsafe-identity":
						b.Layers[2].Identity = "../secret"
					case "empty-identity":
						b.Layers[2].Identity = ""
					}
				})
			}
			if r, err := manualLayersInProcess(changed, m); err == nil || len(r.Bytes) != 0 {
				t.Fatal("malformed ordered input published output")
			}
		})
	}
}

func TestManualFragmentAdmissionRejectsUnsupportedPayloads(t *testing.T) {
	for _, v := range []struct {
		name string
		pdf  []byte
	}{
		{"wrong-paper", manualTestPDF("", "0 0 201 300", "")},
		{"rotated", manualTestPDF("/Rotate 90", "0 0 200 300", "")},
		{"UserUnit", manualTestPDF("/UserUnit 2", "0 0 200 300", "")},
		{"origin", manualTestPDF("", "1 0 201 300", "")},
		{"crop", manualTestPDF("/CropBox [10 10 190 290]", "0 0 200 300", "")},
		{"annotations", manualTestPDF("/Annots [<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] >>]", "0 0 200 300", "")},
		{"unsupported-group", manualTestPDF("/Group << /S /Transparency /CS /DeviceRGB /Unsupported true >>", "0 0 200 300", "")},
		{"two-pages", buildTestPDF(t, 2)},
		{"invalid", []byte("%PDF-1.7 broken")},
		{"javascript", metadataTestPDF([]string{"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (alert) >> >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 300] /Resources << >> /Contents 4 0 R >>", metadataTestStream("", "")}, "")},
	} {
		t.Run(v.name, func(t *testing.T) {
			d := manualFragmentRequestV1{1, pdfSHA(v.pdf), int64(len(v.pdf)), 200, 300}
			metadata, _ := json.Marshal(d)
			if r, err := manualFragmentInProcess(append(metadata, v.pdf...), len(metadata)); err == nil || r.PDFSHA256 != "" {
				t.Fatal("unsupported fragment admitted")
			}
		})
	}
	for _, n := range []float64{0, -1, math.NaN(), math.Inf(1), 14401} {
		if _, err := admitManualFragmentV1(manualTestPDF("", "0 0 200 300", ""), n, 300, &manualResourceUsage{}); err == nil {
			t.Fatal("invalid expected viewport admitted")
		}
	}
	pdf := manualTestPDF("", "0 0 200 300", "BT /F1 12 Tf 10 15 Td (ORIGINAL_FULL_NAME) Tj ET")
	d := manualFragmentRequestV1{1, pdfSHA(pdf), int64(len(pdf)), 200, 300}
	metadata, _ := json.Marshal(d)
	for _, kind := range []string{"digest", "bytes", "width", "duplicate", "missing", "unknown", "null", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			changed := string(metadata)
			switch kind {
			case "digest":
				changed = strings.Replace(changed, d.PDFSHA256, pdfSHA([]byte("different")), 1)
			case "bytes":
				changed = strings.Replace(changed, fmt.Sprintf("\"pdf_bytes\":%d", len(pdf)), "\"pdf_bytes\":1", 1)
			case "width":
				changed = strings.Replace(changed, "\"width_points\":200", "\"width_points\":201", 1)
			case "duplicate":
				changed = strings.Replace(changed, "\"width_points\":200", "\"width_points\":200,\"width_points\":200", 1)
			case "missing":
				changed = strings.Replace(changed, "\"height_points\":300", "\"other\":300", 1)
			case "unknown":
				changed = strings.Replace(changed, "{", "{\"url\":\"http://private\",", 1)
			case "null":
				changed = strings.Replace(changed, "\"height_points\":300", "\"height_points\":null", 1)
			case "trailing":
				changed += " {}"
			}
			if a, err := manualFragmentInProcess(append([]byte(changed), pdf...), len(changed)); err == nil || a.PDFSHA256 != "" {
				t.Fatal("invalid fragment authority admitted")
			}
		})
	}
}

func manualLayersTestPageWitness(t *testing.T, sources ...[]byte) (*model.Context, manualLayerPageWitnessV1) {
	t.Helper()
	source := manualLayersTestSource()
	if len(sources) > 0 {
		source = sources[0]
	}
	ctx, _, err := observePDFCompositionInput(source)
	if err != nil {
		t.Fatal(err)
	}
	g, err := manualGeometryInProcess(source)
	if err != nil {
		t.Fatal(err)
	}
	usage := &manualResourceUsage{}
	contents, err := manualPageContents(ctx, usage)
	if err != nil {
		t.Fatal(err)
	}
	page, _, attrs, err := ctx.PageDict(1, false)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := manualResourceHash(ctx, attrs.Resources)
	if err != nil {
		t.Fatal(err)
	}
	gh, err := manualResourceHash(ctx, page["Group"])
	if err != nil {
		t.Fatal(err)
	}
	w := manualLayerPageWitnessV1{1, "", pdfSHA(contents[0]), rh, rh, gh, g.Pages[0].Boxes[0], []manualLayerFormWitnessV1{}, pdfSHA(contents[0]), contents[0]}
	layers := manualLayersTestInputs()
	ds := make([]manualLayerDescriptorV1, len(layers))
	fragments := make([]*admittedManualFragmentV1, len(layers))
	for i, l := range layers {
		ds[i] = manualLayerDescriptorV1{l.Page, l.Order, l.Kind, l.Identity, len(l.PDF), pdfSHA(l.PDF)}
		fragments[i], err = admitManualFragmentV1(l.PDF, 400, 200, &manualResourceUsage{})
		if err != nil {
			t.Fatal(err)
		}
	}
	w, err = composeManualLayersPageV1(ctx, g.Pages[0], contents[0], w, ds, fragments, usage)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, w
}

func TestManualLayersWitnessDetectsPaintResourceAndGroupChanges(t *testing.T) {
	for _, kind := range []string{"baseline", "base-box", "fragment-box", "fragment-matrix", "source-group", "fragment-group", "page-group", "hidden-form", "resource-substitution", "extra-form", "paint-order", "paint-matrix", "witness-matrix"} {
		t.Run(kind, func(t *testing.T) {
			ctx, w := manualLayersTestPageWitness(t)
			page, _, attrs, err := ctx.PageDict(1, false)
			if err != nil {
				t.Fatal(err)
			}
			x, err := ctx.DereferenceDict(attrs.Resources["XObject"])
			if err != nil {
				t.Fatal(err)
			}
			base, _, err := ctx.DereferenceStreamDict(x[w.BaseName])
			if err != nil {
				t.Fatal(err)
			}
			fragment, _, err := ctx.DereferenceStreamDict(x[w.Layers[1].Name])
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "base-box":
				base.Dict["BBox"] = types.NewNumberArray(0, 0, 1, 1)
			case "fragment-box":
				fragment.Dict["BBox"] = types.NewNumberArray(0, 0, 1, 1)
			case "fragment-matrix":
				fragment.Dict["Matrix"] = types.NewNumberArray(1, 0, 0, 1, 10, 0)
			case "source-group":
				base.Dict["Group"] = types.Dict{"S": types.Name("Transparency")}
			case "fragment-group":
				delete(fragment.Dict, "Group")
			case "page-group":
				page["Group"] = types.Dict{"S": types.Name("Transparency"), "I": types.Boolean(true)}
			case "hidden-form":
				fragment.Dict["OC"] = types.NewDict()
			case "resource-substitution":
				fragment.Dict["Resources"] = types.NewDict()
			case "extra-form":
				x["Foreign"] = x[w.Layers[0].Name]
			case "paint-order", "paint-matrix":
				calls := string(w.Calls)
				if kind == "paint-order" {
					calls = strings.ReplaceAll(calls, "FragmentV1_2", "Temporary")
					calls = strings.ReplaceAll(calls, "FragmentV1_3", "FragmentV1_2")
					calls = strings.ReplaceAll(calls, "Temporary", "FragmentV1_3")
				} else {
					calls = strings.Replace(calls, "110.000000000000", "111.000000000000", 1)
				}
				stream, err := ctx.NewStreamDictForBuf([]byte(calls))
				if err != nil || stream.Encode() != nil {
					t.Fatal("test stream")
				}
				ir, err := ctx.IndRefForNewObject(*stream)
				if err != nil {
					t.Fatal(err)
				}
				page["Contents"] = *ir
			case "witness-matrix":
				w.Layers[0].Matrix[4]++
			}
			err = verifyManualLayersPageV1(ctx, w, newManualCopyBudget(&manualResourceUsage{}))
			if (kind == "baseline") != (err == nil) {
				t.Fatalf("witness %s: %v", kind, err)
			}
		})
	}
}

func TestManualLayersMandatoryWorkerAndCause(t *testing.T) {
	source, layers := manualLayersTestSource(), manualLayersTestInputs()
	g, err := manualGeometryInProcess(source)
	if err != nil {
		t.Fatal(err)
	}
	previous := activePDFWorker.Swap(nil)
	t.Cleanup(func() { activePDFWorker.Store(previous) })
	if _, err := InspectManualPDFFragmentWithContext(context.Background(), layers[1].PDF, 400, 200); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal("fragment parent-parser fallback")
	}
	if _, err := ApplyManualPDFLayersWithContext(context.Background(), source, g, layers); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal("composition parent-parser fallback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InspectManualPDFFragmentWithContext(ctx, layers[1].PDF, 400, 200); !errors.Is(err, context.Canceled) {
		t.Fatal("fragment cancellation cause lost")
	}
	if _, err := ApplyManualPDFLayersWithContext(ctx, source, g, layers); !errors.Is(err, context.Canceled) {
		t.Fatal("layers cancellation cause lost")
	}
	t.Setenv("HASH_PRIVATE_SYNTHETIC_SECRET", "never-pass-to-parser")
	w := workerTestHelper(t, "protocol")
	activePDFWorker.Store(w)
	a, err := InspectManualPDFFragmentWithContext(context.Background(), layers[1].PDF, 400, 200)
	if err != nil || a.PDFSHA256 != pdfSHA(layers[1].PDF) || a.PDFBytes != int64(len(layers[1].PDF)) {
		t.Fatalf("actual fragment protocol: %v", err)
	}
	r, err := ApplyManualPDFLayersWithContext(context.Background(), source, g, layers)
	if err != nil || ValidatePDFManualLayersResult(r) != nil || len(w.slots) != 0 {
		t.Fatalf("actual ordered protocol: %v", err)
	}
	// Existing v1 semantics remain available through this same executable.
	old, err := ApplyManualPDFOverlaysWithContext(context.Background(), source, g, map[int][]byte{1: layers[0].PDF})
	if err != nil || validateManualResult(old) != nil {
		t.Fatalf("historical operation changed: %v", err)
	}
}

func TestManualLayersMetadataAndSizeBudgetWithoutParsing(t *testing.T) {
	source := manualLayersTestSource()
	g, err := manualGeometryInProcess(source)
	if err != nil {
		t.Fatal(err)
	}
	tooBig := []PDFManualLayerV1{{1, 1, PDFManualLayerBaseV1, "base", make([]byte, MaxPDFBytes-len(source)+1)}}
	if _, err := ApplyManualPDFLayersWithContext(context.Background(), source, g, tooBig); !errors.Is(err, ErrPDFTooLarge) {
		t.Fatal("processing aggregate did not fail before parser dispatch")
	}
	tooBig = nil
	if _, err := InspectManualPDFFragmentWithContext(context.Background(), make([]byte, MaxPDFManualSignatureFragmentBytes+1), 400, 200); !errors.Is(err, ErrPDFTooLarge) {
		t.Fatal("signature PDF-section cap missing")
	}
	descriptors := make([]manualLayerDescriptorV1, MaxPDFManualLayersV1+1)
	for i := range descriptors {
		descriptors[i] = manualLayerDescriptorV1{1, i + 1, PDFManualLayerSignatureV1, fmt.Sprintf("party-%d", i), 1, pdfSHA([]byte("x"))}
	}
	if validateManualLayerDescriptorsV1(descriptors, 2) == nil {
		t.Fatal("layer count is unbounded")
	}
	layers := manualLayersTestInputs()
	layers[2].PDF = make([]byte, MaxPDFManualSignatureFragmentBytes+1)
	if _, err := ApplyManualPDFLayersWithContext(context.Background(), source, g, layers); !errors.Is(err, ErrPDFTooLarge) {
		t.Fatal("signature layer PDF-section cap missing")
	}
}

// The real subprocess executes ServePDFWorker and changes only the emitted
// proof. The parent must refuse even otherwise well-formed protocol output.
func TestPDFManualLayersChildHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--hash-layers-child" {
		return
	}
	if os.Getenv("HASH_PRIVATE_SYNTHETIC_SECRET") != "" {
		os.Exit(2)
	}
	mode := os.Args[len(os.Args)-1]
	var original bytes.Buffer
	if _, err := io.Copy(&original, io.LimitReader(os.Stdin, MaxPDFBytes+pdfWorkerHeaderLimit+1)); err != nil {
		os.Exit(3)
	}
	var output bytes.Buffer
	if ServePDFWorker(bytes.NewReader(original.Bytes()), &output) != nil {
		os.Exit(4)
	}
	reader := bufio.NewReader(bytes.NewReader(output.Bytes()))
	var response pdfWorkerResponse
	if readPDFWorkerHeader(reader, &response) != nil || response.Error != "" {
		os.Exit(5)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		os.Exit(6)
	}
	switch mode {
	case "layers-descriptor":
		response.ManualLayers.DescriptorSHA256 = pdfSHA([]byte("wrong descriptor"))
	case "layers-source":
		response.ManualLayers.SourceSHA256 = pdfSHA([]byte("wrong source"))
	case "layers-count":
		response.ManualLayers.Layers++
	case "layers-report":
		response.Report.BytesBefore++
	case "layers-missing":
		response.ManualLayers = nil
	case "layers-unknown":
		header, _ := json.Marshal(response)
		header = bytes.Replace(header, []byte(`"ordered_painting_sha256":`), []byte(`"future_painting_sha256":`), 1)
		os.Stdout.Write(append(header, '\n'))
		os.Stdout.Write(body)
		os.Exit(0)
	case "fragment-digest", "fragment-width", "fragment-missing", "fragment-unknown":
		var admission PDFManualFragmentAdmission
		if json.Unmarshal(body, &admission) != nil {
			os.Exit(7)
		}
		switch mode {
		case "fragment-digest":
			admission.PDFSHA256 = pdfSHA([]byte("other PDF"))
		case "fragment-width":
			admission.WidthPoints += .1
		}
		body, _ = json.Marshal(admission)
		if mode == "fragment-missing" {
			body = bytes.Replace(body, []byte(`"group_sha256":`), []byte(`"different_group":`), 1)
		}
		if mode == "fragment-unknown" {
			body = bytes.Replace(body, []byte("{"), []byte(`{"caller_url":"private",`), 1)
		}
		response.Length = len(body)
	default:
		os.Exit(8)
	}
	header, err := json.Marshal(response)
	if err != nil {
		os.Exit(9)
	}
	os.Stdout.Write(append(header, '\n'))
	os.Stdout.Write(body)
	os.Exit(0)
}

func manualLayersMalformedWorker(t *testing.T, mode string) *pdfWorker {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := workerTestScript(t, "exec "+shellTestQuote(binary)+" -test.run='^TestPDFManualLayersChildHelper$' -- --hash-layers-child "+shellTestQuote(mode))
	return &pdfWorker{path: path, slots: make(chan struct{}, 2)}
}

func TestManualLayersProtocolRejectsProofSubstitution(t *testing.T) {
	source, layers := manualLayersTestSource(), manualLayersTestInputs()
	g, err := manualGeometryInProcess(source)
	if err != nil {
		t.Fatal(err)
	}
	previous := activePDFWorker.Load()
	t.Cleanup(func() { activePDFWorker.Store(previous) })
	for _, mode := range []string{"layers-descriptor", "layers-source", "layers-count", "layers-report", "layers-missing", "layers-unknown", "fragment-digest", "fragment-width", "fragment-missing", "fragment-unknown"} {
		t.Run(mode, func(t *testing.T) {
			w := manualLayersMalformedWorker(t, mode)
			activePDFWorker.Store(w)
			if strings.HasPrefix(mode, "fragment-") {
				a, err := InspectManualPDFFragmentWithContext(context.Background(), layers[1].PDF, 400, 200)
				if !errors.Is(err, ErrPDFWorkerUnavailable) || a.PDFSHA256 != "" || len(w.slots) != 0 {
					t.Fatalf("substituted fragment proof: %v", err)
				}
			} else {
				r, err := ApplyManualPDFLayersWithContext(context.Background(), source, g, layers)
				if !errors.Is(err, ErrPDFWorkerUnavailable) || len(r.Bytes) != 0 || len(w.slots) != 0 {
					t.Fatalf("substituted composition proof: %v", err)
				}
			}
		})
	}
}

func TestManualLayersCancellationReapsOwnedWorker(t *testing.T) {
	source, layers := manualLayersTestSource(), manualLayersTestInputs()
	g, err := manualGeometryInProcess(source)
	if err != nil {
		t.Fatal(err)
	}
	previous := activePDFWorker.Load()
	t.Cleanup(func() { activePDFWorker.Store(previous) })
	for _, operation := range []string{"fragment", "layers"} {
		t.Run(operation, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "pid")
			path := workerTestScript(t, "echo $$ > "+shellTestQuote(pidFile)+"\nexec /bin/sleep 60")
			w := &pdfWorker{path: path, slots: make(chan struct{}, 1)}
			activePDFWorker.Store(w)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "fragment" {
					_, err := InspectManualPDFFragmentWithContext(ctx, layers[1].PDF, 400, 200)
					done <- err
				} else {
					_, err := ApplyManualPDFLayersWithContext(ctx, source, g, layers)
					done <- err
				}
			}()
			deadline := time.Now().Add(3 * time.Second)
			var pidRaw []byte
			for {
				pidRaw, _ = os.ReadFile(pidFile)
				if len(pidRaw) > 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("owned worker did not start")
				}
				time.Sleep(10 * time.Millisecond)
			}
			started := time.Now()
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) || len(w.slots) != 0 || time.Since(started) > 2*time.Second {
					t.Fatalf("new operation lost cancellation/capacity: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("new operation did not finish cancellation")
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(pidRaw)))
			if err != nil {
				t.Fatal(err)
			}
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatal("owned child was not reaped")
			}
		})
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := ApplyManualPDFLayersWithContext(expired, source, g, layers); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("layers deadline cause lost")
	}
	if _, err := InspectManualPDFFragmentWithContext(expired, layers[1].PDF, 400, 200); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("fragment deadline cause lost")
	}
}

func TestManualLayersBindsPageGroupNamedColorSpace(t *testing.T) {
	source := metadataTestPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [-30 -40 150 300] /CropBox [10 20 110 220] /Rotate 90 /UserUnit 2 /Group << /S /Transparency /CS /HashSourceCS >> /Resources << /ColorSpace << /HashSourceCS /DeviceRGB >> /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		metadataTestStream("", "BT /F1 12 Tf 20 30 Td (ORIGINAL_SOURCE) Tj ET"),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}, "")
	ctx, w := manualLayersTestPageWitness(t, source)
	if err := verifyManualLayersPageV1(ctx, w, newManualCopyBudget(&manualResourceUsage{})); err != nil {
		t.Fatal("named source Group color space refused", err)
	}
	_, _, attrs, err := ctx.PageDict(1, false)
	if err != nil {
		t.Fatal(err)
	}
	colors, err := ctx.DereferenceDict(attrs.Resources["ColorSpace"])
	if err != nil {
		t.Fatal(err)
	}
	attrs.Resources["ColorSpace"] = types.Dict{"HashSourceCS": types.Name("DeviceGray")}
	x, err := ctx.DereferenceDict(attrs.Resources["XObject"])
	if err != nil {
		t.Fatal(err)
	}
	base, _, err := ctx.DereferenceStreamDict(x[w.BaseName])
	if err != nil {
		t.Fatal(err)
	}
	unchanged, _ := manualResourceHash(ctx, base.Dict["Resources"])
	if unchanged != w.ResourcesSHA256 {
		t.Fatal("fixture changed source Form instead of top-level page color space")
	}
	if len(colors) != 1 {
		t.Fatal("named source color space fixture")
	}
	if err := verifyManualLayersPageV1(ctx, w, newManualCopyBudget(&manualResourceUsage{})); err == nil {
		t.Fatal("page Group color space changed without changing source Form or Group name")
	}
}

func manualVisibilityTestPDF(catalogExtra, resourceExtra, content string, extraObjects ...string) []byte {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R " + catalogExtra + " >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 300] /Resources << /Font << /F1 5 0 R >> " + resourceExtra + " >> /Contents 4 0 R >>",
		metadataTestStream("", content),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	objects = append(objects, extraObjects...)
	return metadataTestPDF(objects, "")
}

func TestManualFragmentRefusesOptionalContentVisibility(t *testing.T) {
	for _, v := range []struct {
		name string
		pdf  []byte
	}{
		{"catalog-default-off", manualVisibilityTestPDF("/OCProperties << /OCGs [6 0 R] /D << /BaseState /ON /OFF [6 0 R] >> >>", "/Properties << /Hidden 6 0 R >>", "/OC /Hidden BDC BT /F1 12 Tf 10 20 Td (SIGNATURE) Tj ET EMC", "<< /Type /OCG /Name (hidden) >>")},
		{"resource-OCG", manualVisibilityTestPDF("", "/Properties << /Hidden 6 0 R >>", "BT /F1 12 Tf 10 20 Td (SIGNATURE) Tj ET", "<< /Type /OCG /Name (hidden) >>")},
		{"resource-OCMD", manualVisibilityTestPDF("", "/Properties << /Hidden 6 0 R >>", "BT /F1 12 Tf 10 20 Td (SIGNATURE) Tj ET", "<< /Type /OCMD /P /AllOn >>")},
		{"inline-OC", manualVisibilityTestPDF("", "", "/OC << /Type /OCG /Name (hidden) >> BDC BT /F1 12 Tf 10 20 Td (SIGNATURE) Tj ET EMC")},
		{"escaped-OC", manualVisibilityTestPDF("", "", "/#4F#43 << /Type /OCG /Name (hidden) >> BDC BT /F1 12 Tf 10 20 Td (SIGNATURE) Tj ET EMC")},
		{"nested-form-visibility", manualVisibilityTestPDF("", "/XObject << /Nested 6 0 R >>", "/Nested Do", metadataTestStream("/Type /XObject /Subtype /Form /BBox [0 0 200 300] /Resources << /Font << /F1 5 0 R >> >>", "/OC << /Type /OCG /Name (hidden) >> BDC BT /F1 12 Tf 10 20 Td (SIGNATURE) Tj ET EMC"))},
	} {
		t.Run(v.name, func(t *testing.T) {
			if _, err := admitManualFragmentV1(v.pdf, 200, 300, &manualResourceUsage{}); err == nil {
				t.Fatal("fragment visibility depended on discarded catalog policy")
			}
		})
	}
	for _, content := range []string{
		"BT /F1 12 Tf 10 20 Td (/OC is literal printable text) Tj ET",
		"BT /F1 12 Tf 10 20 Td (nested (/OC) printable text) Tj ET",
		"BT /F1 12 Tf 10 20 Td <2F4F43> Tj ET",
		"% /OC appears only in a comment\nBT /F1 12 Tf 10 20 Td (SIGNED_NAME) Tj ET",
		"BI /W 4 /H 1 /CS /RGB /BPC 8 ID /OCxxxxxxx EI Q",
	} {
		if err := manualFragmentDrawingVisibilityV1([]byte(content)); err != nil {
			t.Fatal("printable string/comment/image bytes were mistaken for optional-content policy", err)
		}
	}
}

func TestManualWorkerProbeRequiresExactExercisedOperations(t *testing.T) {
	previous := activePDFWorker.Load()
	t.Cleanup(func() { activePDFWorker.Store(previous) })
	for _, capability := range []string{"", "manual-layers-v1", "manual-fragment-inspect-v1+manual-layers-v2"} {
		header, err := json.Marshal(pdfWorkerResponse{ProtocolVersion: pdfWorkerProtocolVersion, Pages: 1, ManualOperations: capability})
		if err != nil {
			t.Fatal(err)
		}
		path := workerTestScript(t, "printf '%s\\n' "+shellTestQuote(string(header)))
		if err := ConfigurePDFWorker(context.Background(), path, "production"); !errors.Is(err, ErrPDFWorkerUnavailable) {
			t.Fatal("old/scope-incomplete protocol-3 worker passed startup")
		}
		if err := CheckPDFWorker(context.Background()); !errors.Is(err, ErrPDFWorkerUnavailable) {
			t.Fatal("old/scope-incomplete worker passed readiness")
		}
	}
	w := workerTestHelper(t, "protocol")
	if err := ConfigurePDFWorker(context.Background(), w.path, "production"); err != nil {
		t.Fatal("new exercised capability refused", err)
	}
	response, body, err := w.run(context.Background(), pdfWorkerRequest{Operation: "probe"}, nil)
	if err != nil || response.ManualOperations != pdfManualOperationsCapabilityV1 || response.Pages != 1 || len(body) != 0 {
		t.Fatal("probe did not commit new operations", err)
	}
	// Exercise the private probe on an independently authored valid viewport too.
	if err := probeManualOperationsV1(manualTestPDF("", "0 0 200 300", "BT /F1 12 Tf 10 20 Td (PROBE) Tj ET")); err != nil {
		t.Fatal(err)
	}
}

func TestManualLayersUnassignedContentIsChargedOnceAfterClean(t *testing.T) {
	// Two independently preserved 9 MiB comment streams are below the shared
	// 32 MiB content budget. Double-reading them during final verification would
	// falsely refuse this otherwise valid, bounded three-page document.
	commentA := "%" + strings.Repeat("a", 9<<20) + "\nBT /F1 12 Tf 10 20 Td (UNASSIGNED_PAGE_A) Tj ET"
	commentB := "%" + strings.Repeat("b", 9<<20) + "\nBT /F1 12 Tf 10 20 Td (UNASSIGNED_PAGE_B) Tj ET"
	source := metadataTestPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R 6 0 R 8 0 R] /Count 3 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 300] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		metadataTestStream("", "BT /F1 12 Tf 10 20 Td (SOURCE_BODY) Tj ET"),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 300] /Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>",
		metadataTestStream("", commentA),
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 300] /Resources << /Font << /F1 5 0 R >> >> /Contents 9 0 R >>",
		metadataTestStream("", commentB),
	}, "")
	fragment := manualTestPDF("", "0 0 200 300", "BT /F1 12 Tf 20 30 Td (SIGNED_PARTY) Tj ET")
	raw, n := manualLayersTestFrame(t, source, []PDFManualLayerV1{{1, 1, PDFManualLayerSignatureV1, "party", fragment}})
	r, err := manualLayersInProcess(raw, n)
	if err != nil || ValidatePDFManualLayersResult(r) != nil || r.Layers.Pages != 3 {
		t.Fatalf("bounded unassigned page content was double-charged: %v", err)
	}
	ctx, _, _, err := observePDF(r.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{commentA, commentB} {
		page, _, _, err := ctx.PageDict(i+2, false)
		if err != nil {
			t.Fatal(err)
		}
		got, err := manualPageContent(ctx, page, &manualResourceUsage{})
		if err != nil || !bytes.Equal(got, []byte(want)) {
			t.Fatal("unassigned content changed")
		}
	}
}

func manualType3VisibilityTestPDF(glyphContent string) []byte {
	return metadataTestPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 300] /Resources << /Font << /F3 5 0 R >> >> /Contents 4 0 R >>",
		metadataTestStream("", "BT /F3 12 Tf 10 20 Td (A) Tj ET"),
		"<< /Type /Font /Subtype /Type3 /FontBBox [0 0 600 600] /FontMatrix [0.001 0 0 0.001 0 0] /CharProcs << /A 6 0 R >> /Encoding << /Type /Encoding /Differences [65 /A] >> /FirstChar 65 /LastChar 65 /Widths [600] /Resources << >> >>",
		metadataTestStream("", glyphContent),
	}, "")
}

func TestManualFragmentScansPatternAndType3DrawingVisibility(t *testing.T) {
	for _, facility := range []string{"pattern", "Type3"} {
		for _, hidden := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-hidden-%v", facility, hidden), func(t *testing.T) {
				drawing := "0 0 20 20 re f"
				if hidden {
					drawing = "/OC << /Type /OCG /Name (hidden) >> BDC " + drawing + " EMC"
				}
				var pdf []byte
				if facility == "pattern" {
					pdf = manualVisibilityTestPDF("", "/Pattern << /P1 6 0 R >>", "/Pattern cs /P1 scn 0 0 50 50 re f", metadataTestStream("/Type /Pattern /PatternType 1 /PaintType 1 /TilingType 1 /BBox [0 0 20 20] /XStep 20 /YStep 20 /Resources << >>", drawing))
				} else {
					pdf = manualType3VisibilityTestPDF("600 0 d0 " + drawing)
				}
				_, err := admitManualFragmentV1(pdf, 200, 300, &manualResourceUsage{})
				if (err == nil) == hidden {
					t.Fatalf("normal drawing facility changed or hidden visibility admitted: %v", err)
				}
			})
		}
	}
}

func TestManualLayersResourcePreservingRoundTrip(t *testing.T) {
	source, layers := manualLayersTestSource(), manualLayersTestInputs()
	raw, n := manualLayersTestFrame(t, source, layers)
	result, err := manualLayersInProcess(raw, n)
	if err != nil || ValidatePDFManualLayersResult(result) != nil {
		t.Fatal("production ordered composition", err)
	}
	_, w := manualLayersTestPageWitness(t)
	final, _, _, err := observePDF(result.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	_, _, attrs, err := final.PageDict(1, false)
	if err != nil {
		t.Fatal(err)
	}
	// Original font use moved inside a Form. Preserve the constructed page
	// dictionary too, instead of accepting its post-clean pruning silently.
	fonts, err := final.DereferenceDict(attrs.Resources["Font"])
	if err != nil || fonts["F1"] == nil {
		t.Fatal("constructed page resource was pruned")
	}
	if err := verifyManualLayersPageV1(final, w, newManualCopyBudget(&manualResourceUsage{})); err != nil {
		t.Fatal("full post-clean resource witness", err)
	}
}

func TestManualLayersNamedGroupColorSpaceRoundTrip(t *testing.T) {
	source := metadataTestPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [-30 -40 150 300] /CropBox [10 20 110 220] /Rotate 90 /UserUnit 2 /Group << /S /Transparency /CS /HashSourceCS >> /Resources << /ColorSpace << /HashSourceCS /DeviceRGB >> /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		metadataTestStream("", "BT /F1 12 Tf 20 30 Td (ORIGINAL_SOURCE) Tj ET"),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}, "")
	raw, n := manualLayersTestFrame(t, source, manualLayersTestInputs())
	result, err := manualLayersInProcess(raw, n)
	if err != nil || ValidatePDFManualLayersResult(result) != nil {
		t.Fatal("production named-Group composition", err)
	}
	_, w := manualLayersTestPageWitness(t, source)
	final, _, _, err := observePDF(result.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	page, _, attrs, err := final.PageDict(1, false)
	if err != nil {
		t.Fatal(err)
	}
	colors, err := final.DereferenceDict(attrs.Resources["ColorSpace"])
	if err != nil || colors == nil || colors["HashSourceCS"] != types.Name("DeviceRGB") {
		t.Fatal("page Group named color-space binding did not survive all cleaning passes")
	}
	group, err := manualResourceHash(final, page["Group"])
	if err != nil || group != w.GroupSHA256 {
		t.Fatal("source page Group changed")
	}
	if err := verifyManualLayersPageV1(final, w, newManualCopyBudget(&manualResourceUsage{})); err != nil {
		t.Fatal("named Group post-clean witness", err)
	}
	// Replacing only the top-level binding must still fail after a genuine
	// serialized/cleaned composition; source Form resources stay unchanged.
	attrs.Resources["ColorSpace"] = types.Dict{"HashSourceCS": types.Name("DeviceGray")}
	x, err := final.DereferenceDict(attrs.Resources["XObject"])
	if err != nil {
		t.Fatal(err)
	}
	base, _, err := final.DereferenceStreamDict(x[w.BaseName])
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := manualResourceHash(final, base.Dict["Resources"])
	if err != nil || unchanged != w.ResourcesSHA256 {
		t.Fatal("tamper fixture changed source Form instead of page Group color space")
	}
	if err := verifyManualLayersPageV1(final, w, newManualCopyBudget(&manualResourceUsage{})); err == nil {
		t.Fatal("post-clean page Group color-space substitution accepted")
	}
}
