// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sanitize

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// Literal PDF coordinates independently specify the source layout. No production
// geometry writer or stamping implementation generates these expectations.
func manualTestPDF(pageExtra, box, content string) []byte {
	return metadataTestPDF([]string{
		`<< /Type /Catalog /Pages 2 0 R >>`,
		`<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [` + box + `] >>`,
		`<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R ` + pageExtra + ` >>`,
		metadataTestStream("", content), `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`,
	}, "")
}
func manualTestBatch(t *testing.T, source []byte, overlays map[int][]byte) ([]byte, int) {
	t.Helper()
	g, err := manualGeometryInProcess(source)
	if err != nil {
		t.Fatal(err)
	}
	b := manualOverlayBatch{SchemaVersion: 1, SourceSHA256: g.SourceSHA256, SourceBytes: g.SourceBytes, GeometrySHA256: g.GeometrySHA256, Pages: len(g.Pages)}
	for i := 1; i <= len(g.Pages); i++ {
		if raw, ok := overlays[i]; ok {
			b.Overlays = append(b.Overlays, manualOverlayDescriptor{i, len(raw), pdfSHA(raw)})
		}
	}
	metadata, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(bytes.Clone(metadata), source...)
	for _, d := range b.Overlays {
		raw = append(raw, overlays[d.Page]...)
	}
	return raw, len(metadata)
}

func TestManualPDFViewportIndependentVectors(t *testing.T) {
	for _, v := range []struct {
		rotation int
		w, h     float64
		matrix   [6]float64
	}{
		{0, 200, 400, [6]float64{.5, 0, 0, .5, 10, 20}},
		{90, 400, 200, [6]float64{0, .5, -.5, 0, 110, 20}},
		{180, 200, 400, [6]float64{-.5, 0, 0, -.5, 110, 220}},
		{270, 400, 200, [6]float64{0, -.5, .5, 0, 10, 220}},
		{-90, 400, 200, [6]float64{0, -.5, .5, 0, 10, 220}},
		{450, 400, 200, [6]float64{0, .5, -.5, 0, 110, 20}},
	} {
		t.Run(fmt.Sprint(v.rotation), func(t *testing.T) {
			source := manualTestPDF(fmt.Sprintf("/CropBox [10 20 110 220] /Rotate %d /UserUnit 2", v.rotation), "-30 -40 150 300", "BT /F1 12 Tf 20 30 Td (APPROVED_BODY) Tj ET")
			g, err := manualGeometryInProcess(source)
			if err != nil {
				t.Fatal(err)
			}
			if len(g.Pages) != 1 || g.Pages[0].Boxes[0] != [4]float64{-30, -40, 150, 300} || g.Pages[0].Boxes[1] != [4]float64{10, 20, 110, 220} || g.Pages[0].Rotation != v.rotation || g.Pages[0].UserUnit != 2 {
				t.Fatal("effective geometry changed")
			}
			w, h, err := g.Pages[0].ViewportPoints()
			if err != nil || w != v.w || h != v.h {
				t.Fatalf("viewport %v %v %v", w, h, err)
			}
			matrix, err := manualPlacementMatrix(g.Pages[0], v.w, v.h)
			if err != nil || matrix != v.matrix {
				t.Fatalf("matrix %v %v", matrix, err)
			}
			overlay := manualTestPDF("", fmt.Sprintf("0 0 %g %g", v.w, v.h), "BT /F1 12 Tf 10 15 Td (VISIBLE_PLACEMENT) Tj ET")
			raw, n := manualTestBatch(t, source, map[int][]byte{1: overlay})
			result, err := manualOverlayInProcess(raw, n)
			if err != nil {
				t.Fatal(err)
			}
			if validateManualResult(result) != nil || result.Overlay.GeometrySHA256 != g.GeometrySHA256 || result.Overlay.SourceSHA256 != pdfSHA(source) {
				t.Fatal("output proof lost source binding")
			}
		})
	}
	for _, v := range []struct {
		crop string
		want [4]float64
	}{
		{"-30 -30 50 120", [4]float64{0, 0, 50, 100}}, {"200 200 300 300", [4]float64{0, 0, 100, 100}},
	} {
		g, err := manualGeometryInProcess(manualTestPDF("/CropBox ["+v.crop+"]", "0 0 100 100", ""))
		if err != nil {
			t.Fatal(err)
		}
		box, err := manualVisibleBox(g.Pages[0])
		if err != nil || box != v.want {
			t.Fatalf("crop intersection %v %v", box, err)
		}
	}
}

func TestManualPDFRefusesUnsafeGeometryAndWrongOverlay(t *testing.T) {
	for _, extra := range []string{"/Rotate 45", "/UserUnit 0", "/UserUnit 75001", "/UserUnit 200", "/CropBox [0 0 0 100]"} {
		if _, err := manualGeometryInProcess(manualTestPDF(extra, "0 0 100 100", "")); err == nil {
			t.Fatalf("accepted %s", extra)
		}
	}
	source := manualTestPDF("", "0 0 200 300", "BT /F1 12 Tf 20 30 Td (BODY) Tj ET")
	for _, overlay := range [][]byte{
		manualTestPDF("", "0 0 210 300", ""), manualTestPDF("/Rotate 90", "0 0 200 300", ""), manualTestPDF("/UserUnit 2", "0 0 200 300", ""), manualTestPDF("", "1 0 201 300", ""), manualTestPDF("/CropBox [10 10 190 290]", "0 0 200 300", ""),
	} {
		raw, n := manualTestBatch(t, source, map[int][]byte{1: overlay})
		if r, err := manualOverlayInProcess(raw, n); err == nil || len(r.Bytes) != 0 {
			t.Fatal("wrong overlay produced output")
		}
	}
}

func TestManualPDFRefusesFragmentVisibilityPolicy(t *testing.T) {
	source := manualTestPDF("", "0 0 200 300", "BT /F1 12 Tf 20 30 Td (BODY) Tj ET")
	for _, fixture := range []struct {
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
		t.Run(fixture.name, func(t *testing.T) {
			raw, n := manualTestBatch(t, source, map[int][]byte{1: fixture.pdf})
			if result, err := manualOverlayInProcess(raw, n); err == nil || len(result.Bytes) != 0 {
				t.Fatal("overlay accepted fragment whose visibility depends on discarded catalog policy")
			}
		})
	}
	t.Run("literal-text", func(t *testing.T) {
		fragment := manualVisibilityTestPDF("", "", "BT /F1 12 Tf 10 20 Td (/OC is printable text) Tj ET")
		raw, n := manualTestBatch(t, source, map[int][]byte{1: fragment})
		if result, err := manualOverlayInProcess(raw, n); err != nil || len(result.Bytes) == 0 {
			t.Fatal("overlay refused ordinary printable text", err)
		}
	})
}

func TestManualPDFStrictPayloadShapeAndSourceBinding(t *testing.T) {
	source := manualTestPDF("", "0 0 200 300", "")
	overlay := manualTestPDF("", "0 0 200 300", "0 0 10 10 re f")
	raw, n := manualTestBatch(t, source, map[int][]byte{1: overlay})
	for _, kind := range []string{"trailing", "source-swap", "overlay-swap", "duplicate", "unknown", "missing", "null", "short-array"} {
		t.Run(kind, func(t *testing.T) {
			altered := bytes.Clone(raw)
			length := n
			switch kind {
			case "trailing":
				altered = append(altered, 'x')
			case "source-swap":
				altered[n+10] ^= 1
			case "overlay-swap":
				altered[len(altered)-10] ^= 1
			default:
				metadata := string(raw[:n])
				switch kind {
				case "duplicate":
					metadata = strings.Replace(metadata, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
				case "unknown":
					metadata = strings.Replace(metadata, `"schema_version":1`, `"schema_version":1,"other":0`, 1)
				case "missing":
					metadata = strings.Replace(metadata, `"schema_version":1,`, "", 1)
				case "null":
					metadata = strings.Replace(metadata, `"overlays":[`, `"overlays":null,"ignored":[`, 1)
				case "short-array":
					metadata = strings.Replace(metadata, `"overlays":[`, `"overlays":[],"ignored":[`, 1)
				}
				length = len(metadata)
				altered = append([]byte(metadata), raw[n:]...)
			}
			if r, err := manualOverlayInProcess(altered, length); err == nil || len(r.Bytes) != 0 {
				t.Fatal("malformed payload produced bytes")
			}
		})
	}
	g, err := manualGeometryInProcess(source)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(g)
	for _, s := range []string{strings.Replace(string(encoded), `"boxes":[[0,0,200,300]`, `"boxes":[[0,0,200]`, 1), strings.Replace(string(encoded), `"rotation":0`, `"Rotation":0`, 1), strings.Replace(string(encoded), `"user_unit":1`, `"user_unit":null`, 1)} {
		var out PDFManualGeometry
		if decodeManualJSON([]byte(s), &out) == nil {
			t.Fatal("inexact geometry decoded")
		}
	}
}

func TestManualPDFPreservesJPEGEncodingAndFilterParameters(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			img.Set(x, y, color.RGBA{220, 20, 30, 255})
		}
	}
	var jpegBytes bytes.Buffer
	if err := jpeg.Encode(&jpegBytes, img, &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	source := manualTestPDF("", "0 0 200 300", "BT /F1 12 Tf 20 30 Td (BODY) Tj ET")
	overlay := metadataTestPDF([]string{
		`<< /Type /Catalog /Pages 2 0 R >>`, `<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 200 300] >>`,
		`<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im1 5 0 R >> >> /Contents 4 0 R >>`, metadataTestStream("", "q 40 0 0 40 20 20 cm /Im1 Do Q"),
		metadataTestStream("/Type /XObject /Subtype /Image /Width 4 /Height 4 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /DecodeParms << /ColorTransform 1 >>", jpegBytes.String()),
	}, "")
	raw, n := manualTestBatch(t, source, map[int][]byte{1: overlay})
	result, err := manualOverlayInProcess(raw, n)
	if err != nil {
		t.Fatal(err)
	}
	ctx, _, _, err := observePDF(result.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range ctx.Table {
		if entry == nil || entry.Free {
			continue
		}
		sd, ok := entry.Object.(types.StreamDict)
		if !ok || !sd.Image() {
			continue
		}
		found = true
		if !bytes.Equal(sd.Raw, jpegBytes.Bytes()) || sd.Dict.NameEntry("Filter") == nil || *sd.Dict.NameEntry("Filter") != "DCTDecode" || sd.Dict["DecodeParms"] == nil {
			t.Fatal("image encoding or decoding parameters changed")
		}
	}
	if !found {
		t.Fatal("JPEG lost")
	}
}

func TestManualPDFResourceBoundsExternalRefsAndAliasDAG(t *testing.T) {
	ctx, _, err := observePDFCompositionInput(manualTestPDF("", "0 0 200 300", ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"Ref", "OPI"} {
		if _, _, err := manualResourceObject(ctx, nil, types.Dict{key: types.Dict{"F": types.StringLiteral("external.pdf")}}, 0, newManualCopyBudget(&manualResourceUsage{})); err == nil {
			t.Fatal("external reference admitted")
		}
	}
	for _, key := range []string{"F", "FFilter", "FDecodeParms"} {
		sd := types.StreamDict{Dict: types.Dict{key: types.StringLiteral("external")}, Raw: []byte("x")}
		if _, _, err := manualResourceObject(ctx, nil, sd, 0, newManualCopyBudget(&manualResourceUsage{})); err == nil {
			t.Fatal("external stream admitted")
		}
	}
	// Two namespaces share admission counters; each acceptable graph cannot reset
	// a nearly-exhausted aggregate budget for the second input.
	usage := &manualResourceUsage{raw: (64 << 20) - 3}
	sd := types.StreamDict{Dict: types.NewDict(), Raw: []byte("ab")}
	if _, _, err := manualResourceObject(ctx, nil, sd, 0, newManualCopyBudget(usage)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manualResourceObject(ctx, nil, sd, 0, newManualCopyBudget(usage)); err == nil {
		t.Fatal("batch raw bound reset")
	}
	var o types.Object = types.Integer(7)
	for i := 0; i < 25; i++ {
		ir, err := ctx.IndRefForNewObject(types.Array{o, o})
		if err != nil {
			t.Fatal(err)
		}
		o = *ir
	}
	hash, err := manualResourceHash(ctx, o)
	if err != nil || !validPDFSHA(hash) {
		t.Fatalf("compact alias graph did not remain bounded: %v", err)
	}
	cycle, err := ctx.IndRefForNewObject(types.NewDict())
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := ctx.FindTableEntry(cycle.ObjectNumber.Value(), 0)
	if !ok {
		t.Fatal("cycle entry")
	}
	entry.Object = types.Array{*cycle}
	if _, err := manualResourceHash(ctx, *cycle); err == nil {
		t.Fatal("cycle admitted")
	}
}

func TestManualPDFBoundedContentAndChecksum(t *testing.T) {
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	zw.Write([]byte(strings.Repeat("X", 4096)))
	zw.Close()
	sd := types.StreamDict{Dict: types.Dict{"Filter": types.Name("FlateDecode")}, FilterPipeline: []types.PDFFilter{{Name: "FlateDecode"}}, Raw: compressed.Bytes()}
	if _, err := manualContentStream(nil, &sd, 4095); err == nil {
		t.Fatal("expanded content admitted")
	}
	content, err := manualContentStream(nil, &sd, 4096)
	if err != nil || len(content) != 4096 {
		t.Fatalf("bounded content: %v", err)
	}
	sd.Raw = append(bytes.Clone(sd.Raw), 'x')
	if _, err := manualContentStream(nil, &sd, 4096); err == nil {
		t.Fatal("trailing encoded content admitted")
	}
	sd.Raw = bytes.Clone(compressed.Bytes())
	sd.Raw[len(sd.Raw)-1] ^= 1
	if _, err := manualContentStream(nil, &sd, 4096); err == nil {
		t.Fatal("bad checksum admitted")
	}
	sd.Raw = compressed.Bytes()
	sd.FilterPipeline[0].DecodeParms = types.Dict{"Predictor": types.Integer(12)}
	if _, err := manualContentStream(nil, &sd, 4096); err == nil {
		t.Fatal("unbounded predictor admitted")
	}
}

func TestManualPDFFormClippingTransformAndGroupsVerified(t *testing.T) {
	source := manualTestPDF(`/Group << /S /Transparency /CS /DeviceRGB >>`, "0 0 200 300", "BT /F1 12 Tf 20 30 Td (BODY) Tj ET")
	overlay := manualTestPDF(`/Group << /S /Transparency /CS /DeviceRGB >>`, "0 0 200 300", "0 0 10 10 re f")
	for _, kind := range []string{"baseline", "base-box", "overlay-box", "matrix", "base-group", "overlay-group", "page-group", "extra-visibility"} {
		t.Run(kind, func(t *testing.T) {
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
			w, err := composeManualPage(ctx, 1, g.Pages[0], contents[0], overlay, newManualCopyBudget(usage), usage)
			if err != nil {
				t.Fatal(err)
			}
			page, _, attrs, err := ctx.PageDict(1, false)
			if err != nil {
				t.Fatal(err)
			}
			x, err := ctx.DereferenceDict(attrs.Resources["XObject"])
			if err != nil {
				t.Fatal(err)
			}
			base, _, err := ctx.DereferenceStreamDict(x[w.baseName])
			if err != nil {
				t.Fatal(err)
			}
			ov, _, err := ctx.DereferenceStreamDict(x[w.overlayName])
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "base-box":
				base.Dict["BBox"] = types.NewNumberArray(0, 0, 1, 1)
			case "overlay-box":
				ov.Dict["BBox"] = types.NewNumberArray(0, 0, 1, 1)
			case "matrix":
				ov.Dict["Matrix"] = types.NewNumberArray(1, 0, 0, 1, 10, 0)
			case "base-group":
				base.Dict["Group"] = types.Dict{"S": types.Name("Transparency")}
			case "overlay-group":
				delete(ov.Dict, "Group")
			case "page-group":
				page["Group"] = types.Dict{"S": types.Name("Transparency"), "I": types.Boolean(true)}
			case "extra-visibility":
				ov.Dict["OC"] = types.NewDict()
			}
			err = verifyManualPage(ctx, w, newManualCopyBudget(&manualResourceUsage{}))
			if (kind == "baseline") != (err == nil) {
				t.Fatalf("verification %s: %v", kind, err)
			}
		})
	}
}

func TestManualPDFMandatoryWorkerAndRealProtocol(t *testing.T) {
	source := manualTestPDF("/Rotate 90 /CropBox [10 20 110 220] /UserUnit 2", "-30 -40 150 300", "BT /F1 12 Tf 20 30 Td (BODY) Tj ET")
	previous := activePDFWorker.Swap(nil)
	t.Cleanup(func() { activePDFWorker.Store(previous) })
	if _, err := InspectManualPDFWithContext(context.Background(), source); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal("parent parser fallback")
	}
	activePDFWorker.Store(workerTestHelper(t, "protocol"))
	g, err := InspectManualPDFWithContext(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	overlay := manualTestPDF("", "0 0 400 200", "BT /F1 12 Tf 10 15 Td (PLACEMENT) Tj ET")
	r, err := ApplyManualPDFOverlaysWithContext(context.Background(), source, g, map[int][]byte{1: overlay})
	if err != nil || validateManualResult(r) != nil {
		t.Fatalf("worker composition %v", err)
	}
	m := r.Overlay
	m.OutputSHA256 = m.SourceSHA256
	if validateManualManifest(m) == nil {
		t.Fatal("unchanged source accepted as stamping proof")
	}
}

func TestManualPDFCommitmentsPreserveByteStringsAndExactNumbers(t *testing.T) {
	ctx, _, err := observePDFCompositionInput(manualTestPDF("", "0 0 200 300", ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]types.Object{
		{types.StringLiteral(string([]byte{0xff})), types.StringLiteral(string([]byte{0xfe}))},
		{types.Dict{string([]byte{0xff}): types.Integer(1)}, types.Dict{string([]byte{0xfe}): types.Integer(1)}},
		{types.Float(1.00000000000001), types.Float(1.00000000000002)},
	} {
		a, err := manualResourceHash(ctx, pair[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := manualResourceHash(ctx, pair[1])
		if err != nil || a == b {
			t.Fatal("distinct PDF resource bytes/numbers collapsed")
		}
	}
}

func serveMalformedManualForTest(mode string) error {
	reader := bufio.NewReaderSize(os.Stdin, pdfWorkerHeaderLimit)
	var request pdfWorkerRequest
	if err := readPDFWorkerHeader(reader, &request); err != nil {
		return err
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	result, err := manualOverlayInProcess(raw, request.ManualMetadataLength)
	if err != nil {
		return err
	}
	response := pdfWorkerResponse{ProtocolVersion: pdfWorkerProtocolVersion, Length: len(result.Bytes), Report: &result.Report, ManualOverlay: &result.Overlay}
	switch mode {
	case "manual-wrong-binding":
		response.ManualOverlay.DescriptorSHA256 = strings.Repeat("0", 64)
	case "manual-wrong-report":
		response.Report.BytesAfter++
	case "manual-missing-proof":
		response.ManualOverlay = nil
	case "manual-no-op":
		start := request.ManualMetadataLength
		result.Bytes = raw[start : start+int(result.Overlay.SourceBytes)]
		response.Length = len(result.Bytes)
		response.ManualOverlay.OutputSHA256 = response.ManualOverlay.SourceSHA256
		response.ManualOverlay.OutputBytes = int64(len(result.Bytes))
		response.Report.BytesAfter = int64(len(result.Bytes))
		response.Report.PDF.OutputSHA256 = pdfSHA(result.Bytes)
	}
	header, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintf(os.Stdout, "%s\n", header); err != nil {
		return err
	}
	_, err = os.Stdout.Write(result.Bytes)
	return err
}

func TestManualPDFRejectsChildProofSubstitutionAndStaleWorker(t *testing.T) {
	source := manualTestPDF("", "0 0 200 300", "")
	overlay := manualTestPDF("", "0 0 200 300", "0 0 10 10 re f")
	g, err := manualGeometryInProcess(source)
	if err != nil {
		t.Fatal(err)
	}
	previous := activePDFWorker.Load()
	t.Cleanup(func() { activePDFWorker.Store(previous) })
	for _, mode := range []string{"manual-wrong-binding", "manual-wrong-report", "manual-missing-proof", "manual-no-op"} {
		t.Run(mode, func(t *testing.T) {
			activePDFWorker.Store(workerTestHelper(t, mode))
			r, err := ApplyManualPDFOverlaysWithContext(context.Background(), source, g, map[int][]byte{1: overlay})
			if !errors.Is(err, ErrPDFWorkerUnavailable) || len(r.Bytes) != 0 {
				t.Fatalf("substitution admitted: %v", err)
			}
		})
	}
	w := workerTestHelper(t, "previous-version")
	if _, _, err := w.run(context.Background(), pdfWorkerRequest{Operation: "probe"}, nil); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal("stale worker admitted")
	}
	for _, header := range []string{
		`{"protocol_version":3,"operation":"probe","length":0,"manual_metadata_length":0}`,
		`{"protocol_version":3,"operation":"manual-inspect-v1","length":10,"manual_metadata_length":1}`,
		`{"protocol_version":3,"operation":"manual-overlay-v1","length":10}`,
		`{"protocol_version":3,"operation":"manual-overlay-v1","length":10,"manual_metadata_length":10}`,
	} {
		var request pdfWorkerRequest
		if readPDFWorkerHeader(bufio.NewReader(strings.NewReader(header+"\n")), &request) == nil {
			t.Fatal("invalid operation framing admitted")
		}
	}
}
