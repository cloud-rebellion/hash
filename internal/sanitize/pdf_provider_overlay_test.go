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
	"io"
	"os"
	"strings"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

func providerBindingsTest() PDFProviderOverlayBindings {
	h := strings.Repeat("a", 64)
	return PDFProviderOverlayBindings{SourceCommitment: h, SigningPlanSHA256: h, BrandingSHA256: h, PolicySHA256: h, GrantSHA256: h, Font: "Caveat", SpanSHA256: h, SignatureFontSHA256: h, InterFontSHA256: h, DisclosureSHA256: h, RecipeSHA256: h}
}

// The embedded stream is a synthetic resource graph, not a usable font or
// renderer/glyph acceptance. These tests exercise PDF parsing and confinement.
func providerFragmentTestPDF(index int, content, resourceExtra string) []byte {
	r := providerRectangles()[index]
	font := []string{"Caveat-Regular", "Inter-Regular"}[index]
	return metadataTestPDF([]string{
		`<< /Type /Catalog /Pages 2 0 R >>`,
		fmt.Sprintf(`<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 %.9f %.9f] >>`, r[2], r[3]),
		`<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> ` + resourceExtra + ` >> >>`,
		metadataTestStream("", content),
		`<< /Type /Font /Subtype /TrueType /BaseFont /` + font + ` /FirstChar 32 /LastChar 32 /Widths [600] /FontDescriptor 6 0 R /Encoding /WinAnsiEncoding >>`,
		`<< /Type /FontDescriptor /FontName /` + font + ` /Flags 32 /FontBBox [0 -200 1000 1000] /ItalicAngle 0 /Ascent 1000 /Descent -200 /CapHeight 800 /StemV 80 /FontFile2 7 0 R >>`,
		metadataTestStream("/Length1 4", "TEST"),
	}, "")
}

func providerOverlayTestResult(t *testing.T) (PDFProviderOverlayResult, []byte, []byte, []byte) {
	t.Helper()
	// A balanced source can still leave a changed transform and clip. The
	// overlay wrapper must restore both before its independent placement.
	base := metadataTestPDF([]string{
		`<< /Type /Catalog /Pages 2 0 R >>`,
		`<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 594.959960 841.919980] >>`,
		`<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>`,
		metadataTestStream("", "2 0 0 2 11 13 cm 0 0 10 10 re W n BT /F1 12 Tf 30 40 Td (VISIBLE_SIGNING_PAGE) Tj ET"),
		`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`,
	}, "")
	sig := providerFragmentTestPDF(0, "q 1 0 0 1 -10000 -10000 cm 0 0 20000 20000 re f Q BT /F1 12 Tf ( ) Tj ET", "")
	disc := providerFragmentTestPDF(1, "BT /F1 7.5 Tf ( ) Tj ET", "")
	r, err := providerOverlayInProcess("provider-overlay", base, sig, disc, providerBindingsTest())
	if err != nil {
		t.Fatal("synthetic confined worker fixture", err)
	}
	return r, base, sig, disc
}

func TestPDFProviderOverlayConfinesFormsAndPreservesOriginalContent(t *testing.T) {
	r, base, _, _ := providerOverlayTestResult(t)
	if ValidatePDFProviderOverlayResult(r) != nil {
		t.Fatal("observed result invalid")
	}
	before, _, _ := observePDFCompositionInput(base)
	after, _, _, err := observePDF(r.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := providerContentDigests(before)
	current, _ := providerContentDigests(after)
	if r.Overlay.OriginalContentSHA256 != providerContentSHA(old) || !bytes.HasPrefix(current[0], append([]byte("q\n"), old[0]...)) || !bytes.Contains(current[0], []byte("\nQ\nq 1 0 0 1 ")) || verifyProviderForms(after, r.Overlay.Forms) != nil {
		t.Fatal("original painting or independent fixed Form placement changed")
	}
	for i, f := range r.Overlay.Forms {
		if f.RectangleMicroPoints != providerRectangleMicros(i) {
			t.Fatal("worker proof does not bind clipping rectangle")
		}
	}
	response, err := json.Marshal(pdfWorkerResponse{ProtocolVersion: pdfWorkerProtocolVersion, Length: len(r.Bytes), Report: &r.Report, ProviderOverlay: &r.Overlay})
	if err != nil || len(response)+1 > pdfWorkerHeaderLimit {
		t.Fatal("new proof exceeds unchanged isolated header bound")
	}
}

func TestPDFProviderOverlayRejectsUnconfinedOrMalformedFragments(t *testing.T) {
	base := signingPageTestPDF("", "")
	good := providerFragmentTestPDF(1, "BT /F1 7.5 Tf ( ) Tj ET", "")
	for _, tt := range []struct {
		name string
		raw  []byte
	}{
		{"full-page", signingPageTestPDF("", "")},
		{"restore-underflow", providerFragmentTestPDF(0, "Q", "")},
		{"unbalanced-save", providerFragmentTestPDF(0, "q 0 0 10 10 re f", "")},
		{"indirect-paint", providerFragmentTestPDF(0, "/Foreign Do", "")},
		{"inline-image", providerFragmentTestPDF(0, "BI /W 1 /H 1 ID x EI", "")},
		{"shading", providerFragmentTestPDF(0, "/Shade sh", "")},
		{"nested-resources", providerFragmentTestPDF(0, "BT /F1 12 Tf ( ) Tj ET", "/XObject << >>")},
		{"transparency", providerFragmentTestPDF(0, "BT /F1 12 Tf ( ) Tj ET", "/ExtGState << /GS << /Type /ExtGState /ca 0.5 >> >>")},
		{"wrong-font", bytes.Replace(providerFragmentTestPDF(0, "BT /F1 12 Tf ( ) Tj ET", ""), []byte("Caveat-Regular"), []byte("Remote-Regular"), -1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := providerOverlayInProcess("provider-overlay", base, tt.raw, good, providerBindingsTest())
			if err == nil || len(r.Bytes) != 0 {
				t.Fatal("invalid fragment yielded paintable result")
			}
		})
	}
}

func TestPDFProviderOperatorAdmissionCannotEscapeThroughOperands(t *testing.T) {
	for _, raw := range []string{"q BT /F1 12 Tf (Q /X Do literal) Tj ET Q", "q [1 2 3] 0 d /Span << /ActualText (Q) >> BDC BT <2051> Tj ET EMC Q"} {
		if err := validateProviderOperators([]byte(raw), true); err != nil {
			t.Fatal("complete inert operands refused", err)
		}
	}
	for _, raw := range []string{"Q", "q", "BT BT ET ET", "/X Do", "/S sh", "BI x EI", "NaN 0 cm", "1e3 0 cm", "[1 Q] TJ", "<< /A Q >> BDC EMC", "(unterminated", "<xz> Tj", "q BX EX Q", "EMC"} {
		if validateProviderOperators([]byte(raw), true) == nil {
			t.Fatal("unsafe graphics stream admitted")
		}
	}
}

func TestPDFProviderProofStrictShapeAndPurposeBindings(t *testing.T) {
	r, _, _, _ := providerOverlayTestResult(t)
	raw, _ := json.Marshal(r.Overlay)
	if _, err := DecodePDFProviderOverlayManifest(raw); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for _, kind := range []string{"null", "omitted", "aliased", "short-forms", "rectangle"} {
		t.Run(kind, func(t *testing.T) {
			var f map[string]json.RawMessage
			_ = json.Unmarshal(raw, &f)
			switch kind {
			case "null":
				f["base_bytes"] = json.RawMessage("null")
			case "omitted":
				delete(f, "bindings_sha256")
			case "aliased":
				f["Bindings_sha256"] = f["bindings_sha256"]
				delete(f, "bindings_sha256")
			case "short-forms":
				f["forms"] = json.RawMessage("[]")
			case "rectangle":
				m := r.Overlay
				m.Forms[0].RectangleMicroPoints[0]++
				f["forms"], _ = json.Marshal(m.Forms)
			}
			bad, _ := json.Marshal(f)
			if _, err := DecodePDFProviderOverlayManifest(bad); err == nil {
				t.Fatal("partial or drifting proof admitted")
			}
		})
	}
	b := providerBindingsTest()
	before := PDFProviderOverlayBindingsSHA256(b)
	b.SourceCommitment = strings.Repeat("b", 64)
	if before == PDFProviderOverlayBindingsSHA256(b) || before == pdfSHA(raw) {
		t.Fatal("bindings digest lacks exact input/purpose separation")
	}
}

func TestPDFProviderWorkerUsesFreshOperationAndRefusesStaleChild(t *testing.T) {
	r, base, sig, disc := providerOverlayTestResult(t)
	_ = r
	bindings := providerBindingsTest()
	raw := append(append(bytes.Clone(base), sig...), disc...)
	req := pdfWorkerRequest{Operation: pdfProviderOverlayOperation, Asset: "provider-overlay", Length: len(raw), BodyLength: len(base), SignatureLength: len(sig), DisclosureLength: len(disc), ProviderBindings: &bindings}
	w := workerTestHelper(t, "protocol")
	response, out, err := w.run(context.Background(), req, raw)
	if err != nil || response.ProviderOverlay == nil || len(out) == 0 {
		t.Fatal("new operation did not receive actual child proof", err)
	}
	w = workerTestHelper(t, "short")
	if _, body, err := w.run(context.Background(), req, raw); !errors.Is(err, ErrPDFWorkerUnavailable) || len(body) != 0 {
		t.Fatal("stale/invalid worker yielded usable evidence")
	}
	for _, tt := range []struct {
		name, mode, operation string
		want                  error
	}{
		{"known-fixed-stage", "provider-refusal-stage", pdfProviderOverlayOperation, ErrPDFProviderOverlay},
		{"unknown-stage", "provider-refusal-unknown-stage", pdfProviderOverlayOperation, ErrPDFWorkerUnavailable},
		{"stage-on-legacy-operation", "provider-refusal-stage", "pages", ErrPDFWorkerUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := req
			request.Operation = tt.operation
			if _, body, err := workerTestHelper(t, tt.mode).run(context.Background(), request, raw); !errors.Is(err, tt.want) || len(body) != 0 || strings.Contains(err.Error(), "PRIVATE_PARSER_OR_CONTRACT_TEXT") {
				t.Fatal("refusal diagnostic escaped vocabulary/operation or returned PDF bytes")
			}
		})
	}
	t.Run("actual-child-redacts-resource-name", func(t *testing.T) {
		// Equal byte length retains the fixture's original xref offsets.
		bad := bytes.ReplaceAll(sig, []byte("Caveat-Regular"), []byte("SECRET-Regular"))
		body := append(append(bytes.Clone(base), bad...), disc...)
		request := req
		request.Length, request.SignatureLength = len(body), len(bad)
		if _, out, err := workerTestHelper(t, "protocol").run(context.Background(), request, body); !errors.Is(err, ErrPDFProviderOverlay) || len(out) != 0 || err.Error() != "sanitize: invalid provider overlay: font-name" {
			t.Fatal("actual worker omitted fixed stage or leaked the resource name")
		}
	})
	old := activePDFWorker.Load()
	activePDFWorker.Store(nil)
	t.Cleanup(func() { activePDFWorker.Store(old) })
	if _, err := ApplyProviderOverlayWithContext(context.Background(), "provider-overlay", base, sig, disc, bindings); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal("no isolated worker fell back to parent parsing", err)
	}
}

func serveMalformedProviderOverlayForTest(mode string) error {
	reader := bufio.NewReader(os.Stdin)
	var req pdfWorkerRequest
	if err := readPDFWorkerHeader(reader, &req); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(reader, int64(req.Length)+1))
	if err != nil || len(raw) != req.Length || !validProviderRequest(req, len(raw)) {
		return ErrPDFProviderOverlay
	}
	b, s := req.BodyLength, req.SignatureLength
	result, err := providerOverlayInProcess(req.Asset, raw[:b], raw[b:b+s], raw[b+s:], *req.ProviderBindings)
	if err != nil {
		return err
	}
	response := pdfWorkerResponse{ProtocolVersion: pdfWorkerProtocolVersion, Length: len(result.Bytes), Report: &result.Report, ProviderOverlay: &result.Overlay}
	switch mode {
	case "provider-wrong-input":
		response.ProviderOverlay.BaseSHA256 = strings.Repeat("b", 64)
	case "provider-wrong-output":
		response.ProviderOverlay.OutputSHA256 = strings.Repeat("b", 64)
	case "provider-wrong-bindings":
		response.ProviderOverlay.BindingsSHA256 = strings.Repeat("b", 64)
	case "provider-missing-proof":
		response.ProviderOverlay = nil
	case "provider-wrong-report":
		response.Report.PDF.SourceSHA256 = strings.Repeat("b", 64)
	default:
		return ErrPDFProviderOverlay
	}
	header, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if _, err = os.Stdout.Write(append(header, '\n')); err != nil {
		return err
	}
	_, err = os.Stdout.Write(result.Bytes)
	return err
}

func TestPDFProviderParentRefusesChildInputAndProofSubstitution(t *testing.T) {
	_, base, sig, disc := providerOverlayTestResult(t)
	b := providerBindingsTest()
	raw := append(append(bytes.Clone(base), sig...), disc...)
	req := pdfWorkerRequest{Operation: pdfProviderOverlayOperation, Asset: "provider-overlay", Length: len(raw), BodyLength: len(base), SignatureLength: len(sig), DisclosureLength: len(disc), ProviderBindings: &b}
	for _, mode := range []string{"provider-wrong-input", "provider-wrong-output", "provider-wrong-bindings", "provider-missing-proof", "provider-wrong-report"} {
		t.Run(mode, func(t *testing.T) {
			w := workerTestHelper(t, mode)
			if _, body, err := w.run(context.Background(), req, raw); !errors.Is(err, ErrPDFWorkerUnavailable) || len(body) != 0 || len(w.slots) != 0 {
				t.Fatal("parent accepted substituted input/proof or leaked capacity", err)
			}
		})
	}
}

func TestPDFProviderResourcesHaveAggregateExpansionBound(t *testing.T) {
	ctx, _, err := observePDFCompositionInput(providerFragmentTestPDF(0, "BT /F1 12 Tf ( ) Tj ET", ""))
	if err != nil {
		t.Fatal(err)
	}
	_, _, attrs, err := ctx.PageDict(1, false)
	if err != nil {
		t.Fatal(err)
	}
	budget := &providerCopyBudget{decodedBytes: 16 << 20}
	if _, _, err := copyProviderObject(ctx, nil, attrs.Resources, 0, budget); !errors.Is(err, ErrPDFProviderOverlay) {
		t.Fatal("aggregate resource expansion not bounded")
	}
	if _, _, err := copyProviderObject(ctx, nil, types.Dict{"XObject": types.Dict{}}, 0, new(providerCopyBudget)); !errors.Is(err, ErrPDFProviderOverlay) {
		t.Fatal("nested external paint resource admitted")
	}
	if validateProviderOperators([]byte(strings.Repeat("[", 65)+strings.Repeat("]", 65)+" TJ"), true) == nil {
		t.Fatal("deep operand graph admitted")
	}
}

func TestPDFProviderInspectsOriginalBaseBeforeAnyNewPainting(t *testing.T) {
	sig := providerFragmentTestPDF(0, "BT /F1 12 Tf ( ) Tj ET", "")
	disc := providerFragmentTestPDF(1, "BT /F1 7.5 Tf ( ) Tj ET", "")
	for _, tt := range []struct {
		name string
		raw  []byte
	}{
		{"active", signingPageTestPDF("", "/OpenAction 8 0 R", `<< /Type /Action /S /JavaScript /JS (synthetic) >>`)},
		{"aliased-info", signingPageTestPDF("/VisualAlias 6 0 R", "")},
		{"shifted-media", signingPageTestPDF("/MediaBox [-1 0 594.959960 841.919980]", "")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := providerOverlayInProcess("provider-overlay", tt.raw, sig, disc, providerBindingsTest())
			if err == nil || len(r.Bytes) != 0 {
				t.Fatal("unsafe base yielded provider evidence")
			}
		})
	}
}

// These Type3 outlines reproduce only the observed resource/operator profile;
// they are synthetic programs, not usable-font or actual renderer acceptance.
func providerType3DisclosureTestPDF() []byte {
	r := providerRectangles()[1]
	return metadataTestPDF([]string{
		`<< /Type /Catalog /Pages 2 0 R >>`,
		fmt.Sprintf(`<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 %.9f %.9f] >>`, r[2], r[3]),
		`<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>`,
		metadataTestStream("", "BT /F1 7.5 Tf <01> Tj ET"),
		`<< /Type /Font /Subtype /Type3 /FontMatrix [0.00048828125 0 0 -0.00048828125 0 0] /FirstChar 0 /LastChar 1 /FontBBox [20 442 1636 -1856] /CIDToGIDMap /Identity /ToUnicode 9 0 R /FontDescriptor 6 0 R /Widths [1344 1522] /Encoding << /Type /Encoding /Differences [0 /g0 /g26] >> /CharProcs << /g0 7 0 R /g26 8 0 R >> >>`,
		`<< /Type /FontDescriptor /FontName /AAAAAA+Inter-Regular /FontFamily (Inter) /FontStretch /Normal /FontWeight 400 /ItalicAngle 0 /CapHeight -1490 /StemV 109 /XHeight 1118 /Flags 4 >>`,
		metadataTestStream("", "1344 0 328 -1856 1016 416 d1\n328 -1856 688 2272 re\nf\n"),
		metadataTestStream("", "1522 0 180 -1490 1342 0 d1\n180 0 m\n180 -1490 l\n370 -1490 l\n370 0 l\nh\nf\n"),
		metadataTestStream("", "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n1 beginbfchar\n<01> <0054>\nendbfchar\nendcmap\nCMapName currentdict /CMap defineresource pop\nend end"),
	}, "")
}

func providerType3TestResources(t *testing.T) (*model.Context, types.Dict, types.Dict) {
	t.Helper()
	ctx, _, err := observePDFCompositionInput(providerType3DisclosureTestPDF())
	if err != nil {
		t.Fatal("synthetic Type3 disclosure resource fixture", err)
	}
	_, _, attrs, err := ctx.PageDict(1, false)
	if err != nil {
		t.Fatal(err)
	}
	fonts, err := ctx.DereferenceDict(attrs.Resources["Font"])
	if err != nil {
		t.Fatal(err)
	}
	font, err := ctx.DereferenceDict(fonts["F1"])
	if err != nil {
		t.Fatal(err)
	}
	return ctx, attrs.Resources, font
}

func providerType3TestStream(raw []byte, compressed bool) types.StreamDict {
	dict := types.Dict{}
	var filters []types.PDFFilter
	if compressed {
		var b bytes.Buffer
		writer := zlib.NewWriter(&b)
		_, _ = writer.Write(raw)
		_ = writer.Close()
		raw = b.Bytes()
		dict["Filter"] = types.Name("FlateDecode")
		filters = []types.PDFFilter{{Name: "FlateDecode"}}
	}
	dict["Length"] = types.Integer(len(raw))
	return types.StreamDict{Dict: dict, Raw: bytes.Clone(raw), FilterPipeline: filters}
}

func TestPDFProviderType3DisclosurePreservesConfinedPaintingAndProof(t *testing.T) {
	base := signingPageTestPDF("", "")
	signature := providerFragmentTestPDF(0, "BT /F1 12 Tf ( ) Tj ET", "")
	disclosure := providerType3DisclosureTestPDF()
	bindings := providerBindingsTest()
	bindings.InterFontSHA256 = providerInterFontSHA256
	result, err := providerOverlayInProcess("provider-overlay", base, signature, disclosure, bindings)
	if err != nil || ValidatePDFProviderOverlayResult(result) != nil || result.Overlay.DisclosureSHA256 != pdfSHA(disclosure) {
		t.Fatal("confined Type3 disclosure lost actual result/proof", err)
	}
	final, _, _, err := observePDF(result.Bytes)
	if err != nil || verifyProviderForms(final, result.Overlay.Forms) != nil {
		t.Fatal("cleaned Type3 resources changed their semantic hash")
	}
	ctx, resources, font := providerType3TestResources(t)
	font["Resources"] = types.Dict{}
	if err := validateProviderResources(ctx, resources, "Inter-Regular", true); err != nil {
		t.Fatal("bounded synthetic Type3 resource profile refused", err)
	}
	glyphs, _ := ctx.DereferenceDict(font["CharProcs"])
	for _, o := range glyphs {
		stream, _, err := ctx.DereferenceStreamDict(o)
		if err != nil || stream == nil || len(stream.Content) == 0 || len(stream.Content) > providerType3StreamLimit {
			t.Fatal("indirect glyph lost its validated bounded content before copy")
		}
	}
	cmap, _, err := ctx.DereferenceStreamDict(font["ToUnicode"])
	if err != nil || cmap == nil || len(cmap.Content) == 0 {
		t.Fatal("indirect ToUnicode lost validated bounded content before copy")
	}
}

func TestPDFProviderType3RefusesForeignScopeAndMalformedFontMetadata(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*model.Context, types.Dict)
	}{
		{"missing-identity", func(ctx *model.Context, f types.Dict) {
			d, _ := ctx.DereferenceDict(f["FontDescriptor"])
			delete(d, "FontName")
		}},
		{"foreign-identity", func(ctx *model.Context, f types.Dict) {
			d, _ := ctx.DereferenceDict(f["FontDescriptor"])
			d["FontName"] = types.Name("AAAAAA+OTHER-Regular")
		}},
		{"foreign-family", func(ctx *model.Context, f types.Dict) {
			d, _ := ctx.DereferenceDict(f["FontDescriptor"])
			d["FontFamily"] = types.StringLiteral("OTHER")
		}},
		{"foreign-weight", func(ctx *model.Context, f types.Dict) {
			d, _ := ctx.DereferenceDict(f["FontDescriptor"])
			d["FontWeight"] = types.Integer(700)
		}},
		{"font-file", func(ctx *model.Context, f types.Dict) {
			d, _ := ctx.DereferenceDict(f["FontDescriptor"])
			d["FontFile2"] = f["ToUnicode"]
		}},
		{"contradictory-base-font", func(_ *model.Context, f types.Dict) { f["BaseFont"] = types.Name("AAAAAA+Inter-Regular") }},
		{"translated-matrix", func(_ *model.Context, f types.Dict) {
			f["FontMatrix"] = types.NewNumberArray(1.0/2048, 0, 0, -1.0/2048, 1, 0)
		}},
		{"wrong-box-orientation", func(_ *model.Context, f types.Dict) { f["FontBBox"] = types.NewNumberArray(20, -1856, 1636, 442) }},
		{"oversized-box", func(_ *model.Context, f types.Dict) { f["FontBBox"] = types.NewNumberArray(20, 442, 9000, -1856) }},
		{"negative-width", func(_ *model.Context, f types.Dict) { f["Widths"] = types.NewNumberArray(-1, 1522) }},
		{"mismatched-width", func(_ *model.Context, f types.Dict) { f["Widths"] = types.NewNumberArray(1000, 1522) }},
		{"short-widths", func(_ *model.Context, f types.Dict) { f["Widths"] = types.NewNumberArray(1344) }},
		{"undefined-encoding", func(_ *model.Context, f types.Dict) {
			f["Encoding"] = types.Dict{"Type": types.Name("Encoding"), "Differences": types.Array{types.Integer(0), types.Name("g0"), types.Name("gFF")}}
		}},
		{"encoding-code-reset", func(_ *model.Context, f types.Dict) {
			f["Encoding"] = types.Dict{"Type": types.Name("Encoding"), "Differences": types.Array{types.Integer(0), types.Name("g0"), types.Integer(1)}}
		}},
		{"inherited-resource-lookup", func(_ *model.Context, f types.Dict) { f["Resources"] = types.Dict{"Font": types.Dict{}} }},
		{"external-image-resource", func(_ *model.Context, f types.Dict) { f["Resources"] = types.Dict{"XObject": types.Dict{}} }},
		{"glyph-inherited-paint", func(ctx *model.Context, f types.Dict) {
			glyphs, _ := ctx.DereferenceDict(f["CharProcs"])
			glyphs["g26"] = providerType3TestStream([]byte("1522 0 180 -1490 1342 0 d1\n/X Do"), true)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, resources, font := providerType3TestResources(t)
			tt.mutate(ctx, font)
			if err := validateProviderResources(ctx, resources, "Inter-Regular", true); !errors.Is(err, ErrPDFProviderOverlay) {
				t.Fatal("malformed Type3 identity/geometry/encoding/resource state admitted")
			}
		})
	}
	t.Run("signature-slot", func(t *testing.T) {
		ctx, resources, _ := providerType3TestResources(t)
		if err := validateProviderResources(ctx, resources, "Inter-Regular", false); !errors.Is(err, ErrPDFProviderOverlay) {
			t.Fatal("Type3 escaped disclosure-only gate")
		}
	})
	t.Run("wrong-inter-pin", func(t *testing.T) {
		bindings := providerBindingsTest()
		if out, err := providerOverlayInProcess("provider-overlay", signingPageTestPDF("", ""), providerFragmentTestPDF(0, "BT /F1 12 Tf ( ) Tj ET", ""), providerType3DisclosureTestPDF(), bindings); !errors.Is(err, ErrPDFProviderOverlay) || len(out.Bytes) != 0 {
			t.Fatal("unapproved Inter pin yielded a paintable Type3 disclosure")
		}
	})
}

func TestPDFProviderType3GlyphProgramsCannotInvokePageResources(t *testing.T) {
	prefix := "1344 0 328 -1856 1016 416 d1\n"
	for _, tt := range []struct{ name, program string }{
		{"indirect-paint", prefix + "/X Do"},
		{"text", prefix + "BT /F1 12 Tf (TEXT) Tj ET"},
		{"image", prefix + "BI /W 1 /H 1 ID x EI"},
		{"shading", prefix + "/S sh"},
		{"color", prefix + "1 0 0 rg"},
		{"transform", prefix + "1 0 0 1 0 0 cm"},
		{"graphics-state", prefix + "/GS gs"},
		{"restore", prefix + "Q"},
		{"d0", "1344 0 d0"},
		{"second-metrics", prefix + prefix},
		{"metrics-not-first", "0 0 m\n" + prefix},
		{"malformed-arity", prefix + "0 0 0 m f"},
		{"unfinished-path", prefix + "0 0 m"},
		{"trailing-operands", prefix + "1 2"},
		{"exponential-number", prefix + "1e3 0 m f"},
		{"oversized-number", prefix + "9000 0 m f"},
		{"degenerate-painted-metrics", "1344 0 0 0 0 0 d1\n0 0 1 1 re f"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := validateProviderType3Glyph([]byte(tt.program)); !errors.Is(err, ErrPDFProviderOverlay) {
				t.Fatal("glyph invoked inherited painting or malformed numeric operands")
			}
		})
	}
	if _, err := validateProviderType3Glyph([]byte("576 0 0 0 0 0 d1")); err != nil {
		t.Fatal("observed metrics-only space glyph refused", err)
	}
	if _, err := validateProviderType3Glyph([]byte(prefix + "328 -1856 m\n400 -1800 500 -1700 600 -1600 c\n1016 416 l\nh f")); err != nil {
		t.Fatal("observed cubic outline refused", err)
	}
}

func TestPDFProviderType3StrictDecodeBoundsEveryFontGraph(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*types.StreamDict)
	}{
		{"limit-plus-one", func(s *types.StreamDict) {
			*s = providerType3TestStream(bytes.Repeat([]byte("x"), providerType3StreamLimit+1), true)
		}},
		{"unfiltered-limit-plus-one", func(s *types.StreamDict) {
			*s = providerType3TestStream(bytes.Repeat([]byte("x"), providerType3StreamLimit+1), false)
		}},
		{"truncated-zlib", func(s *types.StreamDict) { s.Raw = s.Raw[:len(s.Raw)-1]; s.Dict["Length"] = types.Integer(len(s.Raw)) }},
		{"bad-zlib-checksum", func(s *types.StreamDict) { s.Raw[len(s.Raw)-1] ^= 1 }},
		{"trailing-zlib-member", func(s *types.StreamDict) { s.Raw = append(s.Raw, 0); s.Dict["Length"] = types.Integer(len(s.Raw)) }},
		{"cached-bad-zlib", func(s *types.StreamDict) { s.Content = []byte("actual"); s.Raw[len(s.Raw)-1] ^= 1 }},
		{"contradictory-cache", func(s *types.StreamDict) { s.Content = []byte("different") }},
		{"decode-parameters", func(s *types.StreamDict) { s.Dict["DecodeParms"] = types.Dict{} }},
		{"filter-array", func(s *types.StreamDict) { s.Dict["Filter"] = types.Array{types.Name("FlateDecode")} }},
		{"external-stream", func(s *types.StreamDict) { s.Dict["F"] = types.StringLiteral("external") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, _, _ := providerType3TestResources(t)
			stream := providerType3TestStream([]byte("actual"), true)
			tt.mutate(&stream)
			if _, err := providerType3Stream(ctx, stream, new(providerType3Budget)); !errors.Is(err, ErrPDFProviderOverlay) {
				t.Fatal("unsafe encoded Type3 stream admitted")
			}
		})
	}
	t.Run("exact-stream-limit", func(t *testing.T) {
		ctx, _, _ := providerType3TestResources(t)
		for _, compressed := range []bool{false, true} {
			stream := providerType3TestStream(bytes.Repeat([]byte("x"), providerType3StreamLimit), compressed)
			out, err := providerType3Stream(ctx, stream, new(providerType3Budget))
			if err != nil || len(out.Content) != providerType3StreamLimit {
				t.Fatal("exact bounded stream limit refused", err)
			}
		}
	})
	for _, tt := range []struct {
		name      string
		glyphs    int
		wantError bool
	}{{"two-fonts-within-budget", 7, false}, {"two-fonts-exceed-shared-budget", 16, true}} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, resources, font := providerType3TestResources(t)
			fonts, _ := ctx.DereferenceDict(resources["Font"])
			for index := 0; index < 2; index++ {
				copy := font.Clone().(types.Dict)
				widths, differences, glyphs := types.Array{}, types.Array{types.Integer(0)}, types.Dict{}
				for n := 0; n < tt.glyphs; n++ {
					name := fmt.Sprintf("g%X", n)
					program := "1344 0 328 -1856 1016 416 d1\n328 -1856 688 2272 re\nf\n%"
					program += strings.Repeat("x", providerType3StreamLimit-len(program))
					glyphs[name] = providerType3TestStream([]byte(program), true)
					widths = append(widths, types.Integer(1344))
					differences = append(differences, types.Name(name))
				}
				copy["LastChar"], copy["Widths"], copy["CharProcs"] = types.Integer(tt.glyphs-1), widths, glyphs
				copy["Encoding"] = types.Dict{"Type": types.Name("Encoding"), "Differences": differences}
				copy["ToUnicode"] = providerType3TestStream(bytes.Repeat([]byte("x"), providerType3StreamLimit), true)
				fonts[fmt.Sprintf("F%d", index+1)] = copy
			}
			err := validateProviderResources(ctx, resources, "Inter-Regular", true)
			if (err != nil) != tt.wantError || (tt.wantError && !errors.Is(err, ErrPDFProviderOverlay)) {
				t.Fatal("Type3 decoded budget reset across font faces")
			}
		})
	}
}
