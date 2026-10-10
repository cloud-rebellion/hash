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
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/malwarescan"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

func signingPageTestPDF(pageExtra, catalogExtra string, extraObjects ...string) []byte {
	objects := []string{
		`<< /Type /Catalog /Pages 2 0 R /Metadata 7 0 R ` + catalogExtra + ` >>`,
		`<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 594.959960 841.919980] >>`,
		`<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> /Metadata 7 0 R ` + pageExtra + ` >>`,
		metadataTestStream("", "BT /F1 12 Tf 30 40 Td (VISIBLE_SIGNING_PAGE) Tj ET"),
		`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`,
		`<< /Title (PRIVATE_METADATA_SIGNING_TITLE) /Author (PRIVATE_METADATA_SIGNING_AUTHOR) >>`,
		metadataTestStream("/Type /Metadata /Subtype /XML", `<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>PRIVATE_METADATA_SIGNING_XMP</dc:title></rdf:Description></rdf:RDF></x:xmpmeta>`),
	}
	return metadataTestPDF(append(objects, extraObjects...), "/Info 6 0 R")
}

func compositionTestResult(t *testing.T) (PDFCompositionResult, []byte, []byte) {
	t.Helper()
	body, suffix := sensitiveMetadataPDF(), signingPageTestPDF("", "")
	result, err := composeSigningPageInProcess("html-composed-pdf", body, suffix)
	if err != nil {
		t.Fatal(err)
	}
	return result, body, suffix
}

func TestPDFCompositionPreservesBodyAndBindsFinalObservedBytes(t *testing.T) {
	result, body, suffix := compositionTestResult(t)
	if ValidatePDFCompositionResult(result) != nil || result.Composition.BodySHA256 != pdfSHA(body) || result.Composition.SigningPageSHA256 != pdfSHA(suffix) || result.Composition.BodyPages != 1 || result.Composition.FinalPages != 2 {
		t.Fatal("composition does not bind its exact inputs and final output")
	}
	if result.Report.PDF.SourceSHA256 == pdfSHA(body) || result.Report.PDF.SourceSHA256 == pdfSHA(suffix) || result.Report.PDF.SourceSHA256 != result.Composition.MergedSHA256 {
		t.Fatal("intake proof does not identify the merged processing copy")
	}
	if bytes.Contains(result.Bytes, []byte("PRIVATE_METADATA_")) {
		t.Fatal("source metadata survived composition")
	}
	ctx, _, geometry, err := observePDF(result.Bytes)
	if err != nil || ctx.PageCount != 2 || geometry != result.Composition.GeometrySHA256 || verifyGeneratedInfo(ctx) != nil {
		t.Fatal("final PDF geometry or metadata was not verified", err)
	}
	pages, err := pdfCompositionGeometry(ctx)
	if err != nil || pages[0].Rotation != 90 || pages[0].UserUnit != 1.5 || !isCanonicalSigningPage(pages[1]) || pdfCompositionGeometrySHA(pages[:1]) != result.Composition.BodyGeometrySHA256 {
		t.Fatal("body geometry or appended page position changed", err)
	}
	visible := map[string]bool{"VISIBLE_CONTRACT_TEXT": false, "VISIBLE_SIGNING_PAGE": false}
	for _, entry := range ctx.Table {
		if entry == nil || entry.Free {
			continue
		}
		if stream, ok := entry.Object.(types.StreamDict); ok && stream.Decode() == nil {
			for text := range visible {
				visible[text] = visible[text] || bytes.Contains(stream.Content, []byte(text))
			}
		}
	}
	for _, found := range visible {
		if !found {
			t.Fatal("visible component content did not survive composition")
		}
	}
	encoded, err := json.Marshal(result.Composition)
	decoded, decodeErr := DecodePDFCompositionManifest(encoded)
	if err != nil || decodeErr != nil || decoded != result.Composition {
		t.Fatal("manifest did not round-trip strictly", err, decodeErr)
	}
	response, err := json.Marshal(pdfWorkerResponse{ProtocolVersion: 2, Length: len(result.Bytes), Report: &result.Report, Composition: &result.Composition})
	if err != nil || len(response)+1 > pdfWorkerHeaderLimit {
		t.Fatal("composition exceeds the unchanged protocol header bound")
	}
}

func TestPDFCompositionRejectsNoncanonicalSigningPage(t *testing.T) {
	canonical := signingPageTestPDF("", "")
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"display-rounded-size", bytes.Replace(canonical, []byte("594.959960 841.919980"), []byte("594.960000 841.920000"), 1)},
		{"sub-milli-size-drift", bytes.Replace(canonical, []byte("594.959960"), []byte("594.959961"), 1)},
		{"different-origin", signingPageTestPDF("/MediaBox [-1 0 594.959960 841.919980]", "")},
		{"crop", signingPageTestPDF("/CropBox [0 0 500 800]", "")},
		{"trim", signingPageTestPDF("/TrimBox [0 0 500 800]", "")},
		{"bleed", signingPageTestPDF("/BleedBox [0 0 500 800]", "")},
		{"art", signingPageTestPDF("/ArtBox [0 0 500 800]", "")},
		{"rotation", signingPageTestPDF("/Rotate 90", "")},
		{"full-turn", signingPageTestPDF("/Rotate 360", "")},
		{"user-unit", signingPageTestPDF("/UserUnit 1.000001", "")},
		{"multi-page", buildTestPDF(t, 2)},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := composeSigningPageInProcess("contract", buildObjectGraphPDF(t, "", ""), test.raw)
			if !errors.Is(err, ErrPDFSigningPageInvalid) || len(result.Bytes) != 0 {
				t.Fatal("incompatible signing page returned usable output", err)
			}
		})
	}
}

func TestPDFCompositionRefusesActiveAndAliasedRawComponentsBeforeMerge(t *testing.T) {
	for _, test := range []struct {
		name, component string
		raw             []byte
		active          bool
	}{
		{"suffix-catalog-action", "suffix", signingPageTestPDF("", "/OpenAction 8 0 R", `<< /Type /Action /S /JavaScript /JS (synthetic) >>`), true},
		{"suffix-orphan-action", "suffix", signingPageTestPDF("", "", `<< /Type /Action /S /Launch /F (synthetic) >>`), true},
		{"body-action", "body", buildObjectGraphPDF(t, "/OpenAction 5 0 R", "", `<< /Type /Action /S /JavaScript /JS (synthetic) >>`), true},
		{"suffix-shared-info", "suffix", signingPageTestPDF("/VisualAlias 6 0 R", ""), false},
		{"suffix-shared-metadata", "suffix", signingPageTestPDF("/VisualAlias 7 0 R", ""), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, suffix := sensitiveMetadataPDF(), signingPageTestPDF("", "")
			if test.component == "body" {
				body = test.raw
			} else {
				suffix = test.raw
			}
			result, err := composeSigningPageInProcess("contract", body, suffix)
			if err == nil || len(result.Bytes) != 0 || test.active && !errors.Is(err, ErrActivePDFContent) {
				t.Fatal("unsafe raw component was laundered through merge", err)
			}
		})
	}
}

func TestPDFCompositionBoundsAndWorkerRequirement(t *testing.T) {
	body, suffix := buildObjectGraphPDF(t, "", ""), signingPageTestPDF("", "")
	previous := activePDFWorker.Load()
	activePDFWorker.Store(nil)
	t.Cleanup(func() { activePDFWorker.Store(previous) })
	if result, err := ComposeSigningPageWithContext(context.Background(), "contract", body, suffix); !errors.Is(err, ErrPDFWorkerUnavailable) || len(result.Bytes) != 0 {
		t.Fatal("composition fell back to a parent parser", err)
	}
	if result, err := ComposeSigningPageWithContext(context.Background(), "contract", make([]byte, MaxPDFBytes), []byte{1}); !errors.Is(err, ErrPDFTooLarge) || len(result.Bytes) != 0 {
		t.Fatal("combined input byte limit was not checked before parsing", err)
	}
	if result, err := composeSigningPageInProcess("contract", buildTestPDF(t, MaxPDFPages), suffix); !errors.Is(err, ErrTooManyPages) || len(result.Bytes) != 0 {
		t.Fatal("append crossed the page limit", err)
	}
	for _, pair := range [][2][]byte{{nil, suffix}, {body, nil}, {[]byte("invalid"), suffix}, {body, []byte("invalid")}} {
		if result, err := composeSigningPageInProcess("contract", pair[0], pair[1]); err == nil || len(result.Bytes) != 0 {
			t.Fatal("invalid composition input returned usable output")
		}
	}
	defer malwarescan.Configure(context.Background(), "", "development")
	malwarescan.Configure(context.Background(), "", "production")
	if result, err := ComposeSigningPageWithContext(context.Background(), "contract", body, suffix); !errors.Is(err, malwarescan.ErrUnavailable) || len(result.Bytes) != 0 {
		t.Fatal("composition bypassed the malware admission gate", err)
	}
}

func TestPDFCompositionAcceptsExactFinalPageBoundary(t *testing.T) {
	result, err := composeSigningPageInProcess("contract", buildTestPDF(t, MaxPDFPages-1), signingPageTestPDF("", ""))
	if err != nil || result.Composition.FinalPages != MaxPDFPages || ValidatePDFCompositionResult(result) != nil {
		t.Fatal("exact composed page limit rejected", err)
	}
}

func TestPDFCompositionManifestRefusesMalformedAndConflictingProofs(t *testing.T) {
	result, _, _ := compositionTestResult(t)
	encoded, err := json.Marshal(result.Composition)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(encoded)
	for _, raw := range []string{
		strings.Replace(valid, `"schema_version":1,`, "", 1),
		strings.Replace(valid, `"schema_version":1`, `"schema_version":null`, 1),
		strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		strings.Replace(valid, `"policy":`, `"Policy":`, 1),
		strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"Schema_Version":1`, 1),
		strings.Replace(valid, `"rotation":0`, `"rotation":0,"Rotation":0`, 1),
		strings.Replace(valid, `"user_unit_milli":1000`, `"user_unit_milli":null`, 1),
		strings.Replace(valid, `"rotation":0`, `"rotation":0,"future":0`, 1),
		strings.Replace(valid, `594960`, `594960.0`, 1),
		strings.Replace(valid, `[0,0,594960,841920]`, `[0,0,594960]`, 1),
		strings.Replace(valid, `[0,0,594960,841920]`, `[0,0,594960,841920,0]`, 1),
		strings.Replace(valid, `[[0,0,594960,841920],`, `[[0,0,594960,841920],[0,0,594960,841920],`, 1),
		strings.Replace(valid, `"body_pages":1`, `"body_pages":500`, 1),
		strings.Replace(valid, `"final_pages":2`, `"final_pages":1`, 1),
		strings.Replace(valid, PDFSigningPagePolicy, "future-policy", 1),
	} {
		if _, err := DecodePDFCompositionManifest([]byte(raw)); err == nil {
			t.Fatal("malformed composition manifest accepted")
		}
	}
	for _, change := range []func(*PDFCompositionResult){
		func(r *PDFCompositionResult) { r.Bytes = append([]byte{}, r.Bytes...); r.Bytes[0] ^= 1 },
		func(r *PDFCompositionResult) { r.Composition.MergedBytes++ },
		func(r *PDFCompositionResult) { r.Composition.MergedSHA256 = strings.Repeat("0", 64) },
		func(r *PDFCompositionResult) { r.Composition.GeometrySHA256 = strings.Repeat("0", 64) },
		func(r *PDFCompositionResult) { r.Composition.OutputSHA256 = strings.Repeat("0", 64) },
		func(r *PDFCompositionResult) { r.Composition.SigningPage.Rotation = 90 },
	} {
		copy := result
		change(&copy)
		if ValidatePDFCompositionResult(copy) == nil {
			t.Fatal("composition proof is not bound to final bytes and intake report")
		}
	}
}

func TestPDFCompositionRealChildProtocolAndLegacyOperationIsolation(t *testing.T) {
	t.Setenv("HASH_PRIVATE_SYNTHETIC_SECRET", "never-pass-to-parser")
	w := workerTestHelper(t, "protocol")
	body, suffix := sensitiveMetadataPDF(), signingPageTestPDF("", "")
	result, err := w.composeSigningPage(context.Background(), "contract", body, suffix)
	if err != nil || ValidatePDFCompositionResult(result) != nil {
		t.Fatal("real child failed composition", err)
	}
	for _, mode := range []string{"composition-wrong-input", "composition-wrong-output", "composition-wrong-report", "composition-missing-report", "composition-missing-manifest", "composition-extra-key", "composition-wrong-geometry"} {
		t.Run(mode, func(t *testing.T) {
			if result, err := workerTestHelper(t, mode).composeSigningPage(context.Background(), "contract", body, suffix); !errors.Is(err, ErrPDFWorkerUnavailable) || len(result.Bytes) != 0 {
				t.Fatal("malformed child composition returned publishable output", err)
			}
		})
	}
	for _, header := range []string{
		`{"protocol_version":2,"operation":"probe","length":0,"body_length":0}`,
		`{"protocol_version":2,"operation":"pages","length":0,"signing_page_length":0}`,
		`{"protocol_version":2,"operation":"compose-signing-page-v1","length":2,"body_length":1}`,
		`{"protocol_version":2,"operation":"compose-signing-page-v1","length":2,"body_length":1,"signing_page_length":null}`,
		`{"protocol_version":2,"operation":"compose-signing-page-v1","length":2,"body_length":1,"signing_page_length":2}`,
		`{"protocol_version":2,"operation":"compose-signing-page-v1","length":2,"body_length":0,"signing_page_length":2}`,
		`{"protocol_version":2,"operation":"compose-signing-page-v1","length":2,"body_length":1,"signing_page_length":1,"Body_Length":1}`,
	} {
		var out bytes.Buffer
		if ServePDFWorker(strings.NewReader(header+"\nab"), &out) == nil || out.Len() != 0 {
			t.Fatal("ambiguous component framing accepted")
		}
	}
	request, _ := json.Marshal(pdfWorkerRequest{ProtocolVersion: 2, Operation: "pages", Length: len(body)})
	var legacy bytes.Buffer
	if err := ServePDFWorker(io.MultiReader(bytes.NewReader(append(request, '\n')), bytes.NewReader(body)), &legacy); err != nil || legacy.String() != "{\"protocol_version\":2,\"length\":0,\"pages\":1}\n" {
		t.Fatal("legacy pages response bytes changed", err)
	}
	response, _ := json.Marshal(pdfWorkerResponse{ProtocolVersion: 2, Pages: 1, Composition: &result.Composition})
	legacyWorker := &pdfWorker{path: workerTestScript(t, "printf '%s\\n' "+shellTestQuote(string(response))), slots: make(chan struct{}, 2)}
	if _, _, err := legacyWorker.run(context.Background(), pdfWorkerRequest{Operation: "probe"}, nil); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal("composition proof accepted on a legacy operation", err)
	}
}

func serveMalformedCompositionForTest(mode string) error {
	reader := bufio.NewReaderSize(os.Stdin, pdfWorkerHeaderLimit)
	var request pdfWorkerRequest
	if err := readPDFWorkerHeader(reader, &request); err != nil {
		return err
	}
	raw, err := io.ReadAll(reader)
	if err != nil || request.BodyLength < 1 || request.BodyLength >= len(raw) {
		return errors.New("invalid synthetic request")
	}
	pdfapi.DisableConfigDir()
	result, err := composeSigningPageInProcess(request.Asset, raw[:request.BodyLength], raw[request.BodyLength:])
	if err != nil {
		return err
	}
	response := pdfWorkerResponse{ProtocolVersion: 2, Length: len(result.Bytes), Report: &result.Report, Composition: &result.Composition}
	switch mode {
	case "composition-wrong-input":
		response.Composition.BodySHA256 = strings.Repeat("0", 64)
	case "composition-wrong-output":
		result.Bytes = append([]byte{}, result.Bytes...)
		result.Bytes[0] ^= 1
	case "composition-wrong-report":
		response.Report.BytesBefore++
	case "composition-missing-report":
		response.Report = nil
	case "composition-missing-manifest":
		response.Composition = nil
	case "composition-wrong-geometry":
		response.Composition.SigningPage.BoxesMilliPoints[0][2]++
	}
	header, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if mode == "composition-extra-key" {
		header = bytes.Replace(header, []byte(`"rotation":0`), []byte(`"rotation":0,"Rotation":0`), 1)
	}
	_, err = fmt.Fprintf(os.Stdout, "%s\n", header)
	if err == nil {
		_, err = os.Stdout.Write(result.Bytes)
	}
	return err
}

func TestPDFCompositionGeometryMatchesLegacyCommitment(t *testing.T) {
	ctx, _, legacy, err := observePDF(sensitiveMetadataPDF())
	if err != nil {
		t.Fatal(err)
	}
	geometry, err := pdfCompositionGeometry(ctx)
	if err != nil || pdfCompositionGeometrySHA(geometry) != legacy || reflect.DeepEqual(geometry[0].Boxes, [5][4]float64{}) {
		t.Fatal("composition geometry representation drifted from legacy commitment", err)
	}
}
