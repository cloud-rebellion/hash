// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

func metadataTestStream(dict, content string) string {
	return fmt.Sprintf("<< %s /Length %d >>\nstream\n%s\nendstream", dict, len(content), content)
}

// This diagnostic only reads a locally generated synthetic fixture and prints
// object numbers/types, never uploaded content or metadata values.
func logSyntheticPDFInfoReferences(t *testing.T, raw []byte) {
	t.Helper()
	ctx, err := pdfapi.ReadContext(bytes.NewReader(raw), pdfConfiguration())
	if err != nil || ctx.Info == nil {
		t.Log("synthetic fixture Info unavailable")
		return
	}
	t.Logf("synthetic fixture Info object=%d root object=%d", ctx.Info.ObjectNumber, ctx.Root.ObjectNumber)
	for number, entry := range ctx.Table {
		if entry == nil || entry.Free {
			continue
		}
		for key, value := range pdfObjectDict(entry.Object) {
			if ref, ok := value.(types.IndirectRef); ok && ref.ObjectNumber == ctx.Info.ObjectNumber {
				t.Logf("synthetic Info edge parent=%d type=%T key=%q", number, entry.Object, key)
			}
		}
	}
}

func metadataTestPDF(objects []string, trailer string) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets))
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R %s >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), trailer, xref)
	return out.Bytes()
}

func sensitiveMetadataPDF() []byte {
	xmp := func(label string) string {
		return metadataTestStream("/Type /Metadata /Subtype /XML", `<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>PRIVATE_METADATA_`+label+`</dc:title></rdf:Description></rdf:RDF></x:xmpmeta>`)
	}
	return metadataTestPDF([]string{
		`<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R >>`,
		`<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [-10 -20 240 340] /Rotate 90 >>`,
		`<< /Type /Page /Parent 2 0 R /CropBox [0 0 220 320] /TrimBox [1 2 210 310] /BleedBox [0 1 215 315] /ArtBox [2 3 205 305] /UserUnit 1.5 /Contents 4 0 R /Metadata 7 0 R /Resources << /Font << /F1 11 0 R >> /XObject << /X1 12 0 R >> >> >>`,
		metadataTestStream("", "BT /F1 12 Tf 20 30 Td (VISIBLE_CONTRACT_TEXT) Tj ET\nq /X1 Do Q"),
		`<< /Title (PRIVATE_METADATA_TITLE) /Author (PRIVATE_METADATA_AUTHOR) /Subject (PRIVATE_METADATA_SUBJECT) /Creator (PRIVATE_METADATA_CREATOR) /Producer (PRIVATE_METADATA_PRODUCER) /Keywords (PRIVATE_METADATA_KEYWORDS) /CreationDate (D:20000101000000Z) /ModDate (D:20000101000000Z) /CompanySecret 13 0 R >>`,
		xmp("ROOT"), xmp("PAGE"), xmp("FONT"), xmp("XOBJECT"), xmp("ORPHAN"),
		`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Metadata 8 0 R >>`,
		metadataTestStream("/Type /XObject /Subtype /Form /BBox [0 0 10 10] /Metadata 9 0 R /Resources << >>", "0 0 5 5 re S"),
		`(PRIVATE_METADATA_INDIRECT_INFO)`,
	}, "/Info 5 0 R")
}

func TestCleanPDFObservedSourceMetadataRemovedAndGeometryPreserved(t *testing.T) {
	raw := sensitiveMetadataPDF()
	result, err := cleanPDF("template-pdf", "application/pdf", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePDFResult(result.Report, pdfSHA(raw), pdfSHA(result.Bytes), int64(len(raw)), int64(len(result.Bytes))); err != nil {
		t.Fatal(err)
	}
	proof := result.Report.PDF
	if !proof.Before.InfoDictionary || !proof.Before.XMPMetadata || !proof.After.InfoDictionary || proof.After.XMPMetadata || proof.GeometrySHA256Before != proof.GeometrySHA256After {
		t.Fatalf("incorrect observed proof: %+v", proof)
	}
	if !reflect.DeepEqual(proof.Removed, []string{"source_info_dictionary", "xmp_metadata"}) || !reflect.DeepEqual(proof.Generated, []string{"info_dictionary"}) {
		t.Fatalf("incorrect removal/generation categories: %+v", proof)
	}
	if bytes.Contains(result.Bytes, []byte("PRIVATE_METADATA_")) {
		t.Fatal("sensitive source metadata remains in serialized output")
	}
	ctx, err := pdfapi.ReadContext(bytes.NewReader(result.Bytes), pdfConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGeneratedInfo(ctx); err != nil {
		t.Fatal(err)
	}
	visible := false
	for _, entry := range ctx.Table {
		if entry == nil || entry.Free {
			continue
		}
		if stream, ok := entry.Object.(types.StreamDict); ok {
			if err := stream.Decode(); err == nil && bytes.Contains(stream.Content, []byte("VISIBLE_CONTRACT_TEXT")) {
				visible = true
			}
		}
	}
	if !visible {
		t.Fatal("visible contract content did not survive")
	}
	encoded, err := json.Marshal(result.Report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("PRIVATE_METADATA_")) {
		t.Fatal("report leaks metadata values")
	}
	if _, err := DecodePDFReport(encoded); err != nil {
		t.Fatal(err)
	}
	if directory := os.Getenv("HASH_METADATA_QA_ARTIFACT_DIR"); directory != "" {
		info, err := os.Lstat(directory)
		if err != nil || !filepath.IsAbs(directory) || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			t.Fatal("metadata QA requires an existing private absolute directory")
		}
		for _, artifact := range []struct {
			name string
			data []byte
		}{{"source.pdf", raw}, {"cleaned.pdf", result.Bytes}, {"report.json", encoded}} {
			file, err := os.OpenFile(filepath.Join(directory, artifact.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal("create metadata QA artifact")
			}
			_, writeErr := file.Write(artifact.data)
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatal("write metadata QA artifact")
			}
		}
	}
}

func TestCleanPDFReportsAbsentMetadataWithoutRemovalClaim(t *testing.T) {
	for _, version := range []string{"1.7", "2.0"} {
		t.Run(version, func(t *testing.T) {
			raw := bytes.Replace(buildObjectGraphPDF(t, "", ""), []byte("%PDF-1.7"), []byte("%PDF-"+version), 1)
			result, err := cleanPDF("template-pdf", "application/pdf", raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Report.Stripped) != 0 || len(result.Report.PDF.Removed) != 0 || len(result.Report.PDF.Absent) != 7 {
				t.Fatalf("absent source reported as stripped: %+v", result.Report)
			}
			if version == "2.0" && result.Report.PDF.After.InfoDictionary {
				t.Fatal("unexpected PDF2 Info regeneration")
			}
			if version == "1.7" && !result.Report.PDF.After.InfoDictionary {
				t.Fatal("missing verified generated Info")
			}
		})
	}
}

func TestCleanPDFRejectsSharedMetadataRatherThanChangingVisualContent(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"metadata_content_alias", buildObjectGraphPDF(t, "/Metadata 4 0 R", "")},
		{"metadata_resource_alias", buildObjectGraphPDF(t, "/Metadata 5 0 R", "/Resources << /XObject << /X1 5 0 R >> >>", metadataTestStream("/Type /Metadata /Subtype /XML", "PRIVATE_METADATA_SHARED"))},
		{"info_content_alias", bytes.Replace(buildObjectGraphPDF(t, "", ""), []byte("/Root 1 0 R >>"), []byte("/Root 1 0 R /Info 4 0 R >>"), 1)},
		{"info_catalog_alias", bytes.Replace(buildObjectGraphPDF(t, "", ""), []byte("/Root 1 0 R >>"), []byte("/Root 1 0 R /Info 1 0 R >>"), 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := cleanPDF("template-pdf", "application/pdf", test.raw)
			if err == nil || len(result.Bytes) != 0 {
				t.Fatal("shared metadata was accepted or returned bytes")
			}
		})
	}
}

func TestPDFInfoAliasGuardAllowsOnlyParserTrailerEdge(t *testing.T) {
	raw := buildTestPDF(t, 1)
	read := func(t *testing.T) (*model.Context, int) {
		t.Helper()
		ctx, err := pdfapi.ReadContext(bytes.NewReader(raw), pdfConfiguration())
		if err != nil || ctx.Info == nil {
			t.Fatal("canonical fixture has no parsed Info")
		}
		for number, entry := range ctx.Table {
			if entry == nil || entry.Free {
				continue
			}
			if stream, ok := entry.Object.(types.XRefStreamDict); ok {
				if ref, ok := stream.Dict["Info"].(types.IndirectRef); ok && ref == *ctx.Info {
					return ctx, number
				}
			}
		}
		t.Fatal("canonical fixture must exercise a parser-recognized xref trailer Info edge")
		return nil, 0
	}
	ctx, _ := read(t)
	if _, err := metadataTargets(ctx); err != nil {
		t.Fatalf("legitimate trailer rejected: %v", err)
	}
	for _, kind := range []string{"ordinary_info_key", "ordinary_xref_named_dictionary", "nested_xref_info"} {
		t.Run(kind, func(t *testing.T) {
			ctx, number := read(t)
			switch kind {
			case "ordinary_info_key":
				root, _ := ctx.DereferenceDict(*ctx.Root)
				root["Info"] = *ctx.Info
			case "ordinary_xref_named_dictionary":
				root, _ := ctx.DereferenceDict(*ctx.Root)
				root["FakeTrailer"] = types.Dict{"Type": types.Name("XRef"), "Info": *ctx.Info}
			case "nested_xref_info":
				stream := ctx.Table[number].Object.(types.XRefStreamDict)
				stream.Dict["Extra"] = types.Dict{"Info": *ctx.Info}
			}
			if _, err := metadataTargets(ctx); err == nil {
				t.Fatal("nontrailer source Info alias accepted")
			}
		})
	}
}

func TestPDFProofRejectsContradictoryOrUnboundClaims(t *testing.T) {
	result, err := cleanPDF("template-pdf", "application/pdf", sensitiveMetadataPDF())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result.Report)
	for _, test := range []struct {
		name   string
		change func(*Report)
	}{
		{"legacy_unknown", func(r *Report) { r.Provenance = "legacy-unknown" }},
		{"future_policy", func(r *Report) { r.PDF.Policy = "future" }},
		{"bad_sha", func(r *Report) { r.PDF.OutputSHA256 = strings.Repeat("A", 64) }},
		{"page_drift", func(r *Report) { r.PDF.PagesAfter++ }},
		{"geometry_drift", func(r *Report) { r.PDF.GeometrySHA256After = strings.Repeat("0", 64) }},
		{"remaining_xmp", func(r *Report) { r.PDF.After.XMPMetadata = true }},
		{"duplicate_removal", func(r *Report) { r.PDF.Removed = append(r.PDF.Removed, r.PDF.Removed[0]) }},
		{"absent_claim", func(r *Report) { r.PDF.Absent = append(r.PDF.Absent, "source_info_dictionary") }},
		{"generated_claim", func(r *Report) { r.PDF.Generated = append(r.PDF.Generated, "xmp_metadata") }},
		{"static_stripped", func(r *Report) { r.Stripped = append(r.Stripped, "annotations") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var changed Report
			json.Unmarshal(encoded, &changed)
			test.change(&changed)
			if ValidatePDFReport(changed) == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	if ValidatePDFResult(result.Report, strings.Repeat("0", 64), result.Report.PDF.OutputSHA256, result.Report.BytesBefore, result.Report.BytesAfter) == nil {
		t.Fatal("source hash mismatch accepted")
	}
	if ValidatePDFResult(result.Report, result.Report.PDF.SourceSHA256, result.Report.PDF.OutputSHA256, result.Report.BytesBefore, result.Report.BytesAfter+1) == nil {
		t.Fatal("byte length mismatch accepted")
	}
	for _, raw := range []string{
		strings.Replace(string(encoded), `"xmp_metadata":false,`, "", 1),
		strings.Replace(string(encoded), `"xmp_metadata":false`, `"xmp_metadata":null`, 1),
		strings.Replace(string(encoded), `"xmp_metadata":false`, `"xmp_metadata":"false"`, 1),
		strings.Replace(string(encoded), `"xmp_metadata":false`, `"xmp_metadata":false,"xmp_metadata":false`, 1),
		strings.Replace(string(encoded), `"schema_version":1`, `"schema_version":1,"future":1`, 1),
		strings.Replace(string(encoded), `"generated":["info_dictionary"]`, `"generated":null`, 1),
		strings.Replace(string(encoded), `"source_sha256":`, `"Source_SHA256":`, 1),
		strings.Replace(string(encoded), `"provenance":"observed"`, `"provenance":"observed","Provenance":"observed"`, 1),
	} {
		if _, err := DecodePDFReport([]byte(raw)); err == nil {
			t.Fatal("malformed proof JSON accepted")
		}
	}
}

func TestPDFMetadataWorkerRoundTripAndStrictProtocol(t *testing.T) {
	w := workerTestHelper(t, "protocol")
	raw := sensitiveMetadataPDF()
	result, err := w.clean(context.Background(), "template-pdf", "application/pdf", raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(result.Bytes, []byte("PRIVATE_METADATA_")) || ValidatePDFResult(result.Report, pdfSHA(raw), pdfSHA(result.Bytes), int64(len(raw)), int64(len(result.Bytes))) != nil {
		t.Fatal("worker did not bind verified metadata output")
	}
	for _, header := range []string{
		`{"operation":"probe","length":0}`,
		`{"protocol_version":1,"operation":"probe","length":0}`,
		`{"protocol_version":3,"protocol_version":3,"operation":"probe","length":0}`,
		`{"protocol_version":3,"operation":"probe"}`,
	} {
		var out bytes.Buffer
		if ServePDFWorker(strings.NewReader(header+"\n"), &out) == nil || out.Len() != 0 {
			t.Fatal("old or incomplete request accepted")
		}
	}
	for _, header := range []string{
		`{"protocol_version":3,"length":0,"length":0,"pages":1}`,
		`{"protocol_version":3,"pages":1}`,
		`{"protocol_version":3,"length":0,"pages":1,"unknown":true}`,
		`{"protocol_version":3,"length":0,"Length":0,"pages":1}`,
		`{"protocol_version":3,"length":0,"pages":1,"report":null}`,
	} {
		var response pdfWorkerResponse
		if readPDFWorkerHeader(bufio.NewReader(strings.NewReader(header+"\n")), &response) == nil {
			t.Fatal("ambiguous worker response accepted")
		}
	}
}

func TestPDFWorkerRefusesPageCountBeyondPolicy(t *testing.T) {
	w := workerTestHelper(t, "too-many-pages")
	if _, _, err := w.run(context.Background(), pdfWorkerRequest{Operation: "pages", Length: 1}, []byte("x")); err != ErrPDFWorkerUnavailable {
		t.Fatalf("unbounded worker page count accepted: %v", err)
	}
}

func TestMergeReportsPreservesLegacyBytesAndPromotesObservedProof(t *testing.T) {
	legacy := Report{Asset: "old", ContentType: "application/pdf", Method: "pdfcpu", Stripped: []string{"info_dictionary"}, BytesBefore: 10, BytesAfter: 9}
	want := `{"schema_version":1,"items":[{"asset":"old","content_type":"application/pdf","method":"pdfcpu","stripped":["info_dictionary"],"bytes_before":10,"bytes_after":9}]}`
	encoded, err := MergeReports(nil, legacy)
	if err != nil || string(encoded) != want {
		t.Fatalf("legacy canonical bytes changed: %s (%v)", encoded, err)
	}
	result, err := cleanPDF("new", "application/pdf", buildObjectGraphPDF(t, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := MergeReports(encoded, result.Report)
	if err != nil {
		t.Fatal(err)
	}
	var wrapper struct {
		SchemaVersion int               `json:"schema_version"`
		Items         []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(mixed, &wrapper) != nil || wrapper.SchemaVersion != 2 || len(wrapper.Items) != 2 {
		t.Fatal("mixed observed report not promoted")
	}
	var oldWrapper struct {
		Items []json.RawMessage `json:"items"`
	}
	json.Unmarshal(encoded, &oldWrapper)
	if !bytes.Equal(wrapper.Items[0], oldWrapper.Items[0]) {
		t.Fatal("historical item changed when appending observed proof")
	}
}
