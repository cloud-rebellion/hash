// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/sanitize"
)

func observedRedactionReport(t *testing.T, present bool) sanitize.Report {
	t.Helper()
	p := &sanitize.PDFProof{
		SchemaVersion: 1, Policy: "hash-pdf-intake-v1",
		SourceSHA256: strings.Repeat("1", 64), OutputSHA256: strings.Repeat("2", 64),
		PagesBefore: 2, PagesAfter: 2,
		GeometrySHA256Before: strings.Repeat("3", 64), GeometrySHA256After: strings.Repeat("3", 64),
		Before:  sanitize.PDFProperties{InfoDictionary: present, XMPMetadata: present},
		After:   sanitize.PDFProperties{InfoDictionary: true},
		Removed: []string{}, Absent: []string{}, Generated: []string{"info_dictionary"},
	}
	if present {
		p.Removed = []string{"source_info_dictionary", "xmp_metadata"}
	} else {
		p.Absent = []string{"source_info_dictionary", "xmp_metadata"}
	}
	p.Absent = append(p.Absent, "object_streams", "linearization", "embedded_files", "acroform", "annotations")
	r := sanitize.Report{
		Asset: "proposal-pdf", ContentType: "application/pdf", Method: "pdfcpu",
		Stripped: append([]string{}, p.Removed...), BytesBefore: 1024, BytesAfter: 900,
		Provenance: "observed", PDF: p,
	}
	if err := sanitize.ValidatePDFReport(r); err != nil {
		t.Fatalf("actual sanitizer wire fixture invalid: %v", err)
	}
	return r
}

func redactionJSON(t *testing.T, schema int, items ...any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(struct {
		SchemaVersion int   `json:"schema_version"`
		Items         []any `json:"items"`
	}{schema, items})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertNoBlanketSanitizationClaim(t *testing.T, rendered string) {
	t.Helper()
	for _, forbidden := range []string{"GDPR", "Every asset", "were stripped from each asset", "original bytes were never persisted", "all metadata", "<th>Stripped</th>"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("unsupported sanitization claim %q: %s", forbidden, rendered)
		}
	}
}

func TestRedactionCertificateRendersActualMeasuredPDFWire(t *testing.T) {
	raw := redactionJSON(t, 2, observedRedactionReport(t, true))
	before := bytes.Clone(raw)
	rendered := renderRedactionReportSection(raw)
	for _, want := range []string{
		"Source sanitization report", "Measured PDF intake",
		"Removed: source_info_dictionary, xmp_metadata",
		"Absent before intake: object_streams, linearization, embedded_files, acroform, annotations",
		"Generated at intake: info_dictionary", "Pages: 2 -> 2; page geometry unchanged",
		"Recorded: 1024 -> 900", "later signature stamping, the final PDF, certificate rendering",
		"malware detection", "information printed on document pages",
		"Policy: hash-pdf-intake-v1",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing measured statement %q: %s", want, rendered)
		}
	}
	for label, digest := range map[string]string{
		"Source SHA-256":        strings.Repeat("1", 64),
		"Cleaned SHA-256":       strings.Repeat("2", 64),
		"Page geometry SHA-256": strings.Repeat("3", 64),
	} {
		pattern := regexp.QuoteMeta(label) + `: <code(?:\s[^>]*)?>` + digest + `</code>`
		if !regexp.MustCompile(pattern).MatchString(rendered) {
			t.Fatalf("missing labelled artifact digest %q: %s", label, rendered)
		}
	}
	assertNoBlanketSanitizationClaim(t, rendered)
	if !bytes.Equal(raw, before) {
		t.Fatal("rendering mutated the stored report bytes")
	}
}

func TestRedactionCertificateDistinguishesAbsentAndGenerated(t *testing.T) {
	r := observedRedactionReport(t, false)
	rendered := renderRedactionReportSection(redactionJSON(t, 2, r))
	for _, want := range []string{"Removed: None", "Absent before intake: source_info_dictionary, xmp_metadata", "Generated at intake: info_dictionary"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing distinct intake outcome %q: %s", want, rendered)
		}
	}
	r.PDF.After.InfoDictionary = false
	r.PDF.Generated = []string{}
	if err := sanitize.ValidatePDFReport(r); err != nil {
		t.Fatal(err)
	}
	if rendered = renderRedactionReportSection(redactionJSON(t, 2, r)); !strings.Contains(rendered, "Generated at intake: None") {
		t.Fatalf("absent generated metadata was presented as generated: %s", rendered)
	}
}

func TestRedactionCertificateHistoricalReportsAreUnmeasured(t *testing.T) {
	for _, schema := range []int{1, 2} {
		t.Run(strconv.Itoa(schema), func(t *testing.T) {
			r := sanitize.Report{Asset: "template-pdf", ContentType: "application/pdf", Method: "pdfcpu", Stripped: []string{"info_dictionary", "xmp_metadata"}}
			if schema == 2 {
				r.Provenance = "legacy-unknown"
			}
			rendered := renderRedactionReportSection(redactionJSON(t, schema, r))
			if !strings.Contains(rendered, "Historical processing report; not independently measured") || !strings.Contains(rendered, "<td>Unknown</td>") {
				t.Fatalf("historical report not labelled unknown: %s", rendered)
			}
			for _, forbidden := range []string{"Measured PDF intake", "Removed:", "0 -> 0"} {
				if strings.Contains(rendered, forbidden) {
					t.Fatalf("historical record promoted to observation %q: %s", forbidden, rendered)
				}
			}
			assertNoBlanketSanitizationClaim(t, rendered)
		})
	}
	// A proof-shaped addition to schema 1 does not rewrite its historical meaning.
	if rendered := renderRedactionReportSection(redactionJSON(t, 1, observedRedactionReport(t, true))); strings.Contains(rendered, "Measured PDF intake") {
		t.Fatalf("schema 1 was silently promoted: %s", rendered)
	}
}

func TestRedactionCertificateRejectsIncompleteOrInvalidMeasuredProof(t *testing.T) {
	tests := []struct {
		name string
		edit func(map[string]any, map[string]any)
	}{
		{"future-proof", func(_ map[string]any, p map[string]any) { p["schema_version"] = 2 }},
		{"future-policy", func(_ map[string]any, p map[string]any) { p["policy"] = "future-policy" }},
		{"wrong-source-sha", func(_ map[string]any, p map[string]any) { p["source_sha256"] = "unknown" }},
		{"changed-pages", func(_ map[string]any, p map[string]any) { p["pages_after"] = 3 }},
		{"changed-geometry", func(_ map[string]any, p map[string]any) { p["geometry_sha256_after"] = strings.Repeat("4", 64) }},
		{"missing-before", func(_ map[string]any, p map[string]any) { delete(p, "before") }},
		{"missing-false-observation", func(_ map[string]any, p map[string]any) { delete(p["before"].(map[string]any), "annotations") }},
		{"null-false-observation", func(_ map[string]any, p map[string]any) { p["after"].(map[string]any)["annotations"] = nil }},
		{"surviving-xmp", func(_ map[string]any, p map[string]any) { p["after"].(map[string]any)["xmp_metadata"] = true }},
		{"invented-removal", func(_ map[string]any, p map[string]any) {
			p["removed"] = []string{"source_info_dictionary", "xmp_metadata", "annotations"}
		}},
		{"invented-generation", func(_ map[string]any, p map[string]any) { p["generated"] = []string{"info_dictionary", "xmp_metadata"} }},
		{"stripped-conflicts", func(r map[string]any, _ map[string]any) { r["stripped"] = []string{"javascript"} }},
		{"missing-provenance", func(r map[string]any, _ map[string]any) { delete(r, "provenance") }},
		{"unknown-provenance", func(r map[string]any, _ map[string]any) { r["provenance"] = "future-provenance" }},
		{"unknown-bytes", func(r map[string]any, _ map[string]any) { delete(r, "bytes_before") }},
		{"unknown-proof-field", func(_ map[string]any, p map[string]any) { p["future_field"] = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(observedRedactionReport(t, true))
			if err != nil {
				t.Fatal(err)
			}
			var item map[string]any
			if err := json.Unmarshal(b, &item); err != nil {
				t.Fatal(err)
			}
			tt.edit(item, item["pdf"].(map[string]any))
			rendered := renderRedactionReportSection(redactionJSON(t, 2, item))
			if strings.Contains(rendered, "Measured PDF intake") || strings.Contains(rendered, "Removed:") || !strings.Contains(rendered, "unknown or invalid") {
				t.Fatalf("invalid observation became measured: %s", rendered)
			}
		})
	}
}

func TestRedactionCertificateRejectsDuplicateObservedFields(t *testing.T) {
	item, err := json.Marshal(observedRedactionReport(t, true))
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(item), `"asset":"proposal-pdf"`, `"asset":"earlier label","asset":"proposal-pdf"`, 1)
	if duplicate == string(item) {
		t.Fatal("duplicate field fixture did not change")
	}
	rendered := renderRedactionReportSection(redactionJSON(t, 2, json.RawMessage(duplicate)))
	if strings.Contains(rendered, "Measured PDF intake") || !strings.Contains(rendered, "unknown or invalid") {
		t.Fatalf("ambiguous observed wire was promoted: %s", rendered)
	}
}

func TestRedactionCertificateEscapesAllRecordLabels(t *testing.T) {
	r := sanitize.Report{
		Asset: `<script>alert("asset")</script>`, ContentType: `<img src=x onerror="type">`,
		Method: `<iframe src="method">`, Stripped: []string{`<script>category</script>`},
	}
	rendered := renderRedactionReportSection(redactionJSON(t, 1, r))
	for _, want := range []string{`&lt;script&gt;alert(&#34;asset&#34;)&lt;/script&gt;`, `&lt;img src=x onerror=&#34;type&#34;&gt;`, `&lt;iframe src=&#34;method&#34;&gt;`} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("record label not escaped %q: %s", want, rendered)
		}
	}
	for _, forbidden := range []string{"<script>", "<img ", "<iframe ", "category</script>"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("untrusted label or historical category emitted as HTML %q: %s", forbidden, rendered)
		}
	}
}

func TestRedactionCertificateMixedProcessingDoesNotPromoteOtherAssets(t *testing.T) {
	pdf := observedRedactionReport(t, true)
	pdf.Asset = `<img src=x onerror=alert(1)>`
	image := sanitize.Report{Asset: "logo", ContentType: "image/png", Method: "image-reencode", Stripped: []string{"exif", "gps"}, BytesBefore: 500, BytesAfter: 300}
	svg := sanitize.Report{Asset: "mark", ContentType: "image/svg+xml", Method: "svg-strip", Stripped: []string{"scripts"}}
	unsupported := sanitize.Report{Asset: "other", ContentType: "application/other", Method: "passthrough", UnsupportedT: true}
	rendered := renderRedactionReportSection(redactionJSON(t, 2, pdf, image, svg, unsupported, nil, map[string]any{}))
	if strings.Count(rendered, "<strong>Measured PDF intake</strong>") != 1 || strings.Count(rendered, "Processing recorded; measured PDF intake observations do not apply.") != 2 {
		t.Fatalf("mixed processing records were promoted or lost: %s", rendered)
	}
	for _, want := range []string{"&lt;img src=x onerror=alert(1)&gt;", "Unsupported processing record", "processing record could not be read", "processing record is incomplete", "Recorded: 500 -> 300"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing mixed-record outcome %q: %s", want, rendered)
		}
	}
	if strings.Contains(rendered, "<img") || strings.Contains(rendered, "Removed: exif") || strings.Contains(rendered, "0 -> 0") {
		t.Fatalf("unsafe or invented mixed-asset claims: %s", rendered)
	}
	assertNoBlanketSanitizationClaim(t, rendered)
}

func TestRedactionCertificateUnreadableAndFutureReportsAreNeutral(t *testing.T) {
	for _, raw := range []string{`{"schema_version":2,"items":`, `{"schema_version":88,"items":[{"asset":"sensitive source value"}]}`, `{"schema_version":2,"items":"incorrect type"}`} {
		rendered := renderRedactionReportSection(json.RawMessage(raw))
		if !strings.Contains(rendered, "Source-intake observations are unknown") || strings.Contains(rendered, "sensitive source value") {
			t.Fatalf("unknown report exposed or invented observations: %s", rendered)
		}
		assertNoBlanketSanitizationClaim(t, rendered)
	}
	for _, raw := range []string{"", " ", "null", "{}", `{"schema_version":1,"items":[]}`, `{"schema_version":2,"items":[]}`} {
		if rendered := renderRedactionReportSection(json.RawMessage(raw)); rendered != "" {
			t.Fatalf("absent report unexpectedly rendered: %s", rendered)
		}
	}
}

func TestRedactionCertificateSectionRemainsBoundByDetachedSignature(t *testing.T) {
	signer, err := GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	raw := redactionJSON(t, 2, observedRedactionReport(t, true))
	payload := renderRedactionReportSection(raw)
	signature := signer.SignPayload([]byte(payload))
	if !Verify(signer.PublicKeyBase64(), payload, signature) {
		t.Fatal("new source report failed its certificate signature")
	}
	changed := strings.Replace(payload, "Removed: source_info_dictionary", "Removed: None", 1)
	if changed == payload || Verify(signer.PublicKeyBase64(), changed, signature) {
		t.Fatal("report tampering did not invalidate the detached certificate signature")
	}
	// A different cleaned artifact with identical categories must change the
	// signed HTML, not merely an unsigned record retained elsewhere.
	differentArtifact := observedRedactionReport(t, true)
	differentArtifact.PDF.OutputSHA256 = strings.Repeat("4", 64)
	artifactPayload := renderRedactionReportSection(redactionJSON(t, 2, differentArtifact))
	if artifactPayload == payload || Verify(signer.PublicKeyBase64(), artifactPayload, signature) {
		t.Fatal("changing only the cleaned PDF digest preserved the certificate payload/signature")
	}
	// Rendering a later report does not modify the already signed payload.
	renderRedactionReportSection(redactionJSON(t, 2, observedRedactionReport(t, false)))
	if !Verify(signer.PublicKeyBase64(), payload, signature) {
		t.Fatal("later rendering changed an existing signed certificate payload")
	}
}
