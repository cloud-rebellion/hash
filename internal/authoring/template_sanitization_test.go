// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package authoring

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/jackc/pgx/v5/pgtype"
)

func observedTemplateFixture(t *testing.T) (*generated.Template, sanitize.Report) {
	t.Helper()
	sha := bytes.Repeat([]byte{0xab}, 32)
	report := sanitize.Report{Asset: "template-pdf", ContentType: "application/pdf", Method: "pdfcpu", Provenance: "observed", BytesBefore: 1024, BytesAfter: 900,
		Stripped: []string{"source_info_dictionary", "xmp_metadata"},
		PDF: &sanitize.PDFProof{SchemaVersion: 1, Policy: "hash-pdf-intake-v1", SourceSHA256: strings.Repeat("c", 64), OutputSHA256: hex.EncodeToString(sha), PagesBefore: 2, PagesAfter: 2,
			GeometrySHA256Before: strings.Repeat("d", 64), GeometrySHA256After: strings.Repeat("d", 64),
			Before: sanitize.PDFProperties{InfoDictionary: true, XMPMetadata: true}, After: sanitize.PDFProperties{InfoDictionary: true},
			Removed: []string{"source_info_dictionary", "xmp_metadata"}, Absent: []string{"object_streams", "linearization", "embedded_files", "acroform", "annotations"}, Generated: []string{"info_dictionary"}}}
	tpl := &generated.Template{SourceKind: "pdf", PdfStorageKey: pgtype.Text{String: "org/private/template.pdf", Valid: true}, PdfSha256: sha,
		PdfStorageVersionID: pgtype.Text{String: "storage-version-opaque", Valid: true}, PageCount: pgtype.Int4{Int32: 2, Valid: true}, Version: 1}
	raw, err := BindPDFTemplateSanitization(report, tpl.PdfStorageKey.String, sha, tpl.PdfStorageVersionID.String, 2)
	if err != nil {
		t.Fatal(err)
	}
	tpl.PdfSanitizationReport = raw
	return tpl, report
}

func TestPDFTemplateDocumentReportBindsExactObject(t *testing.T) {
	tpl, report := observedTemplateFixture(t)
	tpl.Version++ // Fields-only edits retain the exact immutable source binding.
	raw, err := PDFTemplateDocumentReport(tpl)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		SchemaVersion int               `json:"schema_version"`
		Items         []sanitize.Report `json:"items"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != 2 || len(envelope.Items) != 1 || envelope.Items[0].PDF.OutputSHA256 != report.PDF.OutputSHA256 {
		t.Fatalf("not observed source: %s", raw)
	}
	if bytes.Contains(raw, []byte(tpl.PdfStorageKey.String)) || bytes.Contains(raw, []byte(tpl.PdfStorageVersionID.String)) {
		t.Fatal("storage capabilities leaked into document report")
	}
}

func TestPDFTemplateDocumentReportRejectsStaleOrCorruptBinding(t *testing.T) {
	tests := map[string]func(*generated.Template){
		"key":              func(t *generated.Template) { t.PdfStorageKey.String += "-new" },
		"version":          func(t *generated.Template) { t.PdfStorageVersionID.String += "-new" },
		"digest":           func(t *generated.Template) { t.PdfSha256 = bytes.Repeat([]byte{0xaa}, 32) },
		"pages":            func(t *generated.Template) { t.PageCount.Int32++ },
		"invalid-page-pin": func(t *generated.Template) { t.PageCount.Valid = false },
		"malformed":        func(t *generated.Template) { t.PdfSanitizationReport = []byte("{") },
		"future-schema": func(t *generated.Template) {
			t.PdfSanitizationReport = bytes.Replace(t.PdfSanitizationReport, []byte(`"schema_version":1`), []byte(`"schema_version":99`), 1)
		},
		"extra-field": func(t *generated.Template) {
			t.PdfSanitizationReport = append([]byte(`{"extra":true,`), t.PdfSanitizationReport[1:]...)
		},
		"extra-json": func(t *generated.Template) {
			t.PdfSanitizationReport = append(t.PdfSanitizationReport, []byte(` {}`)...)
		},
		"duplicate-wrapper": func(t *generated.Template) {
			t.PdfSanitizationReport = append([]byte(`{"schema_version":1,`), t.PdfSanitizationReport[1:]...)
		},
		"case-alias-wrapper": func(t *generated.Template) {
			t.PdfSanitizationReport = bytes.Replace(t.PdfSanitizationReport, []byte(`"object_key"`), []byte(`"Object_Key"`), 1)
		},
		"null-wrapper": func(t *generated.Template) {
			t.PdfSanitizationReport = bytes.Replace(t.PdfSanitizationReport, []byte(`"schema_version":1`), []byte(`"schema_version":null`), 1)
		},
		"missing-observation": func(t *generated.Template) {
			t.PdfSanitizationReport = bytes.Replace(t.PdfSanitizationReport, []byte(`"linearization":false,`), nil, 1)
		},
		"unbound-empty-object": func(t *generated.Template) { t.PdfSanitizationReport = []byte(`{}`) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			tpl, _ := observedTemplateFixture(t)
			mutate(tpl)
			if _, err := PDFTemplateDocumentReport(tpl); err == nil {
				t.Fatal("stale or corrupt report became a document attestation")
			}
		})
	}
}

func TestPDFTemplateDocumentReportLegacyIsExplicitUnknown(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, []byte("null")} {
		tpl, _ := observedTemplateFixture(t)
		tpl.PdfSanitizationReport = raw
		out, err := PDFTemplateDocumentReport(tpl)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out, []byte(`"provenance":"legacy-unknown"`)) || !bytes.Contains(out, []byte(`"stripped":[]`)) || bytes.Contains(out, []byte(`"pdf":`)) {
			t.Fatalf("legacy acquired an observation: %s", out)
		}
	}
}

func TestBindPDFTemplateSanitizationRejectsUnobservedOrWrongPDF(t *testing.T) {
	tpl, report := observedTemplateFixture(t)
	for name, mutate := range map[string]func(*sanitize.Report){
		"legacy":      func(r *sanitize.Report) { r.Provenance = "legacy-unknown" },
		"unsupported": func(r *sanitize.Report) { r.UnsupportedT = true },
		"no-proof":    func(r *sanitize.Report) { r.PDF = nil },
		"wrong-asset": func(r *sanitize.Report) { r.Asset = "other-source" },
	} {
		t.Run(name, func(t *testing.T) {
			r := report
			mutate(&r)
			if _, err := BindPDFTemplateSanitization(r, tpl.PdfStorageKey.String, tpl.PdfSha256, tpl.PdfStorageVersionID.String, 2); err == nil {
				t.Fatal("unverified report stored")
			}
		})
	}
}
