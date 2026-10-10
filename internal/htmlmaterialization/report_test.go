// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaterialization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
)

// These proof-shaped fixtures test persistence and binding only. They contain
// no PDF bytes and do not assert that a renderer or worker measured anything.
func syntheticObservedReport(t *testing.T, pdfSHA []byte, pages int) sanitize.Report {
	t.Helper()
	geometry := sha256.Sum256([]byte("synthetic geometry for report binding only"))
	geometrySHA := hex.EncodeToString(geometry[:])
	return sanitize.Report{
		Asset: "synthetic-policy-shape", ContentType: "application/pdf", Method: "pdfcpu",
		Stripped: []string{"source_info_dictionary"}, BytesBefore: 100, BytesAfter: 80,
		Provenance: "observed", PDF: &sanitize.PDFProof{
			SchemaVersion: 1, Policy: "hash-pdf-intake-v1",
			SourceSHA256: geometrySHA, OutputSHA256: hex.EncodeToString(pdfSHA),
			PagesBefore: pages, PagesAfter: pages,
			GeometrySHA256Before: geometrySHA, GeometrySHA256After: geometrySHA,
			Before:    sanitize.PDFProperties{InfoDictionary: true},
			After:     sanitize.PDFProperties{InfoDictionary: true},
			Removed:   []string{"source_info_dictionary"},
			Absent:    []string{"xmp_metadata", "object_streams", "linearization", "embedded_files", "acroform", "annotations"},
			Generated: []string{"info_dictionary"},
		},
	}
}

func observedEnvelope(t *testing.T, pdfSHA []byte, pages int) json.RawMessage {
	t.Helper()
	raw, err := sanitize.MergeReports(nil, syntheticObservedReport(t, pdfSHA, pages))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHTMLMaterializationReportsRetainLegacyOriginAndProjectFreshArtifact(t *testing.T) {
	in, q := fixture(t)
	legacy := json.RawMessage(`{"schema_version":1,"items":[{"asset":"legacy-pdf","content_type":"application/pdf","method":"pdfcpu","stripped":["info_dictionary"],"bytes_before":100,"bytes_after":80}]}`)
	q.doc.MetadataRedactionReport = bytes.Clone(legacy)
	doc, oldRow, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldRow.MetadataRedactionReport, legacy) || !bytes.Equal(doc.MetadataRedactionReport, legacy) {
		t.Fatal("origin registration rewrote legacy report")
	}
	candidate := *doc
	in.Values["customer"] = "Revised AB"
	candidate.VariablesJson, _ = json.Marshal(in.Values)
	candidate.PdfStorageKey.String = "org/test/documents/revised.pdf"
	candidate.PdfStorageVersionID.String = "new-report-version"
	raw, err := htmlsource.New(in, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	fresh := observedEnvelope(t, candidate.PdfSha256, 2)
	updated, newRow, err := Append(context.Background(), q, doc, &candidate, AppendInput{
		SourceJSON: raw, PageCount: 2, ActorID: uuid.New(), MetadataRedactionReport: fresh,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(updated.MetadataRedactionReport, fresh) || !bytes.Equal(newRow.MetadataRedactionReport, fresh) ||
		len(q.captures) != 1 || !bytes.Equal(q.captures[0].MetadataRedactionReport, legacy) || !bytes.Equal(oldRow.MetadataRedactionReport, legacy) {
		t.Fatal("new projection and retained old report no longer identify their own artifacts")
	}
	historical, err := HistoricalDocument(updated, oldRow)
	if err != nil || !bytes.Equal(historical.MetadataRedactionReport, legacy) {
		t.Fatal("historical PDF inherited the current report", err)
	}
}

func TestHTMLMaterializationLegacyNullReportNeverInheritsCurrentReport(t *testing.T) {
	_, q := fixture(t)
	doc, row, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an append-only row created before the nullable report column.
	row.MetadataRedactionReport = nil
	doc.MetadataRedactionReport = observedEnvelope(t, doc.PdfSha256, 1)
	if _, err := Current(context.Background(), q, doc); err != nil {
		t.Fatal("legacy NULL row changed current signing semantics", err)
	}
	view, err := HistoricalDocument(doc, row)
	if err != nil || len(view.MetadataRedactionReport) != 0 {
		t.Fatal("legacy NULL history acquired current provenance", err)
	}
}

func TestHTMLMaterializationRejectsReportProjectionDriftBeforeHistory(t *testing.T) {
	in, q := fixture(t)
	q.doc.MetadataRedactionReport = observedEnvelope(t, q.doc.PdfSha256, 1)
	doc, _, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	doc.MetadataRedactionReport = json.RawMessage(`{}`)
	q.writes = 0
	if _, err := Current(context.Background(), q, doc); !errors.Is(err, ErrInvalid) {
		t.Fatal("current report drift accepted", err)
	}
	in.Values["customer"] = "Revised AB"
	candidate := *doc
	candidate.VariablesJson, _ = json.Marshal(in.Values)
	raw, err := htmlsource.New(in, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Append(context.Background(), q, doc, &candidate, AppendInput{SourceJSON: raw, PageCount: 1, ActorID: uuid.New()}); !errors.Is(err, ErrInvalid) || q.writes != 0 {
		t.Fatalf("report drift changed history: error=%v writes=%d", err, q.writes)
	}
}

func TestHTMLMaterializationRejectsUnboundObservedReportBeforeEffects(t *testing.T) {
	for _, kind := range []string{"digest", "pages", "schema-downgrade", "duplicate", "unknown-with-proof"} {
		t.Run(kind, func(t *testing.T) {
			in, q := fixture(t)
			candidate := *q.doc
			in.Values["customer"] = "Revised AB"
			candidate.VariablesJson, _ = json.Marshal(in.Values)
			source, err := htmlsource.New(in, &candidate)
			if err != nil {
				t.Fatal(err)
			}
			report := syntheticObservedReport(t, candidate.PdfSha256, 1)
			schema := 2
			if kind == "digest" {
				report.PDF.OutputSHA256 = hex.EncodeToString(bytes.Repeat([]byte{0xff}, 32))
			}
			if kind == "pages" {
				report.PDF.PagesBefore, report.PDF.PagesAfter = 2, 2
			}
			if kind == "schema-downgrade" {
				schema = 1
			}
			if kind == "unknown-with-proof" {
				report.Provenance = "legacy-unknown"
			}
			items := []sanitize.Report{report}
			if kind == "duplicate" {
				items = append(items, report)
			}
			raw, err := json.Marshal(struct {
				SchemaVersion int               `json:"schema_version"`
				Items         []sanitize.Report `json:"items"`
			}{schema, items})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = Append(context.Background(), q, q.doc, &candidate, AppendInput{SourceJSON: source, PageCount: 1, PreviousPageCount: 1, ActorID: uuid.New(), MetadataRedactionReport: raw})
			if !errors.Is(err, ErrInvalid) || q.writes != 0 {
				t.Fatalf("unbound report changed history: error=%v writes=%d", err, q.writes)
			}
		})
	}
}
