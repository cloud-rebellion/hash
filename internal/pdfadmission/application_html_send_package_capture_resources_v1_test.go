// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/jackc/pgx/v5/pgtype"
)

// Scalar pricing tests only: these private model values establish no source,
// native SQL, PDF measurement, resource grant or signing authority.
func captureResourceFixture234(count int) (*generated.Document, *applicationDocumentPackageDraftSnapshotV1) {
	root := &generated.Document{Name: "Main", PdfStorageKey: pgtype.Text{String: "org/synthetic/main.pdf", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "exact-root", Valid: true}, MetadataRedactionReport: []byte("{}")}
	draft := &applicationDocumentPackageDraftSnapshotV1{present: true, count: count}
	for i := 0; i < count && i < len(draft.rows); i++ {
		draft.rows[i] = generated.DocumentAttachmentDraftsV1{Title: "Annex", PdfKey: "org/synthetic/annex.pdf", PdfVersionID: "exact-annex", PdfIntakeReport: []byte("{}")}
	}
	return root, draft
}
func TestHTMLSendPackageCapturePreMarshalAndReportFundingV1(t *testing.T) {
	root, draft := captureResourceFixture234(16)
	small, err := htmlSendPackageCaptureConstructionV1(root, draft)
	if err != nil {
		t.Fatal(err)
	}
	root.Name = strings.Repeat("<", 512)
	root.PdfStorageKey.String = strings.Repeat("k", 1024)
	root.PdfStorageVersionID.String = strings.Repeat("&", 1024)
	for i := range draft.rows {
		a := &draft.rows[i]
		a.Title = strings.Repeat("<", 512)
		a.Category = strings.Repeat("&", 128)
		a.PdfKey = strings.Repeat("k", 1024)
		a.PdfVersionID = strings.Repeat("&", 1024)
	}
	escaped, err := htmlSendPackageCaptureConstructionV1(root, draft)
	if err != nil || escaped <= small || escaped <= documentpackage.MaxManifestBytesV1 {
		t.Fatal("pre-marshal escaped/decode work clamped to accepted payload limit", small, escaped, err)
	}
	beforeRaw, beforeWire, err := htmlSendPackageCaptureStatementV1(root, draft, 1024)
	if err != nil {
		t.Fatal(err)
	}
	root.MetadataRedactionReport = []byte(strings.Repeat("r", 65536))
	for i := range draft.rows {
		draft.rows[i].PdfIntakeReport = []byte(strings.Repeat("r", 65536))
	}
	afterRaw, afterWire, err := htmlSendPackageCaptureStatementV1(root, draft, 1024)
	if err != nil || afterRaw <= beforeRaw+17*65534 || afterWire <= beforeWire+17*65534 {
		t.Fatal("unchanged canonical size concealed M101 report-trigger overlap", beforeRaw, afterRaw, beforeWire, afterWire, err)
	}
}
func TestHTMLSendPackageCapturePricingRejectsUnboundedScalarsV1(t *testing.T) {
	for _, mode := range []string{"count", "title", "category", "key", "version", "report", "manifest"} {
		t.Run(mode, func(t *testing.T) {
			root, draft := captureResourceFixture234(1)
			manifest := 1024
			switch mode {
			case "count":
				draft.count = 17
			case "title":
				root.Name = strings.Repeat("x", 513)
			case "category":
				draft.rows[0].Category = strings.Repeat("x", 129)
			case "key":
				draft.rows[0].PdfKey = strings.Repeat("x", 1025)
			case "version":
				root.PdfStorageVersionID.String = strings.Repeat("x", 1025)
			case "report":
				draft.rows[0].PdfIntakeReport = make([]byte, 65537)
			case "manifest":
				manifest = 65537
			}
			if mode == "report" || mode == "manifest" {
				if _, _, err := htmlSendPackageCaptureStatementV1(root, draft, manifest); err == nil {
					t.Fatal("unbounded statement pricing accepted")
				}
			} else if _, err := htmlSendPackageCaptureConstructionV1(root, draft); err == nil {
				t.Fatal("unbounded constructor pricing accepted")
			}
		})
	}
}
func TestHTMLSendPackageCaptureUnownedReceiversRefuseV1(t *testing.T) {
	for _, work := range []*ApplicationHTMLSendWorkV1{nil, {}} {
		if got, err := work.AppendDocumentPackageCaptureV1(nil, nil); !errors.Is(err, ErrHTMLSendPackageCaptureV1) || got != (HTMLSendPackageCaptureMetadataV1{}) {
			t.Fatal("unowned capture created metadata", got, err)
		}
	}
}
