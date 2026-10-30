//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/jackc/pgx/v5/pgtype"
)

// These tests use actual HTTP/MCP admission, PostgreSQL, the source-built
// isolated PDF worker and the existing versioned S3 protocol peer. The peer
// is not production storage/Object Lock proof; no renderer or SMTP is used.
// The existing upload helper supplies a valid metadata-absent PDF, so its
// recorded absence cannot be confused with observed metadata removal.
func setupPDFTemplateSanitizationE2E(t *testing.T) (lifecycleAuthorizationFixture, *htmlCreationStorageE2E, *generated.Template, sanitize.Report, string) {
	t.Helper()
	if os.Getenv("HASH_E2E_PDF_WORKER_PATH") == "" {
		t.Fatal("PDF template provenance fixture requires the source-built isolated HASH_E2E_PDF_WORKER_PATH")
	}
	f, peer := setupHTMLDocumentCreationE2E(t, &htmlCreationRendererE2E{})
	// The existing operator Pro entitlement is unchanged. Native clone quota
	// reads need this genuinely measured catalog source, not a repaired template.
	metadataPrepareNativePlanE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	w := submitPDFIntakeE2E(f, f.ctx, cookie, "/api/v1/templates")
	if w.Code != http.StatusCreated {
		t.Fatalf("actual template upload=%d %s", w.Code, w.Body.String())
	}
	var response templateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	tpl, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: response.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	var binding struct {
		SchemaVersion   int             `json:"schema_version"`
		ObjectKey       string          `json:"object_key"`
		ObjectSHA256    string          `json:"object_sha256"`
		ObjectVersionID string          `json:"object_version_id"`
		Report          json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(tpl.PdfSanitizationReport, &binding); err != nil {
		t.Fatal("persisted upload binding:", err)
	}
	report, err := sanitize.DecodePDFReport(binding.Report)
	if err != nil {
		t.Fatal("persisted measured upload report:", err)
	}
	peer.mu.Lock()
	stored := bytes.Clone(peer.objects[tpl.PdfStorageKey.String])
	peer.mu.Unlock()
	source := fieldBrowserPDF("Synthetic authorized import")
	sourceSHA, outputSHA := sha256.Sum256(source), sha256.Sum256(stored)
	if binding.SchemaVersion != 1 || !tpl.PdfStorageKey.Valid || binding.ObjectKey != tpl.PdfStorageKey.String ||
		!tpl.PdfStorageVersionID.Valid || binding.ObjectVersionID != tpl.PdfStorageVersionID.String || binding.ObjectVersionID != "import-version-1" ||
		!bytes.Equal(tpl.PdfSha256, outputSHA[:]) || binding.ObjectSHA256 != hex.EncodeToString(outputSHA[:]) ||
		!tpl.PageCount.Valid || tpl.PageCount.Int32 != 1 || !tpl.EvidenceVersionPinRequired || report.Asset != "template-pdf" {
		t.Fatal("upload did not persist a report bound to its exact stored PDF/version/page count")
	}
	if err := sanitize.ValidatePDFResult(report, hex.EncodeToString(sourceSHA[:]), hex.EncodeToString(outputSHA[:]), int64(len(source)), int64(len(stored))); err != nil {
		t.Fatal("upload report does not describe actual submitted/stored bytes:", err)
	}
	if report.PDF.Before.InfoDictionary || report.PDF.Before.XMPMetadata || len(report.PDF.Removed) != 0 || !strings.Contains(strings.Join(report.PDF.Absent, ","), "source_info_dictionary") {
		t.Fatal("metadata-absent input was reported as metadata removal")
	}
	assertImportStorageE2E(t, peer.importStoragePeer, 1, 0, 1)
	return f, peer, tpl, report, cookie
}

func assertPDFTemplateDocumentReportE2E(t *testing.T, doc *generated.Document, tpl *generated.Template, expected sanitize.Report) {
	t.Helper()
	var envelope struct {
		SchemaVersion int               `json:"schema_version"`
		Items         []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(doc.MetadataRedactionReport, &envelope); err != nil || envelope.SchemaVersion != 2 || len(envelope.Items) != 1 {
		t.Fatalf("document report envelope: %s err=%v", doc.MetadataRedactionReport, err)
	}
	observed, err := sanitize.DecodePDFReport(envelope.Items[0])
	if err != nil || !reflect.DeepEqual(observed, expected) {
		t.Fatalf("clone lost or invented an upload observation: got=%s err=%v", envelope.Items[0], err)
	}
	if doc.PdfStorageKey != tpl.PdfStorageKey || doc.PdfStorageVersionID != tpl.PdfStorageVersionID ||
		!bytes.Equal(doc.PdfSha256, tpl.PdfSha256) || !doc.EvidenceVersionPinsRequired {
		t.Fatal("cloned document source pins differ from the measured template")
	}
	for _, forbidden := range []string{`"object_key"`, `"object_version_id"`, tpl.PdfStorageKey.String, tpl.PdfStorageVersionID.String} {
		if forbidden != "" && strings.Contains(string(doc.MetadataRedactionReport), forbidden) {
			t.Fatalf("private template binding leaked into document report: %q", forbidden)
		}
	}
}

func pdfTemplateSanitizationSnapshotE2E(t *testing.T, f lifecycleAuthorizationFixture) string {
	t.Helper()
	var fields string
	if err := f.pool.QueryRow(f.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(df) ORDER BY df.id),'[]'::jsonb)::text
		FROM document_fields df JOIN documents d ON d.id=df.document_id WHERE d.org_id=$1`, f.org).Scan(&fields); err != nil { //nolint:rawsql -- exact fields in the disposable tenant
		t.Fatal(err)
	}
	return templateMutationSnapshotE2E(t, f) + "\n" + fields
}

func TestPDFTemplateMeasuredUploadReportSurvivesRESTMCPAndFieldsEditE2E(t *testing.T) {
	f, peer, tpl, observed, cookie := setupPDFTemplateSanitizationE2E(t)
	beforeRequests := peer.requests.Load()
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			credential, _, _ := documentCreationCredentialE2E(t, f, transport, false)
			args := documentCreationArgsE2E(tpl)
			args["name"] = "Measured PDF template clone " + transport
			doc := loadPDFLayoutCreatedE2E(t, f, transport, submitDocumentCreationE2E(f, f.ctx, transport, credential, args), args["name"].(string))
			assertPDFTemplateDocumentReportE2E(t, doc, tpl, observed)
		})
	}
	// This real fields-only edit changes the template version/layout, not the
	// PDF bytes or the historical observation attached to those exact bytes.
	beforeReport := bytes.Clone(tpl.PdfSanitizationReport)
	w := submitTemplateMutationE2E(f, "pdf", tpl.ID, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("fields-only template update=%d %s", w.Code, w.Body.String())
	}
	updated, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: tpl.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(updated.PdfSanitizationReport, beforeReport) || updated.PdfStorageKey != tpl.PdfStorageKey ||
		updated.PdfStorageVersionID != tpl.PdfStorageVersionID || !bytes.Equal(updated.PdfSha256, tpl.PdfSha256) || updated.Version != tpl.Version+1 {
		t.Fatal("fields-only edit changed upload provenance or source pins")
	}
	for _, transport := range []string{"rest", "mcp"} {
		t.Run("after-fields-edit/"+transport, func(t *testing.T) {
			credential, _, _ := documentCreationCredentialE2E(t, f, transport, false)
			args := documentCreationArgsE2E(updated)
			args["name"] = "Measured PDF template after fields " + transport
			args["expected_template_version"] = updated.Version
			args["parties"] = []map[string]string{{"role": "signer", "name": "Fresh reviewed signer", "email": "fresh-signer@example.test", "locale": "en"}}
			doc := loadPDFLayoutCreatedE2E(t, f, transport, submitDocumentCreationE2E(f, f.ctx, transport, credential, args), args["name"].(string))
			assertPDFTemplateDocumentReportE2E(t, doc, updated, observed)
		})
	}
	if peer.requests.Load() != beforeRequests {
		t.Fatal("cloning or fields-only editing unexpectedly reprocessed/read the stored PDF")
	}
	assertImportStorageE2E(t, peer.importStoragePeer, 1, 0, 1)
}

func TestPDFTemplateCorruptBindingRefusesRESTAndMCPWithoutEffectsE2E(t *testing.T) {
	f, peer, tpl, _, _ := setupPDFTemplateSanitizationE2E(t)
	credentials := map[string]string{}
	for _, transport := range []string{"rest", "mcp"} {
		credentials[transport], _, _ = documentCreationCredentialE2E(t, f, transport, false)
	}
	original := bytes.Clone(tpl.PdfSanitizationReport)
	tamperCases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"storage-key", func(binding map[string]any) { binding["object_key"] = "another/private/source.pdf" }},
		{"storage-version", func(binding map[string]any) { binding["object_version_id"] = "different-version" }},
		{"storage-sha", func(binding map[string]any) { binding["object_sha256"] = strings.Repeat("0", 64) }},
		{"missing-proof", func(binding map[string]any) { binding["report"] = nil }},
		{"missing-observation", func(binding map[string]any) {
			proof := binding["report"].(map[string]any)["pdf"].(map[string]any)
			delete(proof["before"].(map[string]any), "annotations")
		}},
	}
	for _, tc := range tamperCases {
		t.Run(tc.name, func(t *testing.T) {
			var binding map[string]any
			if err := json.Unmarshal(original, &binding); err != nil {
				t.Fatal(err)
			}
			tc.edit(binding)
			corrupt, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Exec(f.ctx, `UPDATE templates SET pdf_sanitization_report=$2::jsonb WHERE id=$1`, tpl.ID, corrupt); err != nil { //nolint:rawsql -- intentional corruption confined to disposable fixture
				t.Fatal(err)
			}
			before := pdfTemplateSanitizationSnapshotE2E(t, f)
			cacheBefore := ownedBlocksTemplateCacheV1(t, f, tpl.ID)
			header, err := f.q.GetPDFTemplateSourceHeaderForShareV1(f.ctx, generated.GetPDFTemplateSourceHeaderForShareV1Params{TemplateID: tpl.ID, OrgID: f.org})
			if err != nil || header.MeasurementServerVersionNum != -1 {
				t.Fatal("intentional report tamper must invalidate the actual native source measurement", err)
			}
			beforeRequests := peer.requests.Load()
			// The current native reader refuses the stale M97 source before
			// expanding the corrupted binding. Semantic binding validation remains
			// covered by the authoring formatter's unit tests; never repair this
			// deliberately corrupted source cache to reach a later validator.
			for _, transport := range []string{"rest", "mcp"} {
				t.Run(transport, func(t *testing.T) {
					w := submitDocumentCreationE2E(f, f.ctx, transport, credentials[transport], documentCreationArgsE2E(tpl))
					if transport == "mcp" {
						assertLifecycleMCPResultE2E(t, w, true)
					} else if w.Code != http.StatusServiceUnavailable {
						t.Fatalf("corrupt template clone=%d %s", w.Code, w.Body.String())
					}
					if pdfTemplateSanitizationSnapshotE2E(t, f) != before || peer.requests.Load() != beforeRequests || ownedBlocksTemplateCacheV1(t, f, tpl.ID) != cacheBefore {
						t.Fatal("refused clone changed template, document/recipient/field, version, audit/outbox or storage state")
					}
				})
			}
			if _, err := f.pool.Exec(f.ctx, `UPDATE templates SET pdf_sanitization_report=$2::jsonb WHERE id=$1`, tpl.ID, original); err != nil { //nolint:rawsql -- restore only this disposable fixture's exact report
				t.Fatal(err)
			}
		})
	}
	assertImportStorageE2E(t, peer.importStoragePeer, 1, 0, 1)
}

func TestPDFTemplateUnmeasuredHistoricalSourceRefusesNativeCloneE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			// Only this negative historical fixture bypasses today's upload
			// producer. Its raw old row has no intake observation or M97 source
			// measurement; the normal reader must refuse instead of inventing one.
			f := setupNativeTemplateAuthorizationE2E(t, "sender")
			peer := templateAuthorizationStoragePeerE2E(t, f)
			digest := sha256.Sum256([]byte("synthetic historical PDF source"))
			tpl, err := f.q.CreatePDFTemplate(f.ctx, generated.CreatePDFTemplateParams{OrgID: f.org, Name: "Explicit unmeasured historical PDF template", CreatedBy: f.user.ID, PdfStorageKey: pgtype.Text{String: "historical-template-source.pdf", Valid: true}, PdfSha256: digest[:], PdfStorageVersionID: pgtype.Text{String: "historical-source-version", Valid: true}, EvidenceVersionPinRequired: true, PageCount: pgtype.Int4{Int32: 1, Valid: true}, FieldsJson: json.RawMessage(`[]`)})
			if err != nil || len(tpl.PdfSanitizationReport) != 0 || ownedBlocksTemplateCacheV1(t, f, tpl.ID) != "missing" {
				t.Fatal("historical source must genuinely lack report and source measurement", err)
			}
			credential, _, _ := documentCreationCredentialE2E(t, f, transport, false)
			args := documentCreationArgsE2E(tpl)
			args["name"] = "Legacy PDF unknown clone " + transport
			before := pdfTemplateSanitizationSnapshotE2E(t, f)
			w := submitDocumentCreationE2E(f, f.ctx, transport, credential, args)
			if transport == "mcp" {
				assertLifecycleMCPResultE2E(t, w, true)
			} else if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("unmeasured historical source clone=%d %s", w.Code, w.Body.String())
			}
			fresh, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: tpl.ID, OrgID: f.org})
			if err != nil || len(fresh.PdfSanitizationReport) != 0 || ownedBlocksTemplateCacheV1(t, f, tpl.ID) != "missing" || pdfTemplateSanitizationSnapshotE2E(t, f) != before {
				t.Fatalf("refusal changed historical source or invented report/measurement: %v", err)
			}
			assertImportStorageE2E(t, peer, 0, 0, 0)
		})
	}
}
