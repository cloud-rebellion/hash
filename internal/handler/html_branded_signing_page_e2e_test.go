//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/testfixture"
)

// These tests require real Chromium rendering and the source-built isolated
// PDF worker. The existing version-enforcing S3 peer remains synthetic: no
// production Object Lock, retention, SMTP or provider acceptance is claimed.
// Missing explicit fixture dependencies skip before starting a database; the
// private acceptance runner requires the selected tests to finish without skips.
func brandedPageFixtureE2E(t *testing.T) (lifecycleAuthorizationFixture, *htmlCreationStorageE2E, string) {
	t.Helper()
	worker, renderer := os.Getenv("HASH_E2E_PDF_WORKER_PATH"), os.Getenv("HASH_E2E_RENDERER_URL")
	if worker == "" || renderer == "" {
		t.Skip("set HASH_E2E_PDF_WORKER_PATH and HASH_E2E_RENDERER_URL for real branded-page fixtures")
	}
	f, peer := setupHTMLDocumentCreationE2E(t, &htmlCreationRendererE2E{})
	f.s.Sign.PDF = render.NewGotenberg(renderer)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	return f, peer, cookie
}

func createBrandedDesignE2E(t *testing.T, f lifecycleAuthorizationFixture, cookie string) *generated.Template {
	t.Helper()
	return createBrandedDesignVariantE2E(t, f, cookie, nil)
}

func createBrandedDesignVariantE2E(t *testing.T, f lifecycleAuthorizationFixture, cookie string, change func(*htmlmaster.Master, map[string]string)) *generated.Template {
	t.Helper()
	input, _, _ := testfixture.HTMLContract(t)
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	master.SchemaVersion = htmlmaster.SigningPageSchemaVersion
	master.SigningPage = testfixture.BrandedSigningPolicy()
	// The short body deliberately fits one page. Only the app-owned suffix has
	// fixed signing geometry; body CSS never enters that separate HTML render.
	master.CSS = `@page {size:A4; margin:20mm;} p {margin:0 0 7pt; font-size:9pt; line-height:11pt;}`
	if change != nil {
		change(&master, input.Values)
	}
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := json.Marshal(input.Values)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, defaults)
	if err != nil {
		t.Fatal("invalid branded fixture master:", err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compiled.SigningPageHTML(htmlmaster.Input{Values: input.Values, Sections: input.Sections}); err != nil {
		t.Fatal("invalid branded fixture identities:", err)
	}
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "Actual-rendered approved branded proposal", HTMLMasterJSON: canonical.MasterJSON, VariablesJSON: canonical.DefaultsJSON}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create branded design=%d bytes=%d", w.Code, w.Body.Len())
	}
	var response templateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	template, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: response.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func approveBrandedDesignE2E(t *testing.T, f lifecycleAuthorizationFixture, template *generated.Template, peer *htmlCreationStorageE2E, cookie string) []byte {
	t.Helper()
	before, storageBefore := brandedPageInventoryE2E(t, f), peer.requests.Load()
	// Do not use previewApprovalInputE2E: that helper intentionally swaps in a
	// synthetic renderer. This preview uses the same actual renderer as create.
	w := submitHTMLPreviewE2E(t, f, template, nil, cookie)
	if w.Code != http.StatusOK || !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF-")) || w.Header().Get("X-Hash-PDF-Pages") != "2" {
		t.Fatalf("actual complete branded preview=%d pages=%q bytes=%d", w.Code, w.Header().Get("X-Hash-PDF-Pages"), w.Body.Len())
	}
	digest := sha256.Sum256(w.Body.Bytes())
	if w.Header().Get("X-Hash-PDF-SHA256") != hex.EncodeToString(digest[:]) {
		t.Fatal("preview witness does not bind returned composed bytes")
	}
	pages, err := sanitize.PageCountWithContext(f.ctx, w.Body.Bytes())
	if err != nil || pages != 2 {
		t.Fatal("preview lacks body plus exactly one real signing page:", err)
	}
	if !bytes.Equal(before, brandedPageInventoryE2E(t, f)) || peer.requests.Load() != storageBefore {
		t.Fatal("preview created document/storage effects")
	}
	in := htmlApprovalInputE2E(template)
	in.PreviewReceipt = w.Header().Get("X-Hash-Preview-Receipt")
	in.ExpectedPreviewPDFSHA256 = w.Header().Get("X-Hash-PDF-SHA256")
	if in.PreviewReceipt == "" {
		t.Fatal("actual preview lacks owner approval proof")
	}
	if result := submitHTMLTemplateE2E(t, f, "approve", template.ID, in, cookie); result.Code != http.StatusOK {
		t.Fatalf("approve actual branded preview=%d bytes=%d", result.Code, result.Body.Len())
	}
	return bytes.Clone(w.Body.Bytes())
}

func createBrandedDocumentE2E(t *testing.T, f lifecycleAuthorizationFixture, template *generated.Template, cookie string) *generated.Document {
	t.Helper()
	doc := createHTMLContractDocumentE2E(t, f, template, cookie)
	// Field insert lifecycle triggers may advance updated_at. Always reload the
	// committed parent before deriving review/revision optimistic-lock witnesses.
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	assertBrandedStateE2E(t, f, doc)
	return doc
}

func assertBrandedStateE2E(t *testing.T, f lifecycleAuthorizationFixture, doc *generated.Document) ([]*generated.Recipient, []*generated.DocumentField, *htmlsource.SigningArtifact) {
	t.Helper()
	policy, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || policy == nil || artifact == nil || artifact.Composition.BodyPages != 1 || artifact.Composition.FinalPages != 2 || !doc.RequiresSignature {
		t.Fatal("missing exact branded source/geometry:", err)
	}
	rows, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || len(fields) != 2 || htmlsource.ValidateContractParties(doc, rows) != nil || htmlsource.ValidateSigningFields(doc, fields, 2) != nil {
		t.Fatal("generated pair differs from exact intended recipients/source")
	}
	brand, err := f.q.GetDocumentBrandingOverride(f.ctx, doc.ID)
	if err != nil || htmlsource.ValidateSigningBranding(doc, brand) != nil || brand.LogoUrl.String != "" || brand.LogoAlt.String != "" {
		t.Fatal("complete approved empty-logo snapshot missing:", err)
	}
	stored, err := f.s.Storage.GetVerifiedVersion(f.ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
	if err != nil {
		t.Fatal("missing exact composed storage version:", err)
	}
	count, err := sanitize.PageCountWithContext(f.ctx, stored)
	if err != nil || count != 2 || artifact.Composition.OutputSHA256 != hex.EncodeToString(doc.PdfSha256) {
		t.Fatal("stored composed bytes/source geometry differ:", err)
	}
	assertHTMLRevisionReportE2E(t, doc.MetadataRedactionReport, doc.PdfSha256, 2)
	return rows, fields, artifact
}

func brandedPageInventoryE2E(t *testing.T, f lifecycleAuthorizationFixture) []byte {
	t.Helper()
	var raw []byte
	err := f.pool.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
SELECT jsonb_build_object(
 'documents',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM documents x WHERE org_id=$1),
 'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM recipients x WHERE document_id IN (SELECT id FROM owned)),
 'fields',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM document_fields x WHERE document_id IN (SELECT id FROM owned)),
 'branding',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY document_id),'[]'::jsonb) FROM document_branding_override x WHERE document_id IN (SELECT id FROM owned)),
 'templates',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM templates x WHERE org_id=$1),
 'template_revisions',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY template_id,version),'[]'::jsonb) FROM html_template_revisions x WHERE org_id=$1),
 'materializations',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY document_id,sequence),'[]'::jsonb) FROM html_document_materializations x WHERE org_id=$1),
 'snapshots',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM html_document_materialization_snapshots x WHERE org_id=$1),
 'versions',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM document_versions x WHERE org_id=$1),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM events x WHERE org_id=$1)
)`, f.org).Scan(&raw) //nolint:rawsql -- exact disposable synthetic tenant rollback inventory
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHTMLBrandedSigningPageCreationPreviewAndManagedFieldRefusalE2E(t *testing.T) {
	f, peer, cookie := brandedPageFixtureE2E(t)
	template := createBrandedDesignE2E(t, f, cookie)
	before, storageBefore := brandedPageInventoryE2E(t, f), peer.requests.Load()
	if w := submitHTMLDocumentCreationE2E(t, f, template.ID, htmlCreationInputE2E(template), cookie); w.Code != http.StatusConflict {
		t.Fatalf("unapproved branded creation=%d", w.Code)
	}
	if !bytes.Equal(before, brandedPageInventoryE2E(t, f)) || peer.requests.Load() != storageBefore {
		t.Fatal("unapproved page created effects")
	}
	approveBrandedDesignE2E(t, f, template, peer, cookie)
	doc := createBrandedDocumentE2E(t, f, template, cookie)
	f.doc = doc
	rows, fields, _ := assertBrandedStateE2E(t, f, doc)
	if rows[0].ID == rows[1].ID || fields[0].ID == fields[1].ID || doc.HtmlReviewedBy.Valid || doc.HtmlReviewedMaterializationID.Valid {
		t.Fatal("generated identities/fields or fresh review invariant failed")
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	required := true
	create, _ := json.Marshal(addFieldInput{RecipientID: rows[0].ID.String(), Type: "signature", Page: 2, XPct: 10, YPct: 42, WPct: 80, HPct: 7, Required: &required, ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
	deletion, _ := json.Marshal(map[string]string{"expected_pdf_sha256": hex.EncodeToString(doc.PdfSha256), "expected_html_source_commitment": commitment})
	for _, op := range []struct {
		name, method, path string
		body               []byte
	}{{"create", http.MethodPost, "/api/v1/documents/" + doc.ID.String() + "/fields", create}, {"delete", http.MethodDelete, "/api/v1/fields/" + fields[0].ID.String(), deletion}} {
		t.Run(op.name, func(t *testing.T) {
			before, requests := brandedPageInventoryE2E(t, f), peer.requests.Load()
			w := submitSessionOperationE2E(f.s, op.method, op.path, string(op.body), cookie)
			if w.Code != http.StatusConflict {
				t.Fatalf("managed field mutation=%d", w.Code)
			}
			if !bytes.Equal(before, brandedPageInventoryE2E(t, f)) || peer.requests.Load() != requests {
				t.Fatal("refused managed field mutation changed exact state/storage")
			}
		})
	}
	t.Run("maximum_latin_identities_and_local_logo_preview", func(t *testing.T) {
		values := map[string]string{}
		var logoSHA string
		template := createBrandedDesignVariantE2E(t, f, cookie, func(master *htmlmaster.Master, defaults map[string]string) {
			// These deliberately unrealistic declarations exercise the approved
			// page limits. They are synthetic QA inputs, never customer identities.
			for _, slot := range []string{"customer", "provider"} {
				defaults[slot+"_company"] = strings.Repeat("W", htmlmaster.MaxSigningPageCompanyNameChars)
				defaults[slot+"_company_id"] = strings.ToUpper(slot[:1]) + strings.Repeat("W", htmlmaster.MaxSigningPageCompanyIDChars-1)
				defaults[slot+"_name"] = "Åsa Zoë " + strings.Repeat("W", htmlmaster.MaxSigningPageRepresentativeNameChars-8)
				defaults[slot+"_email"] = strings.Repeat("w", 64) + "@" + strings.Repeat(slot[:1], 58) + ".test"
				defaults[slot+"_authority"] = strings.Repeat("W", htmlmaster.MaxSigningPageAuthorityChars)
				for _, field := range []string{"company", "company_id", "name", "email", "authority"} {
					values[slot+"_"+field] = defaults[slot+"_"+field]
				}
			}
			master.CSS += ` p {overflow-wrap:anywhere; word-break:break-word;}`
			// Encode a small fixed image rather than trusting opaque PNG bytes.
			logo := image.NewRGBA(image.Rect(0, 0, 64, 16))
			for y := 0; y < 16; y++ {
				for x := 0; x < 64; x++ {
					pixel := color.RGBA{R: 36, G: 88, B: 166, A: 255}
					if x >= 32 {
						pixel = color.RGBA{R: 218, G: 126, B: 32, A: 255}
					}
					logo.SetRGBA(x, y, pixel)
				}
			}
			var encoded bytes.Buffer
			if err := png.Encode(&encoded, logo); err != nil {
				t.Fatal("encode bounded synthetic logo:", err)
			}
			digest := sha256.Sum256(encoded.Bytes())
			logoSHA = hex.EncodeToString(digest[:])
			master.Assets = []htmlmaster.Asset{{Name: "qa_logo", MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString(encoded.Bytes()), SHA256: logoSHA}}
			master.SigningPage.LogoAsset, master.SigningPage.LogoSHA256, master.SigningPage.LogoAlt = "qa_logo", logoSHA, "Synthetic approved logo"
		})
		pdf := approveBrandedDesignE2E(t, f, template, peer, cookie)
		exportBrandedMaximumPreviewE2E(t, pdf, values, logoSHA)
	})
}

func exportBrandedMaximumPreviewE2E(t *testing.T, pdf []byte, values map[string]string, logoSHA string) {
	t.Helper()
	directory := os.Getenv("HASH_SIGNER_PDF_BROWSER_ARTIFACTS")
	if directory == "" {
		return
	}
	info, err := os.Lstat(directory)
	if !filepath.IsAbs(directory) || err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("maximum-identity PDF artifacts require an existing private absolute directory")
	}
	digest := sha256.Sum256(pdf)
	receipt, err := json.MarshalIndent(map[string]any{"scope": "Synthetic maximum supported Latin identities and local PNG logo; actual owner-approval renderer and worker; visual acceptance pending", "page_count": 2, "pdf_sha256": hex.EncodeToString(digest[:]), "font_sha256": htmlmaster.SigningPageFontSHA256, "logo_sha256": logoSHA, "logo_alt": "Synthetic approved logo", "expected_printed_values": values}, "", "  ")
	if err != nil {
		t.Fatal("encode safe maximum-identity QA receipt")
	}
	for _, output := range []struct {
		name string
		body []byte
	}{{"qa-max-identities-logo.pdf", pdf}, {"qa-max-identities-logo.json", append(receipt, '\n')}} {
		file, err := os.OpenFile(filepath.Join(directory, output.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("create fresh synthetic maximum-identity QA artifact")
		}
		_, writeErr := file.Write(output.body)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("write synthetic maximum-identity QA artifact")
		}
	}
}

type brandedSQLMutationE2E struct {
	name, statement string
	args            []any
}

func brandedSQLMutationsE2E(doc *generated.Document, rows []*generated.Recipient, fields []*generated.DocumentField) []brandedSQLMutationE2E {
	var customer, provider uuid.UUID
	for _, row := range rows {
		if row.Role == "customer" {
			customer = row.ID
		} else if row.Role == "provider" {
			provider = row.ID
		}
	}
	var field uuid.UUID
	for _, f := range fields {
		if f.RecipientID.Valid && uuid.UUID(f.RecipientID.Bytes) == customer {
			field = f.ID
		}
	}
	return []brandedSQLMutationE2E{
		{"movement", `UPDATE document_fields SET y_pct=43 WHERE document_id=$1 AND id=$2`, []any{doc.ID, field}},
		{"empty_field_identity", `UPDATE document_fields SET id='00000000-0000-0000-0000-000000000000' WHERE document_id=$1 AND id=$2`, []any{doc.ID, field}},
		{"deletion", `DELETE FROM document_fields WHERE document_id=$1 AND id=$2`, []any{doc.ID, field}},
		{"reassignment", `UPDATE document_fields SET recipient_id=$3 WHERE document_id=$1 AND id=$2`, []any{doc.ID, field, provider}},
		{"extra", `INSERT INTO document_fields(document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required,label,options_json) SELECT document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required,label,options_json FROM document_fields WHERE document_id=$1 AND id=$2`, []any{doc.ID, field}},
		{"options", `UPDATE document_fields SET options_json='{}'::jsonb WHERE document_id=$1 AND id=$2`, []any{doc.ID, field}},
		{"optional_signature", `UPDATE document_fields SET required=false WHERE document_id=$1 AND id=$2`, []any{doc.ID, field}},
		{"branding", `UPDATE document_branding_override SET primary_hex='#334455' WHERE document_id=$1`, []any{doc.ID}},
		{"branding_deletion", `DELETE FROM document_branding_override WHERE document_id=$1`, []any{doc.ID}},
		{"recipient_identity", `UPDATE recipients SET name='Unexpected customer' WHERE document_id=$1 AND id=$2`, []any{doc.ID, customer}},
		{"recipient_mailbox", `UPDATE recipients SET email='unexpected@example.test' WHERE document_id=$1 AND id=$2`, []any{doc.ID, customer}},
		{"recipient_role", `UPDATE recipients SET role='provider' WHERE document_id=$1 AND id=$2`, []any{doc.ID, customer}},
		{"recipient_deletion", `DELETE FROM recipients WHERE document_id=$1 AND id=$2`, []any{doc.ID, customer}},
		{"signature_downgrade", `UPDATE documents SET requires_signature=false WHERE id=$1 AND org_id=$2`, []any{doc.ID, doc.OrgID}},
	}
}

func assertBrandedCommitRefusalE2E(t *testing.T, f lifecycleAuthorizationFixture, mutation brandedSQLMutationE2E) {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	rows, err := tx.Exec(f.ctx, mutation.statement, mutation.args...) //nolint:rawsql -- exact owned corruption simulation, must reach deferred guard
	if mutation.name == "empty_field_identity" {
		// The current measurement row retains this exact field identity with an
		// immediate foreign key. Refusal before commit is stronger than the older
		// deferred branded-page check; the caller still proves full rollback.
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "23503" && rows.RowsAffected() == 0 {
			return
		}
	}
	if err != nil || rows.RowsAffected() != 1 {
		t.Fatalf("scoped corruption did not reach deferred guard: rows=%d error=%v", rows.RowsAffected(), err)
	}
	err = tx.Commit(f.ctx)
	assertBrandedConstraintErrorE2E(t, err)
}

func assertBrandedConstraintErrorE2E(t *testing.T, err error) {
	t.Helper()
	var pgerr *pgconn.PgError
	// Migration76 translates missing or duplicate bindings to the same check
	// violation as an exact-value mismatch. A successful one-row mutation plus
	// exact rollback inventory proves refusal occurred at deferred commit.
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
		t.Fatalf("branded deferred constraint did not refuse commit: %v", err)
	}
}

func TestHTMLBrandedSigningPageDatabaseGuardsAndRetainedRollbackE2E(t *testing.T) {
	f, peer, cookie := brandedPageFixtureE2E(t)
	template := createBrandedDesignE2E(t, f, cookie)
	approveBrandedDesignE2E(t, f, template, peer, cookie)
	doc := createBrandedDocumentE2E(t, f, template, cookie)
	f.doc = doc
	rows, fields, _ := assertBrandedStateE2E(t, f, doc)
	mutations := brandedSQLMutationsE2E(doc, rows, fields)
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			before, requests := brandedPageInventoryE2E(t, f), peer.requests.Load()
			assertBrandedCommitRefusalE2E(t, f, mutation)
			if !bytes.Equal(before, brandedPageInventoryE2E(t, f)) || requests != peer.requests.Load() {
				t.Fatal("deferred refusal changed original exact state/storage")
			}
		})
	}
	for _, name := range []string{"movement", "branding", "recipient_identity"} {
		t.Run("parent_lock_"+name, func(t *testing.T) {
			var mutation brandedSQLMutationE2E
			for _, candidate := range mutations {
				if candidate.name == name {
					mutation = candidate
				}
			}
			before, requests := brandedPageInventoryE2E(t, f), peer.requests.Load()
			held, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = held.Rollback(context.Background()) }()
			if _, err := f.q.WithTx(held).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			type result struct {
				rows                   int64
				mutationErr, commitErr error
			}
			done := make(chan result, 1)
			go func() {
				tx, err := f.pool.Begin(ctx)
				if err != nil {
					done <- result{mutationErr: err}
					return
				}
				defer func() { _ = tx.Rollback(context.Background()) }()
				tag, err := tx.Exec(ctx, "/* branded-page-parent-lock */ "+mutation.statement, mutation.args...)
				if err != nil {
					done <- result{mutationErr: err}
					return
				}
				done <- result{rows: tag.RowsAffected(), commitErr: tx.Commit(ctx)}
			}() //nolint:rawsql -- bounded scoped concurrent corruption attempt
			awaitBrandedParentLockE2E(t, f)
			select {
			case <-done:
				t.Fatal("child mutation crossed the held parent lock")
			default:
			}
			if err := held.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case result := <-done:
				if result.mutationErr != nil || result.rows != 1 {
					t.Fatalf("blocked mutation rows=%d error=%v", result.rows, result.mutationErr)
				}
				assertBrandedConstraintErrorE2E(t, result.commitErr)
			case <-ctx.Done():
				t.Fatal("blocked branded mutation did not settle")
			}
			if !bytes.Equal(before, brandedPageInventoryE2E(t, f)) || requests != peer.requests.Load() {
				t.Fatal("blocked refusal changed original state/storage")
			}
		})
	}
	t.Run("token_rotation_serializes_parent_but_ignores_frozen_field_plan", func(t *testing.T) {
		target := rows[0].ID
		before, requests := brandedTokenInventoryE2E(t, f, target), peer.requests.Load()
		held, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal("begin bounded frozen-plan lock fixture")
		}
		defer func() { _ = held.Rollback(context.Background()) }()
		var locked uuid.UUID
		if err := held.QueryRow(f.ctx, `SELECT id FROM documents WHERE id=$1 AND org_id=$2 FOR SHARE`, doc.ID, f.org).Scan(&locked); err != nil || locked != doc.ID {
			t.Fatal("hold exact fixture document share lock")
		}
		fieldLock, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal("begin independent frozen-field lock")
		}
		defer func() { _ = fieldLock.Rollback(context.Background()) }()
		if _, err := fieldLock.Exec(f.ctx, `LOCK TABLE document_fields IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal("hold unrelated field-plan table lock")
		}
		// Current admission guards serialize all recipient changes on the parent.
		// Release only that legitimate fence after observing its actual waiter;
		// the independent field-plan lock stays held through token COMMIT. The
		// branded checker's identity-preserving fast path must not touch fields.
		hash := sha256.Sum256([]byte("Synthetic branded-page token rotation regression"))
		expiry := time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)
		ctx, cancel := context.WithTimeout(f.ctx, time.Second)
		defer cancel()
		type tokenResult struct {
			tag pgconn.CommandTag
			err error
		}
		done := make(chan tokenResult, 1)
		joined := false
		go func() {
			tag, err := f.pool.Exec(ctx, `/* branded-token-parent-fence */ UPDATE recipients SET magic_token_hash=$3,magic_token_expires_at=$4 WHERE document_id=$1 AND id=$2`, doc.ID, target, hash[:], expiry)
			done <- tokenResult{tag, err}
		}()
		defer func() {
			cancel()
			_ = held.Rollback(context.Background())
			_ = fieldLock.Rollback(context.Background())
			if !joined {
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					t.Error("token rotation did not join before fixture cleanup")
				}
			}
		}()
		awaitSessionOperationLockE2E(t, f.ctx, f.pool, "branded-token-parent-fence", "transactionid")
		var blockedByParent int
		var parentPID int
		if err := held.QueryRow(f.ctx, "SELECT pg_backend_pid()").Scan(&parentPID); err != nil {
			t.Fatal(err)
		}
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND query LIKE '%branded-token-parent-fence%' AND state='active' AND $1=ANY(pg_blocking_pids(pid))`, parentPID).Scan(&blockedByParent); err != nil || blockedByParent != 1 {
			t.Fatal("token rotation did not retain the exact current parent fence", err)
		}
		if err := held.Rollback(f.ctx); err != nil {
			t.Fatal("release current recipient parent fence")
		}
		select {
		case result := <-done:
			joined = true
			if result.err != nil || result.tag.RowsAffected() != 1 {
				t.Fatal("token rotation touched the unrelated field plan or did not commit", result.err)
			}
		case <-ctx.Done():
			t.Fatal("token rotation did not commit within its original bounded deadline")
		}
		if err := fieldLock.Rollback(f.ctx); err != nil {
			t.Fatal("release independent field-plan lock")
		}
		updated, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
		if err != nil {
			t.Fatal("read rotated synthetic recipient")
		}
		found := false
		for _, row := range updated {
			if row.ID == target {
				found = bytes.Equal(row.MagicTokenHash, hash[:]) && row.MagicTokenExpiresAt.Valid && row.MagicTokenExpiresAt.Time.Equal(expiry)
			}
		}
		if !found || !equalBrandedJSONE2E(before, brandedTokenInventoryE2E(t, f, target)) || requests != peer.requests.Load() {
			t.Fatal("token rotation changed frozen source/plan/identity or failed to persist exactly")
		}
	}) //nolint:rawsql -- exact disposable recipient token regression with held independent transaction locks
	t.Run("retained_down_refusal", func(t *testing.T) {
		before := brandedPageInventoryE2E(t, f)
		raw, err := os.ReadFile("../db/migrations/00076_branded_signing_pages.sql")
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.SplitN(string(raw), "-- +goose Down", 2)
		if len(parts) != 2 {
			t.Fatal("migration76 has no explicit Down")
		}
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		_, err = tx.Exec(f.ctx, parts[1])
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Fatalf("retained branded migration Down=%v", err)
		}
		if err := tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
		var guards int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_trigger WHERE tgname IN('branded_signing_page_document','branded_signing_page_fields','branded_signing_page_branding','branded_signing_page_recipients') AND tgdeferrable AND tginitdeferred AND tgenabled='O'`).Scan(&guards); err != nil || guards != 4 {
			t.Fatal("failed Down removed forward deferred guards:", err)
		} //nolint:rawsql -- migration refusal must preserve all four exact forward guards
		assertBrandedCommitRefusalE2E(t, f, mutations[0])
		if !bytes.Equal(before, brandedPageInventoryE2E(t, f)) {
			t.Fatal("failed Down/forward refusal changed retained context")
		}
	})
}

func brandedTokenInventoryE2E(t *testing.T, f lifecycleAuthorizationFixture, target uuid.UUID) []byte {
	t.Helper()
	var inventory map[string]json.RawMessage
	if err := json.Unmarshal(brandedPageInventoryE2E(t, f), &inventory); err != nil {
		t.Fatal("decode synthetic token inventory")
	}
	var recipients []map[string]json.RawMessage
	if err := json.Unmarshal(inventory["recipients"], &recipients); err != nil {
		t.Fatal("decode synthetic token recipient inventory")
	}
	matched := 0
	for _, row := range recipients {
		var id uuid.UUID
		if err := json.Unmarshal(row["id"], &id); err != nil {
			t.Fatal("decode synthetic token recipient identity")
		}
		if id == target {
			matched++
			delete(row, "magic_token_hash")
			delete(row, "magic_token_expires_at")
		}
	}
	if matched != 1 {
		t.Fatal("synthetic token inventory lacks its exact recipient")
	}
	raw, err := json.Marshal(recipients)
	if err != nil {
		t.Fatal("encode synthetic token recipient inventory")
	}
	inventory["recipients"] = raw
	raw, err = json.Marshal(inventory)
	if err != nil {
		t.Fatal("encode synthetic token inventory")
	}
	return raw
}

func awaitBrandedParentLockE2E(t *testing.T, f lifecycleAuthorizationFixture) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND state='active' AND wait_event='transactionid' AND (query LIKE '/* branded-page-parent-lock */%' OR lower(query)='commit')`, f.pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	} //nolint:rawsql -- actual child mutation/deferred commit lock wait, scoped to this private fixture
	t.Fatal("branded child mutation did not wait for the original parent lock")
}

func TestHTMLBrandedSigningPageRevisionPreservesExactHistoricalContextE2E(t *testing.T) {
	f, peer, cookie := brandedPageFixtureE2E(t)
	template := createBrandedDesignE2E(t, f, cookie)
	approveBrandedDesignE2E(t, f, template, peer, cookie)
	original := createBrandedDocumentE2E(t, f, template, cookie)
	f.doc = original
	commitment, err := htmlsource.Commitment(original)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: original.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(original.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
	if w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+original.ID.String()+"/html/review", string(proof), cookie); w.Code != http.StatusOK {
		t.Fatalf("review branded source=%d bytes=%d", w.Code, w.Body.Len())
	}
	original, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	f.doc = original
	oldRows, oldFields, oldArtifact := assertBrandedStateE2E(t, f, original)
	var oldBrand json.RawMessage
	if err := f.pool.QueryRow(f.ctx, `SELECT to_jsonb(b) FROM document_branding_override b WHERE document_id=$1`, original.ID).Scan(&oldBrand); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- exact snapshot branding assertion
	in := htmlDocumentRevisionInput{ExpectedUpdatedAt: original.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: commitment, Values: htmlStringMap{"customer_name": "Åsa Reviewed Customer", "customer_email": "Reviewed.Customer@Example.Test"}, Sections: htmlStringMap{}, Summary: "Agreed customer representative revision"}
	w := submitRevisionE2E(t, f, in, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("branded identity revision=%d bytes=%d", w.Code, w.Body.Len())
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	rows, fields, artifact := assertBrandedStateE2E(t, f, current)
	if current.HtmlCurrentMaterializationSequence.Int32 != 2 || current.HtmlReviewedBy.Valid || current.HtmlReviewedMaterializationID.Valid || !bytes.Equal(current.HtmlSourceJson, original.HtmlSourceJson) || bytes.Equal(current.PdfSha256, original.PdfSha256) || artifact.PlanSHA256 == oldArtifact.PlanSHA256 {
		t.Fatal("revision changed origin, retained review or failed to rebind fresh printed page")
	}
	if err := htmlsource.Validate(current, true); !errors.Is(err, htmlsource.ErrReviewRequired) {
		t.Fatal("fresh branded artifact reused old review:", err)
	}
	oldIDs := map[uuid.UUID]bool{}
	for _, field := range oldFields {
		oldIDs[field.ID] = true
	}
	for _, field := range fields {
		if oldIDs[field.ID] {
			t.Fatal("revision reused archived field UUID")
		}
	}
	for _, old := range oldRows {
		found := false
		for _, row := range rows {
			if row.ID == old.ID {
				found = true
				if row.Role != old.Role {
					t.Fatal("revision changed stable party role")
				}
				if row.Role == "customer" && (row.Name != "Åsa Reviewed Customer" || row.Email != "Reviewed.Customer@Example.Test") {
					t.Fatal("fresh recipient differs from printed customer")
				}
			}
		}
		if !found {
			t.Fatal("revision replaced intended recipient UUID")
		}
	}
	input, err := htmlsource.InputForCurrent(current)
	if err != nil || input.Values["customer_name"] != "Åsa Reviewed Customer" || input.Values["customer_email"] != "Reviewed.Customer@Example.Test" {
		t.Fatal("current source did not print new customer identity:", err)
	}
	oldMaterialization, err := f.q.GetHTMLDocumentMaterialization(f.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: original.ID, OrgID: f.org, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	historical, err := htmlmaterialization.HistoricalDocument(current, oldMaterialization)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(historical.PdfSha256, original.PdfSha256) || !bytes.Equal(historical.MetadataRedactionReport, original.MetadataRedactionReport) || htmlsource.ValidateContractParties(historical, oldRows) != nil || htmlsource.ValidateSigningFields(historical, oldFields, 2) != nil {
		t.Fatal("historical source/report/party/field binding changed")
	}
	var snapshotSource, snapshotFields, snapshotRecipients, snapshotNotice, snapshotReport json.RawMessage
	var reviewedSHA []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT source_json,fields_json,recipients_json,notice_context_json,metadata_redaction_report,reviewed_pdf_sha256 FROM html_document_materialization_snapshots WHERE document_id=$1 AND materialization_id=$2 AND kind='draft_superseded'`, original.ID, oldMaterialization.ID).Scan(&snapshotSource, &snapshotFields, &snapshotRecipients, &snapshotNotice, &snapshotReport, &reviewedSHA); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- immutable old-context snapshot proof
	if !equalBrandedJSONE2E(snapshotSource, original.HtmlCurrentSourceJson) || !bytes.Equal(reviewedSHA, original.PdfSha256) || !equalBrandedJSONE2E(snapshotReport, original.MetadataRedactionReport) {
		t.Fatal("snapshot lost exact old source/review/report")
	}
	var archivedFields []*generated.DocumentField
	if err := json.Unmarshal(snapshotFields, &archivedFields); err != nil {
		t.Fatal("snapshot fields cannot decode:", err)
	}
	oldFieldsJSON, err := json.Marshal(oldFields)
	if err != nil {
		t.Fatal(err)
	}
	archivedFieldsJSON, err := json.Marshal(archivedFields)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBrandedJSONE2E(archivedFieldsJSON, oldFieldsJSON) {
		t.Fatal("snapshot lost exact old field UUID/geometry/options")
	}
	var context map[string]json.RawMessage
	if json.Unmarshal(snapshotNotice, &context) != nil || !equalBrandedJSONE2E(context["branding"], oldBrand) {
		t.Fatal("snapshot lost exact old approved branding")
	}
	var archivedRecipients []struct {
		ID                uuid.UUID `json:"id"`
		Role, Name, Email string
	}
	if json.Unmarshal(snapshotRecipients, &archivedRecipients) != nil || len(archivedRecipients) != 2 {
		t.Fatal("snapshot lost old recipient declarations")
	}
	for _, old := range oldRows {
		found := false
		for _, row := range archivedRecipients {
			if row.ID == old.ID && row.Role == old.Role && row.Name == old.Name && row.Email == old.Email {
				found = true
			}
		}
		if !found {
			t.Fatal("snapshot mixed revised identity into old UUID/context")
		}
	}
	if _, err := f.s.Storage.GetVerifiedVersion(f.ctx, original.PdfStorageKey.String, original.PdfStorageVersionID.String, original.PdfSha256); err != nil {
		t.Fatal("revision discarded old PDF object version:", err)
	}
}

func equalBrandedJSONE2E(a, b []byte) bool {
	var left, right any
	return json.Unmarshal(a, &left) == nil && json.Unmarshal(b, &right) == nil && reflect.DeepEqual(left, right)
}
