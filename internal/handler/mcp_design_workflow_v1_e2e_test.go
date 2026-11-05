//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"net/http"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/branding/catalog"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/google/uuid"
)

func callDesign783(t *testing.T, f lifecycleAuthorizationFixture, key, tool string, args map[string]any, dst any, wantError bool) {
	t.Helper()
	w := submitRecipientMCPE2E(f, tool, key, args)
	var envelope struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &envelope) != nil || len(envelope.Error) > 0 || envelope.Result.IsError != wantError || len(envelope.Result.Content) != 1 {
		t.Fatalf("native %s result differs: HTTP %d %s", tool, w.Code, w.Body.String())
	}
	if !wantError && dst != nil {
		if err := json.Unmarshal([]byte(envelope.Result.Content[0].Text), dst); err != nil {
			t.Fatal(tool, err)
		}
	}
}

func TestMCPDesign783NativeBrandExpansionAndAtomicProvenanceE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.BrandCatalog = catalog.NewServiceV1(f.pool, f.s.Audit, f.s.Storage)
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage, Billing: f.s.Billing, PDFCreationSessions: q.runtime.SessionsV1(), Design: f.s.MCPDesignBridgeV1(), BrandCatalog: f.s.BrandCatalog})
	key, _ := automationDocumentKeyE2E(t, q, "read", "write:authoring")
	var imageBytes bytes.Buffer
	if err := png.Encode(&imageBytes, image.NewNRGBA(image.Rect(0, 0, 8, 8))); err != nil {
		t.Fatal(err)
	}
	original := base64.StdEncoding.EncodeToString(imageBytes.Bytes())
	var asset catalog.AssetV1
	callDesign783(t, f, key, "upload_brand_asset", map[string]any{"input": map[string]any{"request_id": uuid.New(), "expected_revision": 0, "name": "Example logo original", "media_type": "image/png", "original_base64": original}}, &asset, false)
	profileInput := catalog.ProfileInputV1{Name: "Example complete brand profile", Profile: catalog.DefaultProfileDataV1()}
	profileInput.Profile.Assets = []catalog.AssetRefV1{{Slot: "logo_primary", AssetID: asset.AssetID, Revision: asset.Revision, Alt: "Example organization", Usage: catalog.LogoUsageV1{ClearSpace: "One symbol width", MinimumWidthPX: 16, AllowedBackgrounds: []string{"surface"}}}}
	var profile catalog.ProfileV1
	callDesign783(t, f, key, "save_brand_profile", map[string]any{"input": profileInput}, &profile, false)
	ref := catalog.ProfileRefV1{ProfileID: profile.ProfileID, Revision: profile.Revision, ContentSHA256: profile.ContentSHA256, AssetSlots: []string{"logo_primary"}}
	master := htmlmaster.Master{SchemaVersion: 1, HTML: `<main><img src="hash-asset:brand_logo_primary" alt="Example organization"><h1>Example proposal</h1></main>`, CSS: `@page{size:A4;margin:20mm;}img{width:80px;}`}
	input := map[string]any{"name": "Server-resolved editable design", "html_master_json": master, "variables_json": map[string]string{}}
	var design struct {
		ID      uuid.UUID `json:"template_id"`
		Version int32     `json:"version"`
		SHA     string    `json:"content_sha256"`
	}
	callDesign783(t, f, key, "create_design_template", map[string]any{"input": input, "brand_profile": ref}, &design, false)
	stored, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: design.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := htmlmaster.Decode(stored.HtmlMasterJson)
	if err != nil || len(actual.Assets) != 1 || actual.Assets[0].Name != "brand_logo_primary" || actual.Assets[0].SHA256 != asset.Render.SHA256 {
		t.Fatal("server did not persist the exact resolved native asset", err)
	}
	resolvedBytes, err := base64.StdEncoding.DecodeString(actual.Assets[0].DataBase64)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(resolvedBytes)
	if hex.EncodeToString(sum[:]) != asset.Render.SHA256 {
		t.Fatal("resolved asset bytes differ from exact catalog render version")
	}
	binding, err := f.q.GetBrandTemplateBindingV1(f.ctx, generated.GetBrandTemplateBindingV1Params{OrgID: f.org, TemplateID: design.ID, TemplateVersion: design.Version})
	if err != nil || binding.ProfileID != profile.ProfileID || binding.ProfileRevision != profile.Revision || !bytes.Equal(binding.ProfileSha256, storedBrandSHA783(t, profile.ContentSHA256)) || len(binding.SelectedSlots) != 1 || binding.SelectedSlots[0] != "logo_primary" {
		t.Fatal("exact template/profile/selected asset provenance missing", err)
	}
	counts := func() [3]int64 {
		var n [3]int64
		if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM templates WHERE org_id=$1),(SELECT count(*) FROM brand_design_template_bindings_v1 WHERE org_id=$1),(SELECT count(*) FROM events WHERE org_id=$1)`, f.org).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	} //nolint:rawsql -- scalar read-only fixture assertions
	before := counts()
	if _, err = f.pool.Exec(f.ctx, `CREATE FUNCTION mcp_brand_bind_refuse783() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic provenance refusal'; END $$; CREATE TRIGGER mcp_brand_bind_refuse783 BEFORE INSERT ON brand_design_template_bindings_v1 FOR EACH ROW EXECUTE FUNCTION mcp_brand_bind_refuse783()`); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- fault injection in this fixture's unique owned database, never business/cache rows
	defer func() {
		if _, err := f.pool.Exec(f.ctx, `DROP TRIGGER IF EXISTS mcp_brand_bind_refuse783 ON brand_design_template_bindings_v1; DROP FUNCTION IF EXISTS mcp_brand_bind_refuse783()`); err != nil {
			t.Error(err)
		}
	}()
	callDesign783(t, f, key, "create_design_template", map[string]any{"input": input, "brand_profile": ref}, nil, true)
	if after := counts(); after != before {
		t.Fatal("failed same-transaction provenance insert retained template, binding or audit", before, after)
	}
	ownedCreationAssertDrainedV1(t, q, 2)
}
func storedBrandSHA783(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Actual key middleware, native HTML owners/writers, real PG history/CAS and
// production PDF-worker preflight. The controlled renderer/storage fixture is
// synthetic; explicit caller review attestations here are NOT visual QA claims.
func TestMCPDesign783NativeVersionedDraftWorkflowE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage, Billing: f.s.Billing, Versions: f.s.Versions, Send: f.s.Send, PDF: f.s.Sign.PDF, PDFCreationSessions: q.runtime.SessionsV1(), Design: f.s.MCPDesignBridgeV1()})
	key, _ := automationDocumentKeyE2E(t, q, "read", "write:authoring")
	master := htmlmaster.Master{SchemaVersion: 1, HTML: `<main><h1>Example proposal</h1><p>For <span data-hash-value="customer"></span></p><div data-hash-section="scope"></div></main>`, CSS: `@page{size:A4;margin:20mm;}div{white-space:pre-wrap;}`, Values: []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 200}}, Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Exact provided scope. No invented terms.", MaxChars: 2000}}}
	input := map[string]any{"name": "Neutral editable proposal", "html_master_json": master, "variables_json": map[string]string{"customer": "Example customer"}}
	var design struct {
		TemplateID uuid.UUID `json:"template_id"`
		Version    int32     `json:"version"`
		SHA        string    `json:"content_sha256"`
		Approved   bool      `json:"approved"`
	}
	callDesign783(t, f, key, "create_design_template", map[string]any{"input": input}, &design, false)
	if design.TemplateID == uuid.Nil || design.Version != 1 || len(design.SHA) != 64 || design.Approved {
		t.Fatal("design was not a new unapproved native revision")
	}
	var preview struct {
		PDF     string `json:"pdf_base64"`
		SHA     string `json:"pdf_sha256"`
		Pages   int    `json:"page_count"`
		Receipt string `json:"preview_receipt"`
		Review  string `json:"visual_review"`
	}
	callDesign783(t, f, key, "preview_design_template", map[string]any{"template_id": design.TemplateID, "input": map[string]any{"expected_version": design.Version, "expected_content_sha256": design.SHA}}, &preview, false)
	if preview.Pages < 1 || preview.Review != "pending" || preview.Receipt == "" {
		t.Fatal("preview silently approved or omitted exact PDF metadata")
	}
	bytes, err := base64.StdEncoding.DecodeString(preview.PDF)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bytes)
	if hex.EncodeToString(digest[:]) != preview.SHA {
		t.Fatal("preview bytes differ from commitment")
	}
	pages := make([]int, preview.Pages)
	for i := range pages {
		pages[i] = i + 1
	}
	approve := map[string]any{"template_id": design.TemplateID, "visually_reviewed": false, "reviewed_pages": pages, "input": map[string]any{"expected_version": design.Version, "expected_content_sha256": design.SHA, "expected_preview_pdf_sha256": preview.SHA, "preview_receipt": preview.Receipt}}
	callDesign783(t, f, key, "approve_design_template", approve, nil, true)
	approve["visually_reviewed"] = true
	other, _ := automationDocumentKeyE2E(t, q, "read", "write:authoring")
	callDesign783(t, f, other, "approve_design_template", approve, nil, true)
	callDesign783(t, f, key, "approve_design_template", approve, nil, false)
	creation := map[string]any{"purpose": "document", "template_id": design.TemplateID, "input": map[string]any{"name": "Internal example proposal", "request_id": uuid.New(), "expected_template_version": design.Version, "expected_template_content_sha256": design.SHA, "values": map[string]string{"customer": "Exact populated customer"}}}
	var created struct {
		Document struct {
			ID uuid.UUID `json:"id"`
		} `json:"document"`
		Review bool `json:"review_required"`
	}
	callDesign783(t, f, key, "create_document_from_design", creation, &created, false)
	if created.Document.ID == uuid.Nil || !created.Review {
		t.Fatal("native internal document missing or auto-reviewed")
	}
	id := created.Document.ID
	var replay struct {
		Document struct {
			ID uuid.UUID `json:"id"`
		} `json:"document"`
	}
	callDesign783(t, f, key, "create_document_from_design", creation, &replay, false)
	if replay.Document.ID != id {
		t.Fatal("creation request replay duplicated the draft")
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := f.q.ListRecipientsByDocument(f.ctx, id)
	if err != nil || len(recipients) != 0 || doc.Status != "draft" || doc.SentAt.Valid || documentpurpose.Response(doc.Metadata) != documentpurpose.Document {
		t.Fatal("internal creation added recipients, sent or changed purpose", err)
	}
	var source struct {
		Declared htmlDocumentSourceResponse `json:"declared_source"`
		Editable struct {
			ReadArguments map[string]any `json:"read_arguments"`
		} `json:"editable_template"`
	}
	callDesign783(t, f, key, "get_document_design_source", map[string]any{"document_id": id}, &source, false)
	if source.Declared.TemplateID != design.TemplateID || source.Declared.TemplateVersion != 1 || source.Declared.TemplateContentSHA256 != design.SHA {
		t.Fatal("frozen editable origin lost")
	}
	downloadInput := map[string]any{"expected_updated_at": source.Declared.UpdatedAt, "expected_pdf_sha256": source.Declared.PDFSHA256, "expected_html_source_commitment": source.Declared.HTMLSourceCommitment}
	var pdf struct {
		PDF    string `json:"pdf_base64"`
		SHA    string `json:"pdf_sha256"`
		Pages  int    `json:"page_count"`
		Review string `json:"visual_review"`
	}
	callDesign783(t, f, key, "download_document_pdf", map[string]any{"document_id": id, "input": downloadInput}, &pdf, false)
	bytes, err = base64.StdEncoding.DecodeString(pdf.PDF)
	if err != nil {
		t.Fatal(err)
	}
	digest = sha256.Sum256(bytes)
	if pdf.SHA != source.Declared.PDFSHA256 || hex.EncodeToString(digest[:]) != pdf.SHA || pdf.Pages != int(source.Declared.PageCount) || pdf.Review != "pending" {
		t.Fatal("exact document PDF/read boundary differs")
	}
	pages = make([]int, pdf.Pages)
	for i := range pages {
		pages[i] = i + 1
	}
	callDesign783(t, f, key, "review_document_design", map[string]any{"document_id": id, "input": downloadInput, "visually_reviewed": true, "reviewed_pages": pages}, nil, false)
	input["expected_version"] = design.Version
	master.CSS = `@page{size:A4;margin:25mm;}div{white-space:pre-wrap;}`
	input["html_master_json"] = master
	var next struct {
		Version  int32 `json:"version"`
		Approved bool  `json:"approved"`
	}
	callDesign783(t, f, key, "update_design_template", map[string]any{"template_id": design.TemplateID, "input": input}, &next, false)
	if next.Version != 2 || next.Approved {
		t.Fatal("layout update failed to create separate unapproved template version")
	}
	callDesign783(t, f, key, "get_document_design_source", map[string]any{"document_id": id}, &source, false)
	if source.Declared.TemplateVersion != 1 {
		t.Fatal("template edit rewrote document's frozen layout")
	}
	var retained htmlTemplateDesignSourceResponseV1
	callDesign783(t, f, key, "get_design_template", source.Editable.ReadArguments, &retained, false)
	oldMaster, err := htmlmaster.Decode(retained.HTMLMasterJSON)
	if err != nil || retained.TemplateID != design.TemplateID || retained.CurrentParentVersion != 2 || retained.CurrentParentName != "Neutral editable proposal" || retained.Version != 1 || retained.ContentSHA256 != design.SHA || retained.HTMLApproval == nil || retained.HTMLApproval.Version != 1 || retained.HTMLApproval.ApprovedBy != f.user.ID.String() || oldMaster.CSS == master.CSS {
		t.Fatal("frozen document did not recover its actual approved old editable source after parent v2", err)
	}
	var current htmlTemplateDesignSourceResponseV1
	callDesign783(t, f, key, "get_design_template", map[string]any{"template_id": design.TemplateID}, &current, false)
	if current.Version != 2 || current.CurrentParentVersion != 2 || current.ContentSHA256 == retained.ContentSHA256 || current.HTMLApproval == nil || current.HTMLApproval.ApprovedBy != "" {
		t.Fatal("current source or old/current approvals were conflated")
	}
	callDesign783(t, f, key, "get_design_template", map[string]any{"template_id": design.TemplateID, "version": 1, "expected_content_sha256": strings.Repeat("0", 64)}, nil, true)
	// The actual retained source/canonical consumer must survive SQL retirement
	// until response serialization, then return to its pre-read observer state.
	req, reader, authorize, _ := ownedHTMLTemplateReadActorE2E(t, f)
	before := q.snapshotV1(t)
	_, selected, closeSelected, err := f.s.readHTMLTemplateSelectionOwnedV1(req.Context(), reader.OrgID, reader.UserID, design.TemplateID, authorize, htmlTemplateReadSelectionV1{Version: 1, ExpectedContentSHA256: design.SHA})
	if closeSelected != nil {
		defer closeSelected()
	}
	if err != nil || closeSelected == nil || selected.Version != 1 || selected.CurrentParentVersion != 2 {
		t.Fatal("native retained owned selector failed", err)
	}
	heldSource := q.snapshotV1(t)
	if heldSource.Global.ParentBytes <= before.Global.ParentBytes || heldSource.Global.DBStagingBytes <= before.Global.DBStagingBytes || heldSource.GlobalGrants <= before.GlobalGrants {
		t.Fatal("retained native source released before last serialized use")
	}
	if raw, err := json.Marshal(selected); err != nil || len(raw) == 0 {
		t.Fatal("retained source serialization failed", err)
	}
	closeSelected()
	closeSelected()
	after := q.snapshotV1(t)
	if after.Global != before.Global || after.GlobalGrants != before.GlobalGrants || after.Organisation != before.Organisation || after.OrganisationGrants != before.OrganisationGrants {
		t.Fatal("retained source consumer did not settle after final use")
	}
	old := source.Declared
	callDesign783(t, f, key, "revise_document_design_values", map[string]any{"document_id": id, "input": map[string]any{"expected_updated_at": old.UpdatedAt, "expected_html_source_commitment": old.HTMLSourceCommitment, "values": map[string]string{"customer": "Revised supplied customer"}, "summary": "Changed declared customer only"}}, nil, false)
	callDesign783(t, f, key, "get_document_design_source", map[string]any{"document_id": id}, &source, false)
	if source.Declared.MaterializationRevision != old.MaterializationRevision+1 || source.Declared.HTMLSourceCommitment == old.HTMLSourceCommitment || source.Declared.TemplateVersion != 1 {
		t.Fatal("declared-text revision lost history or changed frozen master")
	}
	callDesign783(t, f, key, "download_document_pdf", map[string]any{"document_id": id, "input": downloadInput}, nil, true)
	doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	if err != nil || doc.HtmlReviewedAt.Valid || doc.Status != "draft" || doc.SentAt.Valid {
		t.Fatal("revision retained obsolete review or advanced workflow", err)
	}
	ownedCreationAssertDrainedV1(t, q, 2)
}
