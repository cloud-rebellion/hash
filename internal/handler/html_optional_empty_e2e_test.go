//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const htmlOptionalEmptyVariableE2E = "crm_optional_note"
const htmlOptionalEmptySectionE2E = "manual_scope"
const htmlOptionalEmptyWordingE2E = "Human reviewed scope ÅÄÖ remains unchanged."

// These tests use actual handlers, PostgreSQL, the protected HTTP CRM client
// and exact-version storage. The schema1 renderer returns a synthetic PDF;
// schema3 requires the real renderer and isolated worker via the existing
// branded fixture. The CRM and S3 peers remain synthetic, with no live provider,
// Object Lock, sending, signing or layout acceptance implied by this fixture.
func TestHTMLDocumentOptionalEmptyRevisionRetainsExactHistoryAndResetsPlacementE2E(t *testing.T) {
	f, renderer, peer, original, cookie := setupHTMLOptionalEmptyE2E(t, false)
	runHTMLOptionalEmptyE2E(t, f, renderer, peer, original, cookie, false)
}

func TestHTMLDocumentOptionalEmptyBrandedRevisionRegeneratesPinnedFieldsE2E(t *testing.T) {
	f, renderer, peer, original, cookie := setupHTMLOptionalEmptyE2E(t, true)
	runHTMLOptionalEmptyE2E(t, f, renderer, peer, original, cookie, true)
}

func setupHTMLOptionalEmptyE2E(t *testing.T, branded bool) (lifecycleAuthorizationFixture, *htmlCreationRendererE2E, *htmlCreationStorageE2E, *generated.Document, string) {
	t.Helper()
	if os.Getenv("HASH_E2E_PDF_WORKER_PATH") == "" {
		t.Skip("set HASH_E2E_PDF_WORKER_PATH for isolated optional-empty PDF intake")
	}
	var f lifecycleAuthorizationFixture
	var renderer *htmlCreationRendererE2E
	var peer *htmlCreationStorageE2E
	var cookie string
	var template *generated.Template
	if branded {
		f, peer, cookie = brandedPageFixtureE2E(t)
		template = createBrandedDesignVariantE2E(t, f, cookie, func(master *htmlmaster.Master, defaults map[string]string) {
			master.Values = append(master.Values, htmlmaster.Value{Name: htmlOptionalEmptyVariableE2E, MaxChars: 120})
			master.Sections = append(master.Sections, htmlmaster.Section{Name: htmlOptionalEmptySectionE2E, DefaultText: "Approved default scope", MaxChars: 500})
			master.HTML += `<p><span data-hash-value="crm_optional_note"></span></p><div data-hash-section="manual_scope"></div>`
			if _, present := defaults[htmlOptionalEmptyVariableE2E]; present {
				t.Fatal("optional fixture default must be absent")
			}
		})
		approveBrandedDesignE2E(t, f, template, peer, cookie)
	} else {
		renderer = &htmlCreationRendererE2E{}
		f, peer = setupHTMLDocumentCreationE2E(t, renderer)
		cookie = dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
		master, err := json.Marshal(htmlmaster.Master{SchemaVersion: 1,
			HTML: `<p><span data-hash-value="customer"></span></p><p><span data-hash-value="crm_optional_note"></span></p><div data-hash-section="manual_scope"></div>`,
			Values: []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 200},
				{Name: htmlOptionalEmptyVariableE2E, MaxChars: 120}},
			Sections: []htmlmaster.Section{{Name: htmlOptionalEmptySectionE2E, DefaultText: "Approved default scope", MaxChars: 500}},
		})
		if err != nil {
			t.Fatal(err)
		}
		w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "Optional presence revision design",
			HTMLMasterJSON: master, VariablesJSON: json.RawMessage(`{"customer":"Original AB"}`)}, cookie)
		var response templateResponse
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.ID == uuid.Nil {
			t.Fatalf("create optional design=%d", w.Code)
		}
		template, err = f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: response.ID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		approveHTMLCreationTemplateE2E(t, f, template)
	}
	// Omit all recovery/CRM creation members. This fixture exercises the legacy
	// manual creation command, then the separately reviewed document CRM Apply.
	body, err := json.Marshal(map[string]any{"name": "Optional presence proposal", "expected_template_version": template.Version,
		"expected_template_content_sha256": hex.EncodeToString(template.HtmlContentSha256),
		"sections":                         htmlStringMap{htmlOptionalEmptySectionE2E: htmlOptionalEmptyWordingE2E}})
	if err != nil {
		t.Fatal(err)
	}
	w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/templates/"+template.ID.String()+"/html/documents", string(body), cookie)
	var response struct {
		Document documentResponse `json:"document"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Document.ID == uuid.Nil {
		t.Fatalf("create optional document=%d", w.Code)
	}
	doc := reloadHTMLOptionalEmptyE2E(t, f, response.Document.ID)
	f.doc = doc
	if branded {
		assertBrandedStateE2E(t, f, doc)
	}
	return f, renderer, peer, doc, cookie
}

func reloadHTMLOptionalEmptyE2E(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) *generated.Document {
	t.Helper()
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func optionalEmptyCRMObservationE2E(t *testing.T, f lifecycleAuthorizationFixture, cookie string) (CRMMappingRequest, crmDocumentObservation) {
	t.Helper()
	t.Setenv("HASH_ENVIRONMENT", "development")
	peer := newCRMSourcePeerE2E(t)
	peer.mu.Lock()
	var record map[string]json.RawMessage
	err := json.Unmarshal(peer.deal, &record)
	if err == nil {
		record["currency"] = json.RawMessage(`""`)
		peer.deal, err = json.Marshal(record)
	}
	peer.mu.Unlock()
	if err != nil {
		t.Fatal("could not prepare source-shaped empty CRM scalar")
	}
	client, err := crmconnection.NewClient(peer.server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crmconnection.NewKeyring(crmConnectionKeyE2E, "")
	if err != nil {
		t.Fatal(err)
	}
	f.s.CRMOrigin, f.s.CRMClient, f.s.CRMKeys = peer.server.URL, client, keys
	owner := crmConnectionFixtureE2E{lifecycleAuthorizationFixture: f, cookie: cookie}
	owner.active(t) // Real configure/confirm, two HTTP /me reads and resealing.
	context := crmDocumentReadContextE2E(t, f, cookie)
	in := CRMMappingRequest{CRMDocumentWitnessE2E(context), []crmDocumentMapping{{htmlOptionalEmptyVariableE2E, "crm.deal", crmSourceDealE2E, "currency"}}}
	before, accounts, records := revisionStateE2E(t, f), peer.accounts.Load(), peer.deals.Load()
	out := crmDocumentObserveE2E(t, f, cookie, in)
	if !out.ContentChanged || len(out.Items) != 1 || out.Items[0].CurrentPresent || out.Items[0].CurrentValue != "" ||
		!out.Items[0].Available || out.Items[0].Value == nil || *out.Items[0].Value != "" || out.Items[0].CRMObservation == nil ||
		out.Items[0].CRMObservation.ValueSHA256 != crmScalarSHA("") || out.Items[0].CRMObservation.Origin != peer.server.URL {
		t.Fatal("first optional empty was unavailable, already present or lacked exact protected provenance")
	}
	if !bytes.Equal(before, revisionStateE2E(t, f)) || peer.accounts.Load() != accounts+2 || peer.deals.Load() != records+1 {
		t.Fatal("read-only optional observation mutated state or did not use the protected grouped read")
	}
	return in, out
}

func runHTMLOptionalEmptyE2E(t *testing.T, f lifecycleAuthorizationFixture, renderer *htmlCreationRendererE2E, peer *htmlCreationStorageE2E, original *generated.Document, cookie string, branded bool) {
	t.Helper()
	path := "/api/v1/documents/" + original.ID.String()
	initialInput, err := htmlsource.InputForCurrent(original)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := initialInput.Values[htmlOptionalEmptyVariableE2E]; present || initialInput.Sections[htmlOptionalEmptySectionE2E] != htmlOptionalEmptyWordingE2E {
		t.Fatal("fixture must begin with an absent optional value and exact manual wording")
	}
	originalCID, err := htmlsource.Commitment(original)
	if err != nil {
		t.Fatal(err)
	}
	review, _ := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: original.UpdatedAt.Time.UTC().Format(time.RFC3339Nano),
		ExpectedPDFSHA256: hex.EncodeToString(original.PdfSha256), ExpectedHTMLSourceCommitment: originalCID})
	if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/html/review", string(review), cookie); w.Code != http.StatusOK {
		t.Fatalf("review optional origin=%d", w.Code)
	}
	if !branded {
		field, _ := json.Marshal(addFieldInput{Type: "text", Page: 1, XPct: 15, YPct: 20, WPct: 30, HPct: 5,
			ExpectedPDFSHA256: hex.EncodeToString(original.PdfSha256), ExpectedHTMLSourceCommitment: originalCID})
		if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/fields", string(field), cookie); w.Code != http.StatusCreated {
			t.Fatalf("place origin text field=%d", w.Code)
		}
	}
	original = reloadHTMLOptionalEmptyE2E(t, f, original.ID)
	f.doc = original
	if err := htmlsource.Validate(original, true); err != nil || !original.HtmlReviewedMaterializationID.Valid {
		t.Fatal("fixture has no exact reviewed original materialization", err)
	}
	oldFields, err := f.q.ListFieldsByDocument(f.ctx, original.ID)
	if err != nil || (!branded && len(oldFields) != 1) || (branded && len(oldFields) != 2) {
		t.Fatal("fixture lacks the original field geometry", err)
	}
	oldRecipients, err := f.q.ListRecipientsByDocument(f.ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	oldRecipientJSON, _ := json.Marshal(oldRecipients)
	oldRow, err := f.q.GetHTMLDocumentMaterialization(f.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: original.ID, OrgID: f.org, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	oldRowJSON, _ := json.Marshal(oldRow)
	var oldFieldJSON, oldContextRecipients json.RawMessage
	if err := f.pool.QueryRow(f.ctx, `SELECT c.fields_json,c.recipients_json FROM hash_html_materialization_snapshot_context($1) c`, original.ID).Scan(&oldFieldJSON, &oldContextRecipients); err != nil { //nolint:rawsql -- exact synthetic pre-revision geometry/party context
		t.Fatal(err)
	}
	oldPDF, err := f.s.Storage.GetVerifiedVersion(f.ctx, oldRow.PdfKey, oldRow.PdfVersionID, oldRow.PdfSha256)
	if err != nil {
		t.Fatal(err)
	}
	initialDigest, err := htmlsource.MaterializationDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	request, observation := optionalEmptyCRMObservationE2E(t, f, cookie)
	renders := 0
	if renderer != nil {
		renders = len(renderer.sources())
	}
	w := crmDocumentRequestE2E(t, f, f.ctx, http.MethodPost, "apply", cookie, crmDocumentApplyInputE2E(request, observation.ReviewDigest))
	var response struct {
		Document                documentResponse `json:"document"`
		ContentChanged          bool             `json:"content_changed"`
		ReviewRequired          bool             `json:"review_required"`
		PlacementReset          bool             `json:"placement_reset"`
		MaterializationRevision int32            `json:"materialization_revision"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Document.ID != original.ID ||
		!response.ContentChanged || !response.ReviewRequired || !response.PlacementReset || !response.Document.HTMLReviewRequired || response.MaterializationRevision != 2 {
		t.Fatalf("first empty Apply did not perform a real reviewed PDF revision: status=%d", w.Code)
	}
	current := reloadHTMLOptionalEmptyE2E(t, f, original.ID)
	f.doc = current
	assertCRMNativeRevisionMeasurements621(t, f, current)
	currentInput, err := htmlsource.InputForCurrent(current)
	if err != nil {
		t.Fatal(err)
	}
	expectedValues := maps.Clone(initialInput.Values)
	expectedValues[htmlOptionalEmptyVariableE2E] = ""
	currentCID, err := htmlsource.Commitment(current)
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, err := htmlsource.MaterializationDigest(current)
	if err != nil || currentDigest != initialDigest || currentCID == originalCID || !maps.Equal(currentInput.Values, expectedValues) ||
		!maps.Equal(currentInput.Sections, initialInput.Sections) || !bytes.Equal(current.HtmlSourceJson, original.HtmlSourceJson) ||
		current.PdfStorageKey == original.PdfStorageKey || !current.PdfStorageVersionID.Valid ||
		current.HtmlCurrentMaterializationID == original.HtmlCurrentMaterializationID || current.HtmlCurrentMaterializationSequence.Int32 != 2 {
		t.Fatal("optional presence changed visible inputs/origin or reused the old immutable PDF tuple", err)
	}
	if current.HtmlReviewedAt.Valid || current.HtmlReviewedBy.Valid || current.HtmlReviewedMaterializationID.Valid || len(current.HtmlReviewedPdfSha256) != 0 ||
		!errors.Is(htmlsource.Validate(current, true), htmlsource.ErrReviewRequired) {
		t.Fatal("identical rendered content inherited the old human PDF review")
	}
	newFields, err := f.q.ListFieldsByDocument(f.ctx, current.ID)
	if err != nil || (!branded && len(newFields) != 0) {
		t.Fatal("optional empty revision retained user field placements", err)
	}
	if branded {
		newRecipients, protected, artifact := assertBrandedStateE2E(t, f, current)
		newRecipientJSON, _ := json.Marshal(newRecipients)
		if !bytes.Equal(oldRecipientJSON, newRecipientJSON) || !maps.Equal(partyIDsHTMLOptionalEmptyE2E(initialInput), partyIDsHTMLOptionalEmptyE2E(currentInput)) ||
			artifact.Composition.OutputSHA256 != hex.EncodeToString(current.PdfSha256) || len(protected) != 2 {
			t.Fatal("optional empty replaced a pinned printed party or failed exact final-PDF field binding")
		}
		for _, fresh := range protected {
			var previous *generated.DocumentField
			for _, field := range oldFields {
				if field.RecipientID == fresh.RecipientID {
					previous = field
				}
				if field.ID == fresh.ID {
					t.Fatal("protected field row was reused instead of regenerated")
				}
			}
			if previous == nil || previous.Page != fresh.Page || !sameOptionalEmptyNumericE2E(previous.XPct, fresh.XPct) ||
				!sameOptionalEmptyNumericE2E(previous.YPct, fresh.YPct) || !sameOptionalEmptyNumericE2E(previous.WPct, fresh.WPct) || !sameOptionalEmptyNumericE2E(previous.HPct, fresh.HPct) {
				t.Fatal("regenerated protected geometry differs from the approved fixed page")
			}
		}
	}
	assertHTMLOptionalEmptyHistoryE2E(t, f, original, current, oldRowJSON, oldPDF, oldFieldJSON, oldContextRecipients, cookie)
	assertImportStorageE2E(t, peer.importStoragePeer, 2, 0, 2)
	if renderer != nil && len(renderer.sources()) != renders+1 {
		t.Fatal("optional empty skipped or repeated the normal fresh HTML render")
	}
	context := crmDocumentReadContextE2E(t, f, cookie)
	if context.MappingReviewRequired {
		t.Fatal("confirmed first empty did not persist its CRM mapping review")
	}
	readback := crmDocumentObserveE2E(t, f, cookie, CRMMappingRequest{CRMDocumentWitnessE2E(context), request.Mappings})
	if len(readback.Items) != 1 || !readback.Items[0].CurrentPresent || readback.Items[0].CurrentValue != "" || readback.ContentChanged {
		t.Fatal("explicit empty did not remain present in subsequent observations")
	}
	for _, refusal := range []struct {
		name, variable string
		status         int
	}{{"repeated_empty", htmlOptionalEmptyVariableE2E, http.StatusConflict}, {"required_empty", "customer", http.StatusBadRequest}} {
		if branded && refusal.name == "required_empty" {
			refusal.variable = "customer_name"
		}
		t.Run(refusal.name, func(t *testing.T) {
			before, crmBefore, storageBefore := revisionStateE2E(t, f), crmDocumentStateE2E(t, f), peer.requests.Load()
			in := htmlDocumentRevisionInput{ExpectedUpdatedAt: current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: currentCID,
				Values: htmlStringMap{refusal.variable: ""}, Summary: "Refused repeated or required empty"}
			if w := submitRevisionE2E(t, f, in, cookie); w.Code != refusal.status {
				t.Fatalf("empty refusal=%d want%d", w.Code, refusal.status)
			}
			if !bytes.Equal(before, revisionStateE2E(t, f)) || crmBefore != crmDocumentStateE2E(t, f) || storageBefore != peer.requests.Load() {
				t.Fatal("empty refusal changed source/history/review/fields/mappings/audit or touched storage")
			}
		})
	}
}

func partyIDsHTMLOptionalEmptyE2E(input htmlsource.Input) map[string]uuid.UUID {
	ids := map[string]uuid.UUID{}
	for _, party := range input.PartyBindings {
		ids[party.Slot] = party.RecipientID
	}
	return ids
}

func sameOptionalEmptyNumericE2E(before, after pgtype.Numeric) bool {
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	return bytes.Equal(a, b)
}

func assertHTMLOptionalEmptyHistoryE2E(t *testing.T, f lifecycleAuthorizationFixture, original, current *generated.Document, oldRowJSON, oldPDF []byte, oldFields, oldRecipients json.RawMessage, cookie string) {
	t.Helper()
	oldRow, err := f.q.GetHTMLDocumentMaterialization(f.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: original.ID, OrgID: f.org, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	afterJSON, _ := json.Marshal(oldRow)
	if !bytes.Equal(oldRowJSON, afterJSON) {
		t.Fatal("optional empty rewrote the exact old materialization bytes/report/pins")
	}
	historical, err := htmlmaterialization.HistoricalDocument(current, oldRow)
	if err != nil {
		t.Fatal(err)
	}
	oldInput, err := htmlsource.InputForCurrent(historical)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := oldInput.Values[htmlOptionalEmptyVariableE2E]; present {
		t.Fatal("historical absent value was rewritten as present empty")
	}
	var snapshotSource, snapshotFields, snapshotRecipients, snapshotReport json.RawMessage
	var snapshotSHA, reviewedSHA []byte
	var snapshotKey, snapshotVersion string
	var reviewer uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT source_json,fields_json,recipients_json,metadata_redaction_report,pdf_sha256,reviewed_pdf_sha256,pdf_key,pdf_version_id,reviewed_by FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2 AND materialization_id=$3 AND kind='draft_superseded'`, original.ID, f.org, oldRow.ID).
		Scan(&snapshotSource, &snapshotFields, &snapshotRecipients, &snapshotReport, &snapshotSHA, &reviewedSHA, &snapshotKey, &snapshotVersion, &reviewer); err != nil { //nolint:rawsql -- retained exact pre-revision geometry, review and immutable source tuple
		t.Fatal(err)
	}
	if !bytes.Equal(snapshotSource, oldRow.SourceJson) || !bytes.Equal(snapshotFields, oldFields) || !bytes.Equal(snapshotRecipients, oldRecipients) ||
		!bytes.Equal(snapshotReport, oldRow.MetadataRedactionReport) || !bytes.Equal(snapshotSHA, oldRow.PdfSha256) || !bytes.Equal(reviewedSHA, original.HtmlReviewedPdfSha256) ||
		snapshotKey != oldRow.PdfKey || snapshotVersion != oldRow.PdfVersionID || reviewer != f.user.ID {
		t.Fatal("superseded snapshot lost exact old source/geometry/party/review or PDF proof")
	}
	newRow, err := f.q.GetHTMLDocumentMaterialization(f.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: current.ID, OrgID: f.org, Sequence: 2})
	if err != nil {
		t.Fatal("read fresh optional-empty materialization", err)
	}
	if newRow.ID == oldRow.ID || !newRow.ParentID.Valid || uuid.UUID(newRow.ParentID.Bytes) != oldRow.ID {
		t.Fatal("fresh equal-content revision did not link to the exact original materialization")
	}
	if !bytes.Equal(newRow.ParentCommitment, oldRow.SourceCommitment) || !bytes.Equal(newRow.OriginCommitment, oldRow.OriginCommitment) {
		t.Fatal("fresh equal-content revision changed its parent or immutable origin commitment")
	}
	if newRow.PdfKey == oldRow.PdfKey || newRow.PageCount != oldRow.PageCount {
		t.Fatal("fresh equal-content revision reused the old PDF key or changed its page count")
	}
	// ChangedSections is measured against the approved master defaults on every
	// materialization. The retained human wording must remain declared as an
	// override even though this revision changes only optional-value presence.
	if !slices.Equal(oldRow.ChangedSections, []string{htmlOptionalEmptySectionE2E}) || !slices.Equal(newRow.ChangedSections, oldRow.ChangedSections) {
		t.Fatal("optional presence changed the exact retained human wording override list")
	}
	assertHTMLRevisionReportE2E(t, newRow.MetadataRedactionReport, newRow.PdfSha256, newRow.PageCount)
	var materializations, snapshots, versions int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM html_document_materializations WHERE document_id=$1 AND org_id=$2),(SELECT count(*) FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2),(SELECT count(*) FROM document_versions WHERE document_id=$1)`, current.ID, f.org).
		Scan(&materializations, &snapshots, &versions); err != nil || materializations != 2 || snapshots != 1 || versions != 2 { //nolint:rawsql -- exactly one fresh revision, one retained old context and two durable human versions
		t.Fatal("optional empty did not persist exactly one revision and superseded snapshot", err)
	}
	for _, row := range []*generated.HtmlDocumentMaterialization{oldRow, newRow} {
		w := submitSessionOperationE2E(f.s, http.MethodGet, fmt.Sprintf("/api/v1/documents/%s/html/revisions/%d/pdf", current.ID, row.Sequence), "", cookie)
		digest := sha256.Sum256(w.Body.Bytes())
		if w.Code != http.StatusOK || !bytes.Equal(digest[:], row.PdfSha256) || w.Header().Get("X-Hash-PDF-SHA256") != hex.EncodeToString(row.PdfSha256) ||
			w.Header().Get("X-Hash-Materialization-Revision") != fmt.Sprint(row.Sequence) || (row.Sequence == 1 && !bytes.Equal(oldPDF, w.Body.Bytes())) {
			t.Fatal("historical PDF read did not return its exact retained bytes and pins")
		}
	}
}
