//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// The REST/PG/worker journey uses the existing synthetic renderer and S3
// protocol peer. It proves transactions and exact source/recipient bindings,
// not that Chromium rendered the fixture's words or any live-provider behavior.
func createHTMLContractDesignE2E(t *testing.T, f lifecycleAuthorizationFixture, cookie string) *generated.Template {
	t.Helper()
	input, _, _ := testfixture.HTMLContract(t)
	defaults, err := json.Marshal(input.Values)
	if err != nil {
		t.Fatal(err)
	}
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "Synthetic reviewed contract design", HTMLMasterJSON: input.MasterJSON, VariablesJSON: defaults}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create contract design=%d %s", w.Code, w.Body.String())
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

func createHTMLContractDocumentE2E(t *testing.T, f lifecycleAuthorizationFixture, template *generated.Template, cookie string) *generated.Document {
	t.Helper()
	w := submitHTMLDocumentCreationE2E(t, f, template.ID, htmlCreationInputE2E(template), cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create reviewed contract=%d %s", w.Code, w.Body.String())
	}
	var response struct {
		Document documentResponse `json:"document"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: response.Document.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func setupHTMLContractDocumentE2E(t *testing.T) (lifecycleAuthorizationFixture, *htmlCreationRendererE2E, *htmlCreationStorageE2E, *generated.Document, string) {
	t.Helper()
	renderer := &htmlCreationRendererE2E{}
	f, peer := setupHTMLDocumentCreationE2E(t, renderer)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	template := createHTMLContractDesignE2E(t, f, cookie)
	approveHTMLCreationTemplateE2E(t, f, template)
	doc := createHTMLContractDocumentE2E(t, f, template, cookie)
	f.doc = doc
	return f, renderer, peer, doc, cookie
}

func htmlContractInventoryE2E(t *testing.T, f lifecycleAuthorizationFixture) []byte {
	t.Helper()
	var raw []byte
	if err := f.pool.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
SELECT jsonb_build_object(
 'templates',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]'::jsonb) FROM templates t WHERE org_id=$1),
 'template_revisions',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY template_id,version),'[]'::jsonb) FROM html_template_revisions t WHERE org_id=$1),
 'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
 'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
 'fields',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM document_fields r WHERE document_id IN (SELECT id FROM owned)),
 'materializations',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY document_id,sequence),'[]'::jsonb) FROM html_document_materializations r WHERE document_id IN (SELECT id FROM owned)),
 'snapshots',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM html_document_materialization_snapshots r WHERE document_id IN (SELECT id FROM owned)),
 'versions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM document_versions r WHERE org_id=$1),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM events r WHERE org_id=$1)
)`, f.org).Scan(&raw); err != nil { //nolint:rawsql -- exact synthetic tenant rollback inventory
		t.Fatal(err)
	}
	return raw
}

func TestHTMLContractProfileRESTCreationRequiresEssentialsAndApprovalE2E(t *testing.T) {
	renderer := &htmlCreationRendererE2E{}
	f, peer := setupHTMLDocumentCreationE2E(t, renderer)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	template := createHTMLContractDesignE2E(t, f, cookie)
	before := htmlContractInventoryE2E(t, f)
	storageBefore := peer.requests.Load()
	if w := submitHTMLDocumentCreationE2E(t, f, template.ID, htmlCreationInputE2E(template), cookie); w.Code != http.StatusConflict {
		t.Fatalf("unapproved contract=%d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(before, htmlContractInventoryE2E(t, f)) || peer.requests.Load() != storageBefore || len(renderer.sources()) != 0 {
		t.Fatal("unapproved contract left database/render/storage effects")
	}
	approveHTMLCreationTemplateE2E(t, f, template)
	before = htmlContractInventoryE2E(t, f)
	in := htmlCreationInputE2E(template)
	in.Values = htmlStringMap{"customer_company_id": "", "price": ""}
	if w := submitHTMLDocumentCreationE2E(t, f, template.ID, in, cookie); w.Code != http.StatusBadRequest {
		t.Fatalf("missing contract essentials=%d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(before, htmlContractInventoryE2E(t, f)) || peer.requests.Load() != storageBefore || len(renderer.sources()) != 0 {
		t.Fatal("missing essentials left database/render/storage effects")
	}
	doc := createHTMLContractDocumentE2E(t, f, template, cookie)
	rows, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("automatic intended recipients=%d error=%v", len(rows), err)
	}
	if err := htmlsource.ValidateContractParties(doc, rows); err != nil {
		t.Fatalf("printed source/recipient binding=%v", err)
	}
	parties, err := htmlsource.ContractParties(doc)
	if err != nil || len(parties) != 2 || parties[0].RecipientID == parties[1].RecipientID || !doc.RequiresSignature {
		t.Fatalf("pinned intended parties=%v error=%v", parties, err)
	}
	if err := htmlsource.Validate(doc, true); !errors.Is(err, htmlsource.ErrReviewRequired) {
		t.Fatalf("new contract inherited human PDF review: %v", err)
	}
	sources := renderer.sources()
	if len(sources) != 1 || !strings.Contains(sources[0], "Synthetic Provider") || !strings.Contains(sources[0], "Synthetic Customer") || !strings.Contains(sources[0], "provider@example.test") || !strings.Contains(sources[0], "customer@example.test") {
		t.Fatal("renderer request omitted the same printed representatives used for recipients")
	}
	assertImportStorageE2E(t, peer.importStoragePeer, 1, 0, 1)
}

func TestHTMLContractProfileRESTPreventsGenericPartyAndModeDowngradesE2E(t *testing.T) {
	f, _, peer, doc, cookie := setupHTMLContractDocumentE2E(t)
	rows, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
	if err != nil || len(rows) != 2 {
		t.Fatal("missing automatically bound parties:", err)
	}
	path := "/api/v1/documents/" + doc.ID.String()
	for _, operation := range []struct {
		name, method, path, body string
		status                   int
	}{
		{"signature_toggle", http.MethodPatch, path, `{"expected_updated_at":"` + doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano) + `","requires_signature":false}`, http.StatusConflict},
		{"provider_delete", http.MethodDelete, path + "/recipients/" + rows[0].ID.String(), "", http.StatusBadRequest},
		{"customer_delete", http.MethodDelete, path + "/recipients/" + rows[1].ID.String(), "", http.StatusBadRequest},
		{"recipient_identity", http.MethodPatch, path + "/recipients/" + rows[0].ID.String(), `{"name":"Different representative"}`, http.StatusBadRequest},
		{"third_responder", http.MethodPost, path + "/recipients", `{"role":"signer","name":"Third party","email":"third@example.test","locale":"en"}`, http.StatusBadRequest},
	} {
		t.Run(operation.name, func(t *testing.T) {
			before, storageBefore := htmlContractInventoryE2E(t, f), peer.requests.Load()
			w := submitSessionOperationE2E(f.s, operation.method, operation.path, operation.body, cookie)
			if w.Code != operation.status {
				t.Fatalf("generic contract mutation=%d want%d %s", w.Code, operation.status, w.Body.String())
			}
			if !bytes.Equal(before, htmlContractInventoryE2E(t, f)) || peer.requests.Load() != storageBefore {
				t.Fatal("refused contract downgrade changed exact source, recipients, fields or storage")
			}
		})
	}
}

func contractRepresentativeRevisionE2E(t *testing.T, doc *generated.Document, name, email string) htmlDocumentRevisionInput {
	t.Helper()
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	return htmlDocumentRevisionInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: commitment,
		Values: htmlStringMap{"provider_name": name, "provider_email": email}, Sections: htmlStringMap{}, Summary: "Human-reviewed representative update"}
}

func TestHTMLContractProfileRESTRevisionAtomicallyRebindsPrintedRepresentativeE2E(t *testing.T) {
	f, renderer, peer, original, cookie := setupHTMLContractDocumentE2E(t)
	path := "/api/v1/documents/" + original.ID.String()
	commitment, _ := htmlsource.Commitment(original)
	review, _ := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: original.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(original.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
	if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/html/review", string(review), cookie); w.Code != http.StatusOK {
		t.Fatalf("review contract=%d %s", w.Code, w.Body.String())
	}
	original, _ = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	f.doc = original
	oldRows, err := f.q.ListRecipientsByDocument(f.ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range oldRows {
		required := true
		body, _ := json.Marshal(addFieldInput{RecipientID: row.ID.String(), Type: "signature", Page: 1, XPct: 10, YPct: float64(20 + i*20), WPct: 25, HPct: 8, Required: &required,
			ExpectedPDFSHA256: hex.EncodeToString(original.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
		if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/fields", string(body), cookie); w.Code != http.StatusCreated {
			t.Fatalf("place bound signature=%d %s", w.Code, w.Body.String())
		}
	}
	oldParties, err := htmlsource.ContractParties(original)
	if err != nil {
		t.Fatal(err)
	}
	in := contractRepresentativeRevisionE2E(t, original, "Updated Provider Representative", "Updated.Provider@Example.Test")
	if w := submitRevisionE2E(t, f, in, cookie); w.Code != http.StatusCreated {
		t.Fatalf("representative revision=%d %s", w.Code, w.Body.String())
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.q.ListRecipientsByDocument(f.ctx, current.ID)
	if err != nil || htmlsource.ValidateContractParties(current, rows) != nil {
		t.Fatal("new source and recipients did not commit together:", err)
	}
	newParties, err := htmlsource.ContractParties(current)
	if err != nil || len(newParties) != len(oldParties) {
		t.Fatal("revision lost intended party slots:", err)
	}
	for i, party := range newParties {
		if party.Slot != oldParties[i].Slot || party.RecipientID != oldParties[i].RecipientID {
			t.Fatal("revision replaced immutable party/recipient binding")
		}
		if party.Slot == "provider" && (party.Name != in.Values["provider_name"] || party.Email != in.Values["provider_email"]) {
			t.Fatal("revised representative did not preserve exact printed name/email")
		}
	}
	if !bytes.Equal(current.HtmlSourceJson, original.HtmlSourceJson) || current.HtmlCurrentMaterializationSequence.Int32 != 2 || current.HtmlReviewedBy.Valid || current.HtmlReviewedMaterializationID.Valid || current.PdfStorageKey == original.PdfStorageKey {
		t.Fatal("representative revision changed origin or inherited PDF review")
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, current.ID)
	if err != nil || len(fields) != 0 {
		t.Fatal("representative revision retained stale signature geometry")
	}
	for _, row := range rows {
		if !row.MagicTokenExpiresAt.Valid || row.MagicTokenExpiresAt.Time.After(time.Now()) {
			t.Fatal("representative revision left previous recipient credentials live")
		}
	}
	w := submitSessionOperationE2E(f.s, http.MethodGet, path+"/html/revisions/1/source", "", cookie)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("Synthetic Provider")) || bytes.Contains(w.Body.Bytes(), []byte(in.Values["provider_name"])) {
		t.Fatalf("historical printed identities were rewritten: %d", w.Code)
	}
	var historySource struct {
		ContractParties []htmlsource.ContractParty `json:"contract_parties"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &historySource); err != nil || len(historySource.ContractParties) != 2 {
		t.Fatal("historical source lost the exact party projection:", err)
	}
	for i, party := range historySource.ContractParties {
		if party.Slot != oldParties[i].Slot || party.RecipientID != oldParties[i].RecipientID || party.Name != oldParties[i].Name || party.Email != oldParties[i].Email {
			t.Fatal("historical source changed original intended party identity or UUID")
		}
	}
	var snapshotRecipients []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT recipients_json FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2 AND kind='draft_superseded' ORDER BY created_at,id LIMIT 1`, current.ID, f.org).Scan(&snapshotRecipients); err != nil { //nolint:rawsql -- archived old source must retain its old party identities
		t.Fatal(err)
	}
	var archivedRecipients []struct {
		ID    uuid.UUID `json:"id"`
		Role  string    `json:"role"`
		Name  string    `json:"name"`
		Email string    `json:"email"`
	}
	if err := json.Unmarshal(snapshotRecipients, &archivedRecipients); err != nil || len(archivedRecipients) != len(oldRows) {
		t.Fatal("archived representative snapshot is incomplete:", err)
	}
	for _, old := range oldRows {
		matched := false
		for _, archived := range archivedRecipients {
			if archived.ID == old.ID {
				matched = archived.Name == old.Name && archived.Email == old.Email && archived.Role == old.Role
			}
		}
		if !matched {
			t.Fatal("old draft snapshot contains the revised representative identity")
		}
	}
	before, storageBefore, rendersBefore := htmlContractInventoryE2E(t, f), peer.requests.Load(), len(renderer.sources())
	if w := submitRevisionE2E(t, f, in, cookie); w.Code != http.StatusConflict {
		t.Fatalf("stale representative retry=%d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(before, htmlContractInventoryE2E(t, f)) || peer.requests.Load() != storageBefore || len(renderer.sources()) != rendersBefore {
		t.Fatal("stale revision affected source, representatives or renderer/storage")
	}
	sources := renderer.sources()
	if len(sources) != 2 || !strings.Contains(sources[1], in.Values["provider_name"]) || !strings.Contains(sources[1], in.Values["provider_email"]) {
		t.Fatal("representative revision renderer request differs from committed identity")
	}
	assertImportStorageE2E(t, peer.importStoragePeer, 2, 0, 2)
}

func TestHTMLContractProfileRESTRendererFailurePreservesPrintedPartiesE2E(t *testing.T) {
	f, _, peer, doc, cookie := setupHTMLContractDocumentE2E(t)
	before := htmlContractInventoryE2E(t, f)
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "synthetic renderer unavailable", http.StatusServiceUnavailable)
	}))
	defer failed.Close()
	f.s.Sign.PDF = render.NewGotenberg(failed.URL)
	in := contractRepresentativeRevisionE2E(t, doc, "Uncommitted Provider", "uncommitted@example.test")
	w := submitRevisionE2E(t, f, in, cookie)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("renderer failure=%d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(before, htmlContractInventoryE2E(t, f)) {
		t.Fatal("failed renderer changed printed source, intended recipients, history or audits")
	}
	assertImportStorageE2E(t, peer.importStoragePeer, 1, 0, 1)
}

func TestHTMLContractProfileRESTSourceAndRevisionRespectTenantScopeE2E(t *testing.T) {
	f, _, peer, doc, _ := setupHTMLContractDocumentE2E(t)
	foreignOrg, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Synthetic foreign contract tenant", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	foreignUser, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Name: "Synthetic foreign owner", Role: "owner", Email: uuid.NewString() + "@foreign.example.test", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, foreignUser.ID, foreignUser.SessionGeneration, time.Hour)
	before, storageBefore := htmlContractInventoryE2E(t, f), peer.requests.Load()
	path := "/api/v1/documents/" + doc.ID.String()
	for _, suffix := range []string{"/html/source", "/html/history", "/html/revisions/1/source", "/html/revisions/1/pdf"} {
		w := submitSessionOperationE2E(f.s, http.MethodGet, path+suffix, "", cookie)
		if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "Synthetic Provider") || strings.Contains(w.Body.String(), "provider@example.test") {
			t.Fatalf("foreign contract read %s=%d", suffix, w.Code)
		}
	}
	if w := submitRevisionE2E(t, f, contractRepresentativeRevisionE2E(t, doc, "Foreign attempt", "foreign@example.test"), cookie); w.Code != http.StatusNotFound {
		t.Fatalf("foreign contract revision=%d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(before, htmlContractInventoryE2E(t, f)) || peer.requests.Load() != storageBefore {
		t.Fatal("foreign contract requests changed source or reached storage")
	}
}
