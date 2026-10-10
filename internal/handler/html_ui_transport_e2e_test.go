//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

// These tests use actual PostgreSQL and the real REST session/RBAC/audit
// boundaries. Document creation requires the source-built isolated PDF worker;
// the existing fixed-PDF renderer and version-enforcing S3 HTTP fixtures prove
// transport/transaction behavior, not Chromium layout or provider Object Lock.
// Local transport shapes deliberately test JSON independently of server DTOs.
type htmlUIApprovalTransportE2E struct {
	Version       int32      `json:"version"`
	ContentSHA256 string     `json:"content_sha256"`
	ApprovedBy    *uuid.UUID `json:"approved_by"`
	ApprovedAt    *string    `json:"approved_at"`
}

type htmlUITemplateTransportE2E struct {
	ID            uuid.UUID                   `json:"id"`
	OrgID         uuid.UUID                   `json:"org_id"`
	SourceKind    string                      `json:"source_kind"`
	Version       int32                       `json:"version"`
	ContentSHA256 string                      `json:"content_sha256"`
	Master        json.RawMessage             `json:"html_master_json"`
	Defaults      json.RawMessage             `json:"variables_json"`
	Approval      *htmlUIApprovalTransportE2E `json:"html_approval"`
}

type htmlUIDocumentTransportE2E struct {
	ID                 uuid.UUID `json:"id"`
	OrgID              uuid.UUID `json:"org_id"`
	SenderID           uuid.UUID `json:"sender_id"`
	SourceKind         string    `json:"source_kind"`
	PDFSHA256          string    `json:"pdf_sha256"`
	UpdatedAt          string    `json:"updated_at"`
	HasHTMLSource      bool      `json:"has_html_source"`
	HTMLReviewRequired bool      `json:"html_review_required"`
}

func htmlUIObjectTransportE2E(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		t.Fatalf("expected JSON object transport: err=%v body=%s", err, raw)
	}
	return fields
}

func assertHTMLUITemplateDetailE2E(t *testing.T, f lifecycleAuthorizationFixture, template *generated.Template, cookie string, approved bool) {
	t.Helper()
	w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/templates/"+template.ID.String(), "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("HTML template detail=%d %s", w.Code, w.Body.String())
	}
	var response htmlUITemplateTransportE2E
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(response.Master, response.Defaults)
	expected, expectedErr := htmlmaster.CanonicalTemplate(template.HtmlMasterJson, template.VariablesJson)
	if err != nil || expectedErr != nil || response.ID != template.ID || response.OrgID != f.org || response.SourceKind != "html" || response.Version != template.Version || response.ContentSHA256 != hex.EncodeToString(template.HtmlContentSha256) || canonical.SHA256 != response.ContentSHA256 || canonical.SHA256 != expected.SHA256 || !bytes.Equal(canonical.MasterJSON, expected.MasterJSON) || !bytes.Equal(canonical.DefaultsJSON, expected.DefaultsJSON) {
		t.Fatalf("detail does not transport the exact current master/defaults/pins: %+v err=%v expected_err=%v", response, err, expectedErr)
	}
	if response.Approval == nil || response.Approval.Version != response.Version || response.Approval.ContentSHA256 != response.ContentSHA256 {
		t.Fatalf("HTML detail omitted or mismatched revision approval identity: %+v", response.Approval)
	}
	fields := htmlUIObjectTransportE2E(t, w.Body.Bytes())
	approvalFields := htmlUIObjectTransportE2E(t, fields["html_approval"])
	revision, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: template.Version})
	if err != nil || !bytes.Equal(revision.ContentSha256, template.HtmlContentSha256) {
		t.Fatalf("expected current immutable revision: err=%v", err)
	}
	if !approved {
		_, hasActor := approvalFields["approved_by"]
		_, hasTime := approvalFields["approved_at"]
		if hasActor || hasTime || response.Approval.ApprovedBy != nil || response.Approval.ApprovedAt != nil || revision.ApprovedBy.Valid || revision.ApprovedAt.Valid {
			t.Fatal("unapproved current revision inherited, fabricated or emitted null approval fields")
		}
		return
	}
	if response.Approval.ApprovedBy == nil || response.Approval.ApprovedAt == nil || !revision.ApprovedBy.Valid || !revision.ApprovedAt.Valid || *response.Approval.ApprovedBy != uuid.UUID(revision.ApprovedBy.Bytes) || *response.Approval.ApprovedBy != f.user.ID {
		t.Fatalf("approval transport differs from actual owner revision: %+v", response.Approval)
	}
	when, err := time.Parse(time.RFC3339Nano, *response.Approval.ApprovedAt)
	if err != nil || !when.Equal(revision.ApprovedAt.Time) {
		t.Fatalf("approval transport lost exact database timestamp: %q err=%v", *response.Approval.ApprovedAt, err)
	}
}

func TestHTMLTemplateDetailTransportsExactRevisionApprovalE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	assertHTMLUITemplateDetailE2E(t, f, template, cookie, false)
	approveHTMLCreationTemplateE2E(t, f, template)
	assertHTMLUITemplateDetailE2E(t, f, template, cookie, true)
	approved, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: template.Version})
	if err != nil {
		t.Fatal(err)
	}
	// The list remains metadata-only even when this exact revision is approved;
	// approval/master data is obtained from the explicit current detail route.
	w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/templates", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("template metadata list=%d %s", w.Code, w.Body.String())
	}
	var list struct {
		Templates []map[string]json.RawMessage `json:"templates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Templates) != 1 {
		t.Fatalf("template metadata list shape: count=%d err=%v", len(list.Templates), err)
	}
	if _, present := list.Templates[0]["html_master_json"]; present {
		t.Fatal("template list exposed the HTML master")
	}
	if _, present := list.Templates[0]["html_approval"]; present {
		t.Fatal("template list presented approval without an exact detail lookup")
	}
	if w := submitHTMLTemplateE2E(t, f, "update", template.ID, htmlTemplateInputE2E(t, template.Version, "New current revision"), cookie); w.Code != http.StatusOK {
		t.Fatalf("edit approved design=%d %s", w.Code, w.Body.String())
	}
	current, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: template.ID, OrgID: f.org})
	if err != nil || current.Version != template.Version+1 || bytes.Equal(current.HtmlContentSha256, template.HtmlContentSha256) {
		t.Fatalf("edit did not create a new current commitment: err=%v", err)
	}
	assertHTMLUITemplateDetailE2E(t, f, current, cookie, false)
	history, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: template.Version})
	if err != nil || history.ApprovedBy != approved.ApprovedBy || !history.ApprovedAt.Time.Equal(approved.ApprovedAt.Time) || !bytes.Equal(history.ContentSha256, approved.ContentSha256) || !bytes.Equal(history.HtmlMasterJson, approved.HtmlMasterJson) || !bytes.Equal(history.VariablesJson, approved.VariablesJson) {
		t.Fatal("new transport revision rewrote historical approved content/evidence")
	}
	foreign := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	foreignCookie := dsrSessionCookieE2E(t, foreign.s, foreign.user.ID, foreign.user.SessionGeneration, time.Hour)
	before := htmlTemplateSnapshotE2E(t, f)
	w = submitSessionOperationE2E(foreign.s, http.MethodGet, "/api/v1/templates/"+template.ID.String(), "", foreignCookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("foreign tenant template detail=%d %s", w.Code, w.Body.String())
	}
	if _, present := htmlUIObjectTransportE2E(t, w.Body.Bytes())["html_approval"]; present {
		t.Fatal("foreign tenant response leaked revision approval")
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
}

func htmlUIDocumentResponseE2E(t *testing.T, raw []byte, expected *generated.Document, reviewRequired bool) htmlUIDocumentTransportE2E {
	t.Helper()
	var response htmlUIDocumentTransportE2E
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	fields := htmlUIObjectTransportE2E(t, raw)
	if response.ID != expected.ID || response.OrgID != expected.OrgID || response.SenderID != expected.SenderID || response.SourceKind != "pdf" || !response.HasHTMLSource || response.HTMLReviewRequired != reviewRequired || response.PDFSHA256 != hex.EncodeToString(expected.PdfSha256) || response.UpdatedAt != expected.UpdatedAt.Time.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("document transport lost persistent HTML provenance or exact review pins: %+v", response)
	}
	if _, present := fields["has_html_source"]; !present {
		t.Fatal("document transport omitted persistent authoring origin")
	}
	_, present := fields["html_review_required"]
	if present != reviewRequired {
		t.Fatal("review-required transport was not cleared independently of HTML origin")
	}
	return response
}

func htmlUIReviewDocumentE2E(t *testing.T, f lifecycleAuthorizationFixture, response htmlUIDocumentTransportE2E, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: response.UpdatedAt, ExpectedPDFSHA256: response.PDFSHA256})
	if err != nil {
		t.Fatal(err)
	}
	return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+response.ID.String()+"/html/review", string(body), cookie)
}

func assertHTMLUIReviewAuditE2E(t *testing.T, f lifecycleAuthorizationFixture, doc *generated.Document, actor uuid.UUID, total int) {
	t.Helper()
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	var count, bound int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*), count(*) FILTER (WHERE actor_user_id=$2 AND payload_json->>'html_source_commitment'=$3 AND payload_json->>'pdf_sha256'=$4 AND row_hash IS NOT NULL) FROM events WHERE document_id=$1 AND kind='document.updated' AND payload_json->>'html_pdf_reviewed'='true'`, doc.ID, actor, commitment, hex.EncodeToString(doc.PdfSha256)).Scan(&count, &bound); err != nil || count != total || bound != 1 { //nolint:rawsql -- exact synthetic document review audit readback
		t.Fatalf("review audit actor/commitment mismatch: total=%d bound=%d err=%v", count, bound, err)
	}
}

func TestHTMLDocumentReviewTransportRequiresOriginalSenderOrOwnerE2E(t *testing.T) {
	if os.Getenv("HASH_E2E_PDF_WORKER_PATH") == "" {
		t.Skip("set HASH_E2E_PDF_WORKER_PATH to exercise the isolated production PDF worker")
	}
	f, peer := setupHTMLDocumentCreationE2E(t, &htmlCreationRendererE2E{})
	template := createHTMLTemplateE2E(t, f)
	approveHTMLCreationTemplateE2E(t, f, template)
	createUser := func(role string) *generated.User {
		user, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Name: "Synthetic UI " + role, Email: uuid.NewString() + "@html-ui.test", Role: role})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	sender, unrelated, owner := createUser("sender"), createUser("sender"), createUser("owner")
	cookie := func(user *generated.User) string {
		return dsrSessionCookieE2E(t, f.s, user.ID, user.SessionGeneration, time.Hour)
	}
	senderCookie, unrelatedCookie, ownerCookie := cookie(sender), cookie(unrelated), cookie(owner)
	in := htmlCreationInputE2E(template)
	in.Values = htmlStringMap{"customer": "Synthetic UI declared value <AB>"}
	w := submitHTMLDocumentCreationE2E(t, f, template.ID, in, senderCookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("sender instantiation from owner-approved design=%d %s", w.Code, w.Body.String())
	}
	var creation struct {
		Document       json.RawMessage `json:"document"`
		ReviewRequired bool            `json:"review_required"`
	}
	var identity htmlUIDocumentTransportE2E
	if err := json.Unmarshal(w.Body.Bytes(), &creation); err != nil || !creation.ReviewRequired {
		t.Fatalf("creation transport omitted manual review: err=%v", err)
	}
	if err := json.Unmarshal(creation.Document, &identity); err != nil || identity.ID == uuid.Nil {
		t.Fatalf("creation document identity missing: err=%v", err)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: identity.ID, OrgID: f.org})
	if err != nil || doc.SenderID != sender.ID || doc.HtmlReviewedBy.Valid || doc.HtmlReviewedAt.Valid {
		t.Fatalf("fresh sender document inherited review or wrong owner: err=%v", err)
	}
	observed := htmlUIDocumentResponseE2E(t, creation.Document, doc, true)
	w = submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+doc.ID.String(), "", senderCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("fresh document GET=%d %s", w.Code, w.Body.String())
	}
	if got := htmlUIDocumentResponseE2E(t, w.Body.Bytes(), doc, true); got != observed {
		t.Fatal("GET transport changed the creation review observation")
	}
	before := htmlTemplateSnapshotE2E(t, f)
	storageRequests := peer.requests.Load()
	w = htmlUIReviewDocumentE2E(t, f, observed, unrelatedCookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unrelated same-tenant sender review=%d %s", w.Code, w.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	if peer.requests.Load() != storageRequests {
		t.Fatal("refused review touched object storage")
	}
	w = htmlUIReviewDocumentE2E(t, f, observed, senderCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("original sender exact review=%d %s", w.Code, w.Body.String())
	}
	reviewed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || !reviewed.HtmlReviewedBy.Valid || uuid.UUID(reviewed.HtmlReviewedBy.Bytes) != sender.ID || !bytes.Equal(reviewed.HtmlSourceJson, doc.HtmlSourceJson) || !bytes.Equal(reviewed.PdfSha256, doc.PdfSha256) || reviewed.PdfStorageKey != doc.PdfStorageKey || reviewed.PdfStorageVersionID != doc.PdfStorageVersionID {
		t.Fatalf("sender review changed source/PDF or lost authenticated actor: err=%v", err)
	}
	if err := htmlsource.Validate(reviewed, true); err != nil {
		t.Fatal("sender review commitment invalid:", err)
	}
	htmlUIDocumentResponseE2E(t, w.Body.Bytes(), reviewed, false)
	assertHTMLUIReviewAuditE2E(t, f, reviewed, sender.ID, 1)
	before = htmlTemplateSnapshotE2E(t, f)
	if w := htmlUIReviewDocumentE2E(t, f, observed, ownerCookie); w.Code != http.StatusConflict {
		t.Fatalf("owner reused stale pre-review observation=%d %s", w.Code, w.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	w = submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+doc.ID.String(), "", ownerCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("owner current document detail=%d %s", w.Code, w.Body.String())
	}
	ownerObservation := htmlUIDocumentResponseE2E(t, w.Body.Bytes(), reviewed, false)
	w = htmlUIReviewDocumentE2E(t, f, ownerObservation, ownerCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("separate owner exact review=%d %s", w.Code, w.Body.String())
	}
	ownerReviewed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || !ownerReviewed.HtmlReviewedBy.Valid || uuid.UUID(ownerReviewed.HtmlReviewedBy.Bytes) != owner.ID || !bytes.Equal(ownerReviewed.HtmlSourceJson, doc.HtmlSourceJson) || !bytes.Equal(ownerReviewed.PdfSha256, doc.PdfSha256) {
		t.Fatalf("owner review did not preserve exact source/PDF and actor: err=%v", err)
	}
	if err := htmlsource.Validate(ownerReviewed, true); err != nil {
		t.Fatal("owner review commitment invalid:", err)
	}
	htmlUIDocumentResponseE2E(t, w.Body.Bytes(), ownerReviewed, false)
	assertHTMLUIReviewAuditE2E(t, f, ownerReviewed, owner.ID, 2)
	// Origin remains true after review on the list projection as well as detail.
	w = submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents", "", senderCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("document list=%d %s", w.Code, w.Body.String())
	}
	var list struct {
		Documents []json.RawMessage `json:"documents"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, raw := range list.Documents {
		var candidate htmlUIDocumentTransportE2E
		if err := json.Unmarshal(raw, &candidate); err != nil {
			t.Fatal(err)
		}
		if candidate.ID == doc.ID {
			found = true
			htmlUIDocumentResponseE2E(t, raw, ownerReviewed, false)
		}
	}
	if !found {
		t.Fatal("reviewed HTML-origin document missing from list")
	}
	// Review cannot turn a fresh HTML materialization into a static PDF template.
	before = htmlTemplateSnapshotE2E(t, f)
	export, err := json.Marshal(savePDFTemplateInput{Name: "Reviewed HTML cannot become static template", ExpectedUpdatedAt: ownerReviewed.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedFieldIDs: []uuid.UUID{uuid.New()}, Parties: []savePDFTemplateParty{{RecipientID: uuid.New(), Role: "customer", Label: "Customer"}}})
	if err != nil {
		t.Fatal(err)
	}
	w = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/pdf-template", string(export), senderCookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("reviewed HTML static export=%d %s", w.Code, w.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	if peer.requests.Load() != storageRequests {
		t.Fatal("review or static-export refusal touched object storage")
	}
}
