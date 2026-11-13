//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/testfixture"
)

// Actual REST/PostgreSQL protocol coverage with the synthetic renderer and
// object-storage peer used by the other HTML revision roots.

func moveTemplateMasterE2E(label string) htmlmaster.Master {
	return htmlmaster.Master{SchemaVersion: 1,
		HTML:     `<h1>` + label + `</h1><p><span data-hash-value="customer"></span></p><div data-hash-section="scope"></div>`,
		Values:   []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 200}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Approved scope " + label, MaxChars: 500}},
	}
}

// publishTemplateVersionE2E saves the next version of the document's template
// and, when approve is set, approves it as the fixture owner (a human).
func publishTemplateVersionE2E(t *testing.T, f lifecycleAuthorizationFixture, doc *generated.Document, cookie string, expected int32, master htmlmaster.Master, approve bool) *generated.Template {
	t.Helper()
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	return publishRawTemplateVersionE2E(t, f, doc, cookie, expected, raw, json.RawMessage(`{"customer":"Second default AB"}`), approve)
}

func publishRawTemplateVersionE2E(t *testing.T, f lifecycleAuthorizationFixture, doc *generated.Document, cookie string, expected int32, raw, defaults json.RawMessage, approve bool) *generated.Template {
	t.Helper()
	w := submitHTMLTemplateE2E(t, f, "update", doc.TemplateID.Bytes, htmlTemplateInput{Name: "Revision design", HTMLMasterJSON: raw, VariablesJSON: defaults, ExpectedVersion: expected}, cookie)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("save template v%d=%d %s", expected+1, w.Code, w.Body.String())
	}
	template, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: doc.TemplateID.Bytes, OrgID: f.org})
	if err != nil || template.Version != expected+1 {
		t.Fatal("saved template version differs", err)
	}
	if approve {
		approveHTMLCreationTemplateE2E(t, f, template)
	}
	return template
}

func templateMoveBodyE2E(t *testing.T, doc *generated.Document, template *generated.Template) map[string]any {
	t.Helper()
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"expected_updated_at": doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_html_source_commitment": commitment,
		"template_version": template.Version, "expected_template_content_sha256": hex.EncodeToString(template.HtmlContentSha256)}
}

func submitTemplateMoveE2E(t *testing.T, f lifecycleAuthorizationFixture, body map[string]any, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/html/template-revisions", string(raw), cookie)
}

func TestHTMLDocumentTemplateMoveRESTResetsReviewAndPreservesHistoryE2E(t *testing.T) {
	f, _, _, original, cookie := setupHTMLRevisionE2E(t)
	path := "/api/v1/documents/" + original.ID.String()
	originalCommitment, _ := htmlsource.Commitment(original)
	review, _ := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: original.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(original.PdfSha256), ExpectedHTMLSourceCommitment: originalCommitment})
	if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/html/review", string(review), cookie); w.Code != http.StatusOK {
		t.Fatalf("initial review=%d %s", w.Code, w.Body.String())
	}
	original, _ = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	f.doc = original
	field, _ := json.Marshal(addFieldInput{Type: "text", Page: 1, XPct: 10, YPct: 10, WPct: 20, HPct: 5, ExpectedPDFSHA256: hex.EncodeToString(original.PdfSha256), ExpectedHTMLSourceCommitment: originalCommitment})
	if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/fields", string(field), cookie); w.Code != http.StatusCreated {
		t.Fatalf("field placement=%d %s", w.Code, w.Body.String())
	}
	template := publishTemplateVersionE2E(t, f, original, cookie, 1, moveTemplateMasterE2E("Second design"), true)
	body := templateMoveBodyE2E(t, original, template)
	body["values"] = map[string]string{"customer": "Moved customer AB"}
	body["summary"] = "Moved to the second approved design"
	w := submitTemplateMoveE2E(t, f, body, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("template move=%d %s", w.Code, w.Body.String())
	}
	var result struct {
		Document documentResponse `json:"document"`
		Revision int32            `json:"materialization_revision"`
		Review   bool             `json:"review_required"`
		Reset    bool             `json:"placement_reset"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Revision != 2 || !result.Review || !result.Reset || result.Document.ID != original.ID {
		t.Fatal("move lost review/placement reset response or changed identity", err)
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current.HtmlSourceJson, original.HtmlSourceJson) || current.HtmlReviewedBy.Valid || current.HtmlReviewedMaterializationID.Valid || current.PdfStorageKey == original.PdfStorageKey || bytes.Equal(current.PdfSha256, original.PdfSha256) {
		t.Fatal("origin changed, review survived the move or the PDF was not replaced")
	}
	in, err := htmlsource.InputForCurrent(current)
	if err != nil || in.TemplateVersion != 2 || in.TemplateContentSHA256 != hex.EncodeToString(template.HtmlContentSha256) || in.Values["customer"] != "Moved customer AB" {
		t.Fatal("current source did not move to the approved version with the supplied value", err)
	}
	if fields, err := f.q.ListFieldsByDocument(f.ctx, current.ID); err != nil || len(fields) != 0 {
		t.Fatal("placed fields survived the move", err)
	}
	var payload []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT payload_json FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.updated' ORDER BY created_at DESC, id DESC LIMIT 1`, original.ID, f.org).Scan(&payload); err != nil { //nolint:rawsql -- audit payload inspection
		t.Fatal(err)
	}
	var event map[string]any
	if json.Unmarshal(payload, &event) != nil || event["template_move"] != true || event["via"] != "human" || event["previous_template_version"] != float64(1) || event["template_version"] != float64(2) ||
		event["previous_template_content_sha256"] == event["template_content_sha256"] || event["previous_html_source_commitment"] != originalCommitment {
		t.Fatalf("audit event lost old and new pins: %s", payload)
	}
	// History keeps both revisions and their exact PDFs.
	for sequence, want := range map[int][]byte{1: original.PdfSha256, 2: current.PdfSha256} {
		rw := submitSessionOperationE2E(f.s, http.MethodGet, fmt.Sprintf("%s/html/revisions/%d/pdf", path, sequence), "", cookie)
		if rw.Code != http.StatusOK || rw.Header().Get("X-Hash-PDF-SHA256") != hex.EncodeToString(want) {
			t.Fatalf("historical PDF %d=%d", sequence, rw.Code)
		}
	}
	// A fresh review of the moved PDF is required and possible.
	currentCommit, _ := htmlsource.Commitment(current)
	fresh, _ := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(current.PdfSha256), ExpectedHTMLSourceCommitment: currentCommit})
	if rw := submitSessionOperationE2E(f.s, http.MethodPost, path+"/html/review", string(fresh), cookie); rw.Code != http.StatusOK {
		t.Fatalf("fresh review=%d %s", rw.Code, rw.Body.String())
	}
	// The move's audit event must carry a size row, or every later revise and
	// review is refused with 503 (N1).
	var unmeasured int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events e WHERE e.document_id=$1 AND e.org_id=$2 AND NOT EXISTS (SELECT 1 FROM html_snapshot_event_payload_sizes_v1 s WHERE s.event_id=e.id)`, original.ID, f.org).Scan(&unmeasured); err != nil || unmeasured != 0 { //nolint:rawsql -- measurement coverage inspection
		t.Fatalf("events without a size row=%d %v", unmeasured, err)
	}
	reviewed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	reviewedCommit, _ := htmlsource.Commitment(reviewed)
	revise, _ := json.Marshal(htmlDocumentRevisionInput{ExpectedUpdatedAt: reviewed.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: reviewedCommit, Sections: htmlStringMap{"scope": "Scope revised after the move"}, Summary: "Revise after move"})
	if rw := submitSessionOperationE2E(f.s, http.MethodPost, path+"/html/revisions", string(revise), cookie); rw.Code != http.StatusCreated && rw.Code != http.StatusOK {
		t.Fatalf("revise after move=%d %s", rw.Code, rw.Body.String())
	}
	revised, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	revisedCommit, _ := htmlsource.Commitment(revised)
	again, _ := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: revised.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(revised.PdfSha256), ExpectedHTMLSourceCommitment: revisedCommit})
	if rw := submitSessionOperationE2E(f.s, http.MethodPost, path+"/html/review", string(again), cookie); rw.Code != http.StatusOK {
		t.Fatalf("review after revise=%d %s", rw.Code, rw.Body.String())
	}
	// Replaying the same pins is stale: the document has moved.
	if rw := submitTemplateMoveE2E(t, f, body, cookie); rw.Code != http.StatusConflict {
		t.Fatalf("replayed move=%d", rw.Code)
	}
}

// Each case gets its own fixture: a target must be the template's current
// version, so one document cannot walk through several target shapes.
type templateMoveCaseE2E struct {
	f      lifecycleAuthorizationFixture
	doc    *generated.Document
	cookie string
	target *generated.Template
}

func newTemplateMoveCaseE2E(t *testing.T, prepare func(*testing.T, lifecycleAuthorizationFixture, *generated.Document, string) *generated.Template) templateMoveCaseE2E {
	t.Helper()
	f, _, _, doc, cookie := setupHTMLRevisionE2E(t)
	f.doc = doc
	return templateMoveCaseE2E{f: f, doc: doc, cookie: cookie, target: prepare(t, f, doc, cookie)}
}

func approvedSecondDesignE2E(t *testing.T, f lifecycleAuthorizationFixture, doc *generated.Document, cookie string) *generated.Template {
	return publishTemplateVersionE2E(t, f, doc, cookie, 1, moveTemplateMasterE2E("Second design"), true)
}

func TestHTMLDocumentTemplateMoveRefusalsE2E(t *testing.T) {
	type refusal struct {
		want    int
		prepare func(*testing.T, lifecycleAuthorizationFixture, *generated.Document, string) *generated.Template
		mutate  func(*testing.T, templateMoveCaseE2E, map[string]any)
	}
	noMutation := func(*testing.T, templateMoveCaseE2E, map[string]any) {}
	cases := map[string]refusal{
		"same version": {http.StatusConflict, approvedSecondDesignE2E, func(t *testing.T, c templateMoveCaseE2E, b map[string]any) {
			original, err := c.f.q.GetHTMLTemplateRevision(c.f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: c.doc.TemplateID.Bytes, OrgID: c.f.org, Version: 1})
			if err != nil {
				t.Fatal(err)
			}
			b["template_version"], b["expected_template_content_sha256"] = original.Version, hex.EncodeToString(original.ContentSha256)
		}},
		"unapproved target": {http.StatusConflict, func(t *testing.T, f lifecycleAuthorizationFixture, d *generated.Document, c string) *generated.Template {
			return publishTemplateVersionE2E(t, f, d, c, 1, moveTemplateMasterE2E("Second design"), false)
		}, noMutation},
		"superseded approved target": {http.StatusConflict, func(t *testing.T, f lifecycleAuthorizationFixture, d *generated.Document, c string) *generated.Template {
			second := approvedSecondDesignE2E(t, f, d, c)
			publishTemplateVersionE2E(t, f, d, c, 2, moveTemplateMasterE2E("Third design"), true)
			return second
		}, noMutation},
		"schema change": {http.StatusUnprocessableEntity, func(t *testing.T, f lifecycleAuthorizationFixture, d *generated.Document, c string) *generated.Template {
			contract, _, _ := testfixture.HTMLContract(t)
			defaults, err := json.Marshal(contract.Values)
			if err != nil {
				t.Fatal(err)
			}
			return publishRawTemplateVersionE2E(t, f, d, c, 1, contract.MasterJSON, defaults, true)
		}, noMutation},
		"other template content": {http.StatusConflict, approvedSecondDesignE2E, func(_ *testing.T, _ templateMoveCaseE2E, b map[string]any) {
			b["expected_template_content_sha256"] = hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
		}},
		"nonexistent version": {http.StatusConflict, approvedSecondDesignE2E, func(_ *testing.T, _ templateMoveCaseE2E, b map[string]any) { b["template_version"] = 99 }},
		"undeclared value": {http.StatusUnprocessableEntity, approvedSecondDesignE2E, func(_ *testing.T, _ templateMoveCaseE2E, b map[string]any) {
			b["values"] = map[string]string{"not_declared": "x"}
		}},
		"undeclared section": {http.StatusUnprocessableEntity, approvedSecondDesignE2E, func(_ *testing.T, _ templateMoveCaseE2E, b map[string]any) {
			b["sections"] = map[string]string{"not_declared": "x"}
		}},
		"stale updated_at": {http.StatusConflict, approvedSecondDesignE2E, func(_ *testing.T, c templateMoveCaseE2E, b map[string]any) {
			b["expected_updated_at"] = c.doc.UpdatedAt.Time.Add(-time.Second).UTC().Format(time.RFC3339Nano)
		}},
		"stale source commitment": {http.StatusConflict, approvedSecondDesignE2E, func(_ *testing.T, _ templateMoveCaseE2E, b map[string]any) {
			b["expected_html_source_commitment"] = hex.EncodeToString(bytes.Repeat([]byte{2}, 32))
		}},
	}
	for _, pin := range []string{"expected_updated_at", "expected_html_source_commitment", "template_version", "expected_template_content_sha256"} {
		cases["missing "+pin] = refusal{http.StatusPreconditionRequired, approvedSecondDesignE2E, func(_ *testing.T, _ templateMoveCaseE2E, b map[string]any) { delete(b, pin) }}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTemplateMoveCaseE2E(t, tc.prepare)
			body := templateMoveBodyE2E(t, c.doc, c.target)
			tc.mutate(t, c, body)
			before := revisionStateE2E(t, c.f)
			if w := submitTemplateMoveE2E(t, c.f, body, c.cookie); w.Code != tc.want {
				t.Fatalf("%s=%d want %d %s", name, w.Code, tc.want, w.Body.String())
			} else {
				var out struct {
					Code string `json:"code"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || !strings.HasPrefix(out.Code, "template_move_") {
					t.Fatalf("%s refusal has no stable template_move_ code: %v %s", name, err, w.Body.String())
				}
			}
			if !bytes.Equal(before, revisionStateE2E(t, c.f)) {
				t.Fatal("refused move changed document state")
			}
		})
	}

	// F8: a body that does not decode gets a fixed, coded refusal and never the
	// Go decoder's text.
	t.Run("undecodable body has a code and no decoder text", func(t *testing.T) {
		c := newTemplateMoveCaseE2E(t, approvedSecondDesignE2E)
		before := revisionStateE2E(t, c.f)
		w := submitSessionOperationE2E(c.f.s, http.MethodPost, "/api/v1/documents/"+c.f.doc.ID.String()+"/html/template-revisions", `{"template_version":"two"}`, c.cookie)
		var body struct{ Error, Code string }
		if w.Code != http.StatusBadRequest || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != "template_move_invalid_body" || body.Error == "" {
			t.Fatalf("undecodable body=%d %s", w.Code, w.Body.String())
		}
		for _, leak := range []string{"json:", "Go struct", "cannot unmarshal", "htmlDocumentTemplateMoveInputV1", "int32"} {
			if strings.Contains(w.Body.String(), leak) {
				t.Fatalf("refusal leaks decoder text %q: %s", leak, w.Body.String())
			}
		}
		if !bytes.Equal(before, revisionStateE2E(t, c.f)) {
			t.Fatal("refused move changed document state")
		}
	})

	t.Run("non-owner non-sender", func(t *testing.T) {
		c := newTemplateMoveCaseE2E(t, approvedSecondDesignE2E)
		other, err := c.f.q.CreateUser(c.f.ctx, generated.CreateUserParams{OrgID: c.f.org, Name: "Other sender", Email: uuid.NewString() + "@move.test", Role: "sender"})
		if err != nil {
			t.Fatal(err)
		}
		otherCookie := dsrSessionCookieE2E(t, c.f.s, other.ID, other.SessionGeneration, time.Hour)
		before := revisionStateE2E(t, c.f)
		if w := submitTemplateMoveE2E(t, c.f, templateMoveBodyE2E(t, c.doc, c.target), otherCookie); w.Code != http.StatusForbidden {
			t.Fatalf("non-sender move=%d %s", w.Code, w.Body.String())
		}
		if !bytes.Equal(before, revisionStateE2E(t, c.f)) {
			t.Fatal("refused move changed document state")
		}
	})
	t.Run("signed recipient", func(t *testing.T) {
		c := newTemplateMoveCaseE2E(t, approvedSecondDesignE2E)
		_, tokenHash, err := auth.MintMagicToken()
		if err != nil {
			t.Fatal(err)
		}
		recipient, err := c.f.q.CreateRecipient(c.f.ctx, generated.CreateRecipientParams{DocumentID: c.doc.ID, Role: "signer", Name: "Signer", Email: uuid.NewString() + "@move.test", Locale: c.doc.DefaultLocale, MagicTokenHash: tokenHash, MagicTokenExpiresAt: magictoken.Expiry(c.doc.ExpiresAt, time.Now())})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.f.pool.Exec(c.f.ctx, `UPDATE recipients SET status='signed', signed_at=clock_timestamp() WHERE id=$1`, recipient.ID); err != nil { //nolint:rawsql -- models a signed recipient
			t.Fatalf("signed-recipient refusal fixture could not be established: %v", err)
		}
		fresh, _ := c.f.q.GetDocument(c.f.ctx, generated.GetDocumentParams{ID: c.doc.ID, OrgID: c.f.org})
		before := revisionStateE2E(t, c.f)
		if w := submitTemplateMoveE2E(t, c.f, templateMoveBodyE2E(t, fresh, c.target), c.cookie); w.Code != http.StatusConflict {
			t.Fatalf("move after a signature=%d %s", w.Code, w.Body.String())
		}
		if !bytes.Equal(before, revisionStateE2E(t, c.f)) {
			t.Fatal("refused move changed document state")
		}
	})
	t.Run("not a draft", func(t *testing.T) {
		c := newTemplateMoveCaseE2E(t, approvedSecondDesignE2E)
		// M124 requires the real saved PDF review before any draft departure.
		// Establish it through the staff route instead of skipping when the
		// database correctly refuses an unreviewed fixture's transition.
		commitment, err := htmlsource.Commitment(c.doc)
		if err != nil {
			t.Fatal(err)
		}
		review, err := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: c.doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(c.doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
		if err != nil {
			t.Fatal(err)
		}
		if w := submitSessionOperationE2E(c.f.s, http.MethodPost, "/api/v1/documents/"+c.doc.ID.String()+"/html/review", string(review), c.cookie); w.Code != http.StatusOK {
			t.Fatalf("review non-draft refusal fixture=%d %s", w.Code, w.Body.String())
		}
		// M65 independently requires Send's complete canonical branding snapshot.
		// Freeze the actual effective theme before modelling the closed state.
		theme, err := c.f.q.GetHTMLSendBrandingInputHeaderV1(c.f.ctx, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: c.doc.ID, OrgID: c.f.org})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.f.q.FreezeHTMLSendBrandingV1(c.f.ctx, htmlSendFreezeFixtureV1(theme)); err != nil {
			t.Fatal("freeze non-draft refusal fixture branding", err)
		}
		frozen, err := c.f.q.GetDocumentBrandingOverride(c.f.ctx, c.doc.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := branding.ValidateFrozenSnapshot(c.doc.ID, frozen); err != nil {
			t.Fatal("canonical non-draft refusal fixture branding", err)
		}
		if _, err := c.f.pool.Exec(c.f.ctx, `UPDATE documents SET status='voided' WHERE id=$1`, c.doc.ID); err != nil { //nolint:rawsql -- models a closed document
			t.Fatalf("non-draft refusal fixture could not be established: %v", err)
		}
		fresh, err := c.f.q.GetDocument(c.f.ctx, generated.GetDocumentParams{ID: c.doc.ID, OrgID: c.f.org})
		if err != nil || fresh.Status != "voided" {
			t.Fatal("non-draft refusal fixture has no closed document", err)
		}
		before := revisionStateE2E(t, c.f)
		if w := submitTemplateMoveE2E(t, c.f, templateMoveBodyE2E(t, fresh, c.target), c.cookie); w.Code != http.StatusConflict {
			t.Fatalf("move of a non-draft=%d %s", w.Code, w.Body.String())
		}
		if !bytes.Equal(before, revisionStateE2E(t, c.f)) {
			t.Fatal("refused non-draft move changed document state")
		}
	})
}

// A value the user typed survives the move even when it equals the old
// default; only newly declared fields take their defaults, and both the
// response and the audit event list them.
func TestHTMLDocumentTemplateMoveKeepsTypedValuesAndReportsAdoptedDefaultsE2E(t *testing.T) {
	c := newTemplateMoveCaseE2E(t, func(t *testing.T, f lifecycleAuthorizationFixture, d *generated.Document, cookie string) *generated.Template {
		master := moveTemplateMasterE2E("Second design")
		master.HTML += `<p><span data-hash-value="extra"></span></p>`
		master.Values = append(master.Values, htmlmaster.Value{Name: "extra", MaxChars: 100})
		raw, err := json.Marshal(master)
		if err != nil {
			t.Fatal(err)
		}
		return publishRawTemplateVersionE2E(t, f, d, cookie, 1, raw, json.RawMessage(`{"customer":"Second default AB","extra":"Extra default"}`), true)
	})
	w := submitTemplateMoveE2E(t, c.f, templateMoveBodyE2E(t, c.doc, c.target), c.cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("move=%d %s", w.Code, w.Body.String())
	}
	var result struct {
		Adopted []string `json:"adopted_default_values"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Adopted) != 1 || result.Adopted[0] != "extra" {
		t.Fatalf("adopted defaults not reported: %s", w.Body.String())
	}
	current, err := c.f.q.GetDocument(c.f.ctx, generated.GetDocumentParams{ID: c.doc.ID, OrgID: c.f.org})
	if err != nil {
		t.Fatal(err)
	}
	in, err := htmlsource.InputForCurrent(current)
	// The creation default ("Original AB") equals the old default and was typed
	// by nobody, but it is still carried exactly rather than replaced.
	if err != nil || in.Values["customer"] != "Original AB" || in.Values["extra"] != "Extra default" {
		t.Fatalf("values after move: %v %v", in.Values, err)
	}
	var payload []byte
	if err := c.f.pool.QueryRow(c.f.ctx, `SELECT payload_json FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.updated' ORDER BY created_at DESC, id DESC LIMIT 1`, c.doc.ID, c.f.org).Scan(&payload); err != nil { //nolint:rawsql -- audit payload inspection
		t.Fatal(err)
	}
	var event map[string]any
	if json.Unmarshal(payload, &event) != nil || fmt.Sprint(event["adopted_default_values"]) != "[extra]" {
		t.Fatalf("audit lost adopted defaults: %s", payload)
	}
}

// Events written before every writer measured its own (CRM population, pre-sign
// births, the legacy revise) have no size row, which blocks the next revise. The
// 00126 backfill measures them; this runs its Up statement against a database
// that has events without a row.
func TestEventMeasurementBackfillCoversExistingHTMLEventsE2E(t *testing.T) {
	f, doc := htmlMaterializationFixtureE2E(t)
	for _, kind := range []string{"crm.template.population.created", "presign.execution.superseded", "presign.source.crm.created"} {
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO events (org_id, document_id, kind, payload_json) VALUES ($1,$2,$3,'{"seeded":true}')`, f.org, doc.ID, kind); err != nil { //nolint:rawsql -- seed pre-migration unmeasured events
			t.Fatal(err)
		}
	}
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM html_snapshot_event_payload_sizes_v1 WHERE document_id=$1`, doc.ID); err != nil { //nolint:rawsql -- recreate the pre-migration state
		t.Fatal(err)
	}
	count := func() (total, unmeasured int) {
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*), count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM html_snapshot_event_payload_sizes_v1 s WHERE s.event_id=e.id)) FROM events e WHERE e.document_id=$1 AND e.org_id=$2`, doc.ID, f.org).Scan(&total, &unmeasured); err != nil { //nolint:rawsql -- coverage inspection
			t.Fatal(err)
		}
		return
	}
	total, unmeasured := count()
	if total < 3 || unmeasured != total {
		t.Fatalf("precondition: total=%d unmeasured=%d", total, unmeasured)
	}
	raw, err := os.ReadFile("../db/migrations/00126_measure_html_document_events.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := strings.SplitN(strings.SplitN(string(raw), "-- +goose Up", 2)[1], "-- +goose Down", 2)[0]
	if _, err = f.pool.Exec(f.ctx, up); err != nil { //nolint:rawsql -- run the migration's own statement
		t.Fatal(err)
	}
	if total, unmeasured = count(); unmeasured != 0 {
		t.Fatalf("backfill left %d of %d events unmeasured", unmeasured, total)
	}
	var bad int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM html_snapshot_event_payload_sizes_v1 WHERE document_id=$1 AND payload_wire_bytes < 2`, doc.ID).Scan(&bad); err != nil || bad != 0 { //nolint:rawsql -- the trigger must measure the real payload
		t.Fatalf("measurements without a real payload size=%d %v", bad, err)
	}
	// Idempotent: a second run changes nothing and does not fail.
	if _, err = f.pool.Exec(f.ctx, up); err != nil { //nolint:rawsql -- rerun
		t.Fatal(err)
	}
}
