//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Confirmation receipts are capabilities and subject identifiers are private.
// Failure output keeps only stable codes and aggregate scope counts.
func safeDSRResponseE2E(raw string) string {
	var body dsrCodedBodyV1
	if json.Unmarshal([]byte(raw), &body) != nil {
		return "non-JSON DSR response"
	}
	return fmt.Sprintf("code=%q documents=%d revisions=%d", body.Code, body.WillErase.Documents, body.WillErase.Revisions)
}

// Existing erasure journeys explicitly review one fresh 409 before confirming.
// Never automatically retry a rejected receipt: a stale response is returned
// to the caller. This helper is test-only and shares the original session.
func confirmedDSRBodyE2E(body string, call func(string) *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	var in dsrTransitionInput
	if json.Unmarshal([]byte(body), &in) != nil || !in.Confirm || in.ConfirmationReceipt != "" {
		return call(body)
	}
	preview := in
	preview.Confirm = false
	raw, _ := json.Marshal(preview)
	w := call(string(raw))
	var response struct {
		Code    string `json:"code"`
		Receipt string `json:"confirmation_receipt"`
	}
	if w.Code != http.StatusConflict || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Code != "confirmation_required" || response.Receipt == "" {
		return w
	}
	in.ConfirmationReceipt = response.Receipt
	raw, _ = json.Marshal(in)
	return call(string(raw))
}

func TestDSRConfirmationRejectsExpandedScopeAndRequiresFreshReviewE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	a := f.seed(f.owner, "ann@corp.test", 1)
	id := f.erasure(a, "ann@corp.test")
	f.start(id, f.ownerCookie)
	path := "/api/v1/dsr/" + id.String()
	call := func(body string) *httptest.ResponseRecorder {
		return f.request(http.MethodPatch, path, body, f.ownerCookie)
	}
	preview := call(`{"status":"fulfilled"}`)
	first := wantDSRCodedV1(t, "initial preview", preview, http.StatusConflict, "confirmation_required")
	if first.ConfirmationReceipt == "" || first.WillErase.Documents != 1 || first.WillErase.Revisions != 1 {
		t.Fatal("initial exact erasure scope missing", safeDSRResponseE2E(preview.Body.String()))
	}
	b := f.seed(f.owner, "ANN@corp.test", 2)
	body, _ := json.Marshal(dsrTransitionInput{Status: "fulfilled", Confirm: true, ConfirmationReceipt: first.ConfirmationReceipt})
	stale := call(string(body))
	fresh := wantDSRCodedV1(t, "expanded scope", stale, http.StatusConflict, "confirmation_required")
	if fresh.ConfirmationReceipt == "" || fresh.WillErase.Documents != 2 || fresh.WillErase.Revisions != 3 {
		t.Fatal("expanded scope not presented", safeDSRResponseE2E(stale.Body.String()))
	}
	if f.revisions(a) != 1 || f.revisions(b) != 2 || f.status(id) != "in_progress" || f.historyEvents(a) != 0 || f.historyEvents(b) != 0 || len(f.pending(a)) != 0 || len(f.pending(b)) != 0 {
		t.Fatal("stale receipt changed erasure state")
	}
	// A boolean alone cannot skip either preview; a receipt alone is not consent.
	for _, input := range []dsrTransitionInput{{Status: "fulfilled", Confirm: true}, {Status: "fulfilled", ConfirmationReceipt: fresh.ConfirmationReceipt}} {
		body, _ = json.Marshal(input)
		wantDSRCodedV1(t, "missing consent component", call(string(body)), http.StatusConflict, "confirmation_required")
	}
	body, _ = json.Marshal(dsrTransitionInput{Status: "fulfilled", Confirm: true, ConfirmationReceipt: fresh.ConfirmationReceipt})
	if w := call(string(body)); w.Code != http.StatusOK {
		t.Fatalf("fresh reviewed scope=%d %s", w.Code, safeDSRResponseE2E(w.Body.String()))
	}
	if f.revisions(a) != 0 || f.revisions(b) != 0 || f.status(id) != "fulfilled" {
		t.Fatal("fresh reviewed scope did not complete")
	}
}

func TestDSRConfirmationRejectsNewRevisionOnTheSameDocumentE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	doc := f.seed(f.owner, "ann@corp.test", 1)
	id := f.erasure(doc, "ann@corp.test")
	f.start(id, f.ownerCookie)
	path := "/api/v1/dsr/" + id.String()
	call := func(body string) *httptest.ResponseRecorder {
		return f.request(http.MethodPatch, path, body, f.ownerCookie)
	}
	preview := wantDSRCodedV1(t, "one revision preview", call(`{"status":"fulfilled"}`), http.StatusConflict, "confirmation_required")
	current, err := f.srv.Queries.GetDocumentByID(f.ctx, doc.id)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := f.srv.Queries.GetLatestDocumentPDFRevisionV1(f.ctx, generated.GetLatestDocumentPDFRevisionV1Params{DocumentID: doc.id, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	key := "org/" + f.org.String() + "/documents/" + uuid.NewString() + ".pdf"
	pdf := []byte("%PDF-1.4 newly committed erasure revision")
	digest := sha256.Sum256(pdf)
	f.setObject(key, pdf)
	// The same generated insert/projection used by the native revision writer:
	// parent triggers enforce a real append-only replacement, not a fake digest.
	revision, err := f.srv.Queries.InsertDocumentPDFRevisionV1(f.ctx, generated.InsertDocumentPDFRevisionV1Params{ID: uuid.New(), OrgID: f.org, DocumentID: doc.id, Sequence: previous.Sequence + 1,
		ParentID: pgtype.UUID{Bytes: previous.ID, Valid: true}, PreviousPdfKey: current.PdfStorageKey.String, PreviousPdfSha256: current.PdfSha256, PreviousPdfVersionID: current.PdfStorageVersionID.String,
		PdfKey: key, PdfSha256: digest[:], PdfVersionID: "import-version-1", PageCount: 1, MetadataRedactionReport: json.RawMessage(`{}`), CreatedBy: f.owner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.srv.Queries.ProjectPDFRevisionV1(f.ctx, generated.ProjectPDFRevisionV1Params{DocumentID: doc.id, OrgID: f.org, ExpectedUpdatedAt: current.UpdatedAt, RevisionID: revision.ID}); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(dsrTransitionInput{Status: "fulfilled", Confirm: true, ConfirmationReceipt: preview.ConfirmationReceipt})
	fresh := wantDSRCodedV1(t, "new revision invalidates receipt", call(string(input)), http.StatusConflict, "confirmation_required")
	if fresh.WillErase.Documents != 1 || fresh.WillErase.Revisions != 2 || f.revisions(doc) != 2 || f.status(id) != "in_progress" || f.historyEvents(doc) != 0 || len(f.pending(doc)) != 0 || !f.present(key) {
		t.Fatal("changed revision scope was not preserved")
	}
	input, _ = json.Marshal(dsrTransitionInput{Status: "fulfilled", Confirm: true, ConfirmationReceipt: fresh.ConfirmationReceipt})
	if w := call(string(input)); w.Code != http.StatusOK {
		t.Fatalf("fresh revision review=%d %s", w.Code, safeDSRResponseE2E(w.Body.String()))
	}
}
