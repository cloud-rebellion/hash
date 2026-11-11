//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// DSR erasure of PDF revision history must touch only the documents it is
// entitled to: the linked document and documents on which the subject is an
// actual recipient (exact email, not a substring), each passing the linked
// document's eligibility checks and the actor's ownership check; the stored
// objects go only after the commit. Audit findings S1, S2, S3 and S7.
//
// The fixture seeds PDF drafts and their revisions through the generated
// writers on the shared DSR server, so these tests need no PDF worker and run on
// any Postgres the DSR e2e suite supports.

type dsrHistoryDocV1 struct {
	id        uuid.UUID
	recipient uuid.UUID
	keys      []string
}

type dsrHistoryFixtureV1 struct {
	t            *testing.T
	ctx          context.Context
	srv          *Server
	peer         *importStoragePeer
	org          uuid.UUID
	owner        uuid.UUID
	ownerCookie  string
	sender       uuid.UUID
	senderCookie string
}

func newDSRHistoryFixtureV1(t *testing.T) *dsrHistoryFixtureV1 {
	t.Helper()
	ctx, _, q, server, orgID, ownerID := setupDSRE2E(t)
	var err error
	server.Cookies, err = auth.NewSignedCookie(strings.Repeat("4b", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.Collab = collab.NewHub(q)
	t.Cleanup(func() { server.Collab.Shutdown(ctx) })
	peer := &importStoragePeer{objects: make(map[string][]byte)}
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	server.Storage, err = storage.New(ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-dsr-history", SecretKey: "synthetic-dsr-history-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	sender, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: orgID, Email: uuid.NewString() + "@dsr-history.test", Name: "History sender", Role: "sender"})
	if err != nil {
		t.Fatal(err)
	}
	f := &dsrHistoryFixtureV1{t: t, ctx: ctx, srv: server, peer: peer, org: orgID, owner: ownerID, sender: sender.ID}
	f.ownerCookie = f.cookie(ownerID)
	f.senderCookie = dsrSessionCookieE2E(t, server, sender.ID, sender.SessionGeneration, time.Hour)
	return f
}

func (f *dsrHistoryFixtureV1) cookie(user uuid.UUID) string {
	f.t.Helper()
	u, err := f.srv.Queries.GetUserForShare(f.ctx, generated.GetUserForShareParams{ID: user, OrgID: f.org})
	if err != nil {
		f.t.Fatal(err)
	}
	return dsrSessionCookieE2E(f.t, f.srv, user, u.SessionGeneration, time.Hour)
}

func (f *dsrHistoryFixtureV1) request(method, path, body, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, f.srv.PublicURL+path, strings.NewReader(body)).WithContext(f.ctx)
	req.Header.Set("Origin", f.srv.PublicURL)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(w, req)
	return w
}

func (f *dsrHistoryFixtureV1) patch(id uuid.UUID, body, cookie string) *httptest.ResponseRecorder {
	return confirmedDSRBodyE2E(body, func(input string) *httptest.ResponseRecorder {
		return f.request(http.MethodPatch, "/api/v1/dsr/"+id.String(), input, cookie)
	})
}

// seed builds an imported PDF draft sent by user, with one recipient and n PDF
// revisions through the generated writers (the M124 insert trigger applies).
func (f *dsrHistoryFixtureV1) seed(user uuid.UUID, email string, n int) dsrHistoryDocV1 {
	f.t.Helper()
	q := f.srv.Queries
	put := func(body string) (string, []byte) {
		key := "org/" + f.org.String() + "/documents/" + uuid.NewString() + ".pdf"
		f.peer.mu.Lock()
		f.peer.objects[key] = []byte(body)
		f.peer.mu.Unlock()
		sum := sha256.Sum256([]byte(body))
		return key, sum[:]
	}
	key0, sha0 := put("%PDF-1.4 original " + email)
	doc, err := q.CreateFreshHTMLPDFDocumentV1(f.ctx, generated.CreateFreshHTMLPDFDocumentV1Params{
		ID: uuid.New(), OrgID: f.org, Name: "history " + email,
		PdfStorageKey: pgtype.Text{String: key0, Valid: true}, PdfSha256: sha0,
		PdfStorageVersionID: pgtype.Text{String: "import-version-1", Valid: true}, EvidenceVersionPinsRequired: true, SenderID: user,
	})
	if err != nil {
		f.t.Fatal("create pdf draft", err)
	}
	rec, err := q.CreateRecipient(f.ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: email, Name: "Name " + email, OrderIndex: 0,
		MagicTokenHash: []byte(uuid.NewString()), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		f.t.Fatal("recipient", err)
	}
	out := dsrHistoryDocV1{id: doc.ID, recipient: rec.ID, keys: []string{key0}}
	parent := pgtype.UUID{}
	for i := 1; i <= n; i++ {
		cur, err := q.GetDocumentByID(f.ctx, doc.ID)
		if err != nil {
			f.t.Fatal(err)
		}
		key, sha := put("%PDF-1.4 revision " + email + " " + uuid.NewString())
		rev, err := q.InsertDocumentPDFRevisionV1(f.ctx, generated.InsertDocumentPDFRevisionV1Params{
			ID: uuid.New(), OrgID: f.org, DocumentID: doc.ID, Sequence: int32(i), ParentID: parent,
			PreviousPdfKey: cur.PdfStorageKey.String, PreviousPdfSha256: cur.PdfSha256, PreviousPdfVersionID: cur.PdfStorageVersionID.String,
			PdfKey: key, PdfSha256: sha, PdfVersionID: "import-version-1", PageCount: 1, MetadataRedactionReport: json.RawMessage(`{}`),
			Summary: "", CreatedBy: user,
		})
		if err != nil {
			f.t.Fatal("insert revision", err)
		}
		if _, err := q.ProjectPDFRevisionV1(f.ctx, generated.ProjectPDFRevisionV1Params{DocumentID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: cur.UpdatedAt, RevisionID: rev.ID}); err != nil {
			f.t.Fatal("project revision", err)
		}
		parent = pgtype.UUID{Bytes: rev.ID, Valid: true}
		out.keys = append(out.keys, key)
	}
	return out
}

// review records one human review of the latest revision.
func (f *dsrHistoryFixtureV1) review(d dsrHistoryDocV1, user uuid.UUID) {
	f.t.Helper()
	doc, err := f.srv.Queries.GetDocumentByID(f.ctx, d.id)
	if err != nil {
		f.t.Fatal(err)
	}
	var revID uuid.UUID
	if err := f.srv.Pool.QueryRow(f.ctx, `SELECT id FROM document_pdf_revisions_v1 WHERE document_id=$1 ORDER BY sequence DESC LIMIT 1`, d.id).Scan(&revID); err != nil { //nolint:rawsql -- fixture reads the latest revision id
		f.t.Fatal(err)
	}
	if _, err := f.srv.Queries.InsertDocumentPDFReviewV1(f.ctx, generated.InsertDocumentPDFReviewV1Params{ID: uuid.New(), OrgID: f.org, DocumentID: d.id, RevisionID: revID, PdfSha256: doc.PdfSha256, ReviewerKind: "human", ReviewedBy: user, VisuallyReviewed: true, ReviewedPages: 1}); err != nil {
		f.t.Fatal("review", err)
	}
}

// send puts the document into a real sent ceremony.
func (f *dsrHistoryFixtureV1) send(d dsrHistoryDocV1) {
	f.t.Helper()
	doc, err := f.srv.Queries.GetDocumentByID(f.ctx, d.id)
	if err != nil {
		f.t.Fatal(err)
	}
	rec, err := f.srv.Queries.GetRecipient(f.ctx, generated.GetRecipientParams{ID: d.recipient, OrgID: f.org})
	if err != nil {
		f.t.Fatal(err)
	}
	if sent := sendDSRDocumentE2E(f.t, f.ctx, f.srv.Pool, f.srv.Queries, doc, rec); sent.Status != "sent" {
		f.t.Fatalf("fixture document status=%s, want sent", sent.Status)
	}
}

func (f *dsrHistoryFixtureV1) erasure(d dsrHistoryDocV1, email string) uuid.UUID {
	f.t.Helper()
	dsr, err := f.srv.Queries.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{
		OrgID: f.org, DocumentID: pgtype.UUID{Bytes: d.id, Valid: true}, RecipientID: pgtype.UUID{Bytes: d.recipient, Valid: true},
		SubjectEmail: email, SubjectName: "History subject", Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return dsr.ID
}

func (f *dsrHistoryFixtureV1) start(id uuid.UUID, cookie string) {
	f.t.Helper()
	if w := f.patch(id, `{"status":"in_progress"}`, cookie); w.Code != http.StatusOK {
		f.t.Fatalf("in_progress=%d %s", w.Code, w.Body.String())
	}
}

func (f *dsrHistoryFixtureV1) count(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.srv.Pool.QueryRow(f.ctx, query, args...).Scan(&n); err != nil { //nolint:rawsql -- fixed count oracles
		f.t.Fatal(err)
	}
	return n
}

func (f *dsrHistoryFixtureV1) revisions(d dsrHistoryDocV1) int {
	return f.count(`SELECT count(*) FROM document_pdf_revisions_v1 WHERE document_id=$1`, d.id)
}

func (f *dsrHistoryFixtureV1) markers(d dsrHistoryDocV1) int {
	return f.count(`SELECT count(*) FROM document_pdf_history_erasures_v1 WHERE document_id=$1`, d.id)
}

func (f *dsrHistoryFixtureV1) historyEvents(d dsrHistoryDocV1) int {
	return f.count(`SELECT count(*) FROM events WHERE document_id=$1 AND kind='data_subject.pdf_history_erased'`, d.id)
}

func (f *dsrHistoryFixtureV1) present(key string) bool {
	f.peer.mu.Lock()
	defer f.peer.mu.Unlock()
	_, ok := f.peer.objects[key]
	return ok
}

func (f *dsrHistoryFixtureV1) presentCount(keys []string) int {
	n := 0
	for _, key := range keys {
		if f.present(key) {
			n++
		}
	}
	return n
}

func (f *dsrHistoryFixtureV1) recipientEmail(d dsrHistoryDocV1) string {
	f.t.Helper()
	r, err := f.srv.Queries.GetRecipient(f.ctx, generated.GetRecipientParams{ID: d.recipient, OrgID: f.org})
	if err != nil {
		f.t.Fatal(err)
	}
	return r.Email
}

func (f *dsrHistoryFixtureV1) status(id uuid.UUID) string {
	f.t.Helper()
	r, err := f.srv.Queries.GetDataSubjectRequest(f.ctx, generated.GetDataSubjectRequestParams{ID: id, OrgID: f.org})
	if err != nil {
		f.t.Fatal(err)
	}
	return r.Status
}

type dsrCodedBodyV1 struct {
	ConfirmationReceipt string `json:"confirmation_receipt"`
	Code                string `json:"code"`
	BlockingDocuments   int    `json:"blocking_documents"`
	Unauthorized        int    `json:"unauthorized_documents"`
	WillErase           struct {
		Documents int `json:"pdf_revision_documents"`
		Revisions int `json:"pdf_revisions"`
	} `json:"will_erase"`
}

func wantDSRCodedV1(t *testing.T, name string, w *httptest.ResponseRecorder, status int, code string) dsrCodedBodyV1 {
	t.Helper()
	var body dsrCodedBodyV1
	if w.Code != status || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != code {
		t.Fatalf("%s: want %d %s, got %d %s", name, status, code, w.Code, safeDSRResponseE2E(w.Body.String()))
	}
	return body
}

// Behaviours 1, 4 and 5: exact recipient match (ann@ does not reach joann@, a
// case variant does), the confirmation count equals the documents erased, and
// one audit event per erased document carries the counts.
func TestDSRHistoryScopeIsExactRecipientMatchE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	linked := f.seed(f.owner, "ann@corp.test", 1)
	f.review(linked, f.owner)
	sibling := f.seed(f.owner, "joann@corp.test", 2)
	caseVariant := f.seed(f.owner, "ANN@Corp.Test", 1)
	dsr := f.erasure(linked, "ann@corp.test")
	f.start(dsr, f.ownerCookie)

	body := wantDSRCodedV1(t, "unconfirmed", f.patch(dsr, `{"status":"fulfilled"}`, f.ownerCookie), http.StatusConflict, "confirmation_required")
	if body.WillErase.Documents != 2 {
		t.Fatalf("will_erase documents=%d, want 2 (the linked document and the case variant, not joann)", body.WillErase.Documents)
	}
	if f.revisions(linked) != 1 || f.revisions(caseVariant) != 1 {
		t.Fatal("the unconfirmed request erased rows")
	}
	if w := f.patch(dsr, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("confirmed erasure=%d %s", w.Code, w.Body.String())
	}

	for name, d := range map[string]dsrHistoryDocV1{"linked": linked, "case variant": caseVariant} {
		if f.revisions(d) != 0 || f.markers(d) != 1 || f.historyEvents(d) != 1 {
			t.Fatalf("%s: revisions/marker/events=%d/%d/%d", name, f.revisions(d), f.markers(d), f.historyEvents(d))
		}
	}
	// Positive control: the sibling is untouched in every respect.
	if f.revisions(sibling) != 2 || f.markers(sibling) != 0 || f.historyEvents(sibling) != 0 {
		t.Fatalf("joann@ was erased by an ann@ request: revisions=%d marker=%d events=%d", f.revisions(sibling), f.markers(sibling), f.historyEvents(sibling))
	}
	if f.recipientEmail(sibling) != "joann@corp.test" {
		t.Fatal("the sibling recipient was anonymized")
	}
	if f.presentCount(sibling.keys) != len(sibling.keys) {
		t.Fatal("an object of the sibling document was deleted")
	}
	// The erased documents lost their replaced objects and kept the current PDF.
	for name, d := range map[string]dsrHistoryDocV1{"linked": linked, "case variant": caseVariant} {
		if f.present(d.keys[0]) || !f.present(d.keys[len(d.keys)-1]) {
			t.Fatalf("%s: original present=%v, current present=%v", name, f.present(d.keys[0]), f.present(d.keys[len(d.keys)-1]))
		}
	}

	// One audit event per erased document: ids and counts, DSR id, no email.
	var payload []byte
	if err := f.srv.Pool.QueryRow(f.ctx, `SELECT payload_json FROM events WHERE document_id=$1 AND org_id=$2 AND kind='data_subject.pdf_history_erased'`, linked.id, f.org).Scan(&payload); err != nil { //nolint:rawsql -- audit read oracle
		t.Fatal(err)
	}
	var event struct {
		RequestID     string `json:"request_id"`
		DocumentID    string `json:"document_id"`
		RevisionCount int    `json:"revision_count"`
		ReviewCount   int    `json:"review_count"`
		ObjectCount   int    `json:"object_count"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	// One revision, one review; only the original upload is named by nothing else
	// (the revision's PDF is the document's current one and is kept).
	if event.RequestID != dsr.String() || event.DocumentID != linked.id.String() || event.RevisionCount != 1 || event.ReviewCount != 1 || event.ObjectCount != 1 {
		t.Fatalf("history audit event=%s", payload)
	}
	if strings.Contains(strings.ToLower(string(payload)), "ann@") {
		t.Fatalf("history audit event carries subject data: %s", payload)
	}
	if n := f.count(`SELECT count(*) FROM events WHERE org_id=$1 AND kind='data_subject.pdf_history_erased'`, f.org); n != 2 {
		t.Fatalf("history audit events=%d, want 2", n)
	}
}

// Behaviour 3: a sender may erase the history of their own documents only. A
// document of another sender is refused with a coded 403 for a sender and erased
// for an owner.
func TestDSRHistoryErasureOfOthersDocumentsNeedsOwnerE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	ownersDoc := f.seed(f.owner, "ann@corp.test", 1)
	sendersDoc := f.seed(f.sender, "ann@corp.test", 1)
	soloDoc := f.seed(f.sender, "solo@corp.test", 1)
	dsr := f.erasure(sendersDoc, "ann@corp.test")

	f.start(dsr, f.senderCookie)
	body := wantDSRCodedV1(t, "sender over the owner's document", f.patch(dsr, `{"status":"fulfilled","confirm":true}`, f.senderCookie), http.StatusForbidden, "dsr_history_owner_required")
	if body.Unauthorized != 1 {
		t.Fatalf("unauthorized_documents=%d, want 1", body.Unauthorized)
	}
	// Refused whole: nothing was erased, anonymized, audited or deleted.
	if f.revisions(ownersDoc) != 1 || f.revisions(sendersDoc) != 1 || f.markers(ownersDoc)+f.markers(sendersDoc) != 0 {
		t.Fatal("the refused request erased history")
	}
	if f.recipientEmail(sendersDoc) != "ann@corp.test" || f.historyEvents(ownersDoc)+f.historyEvents(sendersDoc) != 0 || f.status(dsr) != "in_progress" {
		t.Fatal("the refused request anonymized, audited or closed the request")
	}
	if f.presentCount(ownersDoc.keys) != len(ownersDoc.keys) || f.presentCount(sendersDoc.keys) != len(sendersDoc.keys) {
		t.Fatal("the refused request deleted objects")
	}

	// Positive control 1: the owner erases both documents.
	if w := f.patch(dsr, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("owner erasure=%d %s", w.Code, w.Body.String())
	}
	if f.revisions(ownersDoc) != 0 || f.revisions(sendersDoc) != 0 || f.historyEvents(ownersDoc) != 1 || f.historyEvents(sendersDoc) != 1 {
		t.Fatal("the owner's erasure did not cover both documents")
	}

	// Positive control 2: a sender erasing only their own documents is allowed.
	soloDSR := f.erasure(soloDoc, "solo@corp.test")
	f.start(soloDSR, f.senderCookie)
	if w := f.patch(soloDSR, `{"status":"fulfilled","confirm":true}`, f.senderCookie); w.Code != http.StatusOK {
		t.Fatalf("sender erasure of own document=%d %s", w.Code, w.Body.String())
	}
	if f.revisions(soloDoc) != 0 || f.historyEvents(soloDoc) != 1 {
		t.Fatal("the sender's own document was not erased")
	}
}

// Behaviour 2: a document in an active ceremony blocks the whole request.
func TestDSRHistoryErasureBlockedByCeremonyDocumentE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	draft := f.seed(f.owner, "ann@corp.test", 1)
	sent := f.seed(f.owner, "ann@corp.test", 1)
	f.review(sent, f.owner)
	f.send(sent)
	dsr := f.erasure(draft, "ann@corp.test")
	f.start(dsr, f.ownerCookie)

	body := wantDSRCodedV1(t, "in-ceremony document", f.patch(dsr, `{"status":"fulfilled","confirm":true}`, f.ownerCookie), http.StatusConflict, "dsr_history_documents_blocked")
	if body.BlockingDocuments != 1 {
		t.Fatalf("blocking_documents=%d, want 1", body.BlockingDocuments)
	}
	// Never partial: the eligible draft kept its history too.
	if f.revisions(draft) != 1 || f.revisions(sent) != 1 || f.historyEvents(draft)+f.historyEvents(sent) != 0 {
		t.Fatal("a blocked request erased or audited history")
	}
	if f.recipientEmail(draft) != "ann@corp.test" || f.recipientEmail(sent) != "ann@corp.test" || f.status(dsr) != "in_progress" {
		t.Fatal("a blocked request anonymized a recipient or closed the request")
	}
	if f.presentCount(draft.keys) != len(draft.keys) || f.presentCount(sent.keys) != len(sent.keys) {
		t.Fatal("a blocked request deleted objects")
	}

	// Positive control: with the ceremony document voided the same request
	// completes and erases both documents.
	if _, err := f.srv.Queries.VoidDocumentIfActive(f.ctx, generated.VoidDocumentIfActiveParams{ID: sent.id, OrgID: f.org}); err != nil {
		t.Fatal("void", err)
	}
	if w := f.patch(dsr, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("erasure after void=%d %s", w.Code, w.Body.String())
	}
	if f.revisions(draft) != 0 || f.revisions(sent) != 0 || f.historyEvents(draft) != 1 || f.historyEvents(sent) != 1 {
		t.Fatal("the unblocked request did not erase both documents")
	}
}

// Behaviour 6: a request that fails after the history rows are erased rolls back
// and deletes no stored object; objects are retired only after the commit.
func TestDSRHistoryObjectsSurviveAFailedRequestE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	doc := f.seed(f.owner, "ann@corp.test", 2)
	dsr := f.erasure(doc, "ann@corp.test")
	f.start(dsr, f.ownerCookie)

	// Fail the terminal status update, which runs after the history is erased.
	fn := "dsr_history_fail_" + strings.ReplaceAll(dsr.String(), "-", "")
	if _, err := f.srv.Pool.Exec(f.ctx, `CREATE FUNCTION `+fn+`() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected terminal failure'; END; $$ LANGUAGE plpgsql`); err != nil { //nolint:rawsql -- failure injection for this test's request only
		t.Fatal(err)
	}
	if _, err := f.srv.Pool.Exec(f.ctx, `CREATE TRIGGER `+fn+` BEFORE UPDATE ON data_subject_requests FOR EACH ROW WHEN (NEW.id = '`+dsr.String()+`' AND NEW.status = 'fulfilled') EXECUTE FUNCTION `+fn+`()`); err != nil { //nolint:rawsql -- failure injection for this test's request only
		t.Fatal(err)
	}
	removed := false
	removeTrigger := func() {
		if removed {
			return
		}
		removed = true
		_, _ = f.srv.Pool.Exec(context.Background(), `DROP TRIGGER `+fn+` ON data_subject_requests`) //nolint:rawsql -- cleanup of the injected failure
		_, _ = f.srv.Pool.Exec(context.Background(), `DROP FUNCTION `+fn+`()`)                       //nolint:rawsql -- cleanup of the injected failure
	}
	t.Cleanup(removeTrigger)

	if w := f.patch(dsr, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusInternalServerError {
		t.Fatalf("injected failure=%d %s", w.Code, w.Body.String())
	}
	if f.revisions(doc) != 2 || f.markers(doc) != 0 || f.historyEvents(doc) != 0 {
		t.Fatal("the failed request left history rows erased")
	}
	if f.presentCount(doc.keys) != len(doc.keys) {
		t.Fatalf("the failed request deleted objects while the rolled-back rows still name them: present=%d/%d", f.presentCount(doc.keys), len(doc.keys))
	}

	// Positive control: with the failure removed the same request erases the
	// rows and then retires the objects.
	removeTrigger()
	if w := f.patch(dsr, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("retry=%d %s", w.Code, w.Body.String())
	}
	if f.revisions(doc) != 0 || f.presentCount(doc.keys) != 1 {
		t.Fatalf("retry revisions=%d present objects=%d, want 0 and the current PDF only", f.revisions(doc), f.presentCount(doc.keys))
	}
}

// S7: the export refusal matches the recipient exactly too.
func TestDSRExportRefusalIsExactRecipientMatchE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	f.seed(f.owner, "joann@corp.test", 1)
	if w := f.request(http.MethodGet, "/api/v1/data-subject/export?email=ann@corp.test", "", f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("export for ann@ over a joann@ history=%d %s", w.Code, w.Body.String())
	}
	// Positive control: the real recipient's export is still refused.
	if w := f.request(http.MethodGet, "/api/v1/data-subject/export?email=JoAnn@corp.test", "", f.ownerCookie); w.Code != http.StatusConflict {
		t.Fatalf("export for joann@=%d %s", w.Code, w.Body.String())
	}
}
