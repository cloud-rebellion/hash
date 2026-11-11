//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Actual PostgreSQL, middleware, native runtime and the version-aware S3
// protocol peer. These are lifecycle and exact-byte assertions, not provider
// Object Lock or antivirus efficacy evidence.
type pdfRevisionE2EV1 struct {
	q      *ownedPublicReadFixtureV1
	peer   *importStoragePeer
	mcpKey string
}

func newPDFRevisionE2EV1(t *testing.T) *pdfRevisionE2EV1 {
	t.Helper()
	return newPDFRevisionTenantE2EV1(t, false)
}

// The shared provider fixture owns an HTML template, and DSR erasure refuses
// any tenant with HTML authoring inventory. A DSR test therefore runs in a fresh
// PDF-only tenant of the same owned database and runtime, the way
// newPlainDSRNativeFixtureE2E does.
func newPDFRevisionTenantE2EV1(t *testing.T, plainTenant bool) *pdfRevisionE2EV1 {
	t.Helper()
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if plainTenant {
		org, err := q.f.q.CreateOrg(q.f.ctx, generated.CreateOrgParams{Name: "PDF revision DSR tenant", Plan: "pro"})
		if err != nil {
			t.Fatal(err)
		}
		user, err := q.f.q.CreateUser(q.f.ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@pdf-revision-dsr.test", Name: "DSR owner", Role: "owner"})
		if err != nil {
			t.Fatal(err)
		}
		q.f.org, q.f.user = org.ID, user
		q.f.s.Billing = billing.NewOperator(q.f.q, []config.OperatorEntitlement{{OrgID: org.ID, PlanSlug: "pro", ReviewRef: "synthetic PDF revision DSR fixture"}})
		q.cookie = dsrSessionCookieE2E(t, q.f.s, user.ID, user.SessionGeneration, time.Hour)
	}
	peer := &importStoragePeer{objects: make(map[string][]byte)}
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	var err error
	q.f.s.Storage, err = storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-pdf-revision", SecretKey: "synthetic-pdf-revision-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	// Send and sign read the stored PDF through their own storage handles; they
	// must see the same peer or send's preflight answers NoSuchKey (a 500).
	q.f.s.Send.Storage, q.f.s.Sign.Storage = q.f.s.Storage, q.f.s.Storage
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	q.f.s.MCP = mcp.New(mcp.Deps{Pool: q.f.pool, Queries: q.f.q, Audit: q.f.s.Audit, Storage: q.f.s.Storage, Billing: q.f.s.Billing, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: q.f.s.PublicURL, PDFRevisions: q.f.s.MCPPDFRevisionBridgeV1()})
	if err = malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = malwarescan.Configure(context.Background(), "", "development") })
	mint, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.f.q.CreateAPIKey(q.f.ctx, generated.CreateAPIKeyParams{OrgID: q.f.org, UserID: q.f.user.ID, Name: "PDF revision org key", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"read", "write:authoring"}}); err != nil {
		t.Fatal(err)
	}
	return &pdfRevisionE2EV1{q: q, peer: peer, mcpKey: mint.Plaintext}
}

func (p *pdfRevisionE2EV1) session(method, path string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, p.q.f.s.PublicURL+path, body).WithContext(p.q.f.ctx)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Origin", p.q.f.s.PublicURL)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: p.q.cookie})
	w := httptest.NewRecorder()
	p.q.f.s.Routes().ServeHTTP(w, req)
	return w
}

func (p *pdfRevisionE2EV1) multipart(t *testing.T, path string, pdf []byte, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := form.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if pdf != nil {
		part, err := form.CreateFormFile("pdf", "upload.pdf")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = part.Write(pdf); err != nil {
			t.Fatal(err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	return p.session(http.MethodPost, path, &body, form.FormDataContentType())
}

func (p *pdfRevisionE2EV1) importPDF(t *testing.T, text, purpose string) uuid.UUID {
	t.Helper()
	fields := map[string]string{"name": "PDF revision fixture"}
	if purpose != "" {
		fields["purpose"] = purpose
	}
	w := p.multipart(t, "/api/v1/documents/import", fieldBrowserPDF(text), fields)
	var out struct {
		Document documentResponse `json:"document"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Document.ID == uuid.Nil {
		t.Fatalf("import=%d %s", w.Code, w.Body.String())
	}
	return out.Document.ID
}

func (p *pdfRevisionE2EV1) document(t *testing.T, id uuid.UUID) documentResponse {
	t.Helper()
	w := p.session(http.MethodGet, "/api/v1/documents/"+id.String(), nil, "")
	var d documentResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &d) != nil {
		t.Fatalf("get document=%d %s", w.Code, w.Body.String())
	}
	return d
}

func (p *pdfRevisionE2EV1) pins(d documentResponse) map[string]string {
	return map[string]string{"expected_updated_at": d.UpdatedAt, "expected_pdf_sha256": d.PDFSHA256}
}

func (p *pdfRevisionE2EV1) replace(t *testing.T, id uuid.UUID, pdf []byte, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return p.multipart(t, "/api/v1/documents/"+id.String()+"/pdf/revisions", pdf, fields)
}

func (p *pdfRevisionE2EV1) review(id uuid.UUID, d documentResponse) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(p.pins(d))
	return p.session(http.MethodPost, "/api/v1/documents/"+id.String()+"/pdf/review", bytes.NewReader(raw), "application/json")
}

func (p *pdfRevisionE2EV1) currentPDF(t *testing.T, id uuid.UUID) []byte {
	t.Helper()
	w := p.session(http.MethodGet, "/api/v1/documents/"+id.String()+"/pdf", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("current pdf=%d", w.Code)
	}
	return w.Body.Bytes()
}

func (p *pdfRevisionE2EV1) addSigner(t *testing.T, id uuid.UUID) uuid.UUID {
	t.Helper()
	w := p.session(http.MethodPost, "/api/v1/documents/"+id.String()+"/recipients", strings.NewReader(`{"email":"pdf-revision@example.test","name":"PDF revision signer","role":"signer","locale":"en"}`), "application/json")
	var r recipientResponse
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &r) != nil || r.ID == uuid.Nil {
		t.Fatalf("recipient=%d %s", w.Code, w.Body.String())
	}
	return r.ID
}

func (p *pdfRevisionE2EV1) addSignatureField(t *testing.T, id, recipient uuid.UUID) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"type": "signature", "recipient_id": recipient.String(), "page": 1, "required": true, "x_pct": 10, "y_pct": 80, "w_pct": 30, "h_pct": 8})
	if w := p.session(http.MethodPost, "/api/v1/documents/"+id.String()+"/fields", bytes.NewReader(raw), "application/json"); w.Code != http.StatusCreated {
		t.Fatalf("field=%d %s", w.Code, w.Body.String())
	}
}

func (p *pdfRevisionE2EV1) send(id uuid.UUID) *httptest.ResponseRecorder {
	return p.session(http.MethodPost, "/api/v1/documents/"+id.String()+"/send", strings.NewReader(`{"lawful_basis":"contract"}`), "application/json")
}

func (p *pdfRevisionE2EV1) fieldCount(t *testing.T, id uuid.UUID) int {
	t.Helper()
	rows, err := p.q.f.q.ListFieldsByDocument(p.q.f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func TestPDFRevisionReplacesDraftAndGatesSendE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	id := p.importPDF(t, "Original imported PDF", "")
	signer := p.addSigner(t, id)
	p.addSignatureField(t, id, signer)
	first := p.document(t, id)
	if first.PDFReviewRequired || p.fieldCount(t, id) != 1 {
		t.Fatal("a never-replaced imported PDF must not be gated", first.PDFReviewRequired)
	}
	original := p.currentPDF(t, id)

	// Replace: same document, new pins, review required, field layout reset.
	w := p.replace(t, id, fieldBrowserPDF("Replacement one"), func() map[string]string {
		f := p.pins(first)
		f["summary"] = "Corrected cover page"
		return f
	}())
	var replaced struct {
		Document documentResponse `json:"document"`
		Revision int32            `json:"revision"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &replaced) != nil || replaced.Revision != 1 {
		t.Fatalf("replace=%d %s", w.Code, w.Body.String())
	}
	second := replaced.Document
	if second.ID != id || second.PDFSHA256 == first.PDFSHA256 || second.PDFStorageKey == first.PDFStorageKey || !second.PDFReviewRequired || second.UpdatedAt == first.UpdatedAt {
		t.Fatal("replacement kept the old PDF pins or skipped the review gate", second)
	}
	if p.fieldCount(t, id) != 0 {
		t.Fatal("field layout survived a PDF replacement")
	}
	afterFirst := p.currentPDF(t, id)
	if bytes.Equal(afterFirst, original) {
		t.Fatal("current PDF did not change")
	}

	// Identical bytes still get a fresh storage key and a second revision.
	w = p.replace(t, id, fieldBrowserPDF("Replacement one"), p.pins(second))
	var again struct {
		Document documentResponse `json:"document"`
		Revision int32            `json:"revision"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &again) != nil || again.Revision != 2 || again.Document.PDFStorageKey == second.PDFStorageKey {
		t.Fatalf("identical-bytes replace=%d %s", w.Code, w.Body.String())
	}
	_ = again.Document
	p.addSignatureField(t, id, signer)

	// Stale and missing pins.
	wantRefusalV1(t, "stale replace", p.replace(t, id, fieldBrowserPDF("Stale"), p.pins(second)), http.StatusConflict, "pdf_revision_conflict")
	wantRefusalV1(t, "pinless replace", p.replace(t, id, fieldBrowserPDF("No pins"), nil), http.StatusPreconditionRequired, "pdf_revision_pins_required")
	wantRefusalV1(t, "stale review", p.review(id, second), http.StatusConflict, "pdf_revision_conflict")
	wantRefusalV1(t, "pinless review", p.session(http.MethodPost, "/api/v1/documents/"+id.String()+"/pdf/review", strings.NewReader(`{}`), "application/json"), http.StatusPreconditionRequired, "pdf_revision_pins_required")
	current := p.document(t, id) // pins for the review come from a fresh read

	// Send is refused until a human reviews the latest revision.
	wantRefusalV1(t, "unreviewed send", p.send(id), http.StatusConflict, "pdf_review_required")
	if w = p.review(id, current); w.Code != http.StatusOK {
		t.Fatalf("human review=%d %s", w.Code, w.Body.String())
	}
	if p.document(t, id).PDFReviewRequired {
		t.Fatal("review did not clear pdf_review_required")
	}
	wantRefusalV1(t, "second review", p.review(id, p.document(t, id)), http.StatusConflict, "pdf_revision_conflict")

	// History and retained downloads: 0 is the original, N is revision N.
	h := p.session(http.MethodGet, "/api/v1/documents/"+id.String()+"/pdf/history", nil, "")
	var history struct {
		Revisions []struct {
			Sequence int32 `json:"sequence"`
			Reviewed bool  `json:"reviewed"`
			Summary  string
			Review   *struct {
				ReviewerKind string `json:"reviewer_kind"`
			} `json:"review"`
		} `json:"revisions"`
		PDFReviewRequired bool `json:"pdf_review_required"`
	}
	if h.Code != http.StatusOK || json.Unmarshal(h.Body.Bytes(), &history) != nil || len(history.Revisions) != 2 || history.PDFReviewRequired ||
		history.Revisions[0].Sequence != 2 || !history.Revisions[0].Reviewed || history.Revisions[0].Review == nil || history.Revisions[0].Review.ReviewerKind != "human" || history.Revisions[1].Reviewed {
		t.Fatalf("history=%d %s", h.Code, h.Body.String())
	}
	for seq, want := range map[string][]byte{"0": original, "1": afterFirst} {
		d := p.session(http.MethodGet, "/api/v1/documents/"+id.String()+"/pdf/revisions/"+seq+"/pdf", nil, "")
		if d.Code != http.StatusOK || !bytes.Equal(d.Body.Bytes(), want) {
			t.Fatalf("retained revision %s download=%d identical=%v", seq, d.Code, bytes.Equal(d.Body.Bytes(), want))
		}
	}
	if d := p.session(http.MethodGet, "/api/v1/documents/"+id.String()+"/pdf/revisions/9/pdf", nil, ""); d.Code != http.StatusNotFound {
		t.Fatalf("missing revision=%d", d.Code)
	}

	// Audit: document.updated with old and new pins, one event per revision.
	var events int
	if err := p.q.f.pool.QueryRow(p.q.f.ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.updated' AND payload_json ? 'pdf_revision' AND payload_json ? 'previous_pdf_sha256' AND payload_json ? 'pdf_sha256' AND payload_json->>'review_required'='true'`, id, p.q.f.org).Scan(&events); err != nil || events != 2 { //nolint:rawsql -- audit read oracle
		t.Fatal("revision audit events", events, err)
	}

	// The reviewed document sends, then no longer accepts a replacement.
	if w = p.send(id); w.Code != http.StatusOK {
		t.Fatalf("reviewed send=%d %s", w.Code, w.Body.String())
	}
	sent := p.document(t, id)
	if w = p.replace(t, id, fieldBrowserPDF("Too late"), p.pins(sent)); w.Code != http.StatusConflict {
		t.Fatalf("replace after send=%d %s", w.Code, w.Body.String())
	}
	if d := p.session(http.MethodGet, "/api/v1/documents/"+id.String()+"/pdf/revisions/0/pdf", nil, ""); d.Code != http.StatusOK || !bytes.Equal(d.Body.Bytes(), original) {
		t.Fatal("retained original PDF lost after send")
	}

	assertPDFRevisionDownloadSessionRecheckE2EV1(t, p, id)
}

// Hold the exact retained version's GET after middleware admission. Revoking the
// session before starting the request would exercise only the middleware's 401,
// not the history handler's post-storage generation recheck.
func assertPDFRevisionDownloadSessionRecheckE2EV1(t *testing.T, p *pdfRevisionE2EV1, documentID uuid.UUID) {
	t.Helper()
	row, err := p.q.f.q.GetDocumentPDFRevisionBySequenceV1(p.q.f.ctx, generated.GetDocumentPDFRevisionBySequenceV1Params{DocumentID: documentID, OrgID: p.q.f.org, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []string{"0", "1"} {
		for _, change := range []string{"unchanged", "logout"} {
			t.Run("retained-"+sequence+"-"+change, func(t *testing.T) {
				key, version := row.PdfKey, row.PdfVersionID
				if sequence == "0" {
					key, version = row.PreviousPdfKey, row.PreviousPdfVersionID
				}
				p.peer.mu.Lock()
				want := bytes.Clone(p.peer.objects[key])
				p.peer.mu.Unlock()
				if len(want) == 0 || version == "" {
					t.Fatal("retained download fixture has no exact stored source")
				}
				peer := &originalPDFPreviewPeerE2E{importStoragePeer: p.peer, key: key, entered: make(chan string, 1), release: make(chan struct{})}
				server := httptest.NewServer(peer)
				t.Cleanup(server.Close)
				t.Cleanup(peer.unblock)
				client, err := storage.New(p.q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-history-await", SecretKey: "synthetic-history-await-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
				if err != nil {
					t.Fatal(err)
				}
				oldStore := p.q.f.s.Storage
				p.q.f.s.Storage = client
				t.Cleanup(func() { p.q.f.s.Storage = oldStore })
				user, err := p.q.f.q.GetUser(p.q.f.ctx, p.q.f.user.ID)
				if err != nil {
					t.Fatal(err)
				}
				cookie := dsrSessionCookieE2E(t, p.q.f.s, user.ID, user.SessionGeneration, time.Hour)
				ctx, cancel := context.WithTimeout(p.q.f.ctx, 10*time.Second)
				result, done := make(chan *httptest.ResponseRecorder, 1), make(chan struct{})
				request := httptest.NewRequest(http.MethodGet, p.q.f.s.PublicURL+"/api/v1/documents/"+documentID.String()+"/pdf/revisions/"+sequence+"/pdf", nil).WithContext(ctx)
				request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
				go func() {
					defer close(done)
					w := httptest.NewRecorder()
					p.q.f.s.Routes().ServeHTTP(w, request)
					result <- w
				}()
				t.Cleanup(func() {
					cancel()
					peer.unblock()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("retained PDF request did not join before fixture teardown")
					}
				})
				select {
				case got := <-peer.entered:
					if got != version {
						t.Fatalf("retained PDF requested version %q, want %q", got, version)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("retained PDF did not reach storage wait after session admission")
				}
				if change == "logout" {
					affected, err := p.q.f.q.RevokeUserSessions(p.q.f.ctx, generated.RevokeUserSessionsParams{ID: user.ID, OrgID: p.q.f.org, SessionGeneration: user.SessionGeneration})
					if err != nil || affected != 1 {
						t.Fatal("fixture session revocation did not change exactly one generation", affected, err)
					}
				}
				peer.unblock()
				w := receiveSessionOperationE2E(t, result)
				if change == "logout" {
					if w.Code != http.StatusForbidden || w.Header().Get("Content-Type") == "application/pdf" || bytes.Contains(w.Body.Bytes(), []byte("%PDF-")) {
						t.Fatalf("revoked retained download=%d type=%q body=%s, want 403 without PDF", w.Code, w.Header().Get("Content-Type"), w.Body.String())
					}
				} else if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/pdf" || !bytes.Equal(w.Body.Bytes(), want) {
					t.Fatalf("unchanged retained download=%d exact=%v", w.Code, bytes.Equal(w.Body.Bytes(), want))
				}
				if peer.calls.Load() != 1 {
					t.Fatalf("retained download fetched %d source versions, want 1", peer.calls.Load())
				}
			})
		}
	}
}

// A fake clamd that reports every stream as infected.
func pdfRevisionInfectedClamdE2EV1(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "hpr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "clamd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				command := make([]byte, 0, 32)
				one := make([]byte, 1)
				for {
					if _, err := conn.Read(one); err != nil {
						return
					}
					command = append(command, one[0])
					if one[0] == 0 {
						break
					}
				}
				if string(command) == "zVERSIONCOMMANDS\x00" {
					io.WriteString(conn, "ClamAV 1.4/123/"+time.Now().UTC().Format(time.ANSIC)+"| COMMANDS: INSTREAM VERSION\x00")
					return
				}
				for {
					var n uint32
					if binary.Read(conn, binary.BigEndian, &n) != nil || n == 0 {
						break
					}
					if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
						return
					}
				}
				io.WriteString(conn, "stream: Test-Signature FOUND\x00")
			}()
		}
	}()
	return socket
}

func TestPDFRevisionRefusesEvidenceE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	id := p.importPDF(t, "Evidence fixture", "")
	signer := p.addSigner(t, id)
	p.addSignatureField(t, id, signer)
	puts := func() int { p.peer.mu.Lock(); defer p.peer.mu.Unlock(); return p.peer.puts }
	deletes := func() int { p.peer.mu.Lock(); defer p.peer.mu.Unlock(); return p.peer.deletes }
	refuse := func(name string, d documentResponse, want int) {
		t.Helper()
		beforePuts, beforeDeletes := puts(), deletes()
		w := p.replace(t, id, fieldBrowserPDF("Refused "+name), p.pins(d))
		if w.Code != want {
			t.Fatalf("%s: status=%d want %d: %s", name, w.Code, want, w.Body.String())
		}
		// Whatever was stored before the refusal is deleted again.
		if puts()-beforePuts != deletes()-beforeDeletes {
			t.Fatalf("%s: leaked object puts=%d deletes=%d", name, puts()-beforePuts, deletes()-beforeDeletes)
		}
		after := p.document(t, id)
		if after.PDFSHA256 != d.PDFSHA256 || p.fieldCount(t, id) != 1 {
			t.Fatalf("%s: refusal changed the document", name)
		}
	}
	base := p.document(t, id)

	// Missing and stale pins.
	wantRefusalV1(t, "missing pins", p.replace(t, id, fieldBrowserPDF("x"), nil), http.StatusPreconditionRequired, "pdf_revision_pins_required")
	stale := base
	stale.UpdatedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	refuse("stale", stale, http.StatusConflict)

	// A malware verdict refuses before anything is parsed or stored.
	socket := pdfRevisionInfectedClamdE2EV1(t)
	if err := malwarescan.Configure(p.q.f.ctx, socket, "production"); err != nil {
		t.Fatal(err)
	}
	infectedPuts := puts()
	if w := p.replace(t, id, fieldBrowserPDF("infected"), p.pins(base)); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "malware") || puts() != infectedPuts {
		t.Fatalf("scanner refusal=%d %s puts=%d", w.Code, w.Body.String(), puts()-infectedPuts)
	}
	if err := malwarescan.Configure(p.q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}

	// Not a PDF.
	wantRefusalV1(t, "non-PDF", p.replace(t, id, []byte("plain text"), p.pins(base)), http.StatusBadRequest, "pdf_revision_not_pdf")

	// A filled field is retained signing evidence.
	if _, err := p.q.f.pool.Exec(p.q.f.ctx, `UPDATE document_fields SET value='filled', completed_at=clock_timestamp() WHERE document_id=$1`, id); err != nil { //nolint:rawsql -- models a filled field
		t.Fatal(err)
	}
	refuse("filled field", p.document(t, id), http.StatusConflict)
	if _, err := p.q.f.pool.Exec(p.q.f.ctx, `UPDATE document_fields SET value=NULL, completed_at=NULL WHERE document_id=$1`, id); err != nil { //nolint:rawsql -- restores the fixture
		t.Fatal(err)
	}

	// A signed recipient is retained signing evidence.
	if _, err := p.q.f.pool.Exec(p.q.f.ctx, `UPDATE recipients SET signed_at=clock_timestamp() WHERE id=$1`, signer); err != nil { //nolint:rawsql -- models a signed recipient
		t.Fatal(err)
	}
	refuse("signed recipient", p.document(t, id), http.StatusConflict)
	if _, err := p.q.f.pool.Exec(p.q.f.ctx, `UPDATE recipients SET signed_at=NULL WHERE id=$1`, signer); err != nil { //nolint:rawsql -- restores the fixture
		t.Fatal(err)
	}

	// Other source kinds: the lifecycle fixture's document is not an imported PDF.
	other := p.q.f.doc
	w := p.replace(t, other.ID, fieldBrowserPDF("wrong kind"), map[string]string{
		"expected_updated_at": other.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_pdf_sha256": strings.Repeat("0", 64)})
	if other.SourceKind == "pdf" {
		t.Fatal("the lifecycle fixture must not be an imported PDF for the source-kind refusal")
	}
	wantRefusalV1(t, "source kind", w, http.StatusConflict, "pdf_revision_not_draft_pdf")

	// A template-backed PDF is refused on this route.
	templated, err := p.q.f.q.CreatePDFDocument(p.q.f.ctx, generated.CreatePDFDocumentParams{OrgID: p.q.f.org, TemplateID: pgtype.UUID{Bytes: p.q.template.ID, Valid: true}, SenderID: p.q.f.user.ID, Name: "Template-backed PDF",
		PdfStorageKey: pgtype.Text{String: "org/" + p.q.f.org.String() + "/documents/" + uuid.NewString() + ".pdf", Valid: true}, PdfSha256: bytes.Repeat([]byte{3}, 32), PdfStorageVersionID: pgtype.Text{String: "synthetic-template-backed", Valid: true}, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	beforePuts, beforeDeletes := puts(), deletes()
	w = p.replace(t, templated.ID, fieldBrowserPDF("templated"), map[string]string{"expected_updated_at": templated.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_pdf_sha256": strings.Repeat("03", 32)})
	wantRefusalV1(t, "template-backed", w, http.StatusConflict, "pdf_revision_conflict")
	if !strings.Contains(w.Body.String(), "template-backed") || puts()-beforePuts != deletes()-beforeDeletes {
		t.Fatalf("template-backed refusal body or leaked object: %s", w.Body.String())
	}

	// A sent document is not a draft.
	if w = p.send(id); w.Code != http.StatusOK {
		t.Fatalf("send=%d %s", w.Code, w.Body.String())
	}
	refuse("sent", p.document(t, id), http.StatusConflict)
}

func (p *pdfRevisionE2EV1) mcpCall(t *testing.T, tool string, args map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, p.q.f.s.PublicURL+"/mcp", bytes.NewReader(raw)).WithContext(p.q.f.ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+p.mcpKey)
	w := httptest.NewRecorder()
	p.q.f.s.Routes().ServeHTTP(w, r)
	return w
}

// An agent may replace a PDF and review it only for a non-signing document.
func TestPDFRevisionMCPAgentReviewRespectsPurposeE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	for _, purpose := range []string{"document", "signing"} {
		t.Run(purpose, func(t *testing.T) {
			id := p.importPDF(t, "MCP "+purpose, purpose)
			d := p.document(t, id)
			args := map[string]any{"document_id": id.String(), "expected_updated_at": d.UpdatedAt, "expected_pdf_sha256": d.PDFSHA256, "pdf_base64": encodeBase64V1(fieldBrowserPDF("MCP replacement " + purpose))}
			fieldMCPTextE2E(t, p.mcpCall(t, "replace_document_pdf", args), false)
			replaced := p.document(t, id)
			if replaced.PDFSHA256 == d.PDFSHA256 || !replaced.PDFReviewRequired {
				t.Fatal("MCP replacement did not apply or gate")
			}
			// Stale pins are an actionable refusal.
			args["pdf_base64"] = encodeBase64V1(fieldBrowserPDF("stale"))
			fieldMCPTextE2E(t, p.mcpCall(t, "replace_document_pdf", args), true)

			history := fieldMCPTextE2E(t, p.mcpCall(t, "get_document_pdf_history", map[string]any{"document_id": id.String()}), false)
			if !strings.Contains(history, `"pdf_review_required":true`) {
				t.Fatal("history lacks the review state", history)
			}
			review := map[string]any{"document_id": id.String(), "expected_updated_at": replaced.UpdatedAt, "expected_pdf_sha256": replaced.PDFSHA256, "visually_reviewed": true, "reviewed_pages": []int{1}}
			if purpose == "signing" {
				fieldMCPTextE2E(t, p.mcpCall(t, "review_document_pdf", review), true)
				if !p.document(t, id).PDFReviewRequired {
					t.Fatal("agent review of a signing document took effect")
				}
				// Only the human staff session can review it.
				if w := p.review(id, replaced); w.Code != http.StatusOK {
					t.Fatalf("human review=%d %s", w.Code, w.Body.String())
				}
				return
			}
			fieldMCPTextE2E(t, p.mcpCall(t, "review_document_pdf", review), false)
			if p.document(t, id).PDFReviewRequired {
				t.Fatal("agent review of a non-signing document did not apply")
			}
			var kind string
			if err := p.q.f.pool.QueryRow(p.q.f.ctx, `SELECT v.reviewer_kind FROM document_pdf_reviews_v1 v WHERE v.document_id=$1`, id).Scan(&kind); err != nil || kind != "agent" { //nolint:rawsql -- reviewer-kind oracle
				t.Fatal("agent review not recorded as agent", kind, err)
			}
		})
	}
}

// wantRefusalV1 asserts the exact status and the machine code of a JSON refusal.
func wantRefusalV1(t *testing.T, name string, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if w.Code != status || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != code || body.Error == "" {
		t.Fatalf("%s: status=%d want %d code want %q body=%s", name, w.Code, status, code, w.Body.String())
	}
	for _, leak := range []string{"hash-import-fixture", "/documents/", "org/", "versionId", "127.0.0.1"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Fatalf("%s: refusal body leaks %q: %s", name, leak, w.Body.String())
		}
	}
}

func encodeBase64V1(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// E-F1: a replaced PDF that nobody reviewed must not reach signers as an
// attachment or a captured template. The shared gate is hash_pdf_bytes_reviewed_v1.
func TestPDFRevisionReviewGateCoversAttachmentAndCaptureE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	f := p.q.f
	root := p.importPDF(t, "Attachment root", "")
	member := p.importPDF(t, "Attachment member", "")
	memberDoc := p.document(t, member)
	w := p.replace(t, member, fieldBrowserPDF("Member replaced"), p.pins(memberDoc))
	if w.Code != http.StatusCreated {
		t.Fatalf("replace member=%d %s", w.Code, w.Body.String())
	}
	// Send validates recipients before the review gate, so the member needs a
	// signer and a signature field to reach the 409.
	memberSigner := p.addSigner(t, member)
	p.addSignatureField(t, member, memberSigner)
	gate := func(label string) error {
		_, err := f.pool.Exec(f.ctx, `SELECT hash_pdf_bytes_reviewed_v1($1)`, member)
		_ = label
		return err
	}
	rootRow, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: root, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	pkg := packageHeader218(t, f, rootRow)
	attach := func() error {
		memberRow, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: member, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, packageFresh218(t, f, pkg.ID), memberRow, 1))
		return err
	}
	// Unreviewed: the shared gate and the attach trigger both refuse with 23514.
	packageExpectPG218(t, gate("before review"), "23514")
	packageExpectPG218(t, attach(), "23514")
	// The REST send of the member names the same code.
	wantRefusalV1(t, "member send", p.send(member), http.StatusConflict, "pdf_review_required")
	// A human review of the member clears the gate and the attachment passes.
	if w = p.review(member, p.document(t, member)); w.Code != http.StatusOK {
		t.Fatalf("review member=%d %s", w.Code, w.Body.String())
	}
	if err := gate("after review"); err != nil {
		t.Fatal(err)
	}
	if err := attach(); err != nil {
		t.Fatalf("attach after human review: %v", err)
	}
}

// F-F2: a signing document needs a human review; an agent review of a
// non-signing document passes the gate, and after the purpose changes to
// signing a human review is recorded on top of it.
func TestPDFRevisionSigningNeedsHumanReviewE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	f := p.q.f
	id := p.importPDF(t, "Purpose fixture", "document")
	d := p.document(t, id)
	if w := p.replace(t, id, fieldBrowserPDF("Purpose replaced"), p.pins(d)); w.Code != http.StatusCreated {
		t.Fatalf("replace=%d %s", w.Code, w.Body.String())
	}
	var revision uuid.UUID
	var sha []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT id, pdf_sha256 FROM document_pdf_revisions_v1 WHERE document_id=$1 ORDER BY sequence DESC LIMIT 1`, id).Scan(&revision, &sha); err != nil {
		t.Fatal(err)
	}
	// An agent review row (as the MCP path writes it) for a non-signing document.
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO document_pdf_reviews_v1 (id, org_id, document_id, revision_id, pdf_sha256, reviewer_kind, reviewed_by, visually_reviewed, reviewed_pages)
		SELECT gen_random_uuid(), org_id, document_id, id, pdf_sha256, 'agent', created_by, true, page_count FROM document_pdf_revisions_v1 WHERE id=$1`, revision); err != nil { //nolint:rawsql -- models an agent review
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `SELECT hash_pdf_bytes_reviewed_v1($1)`, id); err != nil {
		t.Fatalf("agent review of a non-signing document must pass: %v", err)
	}
	// Switching to signing makes the agent review insufficient.
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET metadata = metadata - 'hash:document-purpose:v1' WHERE id=$1`, id); err != nil { //nolint:rawsql -- models a purpose change to signing
		t.Fatal(err)
	}
	_, err := f.pool.Exec(f.ctx, `SELECT hash_pdf_bytes_reviewed_v1($1)`, id)
	packageExpectPG218(t, err, "23514")
	if !p.document(t, id).PDFReviewRequired {
		t.Fatal("an agent-only review must leave a signing document review-required")
	}
	// A human may review on top of the agent review.
	if w := p.review(id, p.document(t, id)); w.Code != http.StatusOK {
		t.Fatalf("human review on top of agent review=%d %s", w.Code, w.Body.String())
	}
	if _, err = f.pool.Exec(f.ctx, `SELECT hash_pdf_bytes_reviewed_v1($1)`, id); err != nil {
		t.Fatal(err)
	}
	// Nothing is added on top of a human review.
	wantRefusalV1(t, "review after human", p.review(id, p.document(t, id)), http.StatusConflict, "pdf_revision_conflict")
}

// Tom, 2026-11-08: erase at any stage, behind a prompt. A draft with two PDF
// revisions and a review: delete needs confirmation, the purge claim includes
// it, the revision rows and objects can be erased only through the guarded
// path, and DSR erasure of the subject completes.
func TestPDFRevisionHistoryErasureE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	f := p.q.f
	id := p.importPDF(t, "Erase original", "")
	p.addSigner(t, id)
	for i, text := range []string{"Erase one", "Erase two"} {
		d := p.document(t, id)
		if w := p.replace(t, id, fieldBrowserPDF(text), p.pins(d)); w.Code != http.StatusCreated {
			t.Fatalf("replace %d=%d %s", i, w.Code, w.Body.String())
		}
	}
	if w := p.review(id, p.document(t, id)); w.Code >= 300 {
		t.Fatalf("review=%d %s", w.Code, w.Body.String())
	}
	count := func(table string) int {
		var n int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM `+table+` WHERE document_id=$1`, id).Scan(&n); err != nil { //nolint:rawsql -- test-owned table names
			t.Fatal(err)
		}
		return n
	}
	if count("document_pdf_revisions_v1") != 2 || count("document_pdf_reviews_v1") != 1 {
		t.Fatal("fixture lacks two revisions and one review")
	}
	// Append-only still blocks an ordinary DELETE and UPDATE.
	for _, stmt := range []string{`DELETE FROM document_pdf_reviews_v1 WHERE document_id=$1`, `DELETE FROM document_pdf_revisions_v1 WHERE document_id=$1`, `UPDATE document_pdf_revisions_v1 SET summary='x' WHERE document_id=$1`} {
		if _, err := f.pool.Exec(f.ctx, stmt, id); err == nil || !strings.Contains(err.Error(), "append-only") { //nolint:rawsql -- proves the guard
			t.Fatalf("%s: err=%v, want append-only refusal", stmt, err)
		}
	}
	// A different document's name in the setting does not open the guard.
	foreignSettingTx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = foreignSettingTx.Exec(f.ctx, `SELECT set_config('hash.erase_document_history', $1, true)`, uuid.NewString()); err != nil { //nolint:rawsql -- proves the guard
		_ = foreignSettingTx.Rollback(f.ctx)
		t.Fatal(err)
	}
	if _, err = foreignSettingTx.Exec(f.ctx, `DELETE FROM document_pdf_revisions_v1 WHERE document_id=$1`, id); err == nil { //nolint:rawsql -- proves the guard
		_ = foreignSettingTx.Rollback(f.ctx)
		t.Fatal("a foreign document id opened the append-only guard")
	}
	_ = foreignSettingTx.Rollback(f.ctx)
	objectsBefore := len(p.peer.objects)

	// Confirmation is required, with the coded 409 describing the erasure.
	w := p.session(http.MethodDelete, "/api/v1/documents/"+id.String(), nil, "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"confirmation_required"`) || !strings.Contains(w.Body.String(), "pdf_revisions") {
		t.Fatalf("unconfirmed delete=%d %s", w.Code, w.Body.String())
	}
	w = p.session(http.MethodDelete, "/api/v1/documents/"+id.String(), strings.NewReader(`{"confirm":true}`), "application/json")
	if w.Code != http.StatusNoContent {
		t.Fatalf("confirmed delete=%d %s", w.Code, w.Body.String())
	}
	// hash_document_update_clock moves updated_at forward on every UPDATE, so
	// an aged lease can only be modelled with user triggers skipped for this
	// one fixture statement (transaction-local, no table lock).
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, `SET LOCAL session_replication_role = replica`); err != nil { //nolint:rawsql -- fixture-only trigger bypass
		_ = tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, `UPDATE documents SET deleted_at = now() - interval '400 days', updated_at = now() - interval '2 hours' WHERE id=$1`, id); err != nil { //nolint:rawsql -- models an expired soft delete and lease
		_ = tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	claimed, err := f.q.ClaimSoftDeletedDocumentsForPurge(f.ctx, generated.ClaimSoftDeletedDocumentsForPurgeParams{
		Cutoff: pgtype.Timestamptz{Time: time.Now().Add(-24 * time.Hour), Valid: true}, BatchLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var got bool
	for _, doc := range claimed {
		got = got || doc.ID == id
	}
	if !got {
		t.Fatal("the expired draft with revision history was not claimed for purge")
	}
	// The purge path: list objects, erase through the guarded function, then
	// the parent row can be hard-deleted.
	objects, err := f.q.ListDocumentPDFRevisionObjects(f.ctx, generated.ListDocumentPDFRevisionObjectsParams{DocumentID: id, OrgID: f.org})
	if err != nil || len(objects) < 3 {
		t.Fatalf("revision objects=%d err=%v", len(objects), err)
	}
	if n, err := f.q.EraseDocumentPDFHistory(f.ctx, generated.EraseDocumentPDFHistoryParams{DocumentID: id, Purge: true}); err != nil || n != 2 {
		t.Fatalf("erase n=%d err=%v", n, err)
	}
	if count("document_pdf_revisions_v1") != 0 || count("document_pdf_reviews_v1") != 0 {
		t.Fatal("revision or review rows survived erasure")
	}
	if tag, err := f.pool.Exec(f.ctx, `DELETE FROM documents WHERE id=$1`, id); err != nil || tag.RowsAffected() != 1 { //nolint:rawsql -- the worker's hard delete
		t.Fatalf("parent delete rows=%v err=%v", tag, err)
	}
	_ = objectsBefore
}

// DSR erasure of a live draft with revision history needs confirmation, then
// completes, erases the archive and its objects, and keeps the review gate shut.
func TestPDFRevisionHistoryDSRErasureE2E(t *testing.T) {
	p := newPDFRevisionTenantE2EV1(t, true)
	f := p.q.f
	if present, err := f.q.HasHTMLAuthoringDataForDSR(f.ctx, f.org); err != nil || present {
		t.Fatal("DSR tenant has HTML authoring inventory", present, err)
	}
	id := p.importPDF(t, "DSR original", "")
	signer := p.addSigner(t, id)
	for _, text := range []string{"DSR one", "DSR two"} {
		d := p.document(t, id)
		if w := p.replace(t, id, fieldBrowserPDF(text), p.pins(d)); w.Code != http.StatusCreated {
			t.Fatalf("replace=%d %s", w.Code, w.Body.String())
		}
	}
	if w := p.review(id, p.document(t, id)); w.Code >= 300 {
		t.Fatalf("review=%d %s", w.Code, w.Body.String())
	}
	dsr, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{
		OrgID: f.org, DocumentID: pgtype.UUID{Bytes: id, Valid: true}, RecipientID: pgtype.UUID{Bytes: signer, Valid: true},
		SubjectEmail: "pdf-revision@example.test", SubjectName: "PDF revision signer", Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	objectsBefore := len(p.peer.objects)
	patch := func(body string) *httptest.ResponseRecorder {
		return p.session(http.MethodPatch, "/api/v1/dsr/"+dsr.ID.String(), strings.NewReader(body), "application/json")
	}
	if w := patch(`{"status":"in_progress"}`); w.Code != http.StatusOK {
		t.Fatalf("in_progress=%d %s", w.Code, w.Body.String())
	}
	w := patch(`{"status":"fulfilled"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"confirmation_required"`) {
		t.Fatalf("unconfirmed erasure=%d, want confirmation_required", w.Code)
	}
	var preview struct {
		Receipt   string `json:"confirmation_receipt"`
		WillErase struct {
			Documents int `json:"pdf_revision_documents"`
			Revisions int `json:"pdf_revisions"`
		} `json:"will_erase"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil || preview.Receipt == "" || len(preview.Receipt) > 8192 || preview.WillErase.Documents != 1 || preview.WillErase.Revisions != 2 {
		t.Fatal("erasure preview lacks an exact confirmation receipt and revision counts")
	}
	confirmed, err := json.Marshal(map[string]any{"status": "fulfilled", "confirm": true, "confirmation_receipt": preview.Receipt})
	if err != nil {
		t.Fatal("encode confirmed erasure")
	}
	if w = patch(string(confirmed)); w.Code != http.StatusOK {
		t.Fatalf("confirmed erasure=%d", w.Code)
	}
	var revisions, reviews, marker int
	for query, dst := range map[string]*int{
		`SELECT count(*) FROM document_pdf_revisions_v1 WHERE document_id=$1`:        &revisions,
		`SELECT count(*) FROM document_pdf_reviews_v1 WHERE document_id=$1`:          &reviews,
		`SELECT count(*) FROM document_pdf_history_erasures_v1 WHERE document_id=$1`: &marker,
	} {
		if err := f.pool.QueryRow(f.ctx, query, id).Scan(dst); err != nil { //nolint:rawsql -- fixed queries
			t.Fatal(err)
		}
	}
	if revisions != 0 || reviews != 0 || marker != 1 {
		t.Fatalf("after DSR revisions/reviews/marker=%d/%d/%d", revisions, reviews, marker)
	}
	if len(p.peer.objects) >= objectsBefore {
		t.Fatalf("revision objects were not deleted: before=%d after=%d", objectsBefore, len(p.peer.objects))
	}
	// The current PDF is still downloadable.
	if len(p.currentPDF(t, id)) == 0 {
		t.Fatal("the document lost its current PDF")
	}
	// The erased draft cannot pass the send gate without a fresh review.
	if _, err := f.pool.Exec(f.ctx, `SELECT hash_pdf_bytes_reviewed_v1($1)`, id); err == nil || !strings.Contains(err.Error(), "requires review") { //nolint:rawsql -- exercises the gate
		t.Fatalf("send gate after erasure err=%v", err)
	}
}

// N6: template capture must refuse a replaced, unreviewed PDF with the coded 409.
func TestPDFRevisionReviewGateCoversTemplateCaptureE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	f := p.q.f
	id := p.importPDF(t, "Capture source", "")
	if w := p.replace(t, id, fieldBrowserPDF("Capture replaced"), p.pins(p.document(t, id))); w.Code != http.StatusCreated {
		t.Fatalf("replace=%d %s", w.Code, w.Body.String())
	}
	signer := p.addSigner(t, id)
	p.addSignatureField(t, id, signer)
	fields, err := f.q.ListFieldsByDocument(f.ctx, id)
	if err != nil || len(fields) != 1 {
		t.Fatal("field fixture", err)
	}
	capture := func() *httptest.ResponseRecorder {
		d := p.document(t, id)
		raw, _ := json.Marshal(savePDFTemplateInput{Name: "Captured layout", ExpectedUpdatedAt: d.UpdatedAt, ExpectedFieldIDs: []uuid.UUID{fields[0].ID}, Parties: []savePDFTemplateParty{{RecipientID: signer, Role: "customer", Label: "Customer"}}})
		return p.session(http.MethodPost, "/api/v1/documents/"+id.String()+"/pdf-template", bytes.NewReader(raw), "application/json")
	}
	templates := func() int64 {
		n, err := f.q.CountTemplates(f.ctx, f.org)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	baseline := templates()
	wantRefusalV1(t, "template capture", capture(), http.StatusConflict, "pdf_review_required")
	if templates() != baseline {
		t.Fatal("a refused capture stored a template")
	}
	if w := p.review(id, p.document(t, id)); w.Code != http.StatusOK {
		t.Fatalf("review=%d %s", w.Code, w.Body.String())
	}
	if w := capture(); w.Code != http.StatusCreated {
		t.Fatalf("capture after review=%d %s", w.Code, w.Body.String())
	}
	if templates() != baseline+1 {
		t.Fatalf("capture after review stored %d templates, want 1", templates()-baseline)
	}
}

// N6: setting parent_envelope_id on a replaced, unreviewed document is refused
// by the envelope-child trigger, and a signing envelope also needs a human.
func TestPDFRevisionReviewGateCoversEnvelopeChildE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	f := p.q.f
	parent := p.importPDF(t, "Envelope parent", "")
	child := p.importPDF(t, "Envelope child", "document")
	if w := p.replace(t, child, fieldBrowserPDF("Child replaced"), p.pins(p.document(t, child))); w.Code != http.StatusCreated {
		t.Fatalf("replace=%d %s", w.Code, w.Body.String())
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET is_envelope=true WHERE id=$1`, parent); err != nil { //nolint:rawsql -- models an envelope root
		t.Fatalf("envelope root cannot be modelled directly: %v", err)
	}
	_, err := f.pool.Exec(f.ctx, `UPDATE documents SET parent_envelope_id=$1 WHERE id=$2`, parent, child) //nolint:rawsql -- exercises the envelope-child trigger
	packageExpectPG218(t, err, "23514")
}

// N4 and N5: a member of a signing package counts as signing. An agent-only
// review of a non-signing PDF member passes alone but not as a signing member.
func TestPDFRevisionMemberOfSigningPackageNeedsHumanReviewE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	f := p.q.f
	id := p.importPDF(t, "Member purpose", "document")
	if w := p.replace(t, id, fieldBrowserPDF("Member replaced"), p.pins(p.document(t, id))); w.Code != http.StatusCreated {
		t.Fatalf("replace=%d %s", w.Code, w.Body.String())
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO document_pdf_reviews_v1 (id, org_id, document_id, revision_id, pdf_sha256, reviewer_kind, reviewed_by, visually_reviewed, reviewed_pages)
		SELECT gen_random_uuid(), org_id, document_id, id, pdf_sha256, 'agent', created_by, true, page_count FROM document_pdf_revisions_v1 WHERE document_id=$1 ORDER BY sequence DESC LIMIT 1`, id); err != nil { //nolint:rawsql -- models an agent review
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `SELECT hash_pdf_bytes_reviewed_v1($1, false)`, id); err != nil {
		t.Fatalf("agent review passes for a non-signing member alone: %v", err)
	}
	_, err := f.pool.Exec(f.ctx, `SELECT hash_pdf_bytes_reviewed_v1($1, true)`, id)
	packageExpectPG218(t, err, "23514")
	if w := p.review(id, p.document(t, id)); w.Code != http.StatusOK {
		t.Fatalf("human review=%d %s", w.Code, w.Body.String())
	}
	if _, err = f.pool.Exec(f.ctx, `SELECT hash_pdf_bytes_reviewed_v1($1, true)`, id); err != nil {
		t.Fatalf("human review must satisfy the signing-member gate: %v", err)
	}
}
