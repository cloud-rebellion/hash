//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Same constructor/namespace from Send retention through genuine response,
// final/report publication and terminal reads. Exact imported originals use the
// strict version peer; newly published outputs acquire policy at their PUT.
type completedPackagePeer248 struct {
	main         *packageRetentionNativePeer240
	mainKey      string
	originalKeys map[string]struct{}
	mu           sync.Mutex
	until        map[string]time.Time
}

func (p *completedPackagePeer248) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/hash-import-fixture/")
	_, original := p.originalKeys[key]
	if key == p.mainKey || original || ((r.URL.Path == "/hash-import-fixture" || r.URL.Path == "/hash-import-fixture/") && !r.URL.Query().Has("versions")) {
		p.main.ServeHTTP(w, r)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		http.Error(w, "missing SDK authentication", 403)
		return
	}
	if r.URL.Query().Has("versions") {
		p.main.base.ServeHTTP(w, r)
		return
	}
	if r.URL.Query().Has("retention") {
		if r.URL.Query().Get("versionId") != "import-version-1" {
			http.Error(w, "wrong version", 400)
			return
		}
		if r.Method == http.MethodPut {
			var v struct {
				Mode  string    `xml:"Mode"`
				Until time.Time `xml:"RetainUntilDate"`
			}
			if xml.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&v) != nil || v.Mode != "COMPLIANCE" || !v.Until.After(time.Now()) {
				http.Error(w, "bad retention", 400)
				return
			}
			p.mu.Lock()
			p.until[key] = v.Until
			p.mu.Unlock()
			w.WriteHeader(200)
			return
		}
		p.mu.Lock()
		until := p.until[key]
		p.mu.Unlock()
		if r.Method != http.MethodGet || until.IsZero() {
			http.Error(w, "retention absent", 404)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>"+until.Format(time.RFC3339Nano)+"</RetainUntilDate></Retention>")
		return
	}
	if r.Method == http.MethodPut {
		until, err := time.Parse(time.RFC3339Nano, r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"))
		if err != nil || r.Header.Get("X-Amz-Object-Lock-Mode") != "COMPLIANCE" || !until.After(time.Now()) {
			http.Error(w, "retained output required", 400)
			return
		}
		p.mu.Lock()
		p.until[key] = until
		p.mu.Unlock()
	}
	p.main.base.ServeHTTP(w, r)
}

type completedPackageFixture248 struct {
	active      packageResponseHTTPFixture247
	peer        *completedPackagePeer248
	token, etag string
	raw         []byte
}

func newCompletedPackageFixture248(t *testing.T, signed bool) completedPackageFixture248 {
	t.Helper()
	q := inspectionFixturePG236(t)
	var m pdfadmission.HTMLSendPackageIntentMetadataV1
	var recipient uuid.UUID
	if signed {
		m, recipient = packageResponsePreparedSignedBirth247(t, q)
	} else {
		m, recipient = packageCompletionPreparedBirth241(t, q, 2, false)
	}
	root := packageLatest223(t, q, m.Capture.DocumentID)
	peer := &completedPackagePeer248{main: &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}, mainKey: root.PdfStorageKey.String, until: make(map[string]time.Time)}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-terminal-access", SecretKey: "synthetic-terminal-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	packageCompletionRun241(t, q, client, m, "sent")
	q.f.s.Sign.Storage = client
	q.f.s.Storage = client
	q.storagePeer.mu.Lock()
	raw := bytes.Clone(q.storagePeer.objects[root.PdfStorageKey.String])
	q.storagePeer.mu.Unlock()
	hash := sha256.Sum256(raw)
	if !bytes.Equal(hash[:], root.PdfSha256) {
		t.Fatal("genuine imported source mismatch")
	}
	copy := documentpackage.IncorporationCopyV1()
	f := packageResponseHTTPFixture247{q: q, m: m, recipient: recipient, path: "accept", response: documentpackage.ResponseV1{ManifestSHA256: hex.EncodeToString(m.Capture.CanonicalSHA256[:]), LegalCommitmentSHA256: hex.EncodeToString(m.Capture.CommitmentSHA256[:]), IncorporationVersion: copy.Version, IncorporationSHA256: copy.SHA256, Consent: true}}
	if signed {
		f.path = "sign"
	}
	parties, err := q.f.q.ListRecipientsByDocument(q.f.ctx, root.ID)
	if err != nil || len(parties) != 2 {
		t.Fatal("actual party inventory", err)
	}
	original := ""
	fresh := ""
	for i, party := range parties {
		f.recipient = party.ID
		f.token = signerPackageToken242(t, q, party.ID)
		if original == "" {
			original = f.token
		}
		rc := q.lookupV1(t, f.token)
		notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(f.token, ""), rc)
		if err != nil {
			t.Fatal(err)
		}
		f.notice = notice.NoticeDigest
		if err = rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
		response := f.post247(t, &f.response)
		if response.Code != 200 {
			t.Fatal("genuine package response failed", i, response.Code, response.Body.String())
		}
		var result signerSignResponse
		if json.Unmarshal(response.Body.Bytes(), &result) != nil {
			t.Fatal("invalid response result")
		}
		if i == 0 && result.Completed {
			t.Fatal("first party completed before second")
		}
		if i == 1 {
			if !result.Completed || result.Status != "completed" {
				t.Fatal("real final/report publication did not complete", response.Body.String())
			}
			fresh = strings.TrimSuffix(strings.TrimPrefix(result.FinalPDFURL, "/sign/"), "/final-pdf")
			if len(fresh) != 43 || result.AuditCertURL != "/sign/"+fresh+"/audit-cert" || result.PackagePortalURL != "/completed/"+fresh {
				t.Fatal("completion links differ from fresh persisted capability")
			}
		}
	}
	q.assertObserversOnlyV1(t)
	f.token = original
	return completedPackageFixture248{active: f, peer: peer, token: fresh, etag: signerPackageMemberETag246(m.Capture.CanonicalSHA256, m.Capture.CommitmentSHA256), raw: raw}
}
func (f completedPackageFixture248) get248(ctx context.Context, token, path, tag string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, f.active.q.f.s.PublicURL+"/sign/"+token+path, nil).WithContext(ctx)
	if tag != "" {
		r.Header.Set("If-Match", tag)
	}
	w := httptest.NewRecorder()
	f.active.q.f.s.Routes().ServeHTTP(w, r)
	return w
}
func TestCompletedSignerPackageOriginalAndAuthorityV1E2E(t *testing.T) {
	for _, signed := range []bool{false, true} {
		name := "accepted"
		if signed {
			name = "signed"
		}
		t.Run(name, func(t *testing.T) {
			f := newCompletedPackageFixture248(t, signed)
			q := f.active.q
			for _, request := range []struct{ token, path string }{{f.active.token, "/completed-package"}, {f.token, "/package"}, {f.token, "/package/members/0/pdf"}} {
				w := f.get248(q.f.ctx, request.token, request.path, f.etag)
				if w.Code == 200 {
					t.Fatal("active/terminal credential boundary opened", request.path)
				}
			}
			metadata := f.get248(q.f.ctx, f.token, "/completed-package", "")
			var body struct {
				Package *pdfadmission.SignerPackagePresentationV1 `json:"package"`
			}
			if metadata.Code != 200 || json.Unmarshal(metadata.Body.Bytes(), &body) != nil || body.Package == nil || body.Package.ManifestSHA256 != f.active.response.ManifestSHA256 || body.Package.Main.PDFSHA256 != hex.EncodeToString(sha256sum248(f.raw)) || metadata.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("terminal frozen package descriptor unavailable", metadata.Code)
			}
			var emails int
			if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*) FROM email_deliveries WHERE strpos(html_body,$1)>0 AND strpos(text_body,$1)>0", "/completed/"+f.token).Scan(&emails); err != nil || emails != 1 {
				t.Fatal("committed completion email omitted or duplicated the exact archive link", err)
			}
			before := f.active.state247(t)
			for _, c := range []struct {
				name, position, tag string
				status              int
			}{{"missing precondition", "0", "", 428}, {"stale pair", "0", `"` + strings.Repeat("a", 64) + "." + strings.Repeat("b", 64) + `"`, 412}, {"missing annex", "1", f.etag, 404}} {
				t.Run(c.name, func(t *testing.T) {
					w := f.get248(q.f.ctx, f.token, "/completed-package/members/"+c.position+"/pdf", c.tag)
					if w.Code != c.status || bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF")) {
						t.Fatal("terminal refusal leaked original bytes", w.Code)
					}
				})
			}
			pdf := f.get248(q.f.ctx, f.token, "/completed-package/members/0/pdf", f.etag)
			if pdf.Code != 200 || !bytes.Equal(pdf.Body.Bytes(), f.raw) || pdf.Header().Get("X-Hash-PDF-SHA256") != hex.EncodeToString(sha256sum248(f.raw)) || pdf.Header().Get("ETag") != f.etag || pdf.Header().Get("X-Hash-Notice-Digest") != "" || pdf.Header().Get("X-Hash-HTML-Source-Commitment") != "" {
				t.Fatal("terminal route did not return exact archived original", pdf.Code)
			}
			if f.active.state247(t) != before {
				t.Fatal("read-only archive changed response effects")
			}
			q.assertObserversOnlyV1(t)
		})
	}
}
func sha256sum248(raw []byte) []byte { s := sha256.Sum256(raw); return s[:] }
func TestCompletedSignerPackageOriginalExpiryDuringGETV1E2E(t *testing.T) {
	f := newCompletedPackageFixture248(t, false)
	q := f.active.q
	if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1", f.active.recipient); err != nil {
		t.Fatal(err)
	}
	f.peer.main.mu.Lock()
	f.peer.main.blockGET = true
	f.peer.main.mu.Unlock()
	done := make(chan struct{})
	var response *httptest.ResponseRecorder
	go func() {
		defer close(done)
		response = f.get248(q.f.ctx, f.token, "/completed-package/members/0/pdf", f.etag)
	}()
	select {
	case <-f.peer.main.entered:
	case <-done:
		t.Fatal("GET was not held", response.Code)
	case <-q.f.ctx.Done():
		t.Fatal(q.f.ctx.Err())
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("original expiry failed to cancel actual GET")
	}
	select {
	case <-f.peer.main.getDone:
	case <-time.After(5 * time.Second):
		t.Fatal("provider GET did not retire")
	}
	if response.Code == 200 || bytes.HasPrefix(response.Body.Bytes(), []byte("%PDF")) {
		t.Fatal("expired original credential delivered PDF")
	}
	q.assertObserversOnlyV1(t)
}
