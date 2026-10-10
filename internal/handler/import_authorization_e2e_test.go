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
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/storage"
)

// A disposable S3 protocol peer exercises the real version/digest client and
// exact-version compensation. It is not production Object Lock evidence.
type importStoragePeer struct {
	mu            sync.Mutex
	objects       map[string][]byte
	puts, deletes int
}

func (p *importStoragePeer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	const prefix = "/hash-import-fixture/"
	if r.URL.Path == strings.TrimSuffix(prefix, "/") || r.URL.Path == prefix {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet && r.URL.Query().Has("versions") {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>hash-import-fixture</Name><IsTruncated>false</IsTruncated>`)
			for key, body := range p.objects {
				if !strings.HasPrefix(key, r.URL.Query().Get("prefix")) {
					continue
				}
				fmt.Fprint(w, `<Version><Key>`)
				_ = xml.EscapeText(w, []byte(key))
				fmt.Fprintf(w, `</Key><VersionId>import-version-1</VersionId><IsLatest>true</IsLatest><LastModified>%s</LastModified><ETag>fixture</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Version>`, time.Now().UTC().Format(time.RFC3339), len(body))
			}
			fmt.Fprint(w, `</ListVersionsResult>`)
			return
		}
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "unexpected fixture path", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPut {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			body, err = io.ReadAll(httputil.NewChunkedReader(bytes.NewReader(body)))
			if err != nil {
				http.Error(w, "invalid fixture chunked upload", http.StatusBadRequest)
				return
			}
		}
		p.objects[key] = body
		p.puts++
		w.Header().Set("X-Amz-Version-Id", "import-version-1")
		w.Header().Set("ETag", `"fixture"`)
		w.WriteHeader(http.StatusOK)
		return
	}
	body, exists := p.objects[key]
	if !exists || (r.URL.Query().Get("versionId") != "" && r.URL.Query().Get("versionId") != "import-version-1") {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<Error><Code>NoSuchKey</Code><Message>fixture object absent</Message></Error>`)
		return
	}
	if r.Method == http.MethodDelete {
		if r.URL.Query().Get("versionId") != "import-version-1" {
			http.Error(w, "exact version required", http.StatusBadRequest)
			return
		}
		delete(p.objects, key)
		p.deletes++
		w.WriteHeader(http.StatusNoContent)
		return
	}
	digest := sha256.Sum256(body)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("ETag", `"`+hex.EncodeToString(digest[:])+`"`)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.Header().Set("X-Amz-Version-Id", "import-version-1")
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func setupImportAuthorizationE2E(t *testing.T) (lifecycleAuthorizationFixture, *importStoragePeer) {
	t.Helper()
	f := setupLifecycleAuthorizationE2E(t, "sender", false, false)
	f.enableMCP()
	peer := &importStoragePeer{objects: make(map[string][]byte)}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	var err error
	f.s.Storage, err = storage.New(f.ctx, storage.Config{
		Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture",
		AccessKey: "synthetic-import-access", SecretKey: "synthetic-import-secret", BucketLookup: "path",
		AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage})
	return f, peer
}

func submitPDFImportE2E(f lifecycleAuthorizationFixture, ctx context.Context, cookie string) *httptest.ResponseRecorder {
	return submitPDFIntakeE2E(f, ctx, cookie, "/api/v1/documents/import")
}

func submitPDFIntakeE2E(f lifecycleAuthorizationFixture, ctx context.Context, cookie, endpoint string) *httptest.ResponseRecorder {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("name", "Authorized imported proposal")
	part, _ := writer.CreateFormFile("pdf", "proposal.pdf")
	_, _ = part.Write(fieldBrowserPDF("Synthetic authorized import"))
	_ = writer.Close()
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+endpoint, &body).WithContext(ctx)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("Origin", f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func TestPDFTemplateAuditWaitExpiryCompensatesExactVersionE2E(t *testing.T) {
	f, peer := setupImportAuthorizationE2E(t)
	before := f.snapshot(t)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- submitPDFIntakeE2E(f, f.ctx, cookie, "/api/v1/templates") }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "pg_advisory_xact_lock", "advisory")
	awaitSessionCookieExpiryE2E(t, f.s, cookie)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired template import=%d %s", w.Code, w.Body.String())
	}
	templates, err := f.q.CountTemplates(f.ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if templates != 0 || f.snapshot(t) != before {
		t.Fatal("late refusal left committed template, audit or outbox")
	}
	assertImportStorageE2E(t, peer, 1, 1, 0)
}

func TestPDFTemplateRejectsDemotedAuthorAfterStorageWaitE2E(t *testing.T) {
	f, peer := setupImportAuthorizationE2E(t)
	before := f.snapshot(t)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if _, err := f.q.WithTx(blocked).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- submitPDFIntakeE2E(f, f.ctx, cookie, "/api/v1/templates") }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetUserForShare", "transactionid")
	if _, err := f.q.WithTx(blocked).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusForbidden {
		t.Fatalf("demoted template import=%d %s", w.Code, w.Body.String())
	}
	templates, err := f.q.CountTemplates(f.ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if templates != 0 || f.snapshot(t) != before {
		t.Fatal("refused template import changed template, audit or outbox")
	}
	assertImportStorageE2E(t, peer, 1, 1, 0)
}

func assertImportStorageE2E(t *testing.T, peer *importStoragePeer, puts, deletes, objects int) {
	t.Helper()
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.puts != puts || peer.deletes != deletes || len(peer.objects) != objects {
		t.Fatalf("storage puts/deletes/objects=%d/%d/%d want%d/%d/%d", peer.puts, peer.deletes, len(peer.objects), puts, deletes, objects)
	}
}

func TestPDFImportRechecksOriginalSessionAfterMemberWaitE2E(t *testing.T) {
	for _, change := range []string{"demotion", "logout", "expiry"} {
		t.Run(change, func(t *testing.T) {
			f, peer := setupImportAuthorizationE2E(t)
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err := f.q.WithTx(blocked).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
				t.Fatal(err)
			}
			ttl := time.Hour
			if change == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitPDFImportE2E(f, f.ctx, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetUserForShare", "transactionid")
			want := http.StatusForbidden
			switch change {
			case "demotion":
				_, err = f.q.WithTx(blocked).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
			case "logout":
				_, err = f.q.WithTx(blocked).RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration})
			case "expiry":
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				want = http.StatusUnauthorized
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if w := receiveSessionOperationE2E(t, result); w.Code != want {
				t.Fatalf("import=%d want%d %s", w.Code, want, w.Body.String())
			}
			if f.snapshot(t) != before {
				t.Fatal("refused import changed documents, audit, evidence or outbox")
			}
			assertImportStorageE2E(t, peer, 0, 0, 0)
		})
	}
}

func TestPDFImportAuditWaitExpiryCompensatesExactVersionE2E(t *testing.T) {
	f, peer := setupImportAuthorizationE2E(t)
	before := f.snapshot(t)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- submitPDFImportE2E(f, f.ctx, cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "pg_advisory_xact_lock", "advisory")
	awaitSessionCookieExpiryE2E(t, f.s, cookie)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired import=%d %s", w.Code, w.Body.String())
	}
	if f.snapshot(t) != before {
		t.Fatal("late refusal left committed document, audit or outbox")
	}
	assertImportStorageE2E(t, peer, 1, 1, 0)
}

func TestPDFImportAuthorizedRESTAndMCPE2E(t *testing.T) {
	for _, via := range []string{"REST", "MCP"} {
		t.Run(via, func(t *testing.T) {
			f, peer := setupImportAuthorizationE2E(t)
			if via == "REST" {
				w := submitPDFImportE2E(f, f.ctx, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
				if w.Code != http.StatusCreated {
					t.Fatalf("import=%d %s", w.Code, w.Body.String())
				}
			} else {
				key, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
				w := submitRecipientMCPE2E(f, "create_pdf_document", key.Plaintext, map[string]any{"name": "Authorized imported proposal", "pdf_base64": base64.StdEncoding.EncodeToString(fieldBrowserPDF("Synthetic authorized import"))})
				assertLifecycleMCPResultE2E(t, w, false)
			}
			var documents, events int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM documents WHERE org_id=$1 AND source_kind='pdf' AND status='draft' AND evidence_version_pins_required AND pdf_storage_version_id='import-version-1'`, f.org).Scan(&documents); err != nil {
				t.Fatal(err)
			}
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind='document.created'`, f.org).Scan(&events); err != nil {
				t.Fatal(err)
			}
			if documents != 1 || events != 1 {
				t.Fatalf("committed documents/events=%d/%d", documents, events)
			}
			assertImportStorageE2E(t, peer, 1, 0, 1)
		})
	}
}

func TestPDFImportMCPRechecksAdmittedKeyAfterMemberWaitE2E(t *testing.T) {
	for _, change := range []string{"key deletion", "scope removal", "demotion"} {
		t.Run(change, func(t *testing.T) {
			f, peer := setupImportAuthorizationE2E(t)
			key, keyID := mintRecipientMCPKeyE2E(t, f, false, 0)
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err := f.q.WithTx(blocked).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- submitRecipientMCPE2E(f, "create_pdf_document", key.Plaintext, map[string]any{"name": "Refused imported proposal", "pdf_base64": base64.StdEncoding.EncodeToString(fieldBrowserPDF("Synthetic authorized import"))})
			}()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetUserForShare", "transactionid")
			switch change {
			case "key deletion":
				_, err = f.pool.Exec(f.ctx, `DELETE FROM api_keys WHERE id=$1 AND org_id=$2`, keyID, f.org)
			case "scope removal":
				_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1 AND org_id=$2`, keyID, f.org)
			case "demotion":
				_, err = f.q.WithTx(blocked).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			w := receiveSessionOperationE2E(t, result)
			assertLifecycleMCPResultE2E(t, w, true)
			if !strings.Contains(w.Body.String(), "permission or credential revoked") {
				t.Fatalf("imprecise refusal: %s", w.Body.String())
			}
			if f.snapshot(t) != before {
				t.Fatal("refused MCP import changed document, audit or outbox")
			}
			assertImportStorageE2E(t, peer, 0, 0, 0)
		})
	}
}

func TestPDFImportMCPAuditWaitExpiryCompensatesExactVersionE2E(t *testing.T) {
	f, peer := setupImportAuthorizationE2E(t)
	key, keyID := mintRecipientMCPKeyE2E(t, f, false, 0)
	expires := time.Now().Add(2 * time.Second)
	if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=$2 WHERE id=$1`, keyID, expires); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- submitRecipientMCPE2E(f, "create_pdf_document", key.Plaintext, map[string]any{"name": "Refused expired import", "pdf_base64": base64.StdEncoding.EncodeToString(fieldBrowserPDF("Synthetic authorized import"))})
	}()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "pg_advisory_xact_lock", "advisory")
	for time.Now().Before(expires) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	w := receiveSessionOperationE2E(t, result)
	assertLifecycleMCPResultE2E(t, w, true)
	if !strings.Contains(w.Body.String(), "credential expired before transaction committed") {
		t.Fatalf("imprecise expiry refusal: %s", w.Body.String())
	}
	if f.snapshot(t) != before {
		t.Fatal("expired MCP import committed document, audit or outbox")
	}
	assertImportStorageE2E(t, peer, 1, 1, 0)
}
