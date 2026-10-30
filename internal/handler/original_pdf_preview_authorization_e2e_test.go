//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
)

// The real storage client fetches the committed version from the existing S3
// protocol peer. Holding the external GET lets the test change live authority
// or the document after middleware admission, without holding a database lock.
// This is not production-provider or renderer acceptance evidence.
type originalPDFPreviewPeerE2E struct {
	*importStoragePeer
	key         string
	entered     chan string
	release     chan struct{}
	releaseOnce sync.Once
	calls       atomic.Int32
	initialPuts int
}

func (p *originalPDFPreviewPeerE2E) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/hash-import-fixture/"+p.key {
		if p.calls.Add(1) == 1 {
			p.entered <- r.URL.Query().Get("versionId")
		}
		select {
		case <-p.release:
		case <-r.Context().Done():
			return
		}
	}
	p.importStoragePeer.ServeHTTP(w, r)
}

func (p *originalPDFPreviewPeerE2E) unblock() {
	p.releaseOnce.Do(func() { close(p.release) })
}

func setupOriginalPDFPreviewE2E(t *testing.T, role string) (lifecycleAuthorizationFixture, *originalPDFPreviewPeerE2E, []byte) {
	t.Helper()
	return setupOriginalPDFPreviewSourceE2E(t, role, false)
}

func setupOriginalPDFPreviewSourceE2E(t *testing.T, role string, native bool) (lifecycleAuthorizationFixture, *originalPDFPreviewPeerE2E, []byte) {
	t.Helper()
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, role)
	body := fieldBrowserPDF("Committed original PDF preview fixture")
	digest := sha256.Sum256(body)
	key := f.org.String() + "/original-pdf-preview-" + uuid.NewString() + ".pdf"
	peer := &originalPDFPreviewPeerE2E{
		importStoragePeer: &importStoragePeer{objects: map[string][]byte{key: bytes.Clone(body)}},
		key:               key,
		entered:           make(chan string, 1),
		release:           make(chan struct{}),
	}
	if native {
		// Only the positive concurrent edit needs a current measured source.
		// Other cases retain explicit historical read-only coverage.
		peer.objects = make(map[string][]byte)
		peer.key = ""
	}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	// Release first even when an assertion aborts before the normal release.
	t.Cleanup(peer.unblock)
	var err error
	f.s.Storage, err = storage.New(f.ctx, storage.Config{
		Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture",
		AccessKey: "synthetic-original-preview-access", SecretKey: "synthetic-original-preview-secret", BucketLookup: "path",
		AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if native {
		metadataPrepareNativePlanE2E(t, f)
		cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
		w := submitPDFImportE2E(f, f.ctx, cookie)
		var uploaded struct {
			Document struct{ ID uuid.UUID } `json:"document"`
		}
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &uploaded) != nil || uploaded.Document.ID == uuid.Nil {
			t.Fatalf("actual original PDF intake=%d %s", w.Code, w.Body.String())
		}
		f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: uploaded.Document.ID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		peer.mu.Lock()
		peer.key = f.doc.PdfStorageKey.String
		body = bytes.Clone(peer.objects[peer.key])
		peer.initialPuts = peer.puts
		peer.mu.Unlock()
		actual := sha256.Sum256(body)
		if len(body) == 0 || !bytes.Equal(actual[:], f.doc.PdfSha256) || f.doc.PdfStorageVersionID.String != "import-version-1" || peer.initialPuts != 1 {
			t.Fatal("native original source lacks its actual exact stored bytes/version")
		}
	} else {
		f.doc, err = f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{
			OrgID: f.org, SenderID: f.user.ID, Name: "Original PDF preview",
			PdfStorageKey: pgtype.Text{String: key, Valid: true}, PdfSha256: digest[:],
			PdfStorageVersionID: pgtype.Text{String: "import-version-1", Valid: true}, EvidenceVersionPinsRequired: true,
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	return f, peer, body
}

func beginOriginalPDFPreviewE2E(t *testing.T, f lifecycleAuthorizationFixture, peer *originalPDFPreviewPeerE2E, cookie string) <-chan *httptest.ResponseRecorder {
	t.Helper()
	result := make(chan *httptest.ResponseRecorder, 1)
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := httptest.NewRequest(http.MethodGet, f.s.PublicURL+"/api/v1/documents/"+f.doc.ID.String()+"/pdf", nil).WithContext(ctx)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		f.s.Routes().ServeHTTP(w, r)
		result <- w
	}()
	t.Cleanup(func() {
		cancel()
		peer.unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("original PDF request did not join before fixture teardown")
		}
	})
	select {
	case version := <-peer.entered:
		if version != "import-version-1" {
			t.Fatalf("original PDF fetch lost its exact persisted version: %q", version)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original PDF preview did not reach the blocking source GET")
	}
	return result
}

func assertOriginalPDFPreviewStorageUnchangedE2E(t *testing.T, peer *originalPDFPreviewPeerE2E, body []byte) {
	t.Helper()
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.calls.Load() != 1 || peer.puts != peer.initialPuts || peer.deletes != 0 || len(peer.objects) != 1 || !bytes.Equal(peer.objects[peer.key], body) {
		t.Fatal("original PDF read changed storage or fetched a different version")
	}
}

func TestOriginalPDFPreviewRechecksAfterObjectWaitE2E(t *testing.T) {
	for _, change := range []string{"expiry", "logout", "membership-revoked", "document-change", "document-delete"} {
		t.Run(change, func(t *testing.T) {
			f, peer, body := setupOriginalPDFPreviewSourceE2E(t, "sender", change == "document-change")
			ttl := time.Hour
			if change == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			result := beginOriginalPDFPreviewE2E(t, f, peer, cookie)
			want := http.StatusForbidden
			var err error
			switch change {
			case "expiry":
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				want = http.StatusUnauthorized
			case "logout":
				_, err = f.pool.Exec(f.ctx, `UPDATE users SET session_generation=session_generation+1 WHERE id=$1`, f.user.ID) //nolint:rawsql -- fixture-owned live session revocation
			case "membership-revoked":
				other, createErr := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Other synthetic preview tenant", Plan: "starter"})
				if createErr != nil {
					t.Fatal(createErr)
				}
				_, err = f.pool.Exec(f.ctx, `UPDATE users SET org_id=$2 WHERE id=$1`, f.user.ID, other.ID) //nolint:rawsql -- remove this fixture member from the admitted tenant
			case "document-change":
				input, marshalErr := json.Marshal(updateDocumentInput{ExpectedUpdatedAt: f.doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), Name: "Changed while PDF fetch waited"})
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/documents/"+f.doc.ID.String(), string(input), cookie)
				if w.Code != http.StatusOK {
					t.Fatalf("concurrent real document update=%d %s", w.Code, w.Body.String())
				}
				want = http.StatusConflict
			case "document-delete":
				w := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/documents/"+f.doc.ID.String(), "", cookie)
				if w.Code != http.StatusNoContent {
					t.Fatalf("concurrent real document deletion=%d %s", w.Code, w.Body.String())
				}
				want = http.StatusNotFound
			}
			if err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t)
			peer.unblock()
			w := receiveSessionOperationE2E(t, result)
			if w.Code != want || w.Header().Get("Content-Type") == "application/pdf" || bytes.Contains(w.Body.Bytes(), []byte("%PDF-")) {
				t.Fatalf("late original PDF preview=%d type=%q body=%s want%d without PDF bytes", w.Code, w.Header().Get("Content-Type"), w.Body.String(), want)
			}
			f.assertUnchanged(t, before)
			assertOriginalPDFPreviewStorageUnchangedE2E(t, peer, body)
		})
	}
}

func TestOriginalPDFPreviewViewerReadsRemainAllowedE2E(t *testing.T) {
	for _, change := range []string{"viewer", "sender-to-viewer"} {
		t.Run(change, func(t *testing.T) {
			role := "viewer"
			if change == "sender-to-viewer" {
				role = "sender"
			}
			f, peer, body := setupOriginalPDFPreviewE2E(t, role)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			result := beginOriginalPDFPreviewE2E(t, f, peer, cookie)
			if change == "sender-to-viewer" {
				if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
					t.Fatal(err)
				}
			}
			before := f.snapshot(t)
			peer.unblock()
			w := receiveSessionOperationE2E(t, result)
			if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/pdf" || !bytes.Equal(w.Body.Bytes(), body) {
				t.Fatalf("permitted viewer original PDF read=%d type=%q", w.Code, w.Header().Get("Content-Type"))
			}
			f.assertUnchanged(t, before)
			assertOriginalPDFPreviewStorageUnchangedE2E(t, peer, body)
		})
	}
}
