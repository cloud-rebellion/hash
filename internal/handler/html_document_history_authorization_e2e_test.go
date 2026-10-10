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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
)

// Hold a real storage-client GET after middleware admission. The synthetic S3
// peer still supplies the exact stored version; no provider recovery or real
// Chromium layout acceptance is implied by these protocol tests.
type htmlHistoryObjectReadE2E struct {
	base        *htmlCreationStorageE2E
	key         string
	version     string
	entered     chan string
	release     chan struct{}
	releaseOnce sync.Once
	mu          sync.Mutex
	reads       []string
	listCalls   int
	failPinned  bool
}

func (p *htmlHistoryObjectReadE2E) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Query().Has("versions") {
		p.mu.Lock()
		p.listCalls++
		p.mu.Unlock()
	}
	if r.Method == http.MethodGet && r.URL.Path == "/hash-import-fixture/"+p.key {
		version := r.URL.Query().Get("versionId")
		p.mu.Lock()
		p.reads = append(p.reads, version)
		p.mu.Unlock()
		if p.entered != nil {
			select {
			case p.entered <- version:
			default:
			}
		}
		if p.release != nil {
			select {
			case <-p.release:
			case <-r.Context().Done():
				return
			}
		}
		// The latest object remains readable in the base peer. Refusing only
		// the committed version detects an unsafe latest/list fallback.
		if p.failPinned && version == p.version {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchVersion</Code><Message>synthetic pinned version unavailable</Message></Error>`))
			return
		}
	}
	p.base.ServeHTTP(w, r)
}

func (p *htmlHistoryObjectReadE2E) unblock() {
	if p.release != nil {
		p.releaseOnce.Do(func() { close(p.release) })
	}
}

func attachHTMLHistoryObjectReadE2E(t *testing.T, f lifecycleAuthorizationFixture, base *htmlCreationStorageE2E, row *generated.HtmlDocumentMaterialization, block, fail bool) *htmlHistoryObjectReadE2E {
	t.Helper()
	peer := &htmlHistoryObjectReadE2E{base: base, key: row.PdfKey, version: row.PdfVersionID, failPinned: fail}
	if block {
		peer.entered, peer.release = make(chan string, 1), make(chan struct{})
	}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	t.Cleanup(peer.unblock)
	client, err := storage.New(f.ctx, storage.Config{
		Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture",
		AccessKey: "synthetic-html-history-access", SecretKey: "synthetic-html-history-secret", BucketLookup: "path",
		AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.s.Storage = client
	return peer
}

// Register cleanup after the peer/pools so cancellation and draining always
// complete before their cleanup, including a timeout after normal release.
type htmlHistoryReadTaskE2E struct {
	cancel   context.CancelFunc
	result   chan *httptest.ResponseRecorder
	received bool
}

func beginHTMLHistoryReadE2E(t *testing.T, f lifecycleAuthorizationFixture, peer *htmlHistoryObjectReadE2E, path, cookie string) *htmlHistoryReadTaskE2E {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	task := &htmlHistoryReadTaskE2E{cancel: cancel, result: make(chan *httptest.ResponseRecorder, 1)}
	t.Cleanup(func() {
		cancel()
		peer.unblock()
		if !task.received {
			select {
			case <-task.result:
				task.received = true
			case <-time.After(4 * time.Second):
				t.Error("historical PDF request did not drain before fixture cleanup")
			}
		}
	})
	go func() {
		r := httptest.NewRequest(http.MethodGet, f.s.PublicURL+path, nil).WithContext(ctx)
		r.Header.Set("Origin", f.s.PublicURL)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		f.s.Routes().ServeHTTP(w, r)
		task.result <- w
	}()
	select {
	case version := <-peer.entered:
		if version != peer.version {
			t.Fatal("historical PDF dispatch did not use its committed VersionId")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("historical PDF request did not reach storage wait")
	}
	return task
}

func (task *htmlHistoryReadTaskE2E) receive(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case w := <-task.result:
		task.received = true
		return w
	case <-time.After(4 * time.Second):
		t.Fatal("historical PDF request did not complete after release")
		return nil
	}
}

func getHTMLHistoryRowE2E(t *testing.T, f lifecycleAuthorizationFixture, sequence int32) *generated.HtmlDocumentMaterialization {
	t.Helper()
	row, err := f.q.GetHTMLDocumentMaterialization(f.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: f.doc.ID, OrgID: f.org, Sequence: sequence})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func assertHTMLHistoryExactReadE2E(t *testing.T, peer *htmlHistoryObjectReadE2E) {
	t.Helper()
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if len(peer.reads) != 1 || peer.reads[0] != peer.version || peer.listCalls != 0 {
		t.Fatal("historical PDF read lost exact version or attempted latest/list fallback")
	}
}

func TestHTMLHistoricalPDFRechecksOriginalAuthorityAndCurrentSourceAfterStorageWaitE2E(t *testing.T) {
	for _, change := range []string{"expiry", "logout", "membership-revoked", "metadata-changed", "new-materialization", "document-deleted"} {
		t.Run(change, func(t *testing.T) {
			f, _, base, doc, cookie := setupHTMLRevisionE2E(t)
			row := getHTMLHistoryRowE2E(t, f, 1)
			peer := attachHTMLHistoryObjectReadE2E(t, f, base, row, true, false)
			if change == "expiry" {
				cookie = dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
			}
			path := "/api/v1/documents/" + doc.ID.String() + "/html/revisions/1/pdf"
			task := beginHTMLHistoryReadE2E(t, f, peer, path, cookie)
			want := http.StatusForbidden
			switch change {
			case "expiry":
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				want = http.StatusUnauthorized
			case "logout":
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET session_generation=session_generation+1 WHERE id=$1 AND org_id=$2`, f.user.ID, f.org); err != nil { //nolint:rawsql -- fixture-owned live logout
					t.Fatal(err)
				}
			case "membership-revoked":
				other, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Other historical-read fixture tenant", Plan: "starter"})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET org_id=$2 WHERE id=$1 AND org_id=$3`, f.user.ID, other.ID, f.org); err != nil { //nolint:rawsql -- fixture-owned membership revocation
					t.Fatal(err)
				}
			case "metadata-changed":
				body, err := json.Marshal(updateDocumentInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), Name: "Changed during historical PDF read"})
				if err != nil {
					t.Fatal(err)
				}
				w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/documents/"+doc.ID.String(), string(body), cookie)
				if w.Code != http.StatusOK {
					t.Fatalf("concurrent document metadata update=%d", w.Code)
				}
				want = http.StatusConflict
			case "new-materialization":
				w := submitRevisionE2E(t, f, revisionInputE2E(t, doc), cookie)
				if w.Code != http.StatusCreated {
					t.Fatalf("concurrent committed materialization=%d", w.Code)
				}
				want = http.StatusConflict
			case "document-deleted":
				w := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/documents/"+doc.ID.String(), "", cookie)
				if w.Code != http.StatusNoContent {
					t.Fatalf("concurrent document deletion=%d", w.Code)
				}
				want = http.StatusNotFound
			}
			before := revisionStateE2E(t, f)
			base.mu.Lock()
			puts, deletes, objects := base.puts, base.deletes, len(base.objects)
			base.mu.Unlock()
			peer.unblock()
			w := task.receive(t)
			if w.Code != want || w.Header().Get("Content-Type") == "application/pdf" || bytes.Contains(w.Body.Bytes(), []byte("%PDF-")) || w.Header().Get("X-Hash-HTML-Source-Commitment") != "" || w.Header().Get("X-Hash-PDF-SHA256") != "" {
				t.Fatalf("late historical PDF refusal=%d want%d without private PDF/proof headers", w.Code, want)
			}
			if !bytes.Equal(before, revisionStateE2E(t, f)) {
				t.Fatal("historical PDF refusal mutated document/history/evidence")
			}
			assertImportStorageE2E(t, base.importStoragePeer, puts, deletes, objects)
			assertHTMLHistoryExactReadE2E(t, peer)
		})
	}
}

func TestHTMLHistoricalPDFMissingPinnedVersionNeverFallsBackE2E(t *testing.T) {
	f, _, base, doc, cookie := setupHTMLRevisionE2E(t)
	row := getHTMLHistoryRowE2E(t, f, 1)
	peer := attachHTMLHistoryObjectReadE2E(t, f, base, row, false, true)
	before := revisionStateE2E(t, f)
	w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+doc.ID.String()+"/html/revisions/1/pdf", "", cookie)
	if w.Code != http.StatusInternalServerError || bytes.Contains(w.Body.Bytes(), []byte("%PDF-")) || w.Header().Get("X-Hash-PDF-SHA256") != "" {
		t.Fatalf("missing exact historical version=%d without PDF bytes/proof", w.Code)
	}
	if !bytes.Equal(before, revisionStateE2E(t, f)) {
		t.Fatal("missing version changed immutable/current state")
	}
	assertHTMLHistoryExactReadE2E(t, peer)
	assertImportStorageE2E(t, base.importStoragePeer, 1, 0, 1)
}

func TestHTMLHistoricalDescriptorsAndViewerPDFRemainReadOnlyE2E(t *testing.T) {
	f, _, base, doc, cookie := setupHTMLRevisionE2E(t)
	if w := submitRevisionE2E(t, f, revisionInputE2E(t, doc), cookie); w.Code != http.StatusCreated {
		t.Fatalf("prepare historical source=%d", w.Code)
	}
	row := getHTMLHistoryRowE2E(t, f, 1)
	peer := attachHTMLHistoryObjectReadE2E(t, f, base, row, true, false)
	path := "/api/v1/documents/" + doc.ID.String()
	task := beginHTMLHistoryReadE2E(t, f, peer, path+"/html/revisions/1/pdf", cookie)
	// A read-authorized downgrade removes writing but must not invalidate a
	// permitted private read or borrow the historical row's review authority.
	if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	before := revisionStateE2E(t, f)
	peer.unblock()
	w := task.receive(t)
	digest := sha256.Sum256(w.Body.Bytes())
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/pdf" || w.Header().Get("X-Hash-Document-Id") != doc.ID.String() ||
		w.Header().Get("X-Hash-Materialization-Revision") != "1" || w.Header().Get("X-Hash-HTML-Source-Commitment") != hex.EncodeToString(row.SourceCommitment) ||
		w.Header().Get("X-Hash-PDF-SHA256") != hex.EncodeToString(row.PdfSha256) || !bytes.Equal(digest[:], row.PdfSha256) || w.Header().Get("X-Hash-PDF-Pages") != "1" {
		t.Fatalf("viewer historical PDF pins/bytes=%d", w.Code)
	}
	assertHTMLHistoryExactReadE2E(t, peer)
	for _, sequence := range []int{1, 2} {
		w := submitSessionOperationE2E(f.s, http.MethodGet, fmt.Sprintf("%s/html/revisions/%d/source", path, sequence), "", cookie)
		var source htmlDocumentSourceResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &source) != nil || source.CanEdit || source.DocumentID != doc.ID || source.OrgID != f.org || source.MaterializationRevision != int32(sequence) ||
			len(source.Values) != 1 || source.Values[0].Name != "customer" || len(source.Sections) != 1 || source.Sections[0].DefaultText != "Approved scope" ||
			bytes.Contains(w.Body.Bytes(), []byte("html_master_json")) || bytes.Contains(w.Body.Bytes(), []byte("data-hash-value")) {
			t.Fatalf("viewer historical source descriptor %d=%d", sequence, w.Code)
		}
		if sequence == 1 && (source.Values[0].Text != "Original AB" || source.Sections[0].Text != "Approved scope" || len(source.ChangedSections) != 0 || source.HTMLSourceCommitment != hex.EncodeToString(row.SourceCommitment)) {
			t.Fatal("old declared source changed with the current materialization")
		}
		if sequence == 2 && (source.Values[0].Text != "Negotiated customer AB" || source.Sections[0].Text != "Negotiated <plain> wording & commitment" || len(source.ChangedSections) != 1 || source.ChangedSections[0] != "scope" || source.HTMLSourceCommitment == hex.EncodeToString(row.SourceCommitment)) {
			t.Fatal("new source lost plain text, changed-section or distinct commitment")
		}
	}
	w = submitSessionOperationE2E(f.s, http.MethodGet, path+"/html/source", "", cookie)
	var current htmlDocumentSourceResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &current) != nil || current.CanEdit || current.MaterializationRevision != 2 || len(current.Values) != 1 || current.Values[0].Text != "Negotiated customer AB" {
		t.Fatal("current descriptor retained edit authority or historical values after downgrade")
	}
	if !bytes.Equal(before, revisionStateE2E(t, f)) {
		t.Fatal("historical/current viewer reads mutated evidence")
	}
	assertImportStorageE2E(t, base.importStoragePeer, 2, 0, 2)
}
