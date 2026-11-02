//go:build e2e

package handler

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
)

func templatePDFPathE2E(template *generated.Template) string {
	return fmt.Sprintf("/api/v1/templates/%s/pdf?version=%d&sha256=%s", template.ID, template.Version, hex.EncodeToString(template.PdfSha256))
}

// Reuse the established synchronous versioned S3 read peer. The template itself
// is produced by actual PDF upload/sanitization/native source measurement.
func attachTemplatePDFReadE2E(t *testing.T, f lifecycleAuthorizationFixture, base *htmlCreationStorageE2E, template *generated.Template, block, fail bool) *htmlHistoryObjectReadE2E {
	t.Helper()
	peer := &htmlHistoryObjectReadE2E{base: base, key: template.PdfStorageKey.String, version: template.PdfStorageVersionID.String, failPinned: fail}
	if block {
		peer.entered, peer.release = make(chan string, 1), make(chan struct{})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hash-import-fixture/" || r.URL.Path == "/hash-import-fixture" {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == http.MethodGet && r.URL.Query().Has("versioning") {
				_, _ = w.Write([]byte("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"))
				return
			}
			if r.Method == http.MethodGet && r.URL.Query().Has("object-lock") {
				_, _ = w.Write([]byte("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"))
				return
			}
		}
		peer.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(peer.unblock)
	client, err := storage.New(f.ctx, storage.Config{
		Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture",
		AccessKey: "synthetic-template-read-access", SecretKey: "synthetic-template-read-secret", BucketLookup: "path",
		AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true, RequireObjectLock: true, RequireExistingBucket: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.s.Storage = client
	return peer
}

func assertTemplatePDFReadNoWritesE2E(t *testing.T, f lifecycleAuthorizationFixture, base *htmlCreationStorageE2E, template *generated.Template, before string) {
	t.Helper()
	if got := ownedPDFTemplateStateV1(t, &ownedPublicReadFixtureV1{f: f}, template.ID); got != before {
		t.Fatal("PDF read changed template/source-cache/audit state")
	}
	assertImportStorageE2E(t, base.importStoragePeer, 1, 0, 1)
}

func TestTemplatePDFStaffReadBindsTenantVersionAndVerifiedBytesE2E(t *testing.T) {
	f, base, template, _, cookie := setupPDFTemplateSanitizationE2E(t)
	peer := attachTemplatePDFReadE2E(t, f, base, template, false, false)
	before := ownedPDFTemplateStateV1(t, &ownedPublicReadFixtureV1{f: f}, template.ID)
	w := submitSessionOperationE2E(f.s, http.MethodGet, templatePDFPathE2E(template), "", cookie)
	base.mu.Lock()
	expected := bytes.Clone(base.objects[template.PdfStorageKey.String])
	base.mu.Unlock()
	digest := hex.EncodeToString(template.PdfSha256)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), expected) || w.Header().Get("Content-Type") != "application/pdf" ||
		w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" ||
		w.Header().Get("X-Hash-Template-Id") != template.ID.String() || w.Header().Get("X-Hash-Template-Version") != fmt.Sprint(template.Version) ||
		w.Header().Get("X-Hash-PDF-SHA256") != digest || w.Header().Get("ETag") != `"`+digest+`"` {
		t.Fatalf("exact native template PDF=%d; source bytes or response commitment changed", w.Code)
	}
	peer.mu.Lock()
	if len(peer.reads) != 1 || peer.reads[0] != template.PdfStorageVersionID.String || peer.listCalls != 0 {
		t.Error("template PDF read selected latest/list instead of the persisted immutable version")
	}
	peer.mu.Unlock()
	assertTemplatePDFReadNoWritesE2E(t, f, base, template, before)
	for _, suffix := range []string{
		fmt.Sprintf("?version=%d&sha256=%s", template.Version+1, digest),
		fmt.Sprintf("?version=%d&sha256=%s", template.Version, strings.Repeat("0", 64)),
	} {
		w = submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/templates/"+template.ID.String()+"/pdf"+suffix, "", cookie)
		if w.Code != http.StatusPreconditionFailed || strings.Contains(w.Body.String(), "%PDF") {
			t.Fatalf("stale expected commitment=%d", w.Code)
		}
	}
	other, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Synthetic template PDF foreign tenant", Plan: "starter"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: other.ID, Email: "foreign-template@example.invalid", Name: "Foreign reader", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	foreignCookie := dsrSessionCookieE2E(t, f.s, foreign.ID, foreign.SessionGeneration, time.Hour)
	w = submitSessionOperationE2E(f.s, http.MethodGet, templatePDFPathE2E(template), "", foreignCookie)
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "%PDF") {
		t.Fatalf("existing same-database foreign template leaked=%d", w.Code)
	}
	viewer, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: "viewer-template@example.invalid", Name: "Template viewer", Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	w = submitSessionOperationE2E(f.s, http.MethodGet, templatePDFPathE2E(template), "", dsrSessionCookieE2E(t, f.s, viewer.ID, viewer.SessionGeneration, time.Hour))
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), expected) {
		t.Fatalf("native viewer read role changed=%d", w.Code)
	}
	peer.mu.Lock()
	reads, lists := len(peer.reads), peer.listCalls
	peer.mu.Unlock()
	if reads != 2 || lists != 0 {
		t.Fatal("stale or foreign requests performed provider IO")
	}
	assertTemplatePDFReadNoWritesE2E(t, f, base, template, before)
}

func TestTemplatePDFRechecksNativeCredentialAndSourceAfterStorageWaitE2E(t *testing.T) {
	for _, change := range []string{"logout", "expiry", "native-template-edit", "source-cache-corruption", "pinned-version-unavailable", "provider-byte-corruption"} {
		t.Run(change, func(t *testing.T) {
			f, base, template, _, cookie := setupPDFTemplateSanitizationE2E(t)
			blocked := change != "pinned-version-unavailable" && change != "provider-byte-corruption"
			peer := attachTemplatePDFReadE2E(t, f, base, template, blocked, change == "pinned-version-unavailable")
			if change == "provider-byte-corruption" {
				base.mu.Lock()
				base.objects[template.PdfStorageKey.String] = []byte("%PDF-malicious-provider-byte-drift")
				base.mu.Unlock()
			}
			if change == "expiry" {
				cookie = dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
			}
			want := http.StatusServiceUnavailable
			var task *htmlHistoryReadTaskE2E
			if blocked {
				task = beginHTMLHistoryReadE2E(t, f, peer, templatePDFPathE2E(template), cookie)
			}
			switch change {
			case "logout":
				count, err := f.q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration})
				if err != nil || count != 1 {
					t.Fatal("actual session revocation failed", err)
				}
				want = http.StatusForbidden
			case "expiry":
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				want = http.StatusUnauthorized
			case "native-template-edit":
				w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/templates/"+template.ID.String(), "{}", cookie)
				if w.Code != http.StatusOK {
					t.Fatalf("actual source version update during provider wait=%d %s", w.Code, w.Body.String())
				}
				want = http.StatusPreconditionFailed
			case "source-cache-corruption":
				if tag, err := f.pool.Exec(f.ctx, "DELETE FROM pdf_template_source_sizes_v1 WHERE template_id=$1 AND org_id=$2", template.ID, f.org); err != nil || tag.RowsAffected() != 1 {
					t.Fatal("explicit source-cache corruption failed", err)
				} //nolint:rawsql -- deliberate negative cache corruption only; never fabricated measurement
			}
			before := ownedPDFTemplateStateV1(t, &ownedPublicReadFixtureV1{f: f}, template.ID)
			var w *httptest.ResponseRecorder
			if task != nil {
				peer.unblock()
				w = task.receive(t)
			} else {
				w = submitSessionOperationE2E(f.s, http.MethodGet, templatePDFPathE2E(template), "", cookie)
			}
			if w.Code != want || strings.Contains(w.Body.String(), "%PDF") || w.Header().Get("Content-Type") == "application/pdf" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("post-storage %s=%d want%d; PDF must remain unpublished", change, w.Code, want)
			}
			assertTemplatePDFReadNoWritesE2E(t, f, base, template, before)
			peer.mu.Lock()
			defer peer.mu.Unlock()
			if peer.listCalls != 0 || len(peer.reads) != 1 || peer.reads[0] != template.PdfStorageVersionID.String {
				t.Fatal("refusal changed immutable provider read or fell back to version inventory")
			}
		})
	}
}
