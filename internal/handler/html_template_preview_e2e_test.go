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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sign"
)

// These are PostgreSQL/REST protocol tests. The synthetic renderer emits a
// fixed PDF, not a visual rendering of submitted HTML. The source-built Linux
// worker must actually clean and count that PDF. No Chromium layout, provider
// Object Lock, or production credential acceptance is claimed.
func htmlPreviewServerE2E(t *testing.T, f lifecycleAuthorizationFixture, renderer http.Handler) lifecycleAuthorizationFixture {
	t.Helper()
	worker := os.Getenv("HASH_E2E_PDF_WORKER_PATH")
	if worker == "" {
		t.Skip("set HASH_E2E_PDF_WORKER_PATH to the source-built isolated PDF worker")
	}
	if err := sanitize.ConfigurePDFWorker(f.ctx, worker, "production"); err != nil {
		t.Fatal("configure actual preview PDF worker:", err)
	}
	t.Cleanup(func() {
		if err := sanitize.ConfigurePDFWorker(context.Background(), "", "development"); err != nil {
			t.Error("reset preview PDF worker:", err)
		}
	})
	peer := httptest.NewServer(renderer)
	t.Cleanup(peer.Close)
	// Server contains an atomic collaboration gate; borrow explicit immutable
	// configuration/dependency pointers instead of copying that noCopy state.
	server := &Server{Pool: f.s.Pool, HTMLCreationSessions: f.s.HTMLCreationSessions,
		Queries: f.s.Queries, Audit: f.s.Audit, Cookies: f.s.Cookies,
		Billing: f.s.Billing, Storage: f.s.Storage, Versions: f.s.Versions,
		PublicURL: f.s.PublicURL, Environment: f.s.Environment, ProxyAuth: f.s.ProxyAuth, Release: f.s.Release}
	engine := &sign.Engine{}
	if original := f.s.Sign; original != nil {
		// Borrow explicit dependencies; the live Engine keeps its mutex and
		// retained journal lifetime. Preview does not initialize a new journal.
		engine = &sign.Engine{Pool: original.Pool, WorkRuntime: original.WorkRuntime,
			Queries: original.Queries, Storage: original.Storage, Audit: original.Audit,
			Mailer: original.Mailer, Signer: original.Signer, OrgName: original.OrgName,
			BaseURL: original.BaseURL, ActionSecret: original.ActionSecret,
			BrandingCSS: original.BrandingCSS, EnvelopeManifestHTML: original.EnvelopeManifestHTML,
			EnvelopeChildren: original.EnvelopeChildren, Now: original.Now}
	}
	engine.PDF = render.NewGotenberg(peer.URL)
	server.Sign = engine
	f.s = server
	return f
}

func submitHTMLPreviewE2E(t *testing.T, f lifecycleAuthorizationFixture, template *generated.Template, values map[string]string, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	return submitHTMLPreviewContextE2E(t, f.ctx, f, template, values, cookie)
}

func submitHTMLPreviewContextE2E(t *testing.T, ctx context.Context, f lifecycleAuthorizationFixture, template *generated.Template, values map[string]string, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(htmlTemplatePreviewInput{ExpectedVersion: template.Version,
		ExpectedContentSHA256: hex.EncodeToString(template.HtmlContentSha256), Values: htmlStringMap(values)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/v1/templates/"+template.ID.String()+"/html/preview", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.s.PublicURL)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, req)
	return w
}

func previewApprovalInputE2E(t *testing.T, f lifecycleAuthorizationFixture, template *generated.Template, cookie string) htmlTemplateApprovalInput {
	t.Helper()
	// Keep this explicit: raw submitHTMLTemplateE2E still submits a missing proof
	// unchanged. The private renderer avoids changing a blocked creation fixture
	// or its captured source count; the Server and Sign pointers are not mutated.
	preview := htmlPreviewServerE2E(t, f, &htmlCreationRendererE2E{})
	w := submitHTMLPreviewE2E(t, preview, template, nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("preview approval fixture=%d %s", w.Code, w.Body.String())
	}
	in := htmlApprovalInputE2E(template)
	in.PreviewReceipt = w.Header().Get("X-Hash-Preview-Receipt")
	in.ExpectedPreviewPDFSHA256 = w.Header().Get("X-Hash-PDF-SHA256")
	if in.PreviewReceipt == "" || !htmlPreviewSHA256(in.ExpectedPreviewPDFSHA256) {
		t.Fatal("preview did not return its exact PDF proof")
	}
	return in
}

func decodeHTMLPreviewReceiptE2E(t *testing.T, f lifecycleAuthorizationFixture, token string) htmlTemplatePreviewReceipt {
	t.Helper()
	raw, err := f.s.Cookies.VerifyPurpose(htmlTemplatePreviewPurpose, token)
	if err != nil {
		t.Fatal("verify preview proof:", err)
	}
	var proof htmlTemplatePreviewReceipt
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	return proof
}

func signHTMLPreviewReceiptE2E(t *testing.T, f lifecycleAuthorizationFixture, proof htmlTemplatePreviewReceipt) string {
	t.Helper()
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	// A valid outer signature with positive TTL deliberately isolates inner
	// semantic/deadline refusal from an unrelated invalid-MAC refusal.
	token, err := f.s.Cookies.MintPurpose(htmlTemplatePreviewPurpose, raw, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func assertNoHTMLPreviewE2E(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want || strings.HasPrefix(w.Body.String(), "%PDF-") || w.Header().Get("X-Hash-Preview-Receipt") != "" ||
		w.Header().Get("X-Hash-PDF-SHA256") != "" || w.Header().Get("Content-Type") == "application/pdf" {
		t.Fatalf("refused preview=%d want%d disclosed proof=%v response bytes=%d", w.Code, want,
			w.Header().Get("X-Hash-Preview-Receipt") != "", w.Body.Len())
	}
}

func TestHTMLTemplatePreviewApprovalProofAndNoDraftWritesE2E(t *testing.T) {
	renderer := &htmlCreationRendererE2E{}
	f, store := setupHTMLDocumentCreationE2E(t, renderer)
	if os.Getenv("HASH_E2E_PDF_WORKER_PATH") == "" {
		t.Skip("actual source-built isolated PDF worker required")
	}
	template := createHTMLTemplateE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	before, storageBefore := htmlTemplateSnapshotE2E(t, f), store.requests.Load()
	sample := "PRIVATE SAMPLE <em>Company</em> & Partners"
	w := submitHTMLPreviewE2E(t, f, template, map[string]string{"customer": sample}, cookie)
	if w.Code != http.StatusOK || !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF-")) || w.Header().Get("Content-Type") != "application/pdf" ||
		w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Hash-PDF-Pages") != "1" {
		t.Fatalf("sanitized preview=%d type=%q pages=%q response bytes=%d", w.Code,
			w.Header().Get("Content-Type"), w.Header().Get("X-Hash-PDF-Pages"), w.Body.Len())
	}
	digest := sha256.Sum256(w.Body.Bytes())
	pdfSHA := hex.EncodeToString(digest[:])
	proof := decodeHTMLPreviewReceiptE2E(t, f, w.Header().Get("X-Hash-Preview-Receipt"))
	if proof.validate(time.Now()) != nil || proof.OrgID != f.org || proof.ReviewerID != f.user.ID || proof.TemplateID != template.ID ||
		proof.Version != template.Version || proof.TemplateContentSHA256 != hex.EncodeToString(template.HtmlContentSha256) ||
		proof.PDFSHA256 != pdfSHA || proof.PageCount != 1 || proof.SessionSHA256 != htmlPreviewSessionSHA256(cookie) ||
		w.Header().Get("X-Hash-PDF-SHA256") != pdfSHA || w.Header().Get("X-Hash-Template-Id") != template.ID.String() ||
		w.Header().Get("X-Hash-Template-Version") != strconv.Itoa(int(template.Version)) ||
		w.Header().Get("X-Hash-Materialization-SHA256") != proof.MaterializationSHA256 ||
		w.Header().Get("X-Hash-Template-Content-SHA256") != proof.TemplateContentSHA256 ||
		w.Header().Get("X-Hash-Preview-Expires-At") != proof.ExpiresAt.Format(time.RFC3339Nano) {
		t.Fatal("preview headers, original session, saved revision and exact returned PDF do not agree")
	}
	content, err := htmlmaster.CanonicalTemplate(template.HtmlMasterJson, template.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := materializeHTMLTemplatePreview(content, htmlStringMap{"customer": sample})
	if err != nil || materialized.ContentDigest != proof.MaterializationSHA256 {
		t.Fatalf("sample materialization commitment mismatch: %v", err)
	}
	sources := renderer.sources()
	if len(sources) != 1 || !strings.Contains(sources[0], "&lt;em&gt;Company&lt;/em&gt;") || strings.Contains(sources[0], "<em>Company</em>") {
		t.Fatal("preview sample was not rendered as escaped text")
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	if store.requests.Load() != storageBefore {
		t.Fatal("preview touched object storage")
	}
	if bare := submitHTMLTemplateE2E(t, f, "approve", template.ID, htmlApprovalInputE2E(template), cookie); bare.Code != http.StatusBadRequest {
		t.Fatalf("old bare approval=%d %s", bare.Code, bare.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	in := htmlApprovalInputE2E(template)
	in.PreviewReceipt, in.ExpectedPreviewPDFSHA256 = w.Header().Get("X-Hash-Preview-Receipt"), pdfSHA
	if approved := submitHTMLTemplateE2E(t, f, "approve", template.ID, in, cookie); approved.Code != http.StatusOK {
		t.Fatalf("preview-backed owner approval=%d %s", approved.Code, approved.Body.String())
	}
	revision, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: template.Version})
	if err != nil || !revision.ApprovedBy.Valid || uuid.UUID(revision.ApprovedBy.Bytes) != f.user.ID || !revision.ApprovedAt.Valid ||
		!bytes.Equal(revision.VariablesJson, template.VariablesJson) {
		t.Fatalf("approval changed defaults or lost owner identity: %v", err)
	}
	var raw []byte
	if err := f.pool.QueryRow(f.ctx, `SELECT payload_json FROM events WHERE org_id=$1 AND kind='template.updated' AND payload_json->>'approved'='true'`, f.org).Scan(&raw); err != nil { //nolint:rawsql -- exact synthetic approval audit
		t.Fatal(err)
	}
	var audit map[string]any
	if err := json.Unmarshal(raw, &audit); err != nil {
		t.Fatal(err)
	}
	if audit["preview_id"] != proof.PreviewID.String() || audit["preview_pdf_sha256"] != pdfSHA ||
		audit["preview_materialization_sha256"] != proof.MaterializationSHA256 || audit["preview_page_count"] != float64(1) ||
		audit["previewed_by"] != f.user.ID.String() || audit["previewed_at"] != proof.IssuedAt.Format(time.RFC3339Nano) {
		t.Fatalf("approval audit lacks exact preview proof metadata: %s", raw)
	}
	for _, secret := range []string{sample, cookie, in.PreviewReceipt, proof.SessionSHA256} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("approval audit retained sample or credential material")
		}
	}
	for _, forbidden := range []string{"values", "samples", "session_sha256", "preview_receipt"} {
		if _, exists := audit[forbidden]; exists {
			t.Fatalf("approval audit retained forbidden field %s", forbidden)
		}
	}
	if store.requests.Load() != storageBefore {
		t.Fatal("template approval wrote a draft object")
	}
}

func TestHTMLTemplatePreviewReceiptRefusalsE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	valid := previewApprovalInputE2E(t, f, template, cookie)
	proof := decodeHTMLPreviewReceiptE2E(t, f, valid.PreviewReceipt)
	for _, tc := range []struct {
		name string
		edit func(*htmlTemplatePreviewReceipt)
	}{
		{"wrong tenant", func(p *htmlTemplatePreviewReceipt) { p.OrgID = uuid.New() }},
		{"wrong reviewer", func(p *htmlTemplatePreviewReceipt) { p.ReviewerID = uuid.New() }},
		{"wrong template", func(p *htmlTemplatePreviewReceipt) { p.TemplateID = uuid.New() }},
		{"wrong revision", func(p *htmlTemplatePreviewReceipt) { p.Version++ }},
		{"wrong master and defaults commitment", func(p *htmlTemplatePreviewReceipt) { p.TemplateContentSHA256 = strings.Repeat("0", 64) }},
		{"wrong PDF commitment", func(p *htmlTemplatePreviewReceipt) { p.PDFSHA256 = strings.Repeat("0", 64) }},
		{"wrong session", func(p *htmlTemplatePreviewReceipt) { p.SessionSHA256 = strings.Repeat("0", 64) }},
		{"invalid materialization", func(p *htmlTemplatePreviewReceipt) { p.MaterializationSHA256 = "bad" }},
		{"invalid pages", func(p *htmlTemplatePreviewReceipt) { p.PageCount = 0 }},
		{"over-limit pages", func(p *htmlTemplatePreviewReceipt) { p.PageCount = sanitize.MaxPDFPages + 1 }},
		{"expired inner deadline", func(p *htmlTemplatePreviewReceipt) {
			p.IssuedAt = time.Now().Add(-time.Minute)
			p.ExpiresAt = time.Now().Add(-time.Second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := htmlTemplateSnapshotE2E(t, f)
			changed, in := proof, valid
			tc.edit(&changed)
			in.PreviewReceipt = signHTMLPreviewReceiptE2E(t, f, changed)
			if w := submitHTMLTemplateE2E(t, f, "approve", template.ID, in, cookie); w.Code != http.StatusConflict {
				t.Fatalf("signed semantic refusal=%d %s", w.Code, w.Body.String())
			}
			assertHTMLTemplateUnchangedE2E(t, f, before)
		})
	}
	secondOwner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
	for _, tc := range []struct {
		name, cookie string
		input        htmlTemplateApprovalInput
	}{
		{"different original cookie", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, 2*time.Hour), valid},
		{"different owner", dsrSessionCookieE2E(t, f.s, secondOwner, 0, time.Hour), valid},
		{"tampered token", cookie, htmlTemplateApprovalInput{ExpectedVersion: valid.ExpectedVersion, ExpectedContentSHA256: valid.ExpectedContentSHA256, ExpectedPreviewPDFSHA256: valid.ExpectedPreviewPDFSHA256, PreviewReceipt: "p1." + strings.Repeat("A", 60) + "." + strings.Repeat("A", 43)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := htmlTemplateSnapshotE2E(t, f)
			if w := submitHTMLTemplateE2E(t, f, "approve", template.ID, tc.input, tc.cookie); w.Code != http.StatusConflict {
				t.Fatalf("bound proof refusal=%d %s", w.Code, w.Body.String())
			}
			assertHTMLTemplateUnchangedE2E(t, f, before)
		})
	}
}

func TestHTMLTemplatePreviewRechecksAfterRendererWaitE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	for _, change := range []string{"revision", "logout", "demotion", "expiry"} {
		t.Run(change, func(t *testing.T) {
			f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
			_ = seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
			template := createHTMLTemplateE2E(t, f)
			release := make(chan struct{})
			renderer := &htmlCreationRendererE2E{entered: make(chan struct{}, 1), release: release}
			preview := htmlPreviewServerE2E(t, f, renderer)
			ttl := time.Hour
			if change == "expiry" {
				ttl = 2 * time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			requestCtx, cancelRequest := context.WithCancel(f.ctx)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitHTMLPreviewContextE2E(t, requestCtx, preview, template, nil, cookie) }()
			released, received := false, false
			defer func() {
				cancelRequest()
				if !released {
					close(release)
				}
				if !received {
					// Keep the original test failure, cancel its request, and drain
					// even when the renderer was already released but the ordinary
					// response wait timed out. Shared worker/pool cleanup runs later.
					select {
					case <-result:
					case <-time.After(20 * time.Second):
						t.Error("pending preview did not finish before fixture cleanup")
					}
				}
			}()
			select {
			case <-renderer.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("preview did not enter renderer")
			}
			// Each mutation must commit while renderer is still blocked. A retained
			// source/user row lock would prevent this and fail the bounded fixture.
			ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
			defer cancel()
			want := http.StatusConflict
			var err error
			switch change {
			case "revision":
				// The local tenant import slot correctly prevents another REST
				// edit in this process. Use the ordinary CAS+retained-revision
				// queries to model an edit committed by another application
				// instance, without replacing the limiter or weakening guards.
				in := htmlTemplateInputE2E(t, 1, "Changed during preview")
				content, parseErr := htmlmaster.CanonicalTemplate(in.HTMLMasterJSON, in.VariablesJSON)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				digest, _ := hex.DecodeString(content.SHA256)
				tx, beginErr := f.pool.Begin(ctx)
				if beginErr != nil {
					t.Fatal(beginErr)
				}
				defer tx.Rollback(context.Background())
				q := f.q.WithTx(tx)
				current, updateErr := q.UpdateHTMLTemplate(ctx, generated.UpdateHTMLTemplateParams{
					ID: template.ID, OrgID: f.org, Name: in.Name, ExpectedVersion: 1,
					HtmlMasterJson: content.MasterJSON, VariablesJson: content.DefaultsJSON, HtmlContentSha256: digest,
				})
				if updateErr != nil {
					t.Fatal("revision edit blocked during render:", updateErr)
				}
				_, err = q.InsertHTMLTemplateRevision(ctx, generated.InsertHTMLTemplateRevisionParams{
					TemplateID: template.ID, OrgID: f.org, ExpectedVersion: current.Version, CreatedBy: f.user.ID,
					HtmlMasterJson: content.MasterJSON, VariablesJson: content.DefaultsJSON, ContentSha256: digest,
				})
				if err == nil {
					err = tx.Commit(ctx)
				}
			case "logout":
				_, err = f.q.RevokeUserSessions(ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration})
				want = http.StatusForbidden
			case "demotion":
				_, err = f.q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
				want = http.StatusForbidden
			case "expiry":
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				want = http.StatusUnauthorized
			}
			if err != nil {
				t.Fatal("live authority change blocked during external work:", err)
			}
			before := htmlTemplateSnapshotE2E(t, f)
			close(release)
			released = true
			response := receiveSessionOperationE2E(t, result)
			received = true
			assertNoHTMLPreviewE2E(t, response, want)
			assertHTMLTemplateUnchangedE2E(t, f, before)
		})
	}
}

func TestHTMLTemplatePreviewPinsPrecedeMissingCacheE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	renderer := &htmlCreationRendererE2E{}
	preview := htmlPreviewServerE2E(t, f, renderer)
	if tag, err := f.pool.Exec(f.ctx, "DELETE FROM html_authoring_template_sizes_v1 WHERE template_id=$1 AND org_id=$2", template.ID, f.org); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("remove exact genuine fresh template cache")
	} //nolint:rawsql -- exact disposable template cache, never an expanded repair
	before := htmlTemplateSnapshotE2E(t, f)
	digest := hex.EncodeToString(template.HtmlContentSha256)
	wrongDigest := strings.Repeat("0", 64)
	if wrongDigest == digest {
		wrongDigest = strings.Repeat("1", 64)
	}
	for _, tc := range []struct {
		name    string
		version int32
		digest  string
		status  int
	}{
		{"unchanged_pins_stay_unavailable", template.Version, digest, http.StatusServiceUnavailable},
		{"different_version_is_conflict", template.Version + 1, digest, http.StatusConflict},
		{"different_digest_is_conflict", template.Version, wrongDigest, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(htmlTemplatePreviewInput{ExpectedVersion: tc.version, ExpectedContentSHA256: tc.digest})
			if err != nil {
				t.Fatal(err)
			}
			w := submitSessionOperationE2E(preview.s, http.MethodPost, "/api/v1/templates/"+template.ID.String()+"/html/preview", string(body), cookie)
			assertNoHTMLPreviewE2E(t, w, tc.status)
			assertHTMLTemplateUnchangedE2E(t, f, before)
			if len(renderer.sources()) != 0 {
				t.Fatal("missing-cache or mismatched-pin refusal reached renderer")
			}
			var caches int
			if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM html_authoring_template_sizes_v1 WHERE template_id=$1 AND org_id=$2", template.ID, f.org).Scan(&caches); err != nil || caches != 0 {
				t.Fatal("refused preview refreshed an untrusted missing cache")
			} //nolint:rawsql -- exact absence witness, no source expansion
		})
	}
}

func TestHTMLTemplatePreviewReceiptExpiryDuringAuditWaitE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	in := previewApprovalInputE2E(t, f, template, cookie)
	proof := decodeHTMLPreviewReceiptE2E(t, f, in.PreviewReceipt)
	proof.IssuedAt, proof.ExpiresAt = time.Now().Add(-time.Second), time.Now().Add(2*time.Second)
	in.PreviewReceipt = signHTMLPreviewReceiptE2E(t, f, proof)
	before := htmlTemplateSnapshotE2E(t, f)
	hold, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback(context.Background())
	if err := f.q.WithTx(hold).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	requestCtx, cancelRequest := context.WithCancel(f.ctx)
	result := make(chan *httptest.ResponseRecorder, 1)
	finished := make(chan struct{})
	defer joinHTMLAuthoringRequestE2E(t, cancelRequest, finished, hold)
	go func() {
		defer close(finished)
		result <- submitHTMLTemplateContextE2E(t, requestCtx, f, "approve", template.ID, in, cookie)
	}()
	awaitHTMLAuthoringOperationLockE2E(t, f, "-- name: AcquireOrgChainLock", "advisory")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(proof.ExpiresAt) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if time.Now().Before(proof.ExpiresAt) {
		t.Fatal("preview proof did not expire")
	}
	if err := hold.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusConflict {
		t.Fatalf("proof expired after audit wait=%d %s", w.Code, w.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
}

func TestHTMLTemplatePreviewRefusesUnsafeRendererOutputE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	for _, kind := range []string{"non-PDF", "active-PDF", "oversized-PDF"} {
		t.Run(kind, func(t *testing.T) {
			f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
			template := createHTMLTemplateE2E(t, f)
			preview := htmlPreviewServerE2E(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 20<<20))
				w.Header().Set("Content-Type", "application/pdf")
				switch kind {
				case "non-PDF":
					_, _ = w.Write([]byte("not a PDF"))
				case "active-PDF":
					_, _ = w.Write(htmlPreviewActivePDFE2E())
				case "oversized-PDF":
					chunk := make([]byte, 64<<10)
					for remaining := sanitize.MaxPDFBytes + 1; remaining > 0; {
						n := len(chunk)
						if remaining < n {
							n = remaining
						}
						if _, err := w.Write(chunk[:n]); err != nil {
							return
						}
						remaining -= n
					}
				}
			}))
			before := htmlTemplateSnapshotE2E(t, f)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			want := http.StatusBadRequest
			assertNoHTMLPreviewE2E(t, submitHTMLPreviewE2E(t, preview, template, nil, cookie), want)
			assertHTMLTemplateUnchangedE2E(t, f, before)
		})
	}
}

func htmlPreviewActivePDFE2E() []byte {
	// A syntactically valid tiny PDF with a catalog action. No action is ever
	// executed; the isolated sanitizer must refuse it before returning a proof.
	stream := "BT /F1 18 Tf 72 720 Td (Synthetic active PDF) Tj ET\n"
	objects := []string{
		`<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (synthetic) >> >>`,
		`<< /Type /Pages /Kids [3 0 R] /Count 1 >>`,
		`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>`,
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream),
		`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`,
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}
