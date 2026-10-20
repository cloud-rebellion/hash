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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"

	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
)

// These tests exercise the real REST admission, PostgreSQL transactions and
// PDF clean/count path. The loopback renderer returns a fixed valid one-page
// PDF and records submitted HTML; it does not prove Chromium layout or that
// the fixture PDF depicts that HTML. The version-enforcing S3 protocol peer
// exercises the real storage client, not a production provider/Object Lock.
// HASH_E2E_PDF_WORKER_PATH selects the source-built isolated production worker
// for PDF clean/count; without it, these tests explicitly use library mode.
type htmlCreationRendererE2E struct {
	mu      sync.Mutex
	html    []string
	entered chan struct{}
	release <-chan struct{}
}

type htmlCreationStorageE2E struct {
	*importStoragePeer
	requests atomic.Int64
}

func (p *htmlCreationStorageE2E) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.requests.Add(1)
	p.importStoragePeer.ServeHTTP(w, r)
}

func (p *htmlCreationRendererE2E) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.servePaperProtocolV1(w, r, nil)
}

// A fixed synthetic peer may observe the two real dimension fields during
// this SAME bounded protocol parse; ordinary fixture behavior is unchanged.
func (p *htmlCreationRendererE2E) servePaperProtocolV1(w http.ResponseWriter, r *http.Request, paper *[2]string) {
	if r.Method != http.MethodPost || r.URL.Path != "/forms/chromium/convert/html" {
		http.Error(w, "unexpected renderer fixture operation", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 20<<20)
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "invalid renderer fixture multipart", http.StatusBadRequest)
		return
	}
	var source string
	indexes, parts := 0, 0
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		parts++
		if err != nil || parts > 32 {
			http.Error(w, "invalid renderer fixture parts", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(part, (16<<20)+1))
		_ = part.Close()
		if err != nil || len(body) > 16<<20 {
			http.Error(w, "oversized renderer fixture part", http.StatusBadRequest)
			return
		}
		if paper != nil && (part.FormName() == "paperWidth" || part.FormName() == "paperHeight") {
			if part.FileName() != "" || len(body) > 64 {
				http.Error(w, "invalid synthetic paper field", http.StatusBadRequest)
				return
			}
			index := 0
			if part.FormName() == "paperHeight" {
				index = 1
			}
			if paper[index] != "" {
				http.Error(w, "duplicate synthetic paper field", http.StatusBadRequest)
				return
			}
			paper[index] = string(body)
		}
		if part.FormName() == "files" && part.FileName() == "index.html" {
			indexes++
			source = string(body)
		}
	}
	if indexes != 1 || !strings.HasPrefix(source, "<!doctype html>") {
		http.Error(w, "missing canonical rendered HTML", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.html = append(p.html, source)
	p.mu.Unlock()
	if p.entered != nil {
		select {
		case p.entered <- struct{}{}:
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
	w.Header().Set("Content-Type", "application/pdf")
	_, _ = w.Write(fieldBrowserPDF("Synthetic HTML instantiation protocol fixture"))
}

func (p *htmlCreationRendererE2E) sources() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.html...)
}

func setupHTMLDocumentCreationE2E(t *testing.T, renderer *htmlCreationRendererE2E) (lifecycleAuthorizationFixture, *htmlCreationStorageE2E) {
	t.Helper()
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	if workerPath := os.Getenv("HASH_E2E_PDF_WORKER_PATH"); workerPath != "" {
		t.Cleanup(func() {
			if err := sanitize.ConfigurePDFWorker(context.Background(), "", "development"); err != nil {
				t.Error("reset PDF worker fixture:", err)
			}
		})
		if err := sanitize.ConfigurePDFWorker(f.ctx, workerPath, "production"); err != nil {
			t.Fatal("configure isolated PDF worker fixture:", err)
		}
	} else {
		// Offline library mode must not create a configuration directory on the
		// fixture filesystem. This is not isolated-worker acceptance evidence.
		pdfapi.DisableConfigDir()
	}
	f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: "pro", ReviewRef: "synthetic HTML instantiation quota approval"}})
	f.s.Versions = versions.New(f.q)
	rendererServer := httptest.NewServer(renderer)
	t.Cleanup(rendererServer.Close)
	f.s.Sign = &sign.Engine{PDF: render.NewGotenberg(rendererServer.URL)}
	peer := &htmlCreationStorageE2E{importStoragePeer: &importStoragePeer{objects: make(map[string][]byte)}}
	objectServer := httptest.NewServer(peer)
	t.Cleanup(objectServer.Close)
	var err error
	f.s.Storage, err = storage.New(f.ctx, storage.Config{
		Endpoint: strings.TrimPrefix(objectServer.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture",
		AccessKey: "synthetic-html-access", SecretKey: "synthetic-html-secret", BucketLookup: "path",
		AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, peer
}

func approveHTMLCreationTemplateE2E(t *testing.T, f lifecycleAuthorizationFixture, template *generated.Template) {
	t.Helper()
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	in := previewApprovalInputE2E(t, f, template, cookie)
	if w := submitHTMLTemplateE2E(t, f, "approve", template.ID, in, cookie); w.Code != http.StatusOK {
		t.Fatalf("approve instantiation master=%d %s", w.Code, w.Body.String())
	}
}

func htmlCreationInputE2E(template *generated.Template) htmlDocumentInput {
	return htmlDocumentInput{Name: "HTML materialization protocol fixture", ExpectedTemplateVersion: template.Version,
		ExpectedTemplateContentSHA256: hex.EncodeToString(template.HtmlContentSha256)}
}

func submitHTMLDocumentCreationE2E(t *testing.T, f lifecycleAuthorizationFixture, templateID uuid.UUID, input htmlDocumentInput, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	return submitHTMLDocumentCreationContextE2E(t, f.ctx, f, templateID, input, cookie)
}

func submitHTMLDocumentCreationContextE2E(t *testing.T, ctx context.Context, f lifecycleAuthorizationFixture, templateID uuid.UUID, input htmlDocumentInput, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	// Optional maps omitted by callers are different from explicit JSON null.
	// The typed fixture mirrors a normal object-producing API client.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if input.Values == nil {
		delete(fields, "values")
	}
	if input.Sections == nil {
		delete(fields, "sections")
	}
	body, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return submitSessionOperationContextE2E(ctx, f.s, http.MethodPost, "/api/v1/templates/"+templateID.String()+"/html/documents", string(body), cookie)
}

func TestHTMLDocumentInstantiationCommitsExactSourceSnapshotAndAuditE2E(t *testing.T) {
	renderer := &htmlCreationRendererE2E{}
	f, peer := setupHTMLDocumentCreationE2E(t, renderer)
	template := createHTMLTemplateE2E(t, f)
	approveHTMLCreationTemplateE2E(t, f, template)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	for index, values := range []htmlStringMap{nil, {"customer": "Reviewed <AB> & Co"}} {
		t.Run(fmt.Sprintf("values-%d", index), func(t *testing.T) {
			in := htmlCreationInputE2E(template)
			in.Values = values
			in.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			w := submitHTMLDocumentCreationE2E(t, f, template.ID, in, cookie)
			if w.Code != http.StatusCreated {
				t.Fatalf("instantiate approved master=%d %s", w.Code, w.Body.String())
			}
			var response struct {
				Document       documentResponse `json:"document"`
				PageCount      int              `json:"page_count"`
				ReviewRequired bool             `json:"review_required"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Document.ID == uuid.Nil || response.PageCount != 1 || !response.ReviewRequired || !response.Document.HTMLReviewRequired {
				t.Fatalf("creation response does not require exact PDF review: %+v err=%v", response, err)
			}
			doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: response.Document.ID, OrgID: f.org})
			if err != nil || doc.Status != "draft" || doc.SourceKind != "pdf" || !doc.TemplateID.Valid || uuid.UUID(doc.TemplateID.Bytes) != template.ID || len(doc.HtmlSourceJson) == 0 || len(doc.MetadataRedactionReport) == 0 {
				t.Fatalf("immutable source/document missing: %+v err=%v", doc, err)
			}
			if err := htmlsource.Validate(doc, false); err != nil {
				t.Fatal("committed provenance is invalid:", err)
			}
			if err := htmlsource.Validate(doc, true); !errors.Is(err, htmlsource.ErrReviewRequired) {
				t.Fatalf("new PDF inherited human review: %v", err)
			}
			customer := "Approved default AB"
			printed := customer
			if values != nil {
				customer, printed = values["customer"], "Reviewed &lt;AB&gt; &amp; Co"
			}
			var committedValues map[string]string
			if err := json.Unmarshal(doc.VariablesJson, &committedValues); err != nil || len(committedValues) != 1 || committedValues["customer"] != customer {
				t.Fatalf("printed values/default merge drifted: %v err=%v", committedValues, err)
			}
			sources := renderer.sources()
			if len(sources) != index+1 || !strings.Contains(sources[index], printed) || strings.Contains(sources[index], "hash-value") {
				t.Fatal("renderer did not receive the exact escaped materialization")
			}
			stored, err := f.s.Storage.GetVerifiedVersion(f.ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
			if err != nil || len(stored) == 0 || !strings.HasPrefix(doc.PdfStorageKey.String, "org/"+f.org.String()+"/documents/") || !doc.EvidenceVersionPinsRequired || doc.PdfStorageVersionID.String != "import-version-1" {
				t.Fatalf("exact sanitized object commitment invalid: %v", err)
			}
			sum := sha256.Sum256(stored)
			if !bytes.Equal(sum[:], doc.PdfSha256) {
				t.Fatal("stored PDF digest differs from committed source")
			}
			version, err := f.q.GetLatestDocumentVersion(f.ctx, doc.ID)
			if err != nil || version.VersionNo != 1 || version.SourceKind != "pdf" || !bytes.Equal(version.HtmlSourceJson, doc.HtmlSourceJson) || !bytes.Equal(version.VariablesJson, doc.VariablesJson) {
				t.Fatalf("first immutable version dropped source or values: %+v err=%v", version, err)
			}
			var events, complete int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER (WHERE actor_user_id=$2 AND payload_json->>'authoring_kind'='html' AND payload_json->>'template_content_sha256'=$3 AND payload_json->>'pdf_sha256'=$4 AND payload_json->>'review_required'='true' AND row_hash IS NOT NULL) FROM events WHERE document_id=$1 AND kind='document.created'`, doc.ID, f.user.ID, in.ExpectedTemplateContentSHA256, hex.EncodeToString(doc.PdfSha256)).Scan(&events, &complete); err != nil || events != 1 || complete != 1 { //nolint:rawsql -- exact synthetic document audit completeness
				t.Fatalf("creation audit is not atomic/complete: %d/%d err=%v", events, complete, err)
			}
			assertImportStorageE2E(t, peer.importStoragePeer, index+1, 0, index+1)
			assertHTMLCreatedDocumentReviewE2E(t, f, peer, doc, cookie)
		})
	}
}

func assertHTMLCreatedDocumentReviewE2E(t *testing.T, f lifecycleAuthorizationFixture, peer *htmlCreationStorageE2E, doc *generated.Document, cookie string) {
	t.Helper()
	before := htmlTemplateSnapshotE2E(t, f)
	storageRequests := peer.requests.Load()
	// This route must refuse at HTML-source admission, before it inspects
	// static PDF bytes/fields or creates a reusable PDF template that would
	// bypass fresh HTML materialization and its exact-PDF review requirement.
	export, err := json.Marshal(savePDFTemplateInput{Name: "Static export must refuse HTML provenance",
		ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedFieldIDs: []uuid.UUID{uuid.New()},
		Parties: []savePDFTemplateParty{{RecipientID: uuid.New(), Role: "customer", Label: "Customer"}}})
	if err != nil {
		t.Fatal(err)
	}
	if w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/pdf-template", string(export), cookie); w.Code != http.StatusConflict {
		t.Fatalf("HTML-derived static PDF export=%d %s", w.Code, w.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	if peer.requests.Load() != storageRequests {
		t.Fatal("static PDF export read or mutated storage before HTML refusal")
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	input := htmlDocumentReviewInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment}
	submit := func(in htmlDocumentReviewInput) *httptest.ResponseRecorder {
		body, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/html/review", string(body), cookie)
	}
	for _, change := range []string{"PDF digest", "timestamp", "source commitment", "missing source commitment"} {
		stale := input
		if change == "PDF digest" {
			stale.ExpectedPDFSHA256 = strings.Repeat("0", 64)
		} else if change == "timestamp" {
			stale.ExpectedUpdatedAt = doc.UpdatedAt.Time.Add(-time.Second).UTC().Format(time.RFC3339Nano)
		} else if change == "source commitment" {
			stale.ExpectedHTMLSourceCommitment = strings.Repeat("0", 64)
		} else {
			stale.ExpectedHTMLSourceCommitment = ""
		}
		if w := submit(stale); w.Code != http.StatusConflict {
			t.Fatalf("stale %s review=%d %s", change, w.Code, w.Body.String())
		}
		assertHTMLTemplateUnchangedE2E(t, f, before)
	}
	w := submit(input)
	if w.Code != http.StatusOK {
		t.Fatalf("exact rendered PDF review=%d %s", w.Code, w.Body.String())
	}
	reviewed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || !reviewed.HtmlReviewedBy.Valid || uuid.UUID(reviewed.HtmlReviewedBy.Bytes) != f.user.ID || !reviewed.HtmlReviewedAt.Valid || !bytes.Equal(reviewed.HtmlReviewedPdfSha256, doc.PdfSha256) || !bytes.Equal(reviewed.HtmlSourceJson, doc.HtmlSourceJson) {
		t.Fatalf("human review changed source or lost exact actor/PDF binding: %+v err=%v", reviewed, err)
	}
	if err := htmlsource.Validate(reviewed, true); err != nil {
		t.Fatal("exact PDF review is not valid:", err)
	}
	var source struct {
		Commitment string `json:"commitment"`
	}
	if err := json.Unmarshal(reviewed.HtmlSourceJson, &source); err != nil || len(source.Commitment) != 64 {
		t.Fatalf("committed source identity missing: %v", err)
	}
	var creations, reviews int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FILTER (WHERE kind='document.created'),count(*) FILTER (WHERE kind='document.updated' AND payload_json->>'html_pdf_reviewed'='true') FROM events WHERE document_id=$1 AND actor_user_id=$2 AND payload_json->>'html_source_commitment'=$3 AND payload_json->>'pdf_sha256'=$4 AND row_hash IS NOT NULL`, doc.ID, f.user.ID, source.Commitment, input.ExpectedPDFSHA256).Scan(&creations, &reviews); err != nil || creations != 1 || reviews != 1 { //nolint:rawsql -- actual JSONB source commitment must match creation and review audit
		t.Fatalf("creation/review evidence drift after JSONB normalization: %d/%d err=%v", creations, reviews, err)
	}
	before = htmlTemplateSnapshotE2E(t, f)
	if w := submit(input); w.Code != http.StatusConflict {
		t.Fatalf("previous review observation reused=%d %s", w.Code, w.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	if peer.requests.Load() != storageRequests {
		t.Fatal("review protocol unexpectedly touched object storage")
	}
}

func TestHTMLDocumentInstantiationAuditFailureCompensatesExactOwnedVersionE2E(t *testing.T) {
	renderer := &htmlCreationRendererE2E{}
	f, peer := setupHTMLDocumentCreationE2E(t, renderer)
	template := createHTMLTemplateE2E(t, f)
	approveHTMLCreationTemplateE2E(t, f, template)
	function := "html_instantiation_fail_" + strings.ReplaceAll(f.org.String(), "-", "")
	trigger := function + "_trg"
	if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION "%s"() RETURNS trigger LANGUAGE plpgsql AS $body$ BEGIN IF NEW.org_id='%s'::uuid AND NEW.kind='document.created' THEN RAISE EXCEPTION 'synthetic HTML audit failure'; END IF; RETURN NEW; END $body$`, function, f.org)); err != nil { //nolint:rawsql,gosec -- only generated fixture UUID names/literal
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE TRIGGER "%s" BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION "%s"()`, trigger, function)); err != nil { //nolint:rawsql,gosec
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS "%s" ON events`, trigger)) //nolint:rawsql,gosec
		_, _ = f.pool.Exec(ctx, fmt.Sprintf(`DROP FUNCTION IF EXISTS "%s"()`, function))       //nolint:rawsql,gosec
	})
	before := htmlTemplateSnapshotE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	w := submitHTMLDocumentCreationE2E(t, f, template.ID, htmlCreationInputE2E(template), cookie)
	if w.Code != http.StatusInternalServerError || len(renderer.sources()) != 1 {
		t.Fatalf("post-store audit failure=%d %s", w.Code, w.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	// The reused S3 peer refuses DELETE without the exact versionId, and the
	// real storage client verifies the digest before sending that deletion.
	assertImportStorageE2E(t, peer.importStoragePeer, 1, 1, 0)
}

func TestHTMLDocumentInstantiationRefusesExpiryDuringRendererWaitBeforeStorageE2E(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	renderer := &htmlCreationRendererE2E{entered: make(chan struct{}, 1), release: release}
	f, peer := setupHTMLDocumentCreationE2E(t, renderer)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	template := createHTMLTemplateE2E(t, f)
	approveHTMLCreationTemplateE2E(t, f, template)
	before := htmlTemplateSnapshotE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- submitHTMLDocumentCreationE2E(t, f, template.ID, htmlCreationInputE2E(template), cookie)
	}()
	select {
	case <-renderer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach the actual renderer HTTP wait")
	}
	awaitSessionCookieExpiryE2E(t, f.s, cookie)
	once.Do(func() { close(release) })
	if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired renderer-wait request=%d %s", w.Code, w.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	assertImportStorageE2E(t, peer.importStoragePeer, 0, 0, 0)
}

func TestHTMLDocumentInstantiationRefusesUnapprovedAndStalePinsBeforeEffectsE2E(t *testing.T) {
	renderer := &htmlCreationRendererE2E{}
	f, peer := setupHTMLDocumentCreationE2E(t, renderer)
	template := createHTMLTemplateE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	check := func(t *testing.T, input htmlDocumentInput) {
		t.Helper()
		before := htmlTemplateSnapshotE2E(t, f)
		if w := submitHTMLDocumentCreationE2E(t, f, template.ID, input, cookie); w.Code != http.StatusConflict {
			t.Fatalf("unreviewed/stale master=%d %s", w.Code, w.Body.String())
		}
		assertHTMLTemplateUnchangedE2E(t, f, before)
		if len(renderer.sources()) != 0 {
			t.Fatal("refused pin dispatched the renderer")
		}
		assertImportStorageE2E(t, peer.importStoragePeer, 0, 0, 0)
	}
	t.Run("unapproved", func(t *testing.T) { check(t, htmlCreationInputE2E(template)) })
	approveHTMLCreationTemplateE2E(t, f, template)
	t.Run("wrong version", func(t *testing.T) {
		in := htmlCreationInputE2E(template)
		in.ExpectedTemplateVersion++
		check(t, in)
	})
	t.Run("wrong content", func(t *testing.T) {
		in := htmlCreationInputE2E(template)
		in.ExpectedTemplateContentSHA256 = strings.Repeat("0", 64)
		check(t, in)
	})
	// Retain a genuinely approved older version, then advance the library row.
	if w := submitHTMLTemplateE2E(t, f, "update", template.ID, htmlTemplateInputE2E(t, template.Version, "New master"), cookie); w.Code != http.StatusOK {
		t.Fatalf("advance current master=%d %s", w.Code, w.Body.String())
	}
	t.Run("formerly approved version", func(t *testing.T) { check(t, htmlCreationInputE2E(template)) })
}
