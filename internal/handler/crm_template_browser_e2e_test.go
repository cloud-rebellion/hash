//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/crmreview"
	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	crmTemplateBrowserControlE2E   = "/__hash_crm_template_fixture/control"
	crmTemplateBrowserTeamE2E      = "initial_browser_team_CUID2"
	crmTemplateBrowserUserE2E      = "initial_browser_user_CUID2"
	crmTemplateBrowserDealE2E      = "initial_browser_deal_CUID2"
	crmTemplateBrowserFreshE2E     = "1490.7500"
	crmTemplateBrowserDriftE2E     = "1590.1250"
	crmTemplateBrowserReferenceE2E = "Human reference ÅÄÖ <approved & retained>"
	crmTemplateBrowserScopeE2E     = "Approved synthetic initial service scope."
	crmTemplateBrowserManualE2E    = "Human negotiated scope: retain the existing service wording and support window.\nThe customer-approved second line remains exactly as entered."
)

// Only this e2e fixture exposes the task control and external-browser handoff.
// CRM and exact-version S3 are protected source-shaped synthetic peers. Actual
// account encryption/transport, SQL, built UI, Chromium and protocol2 worker
// are mandatory; live-provider, SMTP, signing and deployment are not implied.
type crmTemplateBrowserPeerE2E struct {
	mu                                      sync.Mutex
	token, value                            string
	updated                                 time.Time
	freshBodySHA                            string
	accounts, searches, records, unexpected atomic.Int64
}

func (p *crmTemplateBrowserPeerE2E) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+p.token {
		p.unexpected.Add(1)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/api/v1/auth/me" && r.URL.RawQuery == "" {
		p.accounts.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": crmTemplateBrowserUserE2E, "team_id": crmTemplateBrowserTeamE2E, "is_active": true, "role": "ADMIN"})
		return
	}
	p.mu.Lock()
	value, updated := p.value, p.updated
	p.mu.Unlock()
	record := map[string]any{"id": crmTemplateBrowserDealE2E, "team_id": crmTemplateBrowserTeamE2E, "updated_at": updated.UTC().Format(time.RFC3339Nano), "title": "Synthetic initial reviewed service", "value": json.Number(value), "currency": "", "stage": "PROPOSAL", "contact_id": nil, "company_id": nil, "assigned_to_id": nil}
	switch {
	case r.URL.Path == "/api/v1/deals/" && reflect.DeepEqual(r.URL.Query(), url.Values{"search": {""}, "limit": {"20"}, "offset": {"0"}}):
		p.searches.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{record}, "total": 1, "limit": 20, "offset": 0})
	case r.URL.Path == "/api/v1/deals/"+crmTemplateBrowserDealE2E && r.URL.RawQuery == "":
		p.records.Add(1)
		body, _ := json.Marshal(record)
		body = append(body, '\n')
		if value == crmTemplateBrowserFreshE2E {
			p.mu.Lock()
			p.freshBodySHA = crmDocumentBrowserDigestE2E(body)
			p.mu.Unlock()
		}
		_, _ = w.Write(body)
	default:
		p.unexpected.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}
}

// The original Gotenberg request context is kept intact. The barrier waits
// before one real HTTP conversion, outside SQL locks, for at most ten seconds.
// Browser response loss is handled by retained route.fetch, never by detaching
// the production creation context or replacing an ordinary creation handler.
type crmTemplateBrowserRenderE2E struct {
	mu                                              sync.Mutex
	transport                                       http.RoundTripper
	armed, entered, released, liveAtRelease, failed bool
	release                                         chan struct{}
	ctx                                             context.Context
	requests                                        atomic.Int64
}

func (b *crmTemplateBrowserRenderE2E) RoundTrip(r *http.Request) (*http.Response, error) {
	b.requests.Add(1)
	b.mu.Lock()
	held := b.armed && r.Method == http.MethodPost && r.URL.Path == "/forms/chromium/convert/html"
	if held {
		b.armed = false
		b.entered = true
		b.ctx = r.Context()
	}
	release := b.release
	b.mu.Unlock()
	if held {
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-release:
			b.mu.Lock()
			b.liveAtRelease = r.Context().Err() == nil
			b.mu.Unlock()
		case <-r.Context().Done():
			b.mu.Lock()
			b.failed = true
			b.mu.Unlock()
			return nil, r.Context().Err()
		case <-timer.C:
			b.mu.Lock()
			b.failed = true
			b.mu.Unlock()
			return nil, errors.New("synthetic renderer hold deadline")
		}
	}
	return b.transport.RoundTrip(r)
}

func (b *crmTemplateBrowserRenderE2E) control(action string) (map[string]bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch action {
	case "hold-render":
		if b.armed || b.entered || b.release != nil {
			return nil, errors.New("barrier already used")
		}
		b.release = make(chan struct{})
		b.armed = true
	case "release-render":
		if !b.entered || b.released || b.failed || b.ctx == nil || b.ctx.Err() != nil {
			return nil, errors.New("barrier cannot release original context")
		}
		b.released = true
		close(b.release)
	case "render-status":
	default:
		return nil, errors.New("unknown barrier action")
	}
	return map[string]bool{"entered": b.entered, "context_live": b.ctx != nil && b.ctx.Err() == nil, "released": b.released}, nil
}

func (b *crmTemplateBrowserRenderE2E) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.release != nil && !b.released {
		b.released = true
		close(b.release)
	}
}

type crmTemplateBrowserDispatchE2E struct {
	in      htmlDocumentInput
	status  int
	bodySHA string
}

type crmTemplateBrowserCountsE2E struct {
	mu       sync.Mutex
	posts    []crmTemplateBrowserDispatchE2E
	closures []crmTemplateBrowserClosureE2E
	recovery []int
	controls []string
	failures []string
	sends    int
}

type crmTemplateBrowserClosureE2E struct {
	requestID uuid.UUID
	in        htmlCreationCloseInput
	status    int
}

type crmTemplateBrowserArtifactE2E struct {
	crmDocumentBrowserArtifactE2E
	DocumentID            uuid.UUID `json:"document_id"`
	RequestID             uuid.UUID `json:"request_id"`
	InputDigest           string    `json:"input_digest"`
	TemplateVersion       int32     `json:"template_version"`
	TemplateContentSHA256 string    `json:"template_content_sha256"`
}

// Match JSON.stringify's tuple bytes, including literal <, > and & in the
// synthetic manual value. Go's default HTML escaping is not a shared digest.
func crmTemplateBrowserTupleDigestE2E(t *testing.T, tuples [][2]string) string {
	t.Helper()
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(tuples); err != nil {
		t.Fatal("encode exact browser/source tuple commitment")
	}
	return crmDocumentBrowserDigestE2E(bytes.TrimSuffix(body.Bytes(), []byte{'\n'}))
}

// This inventory is internal, never returned/logged; comparisons prove reads
// and refusals do not create evidence. Owner connection audits are separate.
func crmTemplateBrowserInventoryE2E(ctx context.Context, f lifecycleAuthorizationFixture) (string, error) {
	var raw string
	err := f.pool.QueryRow(ctx, `SELECT jsonb_build_object(
	'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
	'creation',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY request_id),'[]'::jsonb) FROM html_document_creation_requests c WHERE org_id=$1),
	'resolutions',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY actor_user_id,request_id),'[]'::jsonb) FROM html_document_creation_resolutions c WHERE org_id=$1),
	'closure_events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1 AND kind='html.document.creation.closed'),
	'materializations',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id),'[]'::jsonb) FROM html_document_materializations m WHERE org_id=$1),
	'snapshots',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM html_document_materialization_snapshots s WHERE org_id=$1),
	'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.id),'[]'::jsonb) FROM document_versions v JOIN documents d ON d.id=v.document_id WHERE d.org_id=$1),
	'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb) FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1),
	'fields',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY f.id),'[]'::jsonb) FROM document_fields f JOIN documents d ON d.id=f.document_id WHERE d.org_id=$1),
	'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.document_id,b.variable_name),'[]'::jsonb) FROM document_variable_bindings b JOIN documents d ON d.id=b.document_id WHERE d.org_id=$1),
	'reviews',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.document_id),'[]'::jsonb) FROM document_crm_mapping_reviews r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1),
	'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM events e WHERE e.org_id=$1 AND e.document_id IS NOT NULL))::text`, f.org).Scan(&raw) //nolint:rawsql -- disposable exact tenant evidence, never emitted
	return raw, err
}

func TestCRMTemplatePopulationWithExternalBrowserE2E(t *testing.T) {
	if os.Getenv("HASH_CRM_TEMPLATE_BROWSER_E2E") != "1" {
		t.Skip("explicit initial template external browser fixture required")
	}
	for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_RENDERER_URL", "HASH_E2E_PDF_WORKER_PATH"} {
		if os.Getenv(name) == "" {
			t.Fatalf("selected initial browser fixture requires %s", name)
		}
	}
	base, err := url.Parse(os.Getenv("HASH_CRM_TEMPLATE_BROWSER_BASE"))
	if err != nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		t.Fatal("initial browser requires exact loopback HTTPS origin")
	}
	root, inputPath, donePath, artifacts := os.Getenv("HASH_CRM_TEMPLATE_BROWSER_FRONTEND"), os.Getenv("HASH_CRM_TEMPLATE_BROWSER_INPUT"), os.Getenv("HASH_CRM_TEMPLATE_BROWSER_DONE"), os.Getenv("HASH_CRM_TEMPLATE_BROWSER_ARTIFACTS")
	for _, p := range []string{root, inputPath, donePath, artifacts} {
		if !filepath.IsAbs(p) {
			t.Fatal("initial browser requires absolute task-owned paths")
		}
	}
	if inputPath == donePath {
		t.Fatal("private handoff paths must differ")
	}
	for _, p := range []string{inputPath, donePath} {
		if _, err = os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("initial browser handoff paths must be fresh")
		}
	}
	if info, err := os.Stat(artifacts); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("initial browser requires private existing artifact directory")
	}
	target, err := url.Parse(os.Getenv("HASH_E2E_RENDERER_URL"))
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		t.Fatal("initial browser requires explicit real renderer origin")
	}
	probe, err := (&http.Client{Timeout: 5 * time.Second}).Get(target.String() + "/version")
	if err != nil {
		t.Fatal("required real renderer unavailable")
	}
	version, readErr := io.ReadAll(io.LimitReader(probe.Body, 256))
	_ = probe.Body.Close()
	if readErr != nil || probe.StatusCode != 200 || strings.TrimSpace(string(version)) != "8.36.0-hash.1" {
		t.Fatal("required exact renderer differs")
	}
	f := setupHTMLTemplateAuthorizationE2E(t, isolateHTMLTemplateDatabaseE2E(t), "owner")
	ctx, cancel := context.WithTimeout(f.ctx, 320*time.Second)
	defer cancel()
	f.ctx = ctx
	f.s.Environment, f.s.PublicURL = "development", base.String()
	if err = sanitize.ConfigurePDFWorker(ctx, os.Getenv("HASH_E2E_PDF_WORKER_PATH"), "production"); err != nil {
		t.Fatal("required isolated PDF worker unavailable")
	}
	t.Cleanup(func() {
		if err := sanitize.ConfigurePDFWorker(context.Background(), "", "development"); err != nil {
			t.Error("reset task PDF worker")
		}
	})
	f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: "pro", ReviewRef: "synthetic initial CRM browser entitlement"}})
	f.s.Versions = versions.New(f.q)
	pdfRenderer := render.NewGotenberg(target.String())
	barrier := &crmTemplateBrowserRenderE2E{transport: http.DefaultTransport}
	defer barrier.cleanup()
	pdfRenderer.HTTP.Transport = barrier
	f.s.Sign = &sign.Engine{Pool: f.pool, Queries: f.q, PDF: pdfRenderer, Audit: f.s.Audit}
	objects := &htmlCreationStorageE2E{importStoragePeer: &importStoragePeer{objects: make(map[string][]byte)}}
	objectServer := httptest.NewServer(objects)
	defer objectServer.Close()
	f.s.Storage, err = storage.New(ctx, storage.Config{Endpoint: strings.TrimPrefix(objectServer.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-initial-browser", SecretKey: "synthetic-initial-browser-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal("protected exact-version S3 peer unavailable")
	}
	token := crmBrowserRandomHex(t)
	peer := &crmTemplateBrowserPeerE2E{token: token, value: crmTemplateBrowserFreshE2E, updated: time.Now().Add(-time.Minute).UTC()}
	crmServer := httptest.NewServer(peer)
	defer crmServer.Close()
	f.s.CRMClient, err = crmconnection.NewClient(crmServer.URL, true)
	if err != nil {
		t.Fatal("protected CRM HTTP client unavailable")
	}
	f.s.CRMKeys, err = crmconnection.NewKeyring(crmBrowserRandomHex(t), "")
	if err != nil {
		t.Fatal("private CRM keyring unavailable")
	}
	f.s.CRMOrigin = crmServer.URL
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	configure := func(generation int64) bool {
		body, _ := json.Marshal(crmConnectionInput{ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, ExpectedGeneration: strconv.FormatInt(generation, 10), Token: token})
		if submitSessionOperationE2E(f.s, http.MethodPut, "/api/v1/settings/crm/connection", string(body), cookie).Code != 200 {
			return false
		}
		body, _ = json.Marshal(crmConnectionEnableInput{ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, ExpectedGeneration: strconv.FormatInt(generation+1, 10), CRMTeamID: crmTemplateBrowserTeamE2E, CRMUserID: crmTemplateBrowserUserE2E})
		return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/settings/crm/connection/enable", string(body), cookie).Code == 200
	}
	if !configure(0) {
		t.Fatal("seed disabled candidate and explicit active mapping")
	}
	originalConnection, err := f.q.GetCRMConnectionByOrg(ctx, f.org)
	if err != nil || originalConnection.Generation != 2 || originalConnection.Status != "active" {
		t.Fatal("actual account enrollment did not reach generation2")
	}
	input, _, _ := testfixture.HTMLContract(t)
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal("decode reviewed contract fixture")
	}
	master.SchemaVersion = htmlmaster.SigningPageSchemaVersion
	master.SigningPage = testfixture.BrandedSigningPolicy()
	master.Values = append(master.Values, htmlmaster.Value{Name: "manual_reference", Required: true, MaxChars: 200}, htmlmaster.Value{Name: "crm_note", MaxChars: 200})
	master.Sections = []htmlmaster.Section{{Name: "manual_scope", DefaultText: crmTemplateBrowserScopeE2E, MaxChars: 4096}}
	for i := range master.ContractProfile.Terms {
		if master.ContractProfile.Terms[i].Name == "scope" {
			master.ContractProfile.Terms[i].Value = ""
			master.ContractProfile.Terms[i].Section = "manual_scope"
		}
	}
	master.HTML = `<main><h1>Synthetic initial service proposal</h1>` + master.HTML + `<p>Reference: <span data-hash-value="manual_reference"></span></p><p>Optional CRM note: <span data-hash-value="crm_note"></span></p><section class="page-break"><h2>Human reviewed service scope</h2><div class="scope" data-hash-section="manual_scope"></div></section></main>`
	master.CSS = `@page{size:A4;margin:20mm}body{font-family:Inter;font-size:10pt;line-height:1.3;color:#102038}p{margin:0 0 5pt}.page-break{break-before:page;page-break-before:always}.scope{white-space:pre-wrap}`
	input.Values["manual_reference"] = "Approved static reference"
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal("compile bounded essential-section contract")
	}
	if _, err = compiled.Materialize(htmlmaster.Input{Values: input.Values, Sections: map[string]string{}}); err != nil {
		t.Fatal("materialize approved defaults")
	}
	rawMaster, _ := json.Marshal(master)
	rawDefaults, _ := json.Marshal(input.Values)
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "Initial CRM browser approved contract", HTMLMasterJSON: rawMaster, VariablesJSON: rawDefaults}, cookie)
	var templateDTO templateResponse
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &templateDTO) != nil || templateDTO.ID == uuid.Nil {
		t.Fatal("create actual initial design")
	}
	template, err := f.q.GetHTMLTemplate(ctx, generated.GetHTMLTemplateParams{ID: templateDTO.ID, OrgID: f.org})
	if err != nil {
		t.Fatal("read actual design")
	}
	preview := submitHTMLPreviewE2E(t, f, template, nil, cookie)
	if preview.Code != 200 {
		t.Fatal("actual composed owner preview unavailable")
	}
	if pages, err := sanitize.PageCountWithContext(ctx, preview.Body.Bytes()); err != nil || pages != 3 {
		t.Fatal("approved design must render exactly two body pages plus signing suffix")
	}
	approval := htmlApprovalInputE2E(template)
	approval.PreviewReceipt = preview.Header().Get("X-Hash-Preview-Receipt")
	approval.ExpectedPreviewPDFSHA256 = preview.Header().Get("X-Hash-PDF-SHA256")
	if approval.PreviewReceipt == "" || !htmlPreviewSHA256(approval.ExpectedPreviewPDFSHA256) || submitHTMLTemplateE2E(t, f, "approve", template.ID, approval, cookie).Code != 200 {
		t.Fatal("actual exact owner approval failed")
	}
	template, err = f.q.GetHTMLTemplate(ctx, generated.GetHTMLTemplateParams{ID: template.ID, OrgID: f.org})
	if err != nil {
		t.Fatal("read approved design")
	}
	sameUser, err := f.q.CreateUser(ctx, generated.CreateUserParams{OrgID: f.org, Name: "Same organization different owner", Email: uuid.NewString() + "@initial-browser.example.test", Role: "owner"})
	if err != nil {
		t.Fatal("seed distinct same-org actor")
	}
	sameCookie := dsrSessionCookieE2E(t, f.s, sameUser.ID, sameUser.SessionGeneration, time.Hour)
	foreignOrg, err := f.q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Foreign initial browser " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal("seed foreign org")
	}
	foreignUser, err := f.q.CreateUser(ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Name: "Foreign initial owner", Email: uuid.NewString() + "@initial-browser.example.test", Role: "owner"})
	if err != nil {
		t.Fatal("seed foreign actor")
	}
	foreignDoc, err := f.q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: foreignOrg.ID, SenderID: foreignUser.ID, Name: "Foreign untouched initial draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[{"id":"scope","type":"paragraph","text":"Foreign untouched proposal"}]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal("seed foreign draft")
	}
	foreignBefore, _ := json.Marshal(foreignDoc)
	foreignCookie := dsrSessionCookieE2E(t, f.s, foreignUser.ID, foreignUser.SessionGeneration, time.Hour)
	baselinePDFRequests := objects.requests.Load()
	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal("accepted built frontend unavailable")
	}
	f.s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(root))
	f.s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if info, err := os.Stat(filepath.Join(root, clean)); err == nil && !info.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
	counts := &crmTemplateBrowserCountsE2E{}
	control := f.s.requireSameOriginMutation(auth.RequireSession(f.s.Cookies, SessionCookieName, f.q)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		u, ok := auth.FromContext(r.Context())
		if !ok || u.UserID != f.user.ID || u.OrgID != f.org || u.Role != "owner" || r.Method != http.MethodPost {
			w.WriteHeader(403)
			return
		}
		var command struct {
			Action string `json:"action"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if decodeSignerJSON(r, &command) != nil {
			w.WriteHeader(400)
			return
		}
		actor, err := f.s.sessionOwnerActor(r, u)
		if err != nil {
			w.WriteHeader(403)
			return
		}
		controlCtx, stop := context.WithTimeout(r.Context(), authoring.MutationTimeout)
		defer stop()
		tx, err := f.pool.Begin(controlCtx)
		if err != nil {
			w.WriteHeader(503)
			return
		}
		defer func() { _ = tx.Rollback(controlCtx) }()
		guard, err := authoring.LockOwner(controlCtx, tx, actor)
		if err != nil || guard.Recheck(controlCtx) != nil || tx.Commit(controlCtx) != nil {
			w.WriteHeader(403)
			return
		}
		if command.Action == "render-status" {
			state, err := barrier.control(command.Action)
			if err != nil {
				w.WriteHeader(409)
				return
			}
			writeJSON(w, 200, state)
			return
		}
		counts.mu.Lock()
		defer counts.mu.Unlock()
		expected := []string{"hold-render", "release-render", "set-value", "revoke", "restore-active"}
		if len(counts.controls) >= len(expected) || command.Action != expected[len(counts.controls)] {
			w.WriteHeader(409)
			return
		}
		var controlErr error
		switch command.Action {
		case "hold-render", "release-render":
			_, controlErr = barrier.control(command.Action)
		case "set-value":
			peer.mu.Lock()
			peer.value, peer.updated = crmTemplateBrowserDriftE2E, time.Now().UTC()
			peer.mu.Unlock()
		case "revoke":
			body, _ := json.Marshal(map[string]any{"expected_org_id": f.org, "expected_user_id": f.user.ID, "expected_generation": "2"})
			if submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/settings/crm/connection", string(body), cookie).Code != 200 {
				controlErr = errors.New("revoke failed")
			}
		case "restore-active":
			if !configure(3) {
				controlErr = errors.New("restore failed")
			}
		}
		if controlErr != nil {
			w.WriteHeader(503)
			return
		}
		counts.controls = append(counts.controls, command.Action)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})))
	routes := f.s.Routes()
	createPath := "/api/v1/templates/" + template.ID.String() + "/html/documents"
	recoverPrefix := "/api/v1/templates/" + template.ID.String() + "/html/document-requests/"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == crmTemplateBrowserControlE2E {
			control.ServeHTTP(w, r)
			return
		}
		creation := r.Method == http.MethodPost && r.URL.Path == createPath
		recovery := r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, recoverPrefix)
		closure := r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, recoverPrefix) && strings.HasSuffix(r.URL.Path, "/close")
		var in htmlDocumentInput
		var closeIn htmlCreationCloseInput
		var closeRequest uuid.UUID
		var body []byte
		var before string
		var beforeErr error
		requestCount := objects.requests.Load()
		accountReads := peer.accounts.Load()
		recordReads, searchReads, renderRequests := peer.records.Load(), peer.searches.Load(), barrier.requests.Load()
		if creation {
			body, beforeErr = io.ReadAll(io.LimitReader(r.Body, 256<<10+1))
			if beforeErr != nil || len(body) > 256<<10 || json.Unmarshal(body, &in) != nil {
				w.WriteHeader(400)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		if closure {
			body, beforeErr = io.ReadAll(io.LimitReader(r.Body, (2<<10)+1))
			var parseErr error
			closeRequest, parseErr = uuid.Parse(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, recoverPrefix), "/close"))
			if beforeErr != nil || len(body) > 2<<10 || json.Unmarshal(body, &closeIn) != nil || parseErr != nil || closeRequest == uuid.Nil {
				w.WriteHeader(400)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		if creation || recovery || closure {
			before, beforeErr = crmTemplateBrowserInventoryE2E(r.Context(), f)
		}
		tracked := &crmDocumentBrowserStatusE2E{ResponseWriter: w}
		routes.ServeHTTP(tracked, r)
		counts.mu.Lock()
		defer counts.mu.Unlock()
		if creation {
			counts.posts = append(counts.posts, crmTemplateBrowserDispatchE2E{in: in, status: tracked.status, bodySHA: crmDocumentBrowserDigestE2E(body)})
		}
		if recovery {
			counts.recovery = append(counts.recovery, tracked.status)
		}
		if closure {
			counts.closures = append(counts.closures, crmTemplateBrowserClosureE2E{requestID: closeRequest, in: closeIn, status: tracked.status})
			after, readErr := crmTemplateBrowserInventoryE2E(r.Context(), f)
			// Closing may add only terminal metadata and its redacted audit.
			// The two documents and all initial artifact pins stay byte-exact.
			var prior, current map[string]json.RawMessage
			if beforeErr != nil || readErr != nil || json.Unmarshal([]byte(before), &prior) != nil || json.Unmarshal([]byte(after), &current) != nil {
				counts.failures = append(counts.failures, "closure evidence inventory unavailable")
			} else {
				delete(prior, "resolutions")
				delete(prior, "closure_events")
				delete(current, "resolutions")
				delete(current, "closure_events")
				if !reflect.DeepEqual(prior, current) {
					counts.failures = append(counts.failures, "closure changed document/initial artifact evidence")
				}
			}
			if objects.requests.Load() != requestCount || peer.accounts.Load() != accountReads || peer.records.Load() != recordReads || peer.searches.Load() != searchReads || barrier.requests.Load() != renderRequests {
				counts.failures = append(counts.failures, "closure invoked storage/CRM/renderer")
			}
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/send") {
			counts.sends++
		}
		if recovery || (creation && tracked.status != 201 && tracked.status != 200) {
			after, err := crmTemplateBrowserInventoryE2E(r.Context(), f)
			if beforeErr != nil || err != nil || before != after || objects.requests.Load() != requestCount {
				counts.failures = append(counts.failures, "read or refusal changed evidence/storage")
			}
			if creation && r.Header.Get("Cookie") != "" && in.ExpectedUserID == f.user.ID && tracked.status == 409 && strings.Contains(in.Name, "cookie") && peer.accounts.Load() != accountReads {
				counts.failures = append(counts.failures, "actor refusal fetched provider")
			}
		}
	})
	for _, rejectedCookie := range []string{"", sameCookie, foreignCookie} {
		r := httptest.NewRequest(http.MethodPost, base.String()+crmTemplateBrowserControlE2E, strings.NewReader(`{"action":"hold-render"}`)).WithContext(ctx)
		r.Header.Set("Origin", base.String())
		if rejectedCookie != "" {
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rejectedCookie})
		}
		refused := httptest.NewRecorder()
		handler.ServeHTTP(refused, r)
		if refused.Code != 401 && refused.Code != 403 {
			t.Fatal("control admitted anonymous or different actor")
		}
	}
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if err != nil {
		t.Fatal("task TLS listener unavailable")
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	packet, _ := json.Marshal(map[string]any{"base": base.String(), "cookieName": SessionCookieName, "cookie": cookie, "sameOrgCookie": sameCookie, "foreignCookie": foreignCookie, "orgID": f.org, "userID": f.user.ID, "sameOrgUserID": sameUser.ID, "foreignOrgID": foreignOrg.ID, "foreignUserID": foreignUser.ID, "templateID": template.ID, "templateName": template.Name, "templateVersion": template.Version, "templateContentSHA256": hex.EncodeToString(template.HtmlContentSha256), "connectionID": originalConnection.ID, "connectionGeneration": "2", "crmOrigin": crmServer.URL, "crmTeamID": crmTemplateBrowserTeamE2E, "crmUserID": crmTemplateBrowserUserE2E, "dealID": crmTemplateBrowserDealE2E, "priceVariable": "price", "optionalVariable": "crm_note", "sectionName": "manual_scope", "referenceVariable": "manual_reference", "defaultPrice": "1000", "observedPrice": crmTemplateBrowserFreshE2E, "driftPrice": crmTemplateBrowserDriftE2E, "manualReference": crmTemplateBrowserReferenceE2E, "manualWording": crmTemplateBrowserManualE2E, "controlPath": crmTemplateBrowserControlE2E})
	crmDocumentBrowserWriteE2E(t, inputPath, packet)
	defer os.Remove(inputPath)
	for {
		body, err := os.ReadFile(donePath)
		if err == nil {
			var done struct {
				ExitCode *int `json:"exit_code"`
				Verified bool `json:"verified"`
			}
			if len(body) > 4096 || json.Unmarshal(body, &done) != nil || done.ExitCode == nil || *done.ExitCode != 0 || !done.Verified {
				t.Fatal("external initial browser did not accept journey")
			}
			break
		}
		if !os.IsNotExist(err) {
			t.Fatal("external initial browser marker unavailable")
		}
		select {
		case <-ctx.Done():
			t.Fatal("external initial browser deadline exceeded")
		case <-time.After(100 * time.Millisecond):
		}
	}
	counts.mu.Lock()
	posts := append([]crmTemplateBrowserDispatchE2E(nil), counts.posts...)
	closures := append([]crmTemplateBrowserClosureE2E(nil), counts.closures...)
	recoveries := append([]int(nil), counts.recovery...)
	controls := append([]string(nil), counts.controls...)
	failures := append([]string(nil), counts.failures...)
	sends := counts.sends
	counts.mu.Unlock()
	statuses := []int{}
	unique := map[uuid.UUID]bool{}
	successes := []crmTemplateBrowserDispatchE2E{}
	for _, post := range posts {
		statuses = append(statuses, post.status)
		if post.in.RequestID == uuid.Nil || unique[post.in.RequestID] || post.in.ExpectedOrgID != f.org || post.in.ExpectedUserID != f.user.ID || post.in.ExpectedTemplateVersion != template.Version || post.in.ExpectedTemplateContentSHA256 != hex.EncodeToString(template.HtmlContentSha256) || post.in.CRMPopulation == nil {
			t.Fatal("ordinary browser dispatch changed original command witness or repeated UUID")
		}
		unique[post.in.RequestID] = true
		if post.status == 201 {
			successes = append(successes, post)
		}
	}
	if !reflect.DeepEqual(statuses, []int{201, 201, 409, 409, 409, 409}) || len(successes) != 2 || sends != 0 || len(failures) != 0 || !reflect.DeepEqual(controls, []string{"hold-render", "release-render", "set-value", "revoke", "restore-active"}) {
		t.Fatal("initial browser dispatch/control/effect inventory disagrees")
	}
	if !reflect.DeepEqual(recoveries, []int{404, 200, 200}) || len(closures) != 1 || closures[0].status != 200 || closures[0].requestID != posts[len(posts)-1].in.RequestID || closures[0].in.ExpectedOrgID != f.org.String() || closures[0].in.ExpectedUserID != f.user.ID.String() || !closures[0].in.Confirmed {
		t.Fatal("explicit stop did not retain exact final refused UUID and original actor")
	}
	barrier.mu.Lock()
	barrierValid := barrier.entered && barrier.released && barrier.liveAtRelease && !barrier.failed
	barrier.mu.Unlock()
	if !barrierValid {
		t.Fatal("retained actual creation context did not survive bounded response loss")
	}
	if peer.unexpected.Load() != 0 || peer.searches.Load() < 1 || peer.records.Load() < 1 || peer.accounts.Load() != 4+2*(peer.searches.Load()+peer.records.Load()) {
		t.Fatal("protected grouped account/provider inventory disagrees")
	}
	currentConnection, err := f.q.GetCRMConnectionByOrg(ctx, f.org)
	if err != nil || currentConnection.Generation != 5 || currentConnection.Status != "active" || currentConnection.ID != originalConnection.ID {
		t.Fatal("intentional connection revoke/re-enroll did not reach generation5")
	}
	closedRow, err := f.q.GetHTMLDocumentCreationResolutionForShare(ctx, generated.GetHTMLDocumentCreationResolutionForShareParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: closures[0].requestID})
	if err != nil || closedRow.State != "closed" || closedRow.TemplateID != template.ID || !closedRow.ResolvedAt.Valid {
		t.Fatal("stopped last refusal did not persist exact durable closed outcome")
	}
	var committedOutcomes, closedOutcomes, closureEvents int
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM html_document_creation_resolutions WHERE org_id=$1 AND state='committed'),(SELECT count(*) FROM html_document_creation_resolutions WHERE org_id=$1 AND state='closed'),(SELECT count(*) FROM events WHERE org_id=$1 AND actor_user_id=$2 AND kind='html.document.creation.closed' AND payload_json->>'request_id'=$3::text AND payload_json->>'template_id'=$4::text)`, f.org, f.user.ID, closedRow.RequestID, template.ID).Scan(&committedOutcomes, &closedOutcomes, &closureEvents); err != nil || committedOutcomes != 2 || closedOutcomes != 1 || closureEvents != 1 {
		t.Fatal("explicit stop duplicated terminal outcomes or lost actor-bound audit")
	} //nolint:rawsql -- exact disposable terminal cardinality
	artifactsProof := map[string]crmTemplateBrowserArtifactE2E{}
	artifactSHA := map[string]string{}
	docIDs := []uuid.UUID{}
	requestIDs := []uuid.UUID{}
	peer.mu.Lock()
	freshBodySHA := peer.freshBodySHA
	peer.mu.Unlock()
	if !htmlPreviewSHA256(freshBodySHA) {
		t.Fatal("successful grouped records lack their actual raw HTTP body digest")
	}
	for index, post := range successes {
		name := []string{"created", "recovered"}[index]
		proof := assertCRMTemplateBrowserCreationE2E(t, f, template, originalConnection, currentConnection, post, token, cookie, freshBodySHA, artifacts, name)
		artifactsProof[name] = proof
		artifactSHA[name+".pdf"] = proof.SHA256
		docIDs = append(docIDs, proof.DocumentID)
		requestIDs = append(requestIDs, proof.RequestID)
	}
	var requestRows, createdEvents, populationEvents, mail, intents, signatures int
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM html_document_creation_requests WHERE org_id=$1),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='document.created' AND document_id=ANY($2)),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='crm.template.population.created'),(SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM send_sealing_intents WHERE org_id=$1),(SELECT count(*) FROM signatures s JOIN documents d ON d.id=s.document_id WHERE d.org_id=$1)`, f.org, docIDs).Scan(&requestRows, &createdEvents, &populationEvents, &mail, &intents, &signatures); err != nil || requestRows != 2 || createdEvents != 2 || populationEvents != 2 || mail != 0 || intents != 0 || signatures != 0 {
		t.Fatal("initial browser created duplicates or dispatched a ceremony")
	} //nolint:rawsql -- full disposable tenant cardinality
	for _, post := range posts {
		if post.status != 409 {
			continue
		}
		if _, err := f.q.GetHTMLDocumentCreationRequest(ctx, generated.GetHTMLDocumentCreationRequestParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: post.in.RequestID}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("refused creation retained a committed request")
		}
		row, err := f.q.GetHTMLDocumentCreationResolutionForShare(ctx, generated.GetHTMLDocumentCreationResolutionForShareParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: post.in.RequestID})
		if post.in.RequestID == closedRow.RequestID {
			if err != nil || row.State != "closed" || row.ResolvedAt != closedRow.ResolvedAt {
				t.Fatal("last refusal closed outcome changed")
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("another refused nonce gained a terminal outcome")
		}
	}
	foreignAfter, err := f.q.GetDocument(ctx, generated.GetDocumentParams{ID: foreignDoc.ID, OrgID: foreignOrg.ID})
	foreignAfterJSON, _ := json.Marshal(foreignAfter)
	if err != nil || !bytes.Equal(foreignBefore, foreignAfterJSON) {
		t.Fatal("foreign draft changed")
	}
	if _, err := f.q.GetCRMConnectionByOrg(ctx, foreignOrg.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("foreign tenant gained CRM account")
	}
	for _, otherCookie := range []string{sameCookie, foreignCookie} {
		path := recoverPrefix + requestIDs[0].String()
		before, err := crmTemplateBrowserInventoryE2E(ctx, f)
		if err != nil {
			t.Fatal("snapshot before actor recovery")
		}
		r := submitSessionOperationE2E(f.s, http.MethodGet, path, "", otherCookie)
		after, err := crmTemplateBrowserInventoryE2E(ctx, f)
		if r.Code != 404 || err != nil || before != after || bytes.Contains(r.Body.Bytes(), []byte(docIDs[0].String())) || bytes.Contains(r.Body.Bytes(), []byte(crmTemplateBrowserManualE2E)) {
			t.Fatal("different actor recovery leaked or changed result")
		}
	}
	events, err := f.q.ListChainedEventsPageForOrg(ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	result := verifier.Result()
	if err != nil || !result.OK || !result.Complete || result.TotalChecked != len(events) {
		t.Fatal("initial browser audit chain invalid")
	}
	if objects.requests.Load() <= baselinePDFRequests {
		t.Fatal("successful browser creation did not use exact-version storage")
	}
	if barrier.requests.Load() != 6 {
		t.Fatal("stop/fresh review caused an additional PDF render")
	}
	// UI acknowledgement/manual retention belongs to the external browser
	// receipt; this safe backend proof covers the measured terminal mutation.
	stopped := map[string]any{"request_id": closedRow.RequestID, "org_id": f.org, "user_id": f.user.ID, "template_id": template.ID, "closed_at": closedRow.ResolvedAt.Time.UTC().Format(time.RFC3339Nano), "close_status": closures[0].status, "committed_outcomes": committedOutcomes, "closed_outcomes": closedOutcomes, "closure_audits": closureEvents, "no_provider_render_storage": true, "original_creation_pins_unchanged": true}
	receipt, _ := json.MarshalIndent(map[string]any{"result": "pass", "stopped_request": stopped, "close_status_counts": []int{closures[0].status}, "actual_render_requests": barrier.requests.Load(), "actualPostgreSQL": true, "actualRendererVersion": "8.36.0-hash.1", "mandatoryIsolatedPDFWorker": true, "builtFrontend": true, "protectedSyntheticCRMClient": true, "syntheticS3Provider": true, "org_id": f.org, "user_id": f.user.ID, "template_id": template.ID, "committed_request_ids": requestIDs, "committed_document_ids": docIDs, "artifacts": artifactsProof, "artifact_sha256": artifactSHA, "creation_status_counts": statuses, "recovery_status_counts": recoveries, "database_ledger_verified": true, "crm_mapping_review_verified_at_creation_generation": true, "current_generation_invalidates_prior_reviews": true, "fresh_provider_provenance_verified": true, "manual_values_and_wording_preserved": true, "optional_empty_present": true, "generated_fields_exact": true, "retained_fetch_context_live_at_release": true, "foreign_unchanged": true, "anonymous_and_other_actor_controls_refused": true, "different_actor_recovery_refused": true, "send_requests": sends, "email_deliveries": mail, "sealing_intents": intents, "signatures": signatures, "upstream_account_reads": peer.accounts.Load(), "upstream_search_reads": peer.searches.Load(), "upstream_record_reads": peer.records.Load(), "unexpected_upstream_reads": peer.unexpected.Load(), "content_expectations": map[string]string{"price": crmTemplateBrowserFreshE2E, "manual_reference": crmTemplateBrowserReferenceE2E, "manual_wording": crmTemplateBrowserManualE2E}, "live_provider": false, "human_pdf_visual_acceptance": false, "signing_acceptance": false, "deployment": false}, "", "  ")
	crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, "backend-receipt.json"), append(receipt, '\n'))
	t.Log("built initial population/recovery accepted with actual renderer and isolated worker; protected CRM/S3 synthetic, no Send/mail/live-provider/deployment claim")
}

func assertCRMTemplateBrowserCreationE2E(t *testing.T, f lifecycleAuthorizationFixture, template *generated.Template, originalConnection, currentConnection *generated.CrmConnection, post crmTemplateBrowserDispatchE2E, token, cookie, freshBodySHA, artifacts, name string) crmTemplateBrowserArtifactE2E {
	t.Helper()
	row, err := f.q.GetHTMLDocumentCreationRequest(f.ctx, generated.GetHTMLDocumentCreationRequestParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: post.in.RequestID})
	if err != nil || !row.CurrentDocumentID.Valid || row.ActorUserID != f.user.ID || row.TemplateID != template.ID {
		t.Fatal("committed ledger lacks original actor/template")
	}
	resolution, err := f.q.GetHTMLDocumentCreationResolutionForShare(f.ctx, generated.GetHTMLDocumentCreationResolutionForShareParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: post.in.RequestID})
	if err != nil || resolution.State != "committed" || resolution.TemplateID != row.TemplateID || !resolution.ResolvedAt.Time.Equal(row.CreatedAt.Time) {
		t.Fatal("committed registry changed original receipt identity/timestamp")
	}
	actor := authoring.Actor{OrgID: f.org, UserID: f.user.ID}
	digest, err := crmTemplateCreateInputDigest(actor, template.ID, post.in)
	if err != nil || digest != hex.EncodeToString(row.InputDigest) {
		t.Fatal("ledger changed the original complete command digest")
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: row.OriginalDocumentID, OrgID: f.org})
	if err != nil || doc.SenderID != f.user.ID || doc.Status != "draft" || !doc.RequiresSignature || doc.SentAt.Valid || doc.CompletedAt.Valid || doc.HtmlCurrentMaterializationSequence.Int32 != 1 || doc.HtmlReviewedAt.Valid || htmlsource.Validate(doc, false) != nil || !errors.Is(htmlsource.Validate(doc, true), htmlsource.ErrReviewRequired) {
		t.Fatal("new browser draft lost source/review/lifecycle invariants")
	}
	input, err := htmlsource.InputForCurrent(doc)
	expected := maps.Clone(map[string]string(post.in.Values))
	expected["price"] = crmTemplateBrowserFreshE2E
	expected["crm_note"] = ""
	if err != nil || !maps.Equal(input.Values, expected) || input.Values["manual_reference"] != crmTemplateBrowserReferenceE2E || !maps.Equal(input.Sections, map[string]string(post.in.Sections)) || len(input.Sections) != 1 || input.Sections["manual_scope"] != crmTemplateBrowserManualE2E || input.TemplateVersion != template.Version || input.TemplateContentSHA256 != hex.EncodeToString(template.HtmlContentSha256) || input.TemplateApprovedBy != f.user.ID {
		t.Fatal("created source changed mapped/manual/presence/approval inputs")
	}
	if _, present := input.Values["crm_note"]; !present {
		t.Fatal("empty scalar lost explicit presence")
	}
	materialized, err := htmlmaterialization.Current(f.ctx, f.q, doc)
	if err != nil || materialized == nil || materialized.Sequence != 1 || materialized.PageCount != 3 || hex.EncodeToString(materialized.SourceCommitment) != row.HtmlSourceCommitment || !bytes.Equal(materialized.PdfSha256, row.PdfSha256) || row.PageCount != 3 || row.HtmlMaterializationID != materialized.ID || materialized.PdfKey != doc.PdfStorageKey.String || materialized.PdfVersionID != doc.PdfStorageVersionID.String {
		t.Fatal("initial normalized materialization/request/PDF pins disagree")
	}
	policy, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || policy == nil || artifact == nil || artifact.Composition.BodyPages != 2 || artifact.Composition.FinalPages != 3 || artifact.Composition.OutputSHA256 != hex.EncodeToString(doc.PdfSha256) {
		t.Fatal("source3 signing geometry does not bind exact final PDF")
	}
	recipients, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
	if err != nil || len(recipients) != 2 || htmlsource.ValidateContractParties(doc, recipients) != nil {
		t.Fatal("created printed parties are not exact pinned recipients")
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, doc.ID)
	if err != nil || len(fields) != 2 || htmlsource.ValidateSigningFields(doc, fields, 3) != nil {
		t.Fatal("created fixed field pair is not bound to final page")
	}
	branding, err := f.q.GetDocumentBrandingOverride(f.ctx, doc.ID)
	if err != nil || htmlsource.ValidateSigningBranding(doc, branding) != nil {
		t.Fatal("approved frozen signing branding missing")
	}
	for _, r := range recipients {
		if r.SentAt.Valid || r.SignedAt.Valid {
			t.Fatal("creation dispatched a signer")
		}
	}
	bindings, err := f.q.ListVariableBindings(f.ctx, doc.ID)
	if err != nil || len(bindings) != 2 {
		t.Fatal("created mapping ledger incomplete")
	}
	for _, b := range bindings {
		path := map[string]string{"price": "value", "crm_note": "currency"}[b.VariableName]
		if path == "" || b.SourceKind != "crm.deal" || b.SourceRef != crmTemplateBrowserDealE2E || b.SourcePath != path {
			t.Fatal("mapping changed selected scalar")
		}
	}
	review, err := f.q.GetDocumentCRMMappingReview(f.ctx, generated.GetDocumentCRMMappingReviewParams{DocumentID: doc.ID, OrgID: f.org})
	matched, matchErr := crmreview.ReviewMatches(doc, bindings, review, originalConnection)
	fresh, freshErr := crmreview.ReviewMatches(doc, bindings, review, currentConnection)
	if err != nil || matchErr != nil || !matched || freshErr != nil || fresh || review.ReviewedBy != f.user.ID || review.ConnectionGeneration.Int64 != 2 || review.Origin != originalConnection.Origin {
		t.Fatal("preserved creation review did not bind original account or refuse its later rotation")
	}
	var payload []byte
	var versions, rows, snapshots, created int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT payload_json FROM events WHERE document_id=$1 AND kind='crm.template.population.created'),(SELECT count(*) FROM document_versions WHERE document_id=$1),(SELECT count(*) FROM html_document_materializations WHERE document_id=$1),(SELECT count(*) FROM html_document_materialization_snapshots WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.created')`, doc.ID).Scan(&payload, &versions, &rows, &snapshots, &created); err != nil || versions != 1 || rows != 1 || snapshots != 0 || created != 1 {
		t.Fatal("initial browser evidence cardinality invalid")
	} //nolint:rawsql -- exact synthetic cardinality
	var evidence struct {
		HumanConfirmed bool   `json:"human_confirmed"`
		Assurance      string `json:"assurance"`
		ReviewDigest   string `json:"review_digest"`
		Observations   []struct {
			crmDocumentMapping
			Proof *resolver.CRMValueObservation `json:"proof"`
		} `json:"observations"`
	}
	if json.Unmarshal(payload, &evidence) != nil || !evidence.HumanConfirmed || evidence.Assurance != "time-of-read" || evidence.ReviewDigest != post.in.CRMPopulation.ReviewedDigest || len(evidence.Observations) != 2 {
		t.Fatal("creation audit lost human confirmation")
	}
	seen := map[string]bool{}
	for _, item := range evidence.Observations {
		value, known := map[string]string{"price": crmTemplateBrowserFreshE2E, "crm_note": ""}[item.Variable]
		path := map[string]string{"price": "value", "crm_note": "currency"}[item.Variable]
		if !known || seen[item.Variable] || item.SourcePath != path || item.Proof == nil || item.Proof.ConnectionID != originalConnection.ID || item.Proof.Generation != "2" || item.Proof.Origin != originalConnection.Origin || item.Proof.CRMTeamID != crmTemplateBrowserTeamE2E || item.Proof.CRMUserID != crmTemplateBrowserUserE2E || item.SourceKind != "crm.deal" || item.SourceRef != crmTemplateBrowserDealE2E || item.Proof.ValueSHA256 != crmDocumentBrowserDigestE2E([]byte(value)) || item.Proof.BodySHA256 != freshBodySHA || item.Proof.ObservedAt.IsZero() || item.Proof.ObservedAt.After(row.CreatedAt.Time) || !item.Proof.ObservedAt.Add(45*time.Second).After(row.CreatedAt.Time) || item.Proof.RecordUpdatedAt.IsZero() {
			t.Fatal("creation audit differs from exact protected scalar/account provenance")
		}
		seen[item.Variable] = true
	}
	for _, private := range []string{token, cookie, post.in.CRMPopulation.ReviewReceipt, crmTemplateBrowserReferenceE2E, crmTemplateBrowserManualE2E, `"title":`, `"value":`} {
		encoded, _ := json.Marshal(private)
		if bytes.Contains(payload, []byte(private)) || bytes.Contains(payload, encoded[1:len(encoded)-1]) {
			t.Fatal("creation audit exposed credential/receipt/manual text/raw record")
		}
	}
	pdf, err := f.s.Storage.GetVerifiedVersion(f.ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
	if err != nil || len(pdf) == 0 || len(pdf) > 8<<20 || !bytes.HasPrefix(pdf, []byte("%PDF-")) || crmDocumentBrowserDigestE2E(pdf) != hex.EncodeToString(doc.PdfSha256) {
		t.Fatal("created exact-version bytes differ")
	}
	if pages, err := sanitize.PageCountWithContext(f.ctx, pdf); err != nil || pages != 3 {
		t.Fatal("actual composed artifact lacks three inspected pages")
	}
	assertHTMLRevisionReportE2E(t, doc.MetadataRedactionReport, doc.PdfSha256, 3)
	readback := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/templates/"+template.ID.String()+"/html/document-requests/"+post.in.RequestID.String(), "", cookie)
	var response struct {
		OrgID       uuid.UUID         `json:"org_id"`
		UserID      uuid.UUID         `json:"user_id"`
		RequestID   uuid.UUID         `json:"request_id"`
		InputDigest string            `json:"input_digest"`
		Creation    htmlCreationPins  `json:"creation"`
		Document    *documentResponse `json:"document"`
	}
	if readback.Code != 200 || readback.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(readback.Body.Bytes(), &response) != nil || response.OrgID != f.org || response.UserID != f.user.ID || response.RequestID != post.in.RequestID || response.InputDigest != digest || response.Creation != htmlCreationRequestPins(row) || response.Document == nil || response.Document.ID != doc.ID {
		t.Fatal("actual recovery lost original actor/current-vs-initial witness")
	}
	values := [][2]string{}
	for k, v := range input.Values {
		values = append(values, [2]string{k, v})
	}
	sort.Slice(values, func(i, j int) bool { return values[i][0] < values[j][0] })
	proof := crmTemplateBrowserArtifactE2E{crmDocumentBrowserArtifactE2E: crmDocumentBrowserArtifactE2E{SHA256: hex.EncodeToString(doc.PdfSha256), Bytes: len(pdf), Pages: 3, SourceCommitment: row.HtmlSourceCommitment, MaterializationRevision: 1, VariablesSHA256: crmTemplateBrowserTupleDigestE2E(t, values), SectionsSHA256: crmTemplateBrowserTupleDigestE2E(t, [][2]string{{"manual_scope", input.Sections["manual_scope"]}})}, DocumentID: doc.ID, RequestID: post.in.RequestID, InputDigest: digest, TemplateVersion: template.Version, TemplateContentSHA256: hex.EncodeToString(template.HtmlContentSha256)}
	crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, name+".pdf"), pdf)
	return proof
}
