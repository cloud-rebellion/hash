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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
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
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	crmDocumentBrowserTeamE2E    = "sales_browser_team_CUID2"
	crmDocumentBrowserUserE2E    = "sales_browser_user_CUID2"
	crmDocumentBrowserDealE2E    = "sales_browser_deal_CUID2"
	crmDocumentBrowserInitialE2E = "1290.2500"
	crmDocumentBrowserFreshE2E   = "1490.7500"
	crmDocumentBrowserDriftE2E   = "1590.1250"
	crmDocumentBrowserStaticE2E  = "Human reference ÅÄÖ - retained exactly"
	crmDocumentBrowserScopeE2E   = "Approved synthetic service scope. Changes require human review."
	crmDocumentBrowserManualE2E  = "Human negotiated scope: keep the existing service wording and support window.\nThe customer-approved text remains unchanged when the CRM price is applied."
	crmDocumentBrowserControlE2E = "/__hash_crm_document_fixture/control"
)

// The remote account, record and S3 provider are disposable source-shaped
// peers. All account checks, encryption, HTTP transport, authorization, SQL,
// renderer and mandatory isolated worker operations use production code.
// Neither this fixture nor its control path is included in normal builds.
type crmDocumentBrowserPeerE2E struct {
	mu         sync.Mutex
	token      string
	value      string
	updatedAt  time.Time
	accounts   atomic.Int64
	searches   atomic.Int64
	records    atomic.Int64
	unexpected atomic.Int64
}

func (p *crmDocumentBrowserPeerE2E) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+p.token {
		p.unexpected.Add(1)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/api/v1/auth/me" && r.URL.RawQuery == "" {
		p.accounts.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": crmDocumentBrowserUserE2E, "team_id": crmDocumentBrowserTeamE2E, "is_active": true, "role": "ADMIN"})
		return
	}
	p.mu.Lock()
	value, updated := p.value, p.updatedAt
	p.mu.Unlock()
	record := map[string]any{"id": crmDocumentBrowserDealE2E, "team_id": crmDocumentBrowserTeamE2E,
		"updated_at": updated.UTC().Format(time.RFC3339Nano), "title": "Synthetic reviewed service", "value": json.Number(value),
		"currency": "SEK", "stage": "PROPOSAL", "contact_id": nil, "company_id": nil, "assigned_to_id": nil}
	switch {
	case r.URL.Path == "/api/v1/deals/" && reflect.DeepEqual(r.URL.Query(), url.Values{"search": {""}, "limit": {"20"}, "offset": {"0"}}):
		p.searches.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{record}, "total": 1, "limit": 20, "offset": 0})
	case r.URL.Path == "/api/v1/deals/"+crmDocumentBrowserDealE2E && r.URL.RawQuery == "":
		p.records.Add(1)
		_ = json.NewEncoder(w).Encode(record)
	default:
		p.unexpected.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}
}

type crmDocumentBrowserCountsE2E struct {
	mu             sync.Mutex
	apply          []int
	manualRevision int
	PDFReview      int
	Send           int
	controls       []string
}

type crmDocumentBrowserStatusE2E struct {
	http.ResponseWriter
	status int
}

func (w *crmDocumentBrowserStatusE2E) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *crmDocumentBrowserStatusE2E) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func crmDocumentBrowserWriteE2E(t *testing.T, path string, body []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("create fresh private CRM browser artifact")
	}
	if _, err = f.Write(body); err != nil {
		_ = f.Close()
		t.Fatal("write private CRM browser artifact")
	}
	if err = f.Close(); err != nil {
		t.Fatal("close private CRM browser artifact")
	}
}

type crmDocumentBrowserArtifactE2E struct {
	SHA256                  string `json:"sha256"`
	Bytes                   int    `json:"bytes"`
	Pages                   int    `json:"pages"`
	SourceCommitment        string `json:"source_commitment"`
	MaterializationRevision int32  `json:"materialization_revision"`
	VariablesSHA256         string `json:"variables_sha256"`
	SectionsSHA256          string `json:"sections_sha256"`
}

func crmDocumentBrowserDigestE2E(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Explicit selection never skips a missing dependency and never uses a canned
// PDF. The task-owned TLS listener serves current built assets and ordinary
// routes. The host supplies the browser and returns only its completion marker.
func TestCRMDocumentWithExternalBrowserE2E(t *testing.T) {
	if os.Getenv("HASH_CRM_DOCUMENT_BROWSER_E2E") != "1" {
		t.Skip("explicit external CRM document browser fixture required")
	}
	for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_RENDERER_URL", "HASH_E2E_PDF_WORKER_PATH"} {
		if os.Getenv(name) == "" {
			t.Fatalf("selected CRM document browser fixture requires %s", name)
		}
	}
	base, err := url.Parse(os.Getenv("HASH_CRM_DOCUMENT_BROWSER_BASE"))
	if err != nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		t.Fatal("CRM document browser requires exact loopback HTTPS origin")
	}
	root, inputPath, donePath, artifacts := os.Getenv("HASH_CRM_DOCUMENT_BROWSER_FRONTEND"), os.Getenv("HASH_CRM_DOCUMENT_BROWSER_INPUT"), os.Getenv("HASH_CRM_DOCUMENT_BROWSER_DONE"), os.Getenv("HASH_CRM_DOCUMENT_BROWSER_ARTIFACTS")
	for _, path := range []string{root, inputPath, donePath, artifacts} {
		if !filepath.IsAbs(path) {
			t.Fatal("CRM document browser requires absolute task-owned paths")
		}
	}
	if inputPath == donePath {
		t.Fatal("private handoff and completion paths must differ")
	}
	for _, path := range []string{inputPath, donePath} {
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("CRM document browser handoff paths must be fresh")
		}
	}
	info, err := os.Stat(artifacts)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("CRM browser requires an existing private artifact directory")
	}
	target, err := url.Parse(os.Getenv("HASH_E2E_RENDERER_URL"))
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		t.Fatal("CRM browser requires explicit real renderer origin")
	}
	probe, err := (&http.Client{Timeout: 5 * time.Second}).Get(target.String() + "/version")
	if err != nil {
		t.Fatal("required exact renderer unavailable")
	}
	version, readErr := io.ReadAll(io.LimitReader(probe.Body, 256))
	_ = probe.Body.Close()
	if readErr != nil || probe.StatusCode != http.StatusOK || strings.TrimSpace(string(version)) != "8.36.0-hash.1" {
		t.Fatal("required exact renderer version differs")
	}

	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	ctx, cancel := context.WithTimeout(f.ctx, 280*time.Second)
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
	f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: "pro", ReviewRef: "synthetic CRM browser entitlement"}})
	f.s.Versions = versions.New(f.q)
	f.s.Sign = &sign.Engine{Pool: f.pool, Queries: f.q, PDF: render.NewGotenberg(target.String()), Audit: f.s.Audit}
	objectPeer := &htmlCreationStorageE2E{importStoragePeer: &importStoragePeer{objects: make(map[string][]byte)}}
	objectServer := httptest.NewServer(objectPeer)
	defer objectServer.Close()
	f.s.Storage, err = storage.New(ctx, storage.Config{Endpoint: strings.TrimPrefix(objectServer.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-crm-browser", SecretKey: "synthetic-crm-browser-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal("synthetic exact-version S3 client unavailable")
	}
	token := crmBrowserRandomHex(t)
	crmPeer := &crmDocumentBrowserPeerE2E{token: token, value: crmDocumentBrowserFreshE2E, updatedAt: time.Now().Add(-time.Minute).UTC()}
	crmServer := httptest.NewServer(crmPeer)
	defer crmServer.Close()
	f.s.CRMClient, err = crmconnection.NewClient(crmServer.URL, true)
	if err != nil {
		t.Fatal("protected synthetic CRM HTTP client unavailable")
	}
	f.s.CRMKeys, err = crmconnection.NewKeyring(crmBrowserRandomHex(t), "")
	if err != nil {
		t.Fatal("private synthetic CRM encryption keyring unavailable")
	}
	f.s.CRMOrigin = crmServer.URL
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	configure := func(generation int64) bool {
		candidate, _ := json.Marshal(crmConnectionInput{ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, ExpectedGeneration: strconv.FormatInt(generation, 10), Token: token})
		if w := submitSessionOperationE2E(f.s, http.MethodPut, "/api/v1/settings/crm/connection", string(candidate), cookie); w.Code != http.StatusOK {
			return false
		}
		enable, _ := json.Marshal(crmConnectionEnableInput{ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, ExpectedGeneration: strconv.FormatInt(generation+1, 10), CRMTeamID: crmDocumentBrowserTeamE2E, CRMUserID: crmDocumentBrowserUserE2E})
		return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/settings/crm/connection/enable", string(enable), cookie).Code == http.StatusOK
	}
	if !configure(0) {
		t.Fatal("seed actual disabled-candidate and explicit active CRM mapping")
	}
	connection, err := f.q.GetCRMConnectionByOrg(ctx, f.org)
	if err != nil || connection.Generation != 2 || connection.Status != "active" {
		t.Fatal("actual CRM enrollment did not retain generation two")
	}

	master := htmlmaster.Master{SchemaVersion: htmlmaster.SchemaVersion,
		HTML:     `<main><h1>Synthetic service proposal</h1><p>Reviewed price: <span data-hash-value="price"></span> SEK</p><p>Reference: <span data-hash-value="static_reference"></span></p><section class="page-break"><h2>Service scope</h2><div class="scope" data-hash-section="scope"></div></section></main>`,
		CSS:      `@page{size:A4;margin:20mm}body{font-family:Inter;font-size:12pt;line-height:1.5;color:#102038}.page-break{break-before:page;page-break-before:always}.scope{white-space:pre-wrap}`,
		Values:   []htmlmaster.Value{{Name: "price", Required: true, MaxChars: 100}, {Name: "static_reference", Required: true, MaxChars: 200}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: crmDocumentBrowserScopeE2E, MaxChars: 4096}}}
	compiled, err := htmlmaster.Compile(master)
	defaults := map[string]string{"price": crmDocumentBrowserInitialE2E, "static_reference": crmDocumentBrowserStaticE2E}
	if err != nil {
		t.Fatal("compile synthetic approved two-page design")
	}
	if _, err = compiled.Materialize(htmlmaster.Input{Values: defaults, Sections: map[string]string{}}); err != nil {
		t.Fatal("materialize bounded synthetic defaults")
	}
	masterJSON, _ := json.Marshal(master)
	defaultJSON, _ := json.Marshal(defaults)
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "Synthetic CRM reviewed service", HTMLMasterJSON: masterJSON, VariablesJSON: defaultJSON}, cookie)
	var templateDTO templateResponse
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &templateDTO) != nil {
		t.Fatalf("real-renderer design creation status=%d", w.Code)
	}
	template, err := f.q.GetHTMLTemplate(ctx, generated.GetHTMLTemplateParams{ID: templateDTO.ID, OrgID: f.org})
	if err != nil {
		t.Fatal("read real-renderer design")
	}
	preview := submitHTMLPreviewE2E(t, f, template, nil, cookie)
	if preview.Code != http.StatusOK {
		t.Fatalf("real owner preview status=%d", preview.Code)
	}
	approval := htmlApprovalInputE2E(template)
	approval.PreviewReceipt, approval.ExpectedPreviewPDFSHA256 = preview.Header().Get("X-Hash-Preview-Receipt"), preview.Header().Get("X-Hash-PDF-SHA256")
	if approval.PreviewReceipt == "" || !htmlPreviewSHA256(approval.ExpectedPreviewPDFSHA256) {
		t.Fatal("real preview did not issue exact artifact proof")
	}
	if w = submitHTMLTemplateE2E(t, f, "approve", template.ID, approval, cookie); w.Code != http.StatusOK {
		t.Fatalf("actual owner preview approval status=%d", w.Code)
	}
	creationInput := htmlCreationInputE2E(template)
	creationInput.Sections = htmlStringMap{"scope": crmDocumentBrowserScopeE2E}
	w = submitHTMLDocumentCreationE2E(t, f, template.ID, creationInput, cookie)
	var created struct {
		Document documentResponse `json:"document"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &created) != nil || created.Document.ID == uuid.Nil {
		t.Fatalf("real-rendered HTML creation status=%d", w.Code)
	}
	f.doc, err = f.q.GetDocument(ctx, generated.GetDocumentParams{ID: created.Document.ID, OrgID: f.org})
	if err != nil || !f.doc.RequiresSignature || !f.doc.HtmlCurrentPageCount.Valid || f.doc.HtmlCurrentPageCount.Int32 != 2 || f.doc.HtmlCurrentMaterializationSequence.Int32 != 1 {
		t.Fatal("created signature-mode draft must have exactly two real pages and registered origin")
	}
	originJSON := bytes.Clone(f.doc.HtmlSourceJson)
	recipientBody, _ := json.Marshal(createRecipientInput{Role: "signer", Name: "Synthetic service customer", Email: "customer@crm-browser.example.test", Locale: "en"})
	w = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/recipients", string(recipientBody), cookie)
	var recipient recipientResponse
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &recipient) != nil || recipient.ID == uuid.Nil {
		t.Fatal("seed actual authoring recipient")
	}
	initialRecipients, err := f.q.ListRecipientsByDocument(ctx, f.doc.ID)
	if err != nil || len(initialRecipients) != 1 {
		t.Fatal("read original draft recipient credential")
	}
	initialRecipientJSON, _ := json.Marshal(initialRecipients[0])
	commitment, err := htmlsource.Commitment(f.doc)
	if err != nil {
		t.Fatal("created source commitment unavailable")
	}
	fieldBody, _ := json.Marshal(addFieldInput{ExpectedPDFSHA256: hex.EncodeToString(f.doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment,
		RecipientID: recipient.ID.String(), Type: "text", Page: 1, XPct: 10, YPct: 70, WPct: 30, HPct: 5, Label: "Synthetic recipient note"})
	if w = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/fields", string(fieldBody), cookie); w.Code != http.StatusCreated {
		t.Fatalf("seed exact-PDF authoring field status=%d", w.Code)
	}
	foreignOrg, err := f.q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Foreign CRM document browser " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal("seed isolated foreign organization")
	}
	foreignUser, err := f.q.CreateUser(ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Name: "Foreign synthetic owner", Email: uuid.NewString() + "@crm-browser.example.test", Role: "owner"})
	if err != nil {
		t.Fatal("seed foreign browser owner")
	}
	foreignDoc, err := f.q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: foreignOrg.ID, SenderID: foreignUser.ID, Name: "Foreign synthetic proposal", BlocksJson: json.RawMessage(`{"version":1,"blocks":[{"id":"scope","type":"paragraph","text":"Foreign untouched proposal"}]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal("seed foreign browser draft")
	}
	foreignCookie := dsrSessionCookieE2E(t, f.s, foreignUser.ID, foreignUser.SessionGeneration, time.Hour)
	foreignBefore, _ := json.Marshal(foreignDoc)

	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal("current built frontend unavailable")
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
	routes := f.s.Routes()
	counts := &crmDocumentBrowserCountsE2E{}
	control := f.s.requireSameOriginMutation(auth.RequireSession(f.s.Cookies, SessionCookieName, f.q)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		u, ok := auth.FromContext(r.Context())
		if !ok || u.UserID != f.user.ID || u.OrgID != f.org || u.Role != "owner" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var in struct {
			Action string `json:"action"`
			Value  string `json:"value,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if decodeSignerJSON(r, &in) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		actor, err := f.s.sessionOwnerActor(r, u)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		controlCtx, stop := context.WithTimeout(r.Context(), authoring.MutationTimeout)
		defer stop()
		tx, err := f.pool.Begin(controlCtx)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer func() { _ = tx.Rollback(controlCtx) }()
		guard, err := authoring.LockOwner(controlCtx, tx, actor)
		if err != nil || guard.Recheck(controlCtx) != nil || tx.Commit(controlCtx) != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		counts.mu.Lock()
		defer counts.mu.Unlock()
		expected := []string{"set-value", "revoke", "restore-active"}
		if len(counts.controls) >= len(expected) || in.Action != expected[len(counts.controls)] || (in.Action == "set-value" && in.Value != crmDocumentBrowserDriftE2E) || (in.Action != "set-value" && in.Value != "") {
			w.WriteHeader(http.StatusConflict)
			return
		}
		success := false
		switch in.Action {
		case "set-value":
			crmPeer.mu.Lock()
			crmPeer.value, crmPeer.updatedAt = crmDocumentBrowserDriftE2E, time.Now().UTC()
			crmPeer.mu.Unlock()
			success = true
		case "revoke":
			body, _ := json.Marshal(map[string]any{"expected_org_id": f.org, "expected_user_id": f.user.ID, "expected_generation": "2"})
			success = submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/settings/crm/connection", string(body), cookie).Code == http.StatusOK
		case "restore-active":
			success = configure(3)
		}
		if !success {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		counts.controls = append(counts.controls, in.Action)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == crmDocumentBrowserControlE2E {
			control.ServeHTTP(w, r)
			return
		}
		tracked := &crmDocumentBrowserStatusE2E{ResponseWriter: w}
		routes.ServeHTTP(tracked, r)
		if r.Method != http.MethodPost {
			return
		}
		counts.mu.Lock()
		defer counts.mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/documents/" + f.doc.ID.String() + "/crm/apply":
			counts.apply = append(counts.apply, tracked.status)
		case "/api/v1/documents/" + f.doc.ID.String() + "/html/revisions":
			counts.manualRevision++
		case "/api/v1/documents/" + f.doc.ID.String() + "/html/review":
			counts.PDFReview++
		case "/api/v1/documents/" + f.doc.ID.String() + "/send":
			counts.Send++
		}
	})
	for _, rejectedCookie := range []string{"", foreignCookie} {
		r := httptest.NewRequest(http.MethodPost, base.String()+crmDocumentBrowserControlE2E, strings.NewReader(`{"action":"set-value","value":"1590.1250"}`)).WithContext(ctx)
		r.Header.Set("Origin", base.String())
		if rejectedCookie != "" {
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rejectedCookie})
		}
		refused := httptest.NewRecorder()
		handler.ServeHTTP(refused, r)
		if refused.Code != http.StatusUnauthorized && refused.Code != http.StatusForbidden {
			t.Fatal("task control failed anonymous or foreign-actor refusal")
		}
	}
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if err != nil {
		t.Fatal("task HTTPS listener unavailable")
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	packet, _ := json.Marshal(map[string]any{"base": base.String(), "cookieName": SessionCookieName, "cookie": cookie, "foreignCookie": foreignCookie,
		"orgID": f.org, "userID": f.user.ID, "foreignOrgID": foreignOrg.ID, "foreignUserID": foreignUser.ID, "documentID": f.doc.ID,
		"foreignDocumentID": foreignDoc.ID, "dealID": crmDocumentBrowserDealE2E, "variable": "price", "initialValue": crmDocumentBrowserInitialE2E,
		"observedValue": crmDocumentBrowserFreshE2E, "driftValue": crmDocumentBrowserDriftE2E, "sectionName": "scope", "manualWording": crmDocumentBrowserManualE2E,
		"controlPath": crmDocumentBrowserControlE2E})
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
				t.Fatal("external browser did not accept CRM document journey")
			}
			break
		}
		if !os.IsNotExist(err) {
			t.Fatal("external browser completion marker unavailable")
		}
		select {
		case <-ctx.Done():
			t.Fatal("external CRM document browser deadline exceeded")
		case <-time.After(100 * time.Millisecond):
		}
	}

	final, err := f.q.GetDocument(ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil || final.Status != "draft" || !final.RequiresSignature || final.SentAt.Valid || final.CompletedAt.Valid || final.FinalPdfKey.Valid || final.HtmlCurrentMaterializationSequence.Int32 != 3 || !bytes.Equal(final.HtmlSourceJson, originJSON) || htmlsource.Validate(final, true) != nil {
		t.Fatal("browser did not retain reviewed draft, immutable origin and exact final revision")
	}
	if current, err := htmlmaterialization.Current(ctx, f.q, final); err != nil || current == nil || current.Sequence != 3 {
		t.Fatal("final normalized current materialization disagrees")
	}
	finalInput, err := htmlsource.InputForCurrent(final)
	if err != nil || !reflect.DeepEqual(finalInput.Values, map[string]string{"price": crmDocumentBrowserDriftE2E, "static_reference": crmDocumentBrowserStaticE2E}) || finalInput.Sections["scope"] != crmDocumentBrowserManualE2E || len(finalInput.Sections) != 1 {
		t.Fatal("mapped scalar or untouched manual values/section were lost")
	}
	rows, err := f.q.ListHTMLDocumentMaterializations(ctx, generated.ListHTMLDocumentMaterializationsParams{DocumentID: final.ID, OrgID: f.org, RowLimit: 10})
	if err != nil || len(rows) != 3 {
		t.Fatal("refused or mapping-only writes added unexpected PDF history")
	}
	artifactProofs := map[string]crmDocumentBrowserArtifactE2E{}
	artifactHashes := map[string]string{}
	for index, name := range []string{"initial", "manual", "applied"} {
		sequence := int32(index + 1)
		row, err := f.q.GetHTMLDocumentMaterialization(ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: final.ID, OrgID: f.org, Sequence: sequence})
		if err != nil || row.PageCount != 2 || row.CreatedBy != f.user.ID {
			t.Fatal("retained PDF history lacks exact pages/original actor")
		}
		historical, err := htmlmaterialization.HistoricalDocument(final, row)
		if err != nil {
			t.Fatal("retained source/PDF history validation failed")
		}
		input, err := htmlsource.InputForCurrent(historical)
		wantedPrice, wantedScope := crmDocumentBrowserInitialE2E, crmDocumentBrowserScopeE2E
		if sequence >= 2 {
			wantedScope = crmDocumentBrowserManualE2E
		}
		if sequence == 3 {
			wantedPrice = crmDocumentBrowserDriftE2E
		}
		if err != nil || input.Values["price"] != wantedPrice || input.Values["static_reference"] != crmDocumentBrowserStaticE2E || input.Sections["scope"] != wantedScope || len(input.Values) != 2 || len(input.Sections) != 1 {
			t.Fatal("retained revision lost exact declared values or approved/manual scope")
		}
		pdf, err := f.s.Storage.GetVerifiedVersion(ctx, row.PdfKey, row.PdfVersionID, row.PdfSha256)
		if err != nil || len(pdf) == 0 || len(pdf) > 8<<20 || !bytes.HasPrefix(pdf, []byte("%PDF-")) || crmDocumentBrowserDigestE2E(pdf) != hex.EncodeToString(row.PdfSha256) {
			t.Fatal("retained exact-version PDF bytes do not match registered digest")
		}
		if pages, err := sanitize.PageCountWithContext(ctx, pdf); err != nil || pages != 2 {
			t.Fatal("real retained PDF does not contain exactly two inspected pages")
		}
		assertHTMLRevisionReportE2E(t, row.MetadataRedactionReport, row.PdfSha256, 2)
		// Match the external browser's canonical sorted name/text tuple digest.
		valuesJSON, _ := json.Marshal([][2]string{{"price", input.Values["price"]}, {"static_reference", input.Values["static_reference"]}})
		sectionsJSON, _ := json.Marshal([][2]string{{"scope", input.Sections["scope"]}})
		proof := crmDocumentBrowserArtifactE2E{SHA256: hex.EncodeToString(row.PdfSha256), Bytes: len(pdf), Pages: 2,
			SourceCommitment: hex.EncodeToString(row.SourceCommitment), MaterializationRevision: sequence,
			VariablesSHA256: crmDocumentBrowserDigestE2E(valuesJSON), SectionsSHA256: crmDocumentBrowserDigestE2E(sectionsJSON)}
		artifactProofs[name] = proof
		artifactHashes[name+".pdf"] = proof.SHA256
		crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, name+".pdf"), pdf)
	}
	if artifactProofs["initial"].SHA256 == artifactProofs["manual"].SHA256 || artifactProofs["manual"].SHA256 == artifactProofs["applied"].SHA256 || artifactProofs["initial"].SourceCommitment == artifactProofs["manual"].SourceCommitment || artifactProofs["manual"].SourceCommitment == artifactProofs["applied"].SourceCommitment {
		t.Fatal("actual visible content revisions did not produce distinct source/PDF commitments")
	}
	fields, err := f.q.ListFieldsByDocument(ctx, final.ID)
	if err != nil || len(fields) != 0 {
		t.Fatal("new PDF revisions retained obsolete placement fields")
	}
	recipients, err := f.q.ListRecipientsByDocument(ctx, final.ID)
	if err != nil || len(recipients) != 1 || recipients[0].ID != recipient.ID || recipients[0].SentAt.Valid || recipients[0].SignedAt.Valid {
		t.Fatal("CRM revision generated invitations or changed recipient identity")
	}
	finalRecipientJSON, _ := json.Marshal(recipients[0])
	if !bytes.Equal(initialRecipientJSON, finalRecipientJSON) {
		t.Fatal("CRM revision changed the original draft recipient or credential")
	}
	connection, err = f.q.GetCRMConnectionByOrg(ctx, f.org)
	if err != nil || connection.Generation != 5 || connection.Status != "active" || len(connection.CredentialCiphertext) == 0 || connection.CrmTeamID != crmDocumentBrowserTeamE2E || connection.CrmUserID != crmDocumentBrowserUserE2E || connection.Origin != crmServer.URL {
		t.Fatal("actual revoke/re-enroll failed pinned active generation five")
	}
	bindings, err := f.q.ListVariableBindings(ctx, final.ID)
	if err != nil || len(bindings) != 1 || bindings[0].VariableName != "price" || bindings[0].SourceKind != "crm.deal" || bindings[0].SourceRef != crmDocumentBrowserDealE2E || bindings[0].SourcePath != "value" {
		t.Fatal("final selected mapping ledger differs from reviewed record")
	}
	review, err := f.q.GetDocumentCRMMappingReview(ctx, generated.GetDocumentCRMMappingReviewParams{DocumentID: final.ID, OrgID: f.org})
	matched, matchErr := crmreview.ReviewMatches(final, bindings, review, connection)
	if err != nil || matchErr != nil || !matched || !review.HasMappings || review.ReviewedBy != f.user.ID || review.ConnectionGeneration.Int64 != 5 || review.Origin != crmServer.URL {
		t.Fatal("uncertain-write recovery did not retain actual reviewed account/content lineage")
	}
	if _, err = f.q.GetCRMConnectionByOrg(ctx, foreignOrg.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("foreign account substitution created a CRM connection")
	}
	foreignAfter, err := f.q.GetDocument(ctx, generated.GetDocumentParams{ID: foreignDoc.ID, OrgID: foreignOrg.ID})
	foreignAfterJSON, _ := json.Marshal(foreignAfter)
	if err != nil || !bytes.Equal(foreignBefore, foreignAfterJSON) {
		t.Fatal("foreign browser draft changed")
	}
	var appliedEvents, sentEvents, observedEvents, outbox, intents, signatures, wrongActor int
	if err = f.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind='crm.variables.applied'),
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind IN ('document.sent','recipient.invited')),
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind='crm.variables.observed'),
		(SELECT count(*) FROM email_deliveries WHERE to_email=$2),
		(SELECT count(*) FROM send_sealing_intents WHERE document_id=$1),
		(SELECT count(*) FROM signatures WHERE document_id=$1),
		(SELECT count(*) FROM events WHERE document_id=$1 AND actor_user_id IS DISTINCT FROM $3)`, final.ID, recipient.Email, f.user.ID).Scan(&appliedEvents, &sentEvents, &observedEvents, &outbox, &intents, &signatures, &wrongActor); err != nil || appliedEvents != 3 || sentEvents != 0 || observedEvents != 0 || outbox != 0 || intents != 0 || signatures != 0 || wrongActor != 0 { //nolint:rawsql -- exact synthetic draft effect inventory
		t.Fatal("browser escaped confirmed apply, original actor or no-send/no-mail/no-signature scope")
	}
	auditRows, err := f.pool.Query(ctx, `SELECT payload_json FROM events WHERE document_id=$1 AND kind='crm.variables.applied' ORDER BY created_at,id`, final.ID) //nolint:rawsql -- exact safe provenance assertion
	if err != nil {
		t.Fatal("read exact CRM apply audit")
	}
	index := 0
	for auditRows.Next() {
		var raw []byte
		if auditRows.Scan(&raw) != nil || bytes.Contains(raw, []byte(token)) || bytes.Contains(raw, []byte(crmDocumentBrowserDriftE2E)) || bytes.Contains(raw, []byte(`"title":`)) {
			auditRows.Close()
			t.Fatal("apply audit exposed native provider values or credentials")
		}
		var payload struct {
			HumanConfirmed bool   `json:"human_confirmed"`
			ContentChanged bool   `json:"content_changed"`
			HasMappings    bool   `json:"has_mappings"`
			Assurance      string `json:"assurance"`
			PDFSHA256      string `json:"pdf_sha256"`
			Observations   []struct {
				crmDocumentMapping
				Proof resolver.CRMValueObservation `json:"proof"`
			} `json:"observations"`
		}
		if json.Unmarshal(raw, &payload) != nil || index > 2 || !payload.HumanConfirmed || payload.Assurance != "time-of-read" || payload.ContentChanged != (index == 0) || payload.HasMappings != (index != 1) || payload.PDFSHA256 != artifactProofs["applied"].SHA256 || len(payload.Observations) != map[bool]int{true: 1, false: 0}[index != 1] {
			auditRows.Close()
			t.Fatal("apply audit does not match content/mapping-only transitions")
		}
		for _, item := range payload.Observations {
			generation := "2"
			if index == 2 {
				generation = "5"
			}
			if item.Variable != "price" || item.SourceRef != crmDocumentBrowserDealE2E || item.SourceKind != "crm.deal" || item.SourcePath != "value" || item.Proof.ConnectionID != connection.ID || item.Proof.Generation != generation || item.Proof.Origin != crmServer.URL || item.Proof.CRMTeamID != crmDocumentBrowserTeamE2E || item.Proof.CRMUserID != crmDocumentBrowserUserE2E || item.Proof.ValueSHA256 != crmDocumentBrowserDigestE2E([]byte(crmDocumentBrowserDriftE2E)) || !htmlPreviewSHA256(item.Proof.BodySHA256) || item.Proof.ObservedAt.IsZero() || item.Proof.RecordUpdatedAt.IsZero() {
				auditRows.Close()
				t.Fatal("apply audit lost selected scalar/account/source provenance")
			}
		}
		index++
	}
	auditErr := auditRows.Err()
	auditRows.Close()
	if auditErr != nil || index != 3 {
		t.Fatal("CRM apply audit inventory incomplete")
	}
	events, err := f.q.ListChainedEventsPageForOrg(ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal("read synthetic audit chain")
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	if result := verifier.Result(); !result.OK || !result.Complete || result.TotalChecked != len(events) {
		t.Fatal("CRM browser durable audit chain invalid")
	}
	counts.mu.Lock()
	applyStatuses := append([]int(nil), counts.apply...)
	controls := append([]string(nil), counts.controls...)
	manualRevision, PDFReview, sends := counts.manualRevision, counts.PDFReview, counts.Send
	counts.mu.Unlock()
	if !reflect.DeepEqual(applyStatuses, []int{409, 409, 200, 200, 200}) || !reflect.DeepEqual(controls, []string{"set-value", "revoke", "restore-active"}) || manualRevision != 1 || PDFReview != 1 || sends != 0 || crmPeer.unexpected.Load() != 0 || crmPeer.searches.Load() < 1 || crmPeer.records.Load() < 1 || crmPeer.accounts.Load() != 4+2*(crmPeer.searches.Load()+crmPeer.records.Load()) {
		t.Fatal("browser dispatch/control/provider inventory differs from bounded journey")
	}
	receipt, _ := json.MarshalIndent(map[string]any{"result": "pass", "actualPostgreSQL": true, "actualRendererVersion": "8.36.0-hash.1", "mandatoryIsolatedPDFWorker": true,
		"builtFrontend": true, "protectedSyntheticCRMClient": true, "syntheticS3Provider": true, "exactVersionedPDFReads": true,
		"artifact_sha256": artifactHashes, "artifacts": artifactProofs, "org_id": f.org, "user_id": f.user.ID, "document_id": final.ID,
		"content_expectations": map[string]string{"initial_value": crmDocumentBrowserInitialE2E, "applied_value": crmDocumentBrowserDriftE2E,
			"initial_wording": crmDocumentBrowserScopeE2E, "manual_wording": crmDocumentBrowserManualE2E, "static_reference": crmDocumentBrowserStaticE2E},
		"finalStatus": final.Status, "finalMaterializationRevision": 3, "finalPDFSHA256": artifactProofs["applied"].SHA256, "finalSourceCommitment": artifactProofs["applied"].SourceCommitment,
		"finalConnectionGeneration": "5", "finalConnectionStatus": connection.Status, "finalConnectionID": connection.ID,
		"crmOrigin": connection.Origin, "crmTeamID": connection.CrmTeamID, "crmUserID": connection.CrmUserID,
		"selectedRecordKind": "crm.deal", "selectedRecordID": crmDocumentBrowserDealE2E, "selectedScalar": "value", "mappedVariable": "price",
		"mappedValueSHA256": crmDocumentBrowserDigestE2E([]byte(crmDocumentBrowserDriftE2E)), "manualSectionPreserved": true, "unmappedVariablesPreserved": true,
		"immutableOriginPreserved": true, "historyCount": 3, "obsoleteFieldsCleared": true, "exactCurrentPDFReviewed": true,
		"mappingReviewMatched": true, "finalBindingCount": 1, "foreignDocumentUnchanged": true, "foreignConnectionAbsent": true,
		"anonymousAndForeignControlRefused": true, "applyStatuses": applyStatuses, "manualRevisionRequests": manualRevision, "PDFReviewRequests": PDFReview,
		"sendRequests": sends, "appliedAuditEvents": appliedEvents, "queuedMail": outbox, "signatures": signatures, "sealingIntents": intents,
		"upstreamAccountReads": crmPeer.accounts.Load(), "upstreamSearchReads": crmPeer.searches.Load(), "upstreamRecordReads": crmPeer.records.Load(), "unexpectedUpstreamReads": crmPeer.unexpected.Load(),
		"liveProviderAcceptance": false, "humanPDFVisualAcceptance": false, "signingAcceptance": false, "initialTemplatePrefillAcceptance": false, "deploymentAcceptance": false}, "", "  ")
	crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, "backend-receipt.json"), append(receipt, '\n'))
	t.Log("actual built salesperson UI/HTTPS/PostgreSQL/Chromium/isolated worker accepted reviewed scalar Apply with retained manual scope and three exact two-page PDFs; CRM/S3 peers synthetic, no Send/signing/live-provider/deployment acceptance")
}
