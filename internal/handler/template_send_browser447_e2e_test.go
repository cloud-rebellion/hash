//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Passive status/session observations only. The callback cookie stays in
// memory for independent read-only sender-route oracles AFTER browser completion;
// it is never handed to the browser, written or logged. No body is intercepted.
type template447HTTP struct {
	mu        sync.Mutex
	auth      *oidc439Routes
	template  uuid.UUID
	document  uuid.UUID
	cookie    string
	statuses  map[string][]int
	faults    int
	downloads *packageBrowserNativeDownloads419
}

func (c *template447HTTP) serve(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.downloads != nil {
			c.downloads.observe419(r)
		}
		observed := &oidc439StatusWriter{ResponseWriter: w}
		next.ServeHTTP(observed, r)
		if r.URL.Path == "/auth/login" || r.URL.Path == "/auth/callback" || r.URL.Path == "/auth/logout" || r.URL.Path == "/api/v1/me" {
			c.auth.observe(r, observed)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		status := observed.status
		if status == 0 {
			status = http.StatusOK
		}
		if r.Method == http.MethodGet && r.URL.Path == "/auth/callback" && status == http.StatusFound {
			for _, cookie := range (&http.Response{Header: observed.Header()}).Cookies() {
				if cookie.Name == SessionCookieName && cookie.Value != "" {
					if c.cookie != "" {
						c.faults++
					}
					c.cookie = cookie.Value
				}
			}
		}
		// Public recipient requests have no staff cookie; only the genuine
		// view/sign operations are admitted mutations in this one-attempt case.
		if strings.HasPrefix(r.URL.Path, "/sign/") {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				return
			}
			class := ""
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/view") {
				class = "view"
			}
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sign") {
				class = "sign"
			}
			if class == "" || len(c.statuses[class]) >= 32 {
				c.faults++
				return
			}
			c.statuses[class] = append(c.statuses[class], status)
			return
		}
		class := ""
		if r.URL.Path == "/api/v1/templates/"+c.template.String()+"/html/documents" && r.Method == http.MethodPost {
			class = "create"
		} else if strings.HasPrefix(r.URL.Path, "/api/v1/documents/") {
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/documents/"), "/")
			id, err := uuid.Parse(parts[0])
			if err != nil || id == uuid.Nil {
				c.faults++
				return
			}
			if c.document != uuid.Nil && c.document != id {
				c.faults++
			}
			c.document = id
			switch strings.Join(parts[1:], "/") {
			case "":
				class = "document"
			case "html/source":
				class = "source"
			case "html/history":
				class = "history"
			case "pdf":
				class = "pdf"
			case "html/revisions/1/source":
				class = "history_source"
			case "html/revisions/1/pdf":
				class = "history_pdf"
			case "html/review":
				class = "review"
			case "send":
				class = "send"
			default:
				// The ordinary document page also loads recipients, fields,
				// comments and package metadata. Those genuine GETs remain
				// delegated, not additional selected source/PDF/history claims.
				if r.Method != http.MethodGet {
					c.faults++
				}
				return
			}
			if (class == "review" || class == "send") && r.Method != http.MethodPost || (class != "review" && class != "send") && r.Method != http.MethodGet {
				c.faults++
			}
		} else if r.Method != http.MethodGet && r.Method != http.MethodHead && r.URL.Path != "/auth/logout" {
			c.faults++
		}
		if class == "" {
			return
		}
		cookie, err := r.Cookie(SessionCookieName)
		var payload auth.SessionPayload
		if err != nil {
			c.faults++
		} else if raw, err := c.auth.cookies.Verify(cookie.Value); err != nil || json.Unmarshal(raw, &payload) != nil || payload.UserID != c.auth.userID {
			c.faults++
		}
		if len(c.statuses[class]) >= 32 {
			c.faults++
			return
		}
		c.statuses[class] = append(c.statuses[class], status)
	})
}

func (c *template447HTTP) snapshot() (uuid.UUID, string, map[string][]int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string][]int, len(c.statuses))
	for key, values := range c.statuses {
		out[key] = append([]int(nil), values...)
	}
	return c.document, c.cookie, out, c.faults
}

// Controlled same-draft sender-template/Send/signing journey. Owner creation
// and real-rendered template approval below are SETUP, not owner UI proof.
// The unchanged443 helpers provide real HTTPS OIDC with no cookie bootstrap.
// The inherited90s fixture owns setup+browser+oracles; no context is extended.
func TestOrdinaryOIDCTemplateSendCompleteWithExternalBrowser447E2E(t *testing.T) {
	if os.Getenv("HASH_TEMPLATE_SEND_BROWSER_E2E") != "1" {
		t.Skip("explicit external template browser fixture required")
	}
	started := time.Now()
	for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_PDF_WORKER_PATH", "HASH_E2E_RENDERER_URL", "HASH_E2E_RENDERER_IMAGE_ID"} {
		if os.Getenv(name) == "" {
			t.Fatalf("selected template fixture requires %s", name)
		}
	}
	base := oidc439Origin(t, os.Getenv("HASH_OIDC_BROWSER_BASE"))
	issuer := oidc439Origin(t, os.Getenv("HASH_OIDC_BROWSER_ISSUER"))
	if base.Host != "127.0.0.1:8443" || issuer.Host != "127.0.0.1:8444" {
		t.Fatal("fixed owned TLS origins required")
	}
	frontend, input, done, artifacts := os.Getenv("HASH_OIDC_BROWSER_FRONTEND"), os.Getenv("HASH_OIDC_BROWSER_INPUT"), os.Getenv("HASH_OIDC_BROWSER_DONE"), os.Getenv("HASH_OIDC_BROWSER_ARTIFACTS")
	for _, path := range []string{frontend, input, done, artifacts} {
		if !filepath.IsAbs(path) {
			t.Fatal("absolute owned paths required")
		}
	}
	if input == done || filepath.Dir(input) != filepath.Dir(done) {
		t.Fatal("distinct sibling private handoffs required")
	}
	for _, path := range []string{input, done, filepath.Join(artifacts, "template-native447.json"), filepath.Join(artifacts, "template-approval447.pdf"), filepath.Join(artifacts, "template-created447.pdf")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("fresh private template artifacts required")
		}
	}
	info, err := os.Lstat(artifacts)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private artifact directory required")
	}
	files := 0
	err = filepath.WalkDir(frontend, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return os.ErrInvalid
		}
		if !entry.IsDir() {
			if !entry.Type().IsRegular() {
				return os.ErrInvalid
			}
			files++
		}
		return nil
	})
	if err != nil || files != 150 {
		t.Fatal("selected whole150-file production SPA required")
	}
	shell, err := os.ReadFile(filepath.Join(frontend, "index.html"))
	if err != nil || len(shell) == 0 || len(shell) > 1<<20 {
		t.Fatal("qualified production shell required")
	}
	q := newOwnedPublicReadFixtureProfileV1(t, false, true)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	deadline, ok := f.ctx.Deadline()
	if !ok || time.Until(deadline) <= 5*time.Second {
		t.Fatal("inherited native90s remaining deadline unavailable")
	}
	var server, migration int
	err = f.pool.QueryRow(f.ctx, `SELECT current_setting('server_version_num')::integer,(SELECT version_id FROM (SELECT DISTINCT ON(version_id) id,version_id,is_applied FROM goose_db_version ORDER BY version_id,id DESC) x WHERE is_applied ORDER BY id DESC LIMIT 1)`).Scan(&server, &migration)
	if err != nil || server != 160015 || migration != 113 {
		t.Fatal("actual PG16.15/current113 state required")
	}
	target, err := url.Parse(os.Getenv("HASH_E2E_RENDERER_URL"))
	if err != nil || target.Scheme != "http" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		t.Fatal("exact owned renderer origin required")
	}
	probeRequest, err := http.NewRequestWithContext(f.ctx, http.MethodGet, target.String()+"/version", nil)
	if err != nil {
		t.Fatal("create renderer version probe")
	}
	probe, err := (&http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(probeRequest)
	if err != nil {
		t.Fatal("actual renderer unavailable")
	}
	version, readErr := io.ReadAll(io.LimitReader(probe.Body, 257))
	closeErr := probe.Body.Close()
	if readErr != nil || closeErr != nil || probe.StatusCode != http.StatusOK || len(version) > 256 || strings.TrimSpace(string(version)) != "8.36.0-hash.5" {
		t.Fatal("actual renderer version differs")
	}
	// The constructor's unrelated approved design is a synthetic baseline.
	// Only the NEW selected design below is claimed actual-renderer approved.
	f.s.PublicURL = base.String()
	f.s.Sign.BaseURL = base.String()
	f.s.Send.PublicURL = base.String()
	f.s.PrivacyPolicyURL = base.String() + "/legal/privacy"
	f.s.Sign.PDF = render.NewGotenberg(target.String())
	if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal("configure controlled malware peer policy")
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error("restore malware policy", err)
		}
	})
	seed, _, _ := testfixture.HTMLContract(t)
	master, err := htmlmaster.Decode(seed.MasterJSON)
	if err != nil {
		t.Fatal("decode existing contract fixture")
	}
	master.SchemaVersion, master.SigningPage = htmlmaster.SigningPageSchemaVersion, testfixture.BrandedSigningPolicy()
	master.CSS = `@page {size:A4; margin:20mm;} p {margin:0 0 7pt; font-size:9pt; line-height:11pt;} section {font-size:9pt; line-height:11pt; white-space:pre-wrap;}`
	master.Sections = []htmlmaster.Section{{Name: "delivery_terms", DefaultText: "Approved delivery wording444.", MaxChars: 500}}
	master.ContractProfile.Terms = append(master.ContractProfile.Terms, htmlmaster.ContractTerm{Name: "delivery_terms", Section: "delivery_terms"})
	master.HTML += `<section data-hash-section="delivery_terms"></section>`
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal("encode declared schema3 design")
	}
	defaults, err := json.Marshal(seed.Values)
	if err != nil {
		t.Fatal("encode approved defaults")
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, defaults)
	if err != nil {
		t.Fatal("canonical schema3 design invalid")
	}
	created := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "OIDC444 approved service design", HTMLMasterJSON: canonical.MasterJSON, VariablesJSON: canonical.DefaultsJSON}, q.cookie)
	var dto templateResponse
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &dto) != nil || dto.ID == uuid.Nil {
		t.Fatal("native owner design creation failed")
	}
	template, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: dto.ID, OrgID: f.org})
	if err != nil {
		t.Fatal("read created selected design")
	}
	approvalPDF := approveBrandedDesignE2E(t, f, template, q.storagePeer, q.cookie)
	if len(approvalPDF) == 0 || len(approvalPDF) > 4<<20 {
		t.Fatal("approval PDF exceeds original artifact bound")
	}
	template, err = f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: dto.ID, OrgID: f.org})
	if err != nil || template == nil || !bytes.Equal(template.HtmlContentSha256, mustDecodeHex444(t, canonical.SHA256)) {
		t.Fatal("selected canonical design differs")
	}
	approved, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: template.Version})
	if err != nil || approved == nil || !approved.ApprovedAt.Valid || !approved.ApprovedBy.Valid || uuid.UUID(approved.ApprovedBy.Bytes) != f.user.ID || !bytes.Equal(approved.ContentSha256, template.HtmlContentSha256) {
		t.Fatal("exact native owner approval missing")
	}
	q.template = template
	strict := &completedPackagePeer248{main: &packageRetentionNativePeer240{base: q.storagePeer, until: map[string]time.Time{}, entered: make(chan struct{}), getDone: make(chan struct{})}, originalKeys: map[string]struct{}{}, until: map[string]time.Time{}}
	objectsPeer := &template447Storage{strict: strict, org: f.org}
	objects := httptest.NewServer(objectsPeer)
	t.Cleanup(objects.Close)
	retainedClient, err := storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-template447", SecretKey: "synthetic-template447-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal("controlled retained SDK peer unavailable")
	}
	f.s.Storage, f.s.Send.Storage, f.s.Sign.Storage = retainedClient, retainedClient, retainedClient
	f.s.ActionSecret = "synthetic-template447-action-key"
	f.s.Sign.ActionSecret = f.s.ActionSecret
	f.s.Evidence = &evidence.Builder{Q: f.q, Storage: retainedClient, Versions: f.s.Versions, Signer: f.s.Sign.Signer, PublicKeyPEM: f.s.Sign.Signer.PublicKeyPEM(), CertificateTrustedPublicKeys: []string{f.s.Sign.Signer.PublicKeyBase64()}, Issuer: "Controlled ordinary template447"}
	expectedValues := maps.Clone(seed.Values)
	expectedValues["provider_company"], expectedValues["customer_company"] = "Sender444 Provider AB", "Sender444 Customer AB"
	expectedSections := map[string]string{"delivery_terms": "Sender reviewed delivery wording444."}
	initialOwner, err := f.q.GetUser(f.ctx, f.user.ID)
	if err != nil {
		t.Fatal("read original owner")
	}
	invite, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@template444.example.test", Name: "Invited sender444", Role: "sender"})
	if err != nil || invite == nil || invite.ZitadelSub.Valid {
		t.Fatal("unbound invited sender required")
	}
	beforeEvents, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil || len(beforeEvents) >= 98 {
		t.Fatal("bounded original audit baseline unavailable")
	}
	var beforeTemplates string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM templates x WHERE org_id=$1),(SELECT jsonb_agg(to_jsonb(x) ORDER BY template_id,version) FROM html_template_revisions x WHERE org_id=$1))::text`, f.org).Scan(&beforeTemplates); err != nil {
		t.Fatal("capture approved design baseline")
	}
	var baseline [7]int64
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM orgs),(SELECT count(*) FROM users),(SELECT count(*) FROM documents),(SELECT count(*) FROM recipients),(SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM signatures),(SELECT count(*) FROM send_sealing_intents)`).Scan(&baseline[0], &baseline[1], &baseline[2], &baseline[3], &baseline[4], &baseline[5], &baseline[6]); err != nil {
		t.Fatal("capture exact effect baseline")
	}
	cert, roots, spki, err := oidc439TLS()
	if err != nil {
		t.Fatal("create ephemeral CA")
	}
	provider, err := newOIDC439Provider(issuer.String(), base.String()+"/auth/callback", invite.Email)
	if err != nil {
		t.Fatal("create controlled OIDC peer")
	}
	oidc439Server(t, f.ctx, issuer, cert, provider)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	f.s.OIDC, err = auth.NewOIDC(oidc.ClientContext(f.ctx, client), auth.OIDCConfig{IssuerURL: issuer.String(), ClientID: provider.clientID, RedirectURL: base.String() + "/auth/callback", Cookies: f.s.Cookies})
	if err != nil || f.s.OIDC == nil {
		t.Fatal("real issuer discovery failed")
	}
	f.s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(frontend))
	f.s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if file, err := os.Stat(filepath.Join(frontend, clean)); err == nil && !file.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(frontend, "index.html"))
	})
	authCounts := &oidc439Routes{cookies: f.s.Cookies, userID: invite.ID}
	nativeDownloads := &packageBrowserNativeDownloads419{}
	observed := &template447HTTP{auth: authCounts, template: template.ID, statuses: map[string][]int{}, downloads: nativeDownloads}
	routes := observed.serve(f.s.Routes())
	oidc439Server(t, f.ctx, base, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routes.ServeHTTP(w, r.WithContext(oidc.ClientContext(r.Context(), client)))
	}))
	packet, err := json.Marshal(map[string]any{
		"schema": 1, "source": "ordinary-template447", "base": base.String(), "issuer": issuer.String(), "leaf_spki_sha256": spki,
		"org_id": f.org, "user_id": invite.ID, "email": invite.Email, "name": invite.Name, "role": invite.Role, "document_name": "OIDC444 approved design draft", "session_generation": invite.SessionGeneration, "native_deadline_unix_ms": deadline.UnixMilli(),
		"template":       map[string]any{"id": template.ID, "name": template.Name, "version": template.Version, "content_sha256": canonical.SHA256, "schema_version": 3},
		"value_defaults": seed.Values, "values": expectedValues, "section_defaults": map[string]string{"delivery_terms": "Approved delivery wording444."}, "sections": expectedSections, "expected_pages": 2,
	})
	if err != nil || len(packet) > 8192 {
		t.Fatal("bounded safe template bootstrap invalid")
	}
	crmDocumentBrowserWriteE2E(t, input, packet)
	defer os.Remove(input)
	defer os.Remove(done)
	createdPath := filepath.Join(filepath.Dir(input), "template-created447.json")
	firstPath := filepath.Join(filepath.Dir(input), "template-first447.json")
	terminalPath := filepath.Join(filepath.Dir(input), "template-terminal447.json")
	privatePaths := []string{createdPath, firstPath, terminalPath}
	for _, p := range packageBrowserNativeDownloadPaths419(filepath.Dir(input)) {
		privatePaths = append(privatePaths, p)
	}
	for _, p := range privatePaths {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("fresh private447 handoff required")
		}
	}
	defer func() {
		for _, p := range privatePaths {
			_ = os.Remove(p)
		}
	}()
	waitUntil := time.Now().Add(150 * time.Second)
	if deadline.Before(waitUntil) {
		waitUntil = deadline
	}
	assertCreated := func(documentID uuid.UUID) (*generated.Document, uuid.UUID, string, []byte) {
		observedID, actualCookie, statuses, faults := observed.snapshot()
		if faults != 0 || observedID != documentID || actualCookie == "" || !reflect.DeepEqual(statuses["create"], []int{http.StatusCreated}) {
			t.Fatal("actual sender HTTP effect inventory differs")
		}
		for _, class := range []string{"document", "source", "history", "pdf", "history_source", "history_pdf"} {
			if len(statuses[class]) == 0 || len(statuses[class]) > 32 {
				t.Fatal("required actual UI readback missing")
			}
			for _, status := range statuses[class] {
				if status != http.StatusOK {
					t.Fatal("actual UI readback failed")
				}
			}
		}
		if len(statuses["document"]) < 2 || len(statuses["source"]) < 2 {
			t.Fatal("actual saved-document reload not observed")
		}
		member, err := f.q.GetUser(f.ctx, invite.ID)
		if err != nil || member.OrgID != invite.OrgID || member.Role != "sender" || member.Email != invite.Email || member.Name != invite.Name || !member.ZitadelSub.Valid || member.ZitadelSub.String != provider.subject || member.SessionGeneration != invite.SessionGeneration {
			t.Fatal("OIDC changed original sender membership/generation")
		}
		owner, err := f.q.GetUser(f.ctx, f.user.ID)
		if err != nil || !reflect.DeepEqual(owner, initialOwner) {
			t.Fatal("sender journey changed unrelated owner")
		}
		doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: documentID, OrgID: f.org})
		if err != nil || doc.SenderID != invite.ID || doc.Name != "OIDC444 approved design draft" || doc.SourceKind != "pdf" || doc.Status != "draft" || !doc.TemplateID.Valid || uuid.UUID(doc.TemplateID.Bytes) != template.ID || doc.SentAt.Valid || doc.CompletedAt.Valid || doc.HtmlReviewedAt.Valid || doc.HtmlReviewedBy.Valid || len(doc.HtmlReviewedPdfSha256) != 0 {
			t.Fatal("actual template creation lost draft/source/review authority")
		}
		inputProof, err := htmlsource.InputForCurrent(doc)
		if err != nil || inputProof.TemplateID != template.ID || inputProof.TemplateVersion != template.Version || inputProof.TemplateContentSHA256 != canonical.SHA256 || inputProof.TemplateApprovedBy != f.user.ID || !inputProof.TemplateApprovedAt.Equal(approved.ApprovedAt.Time) || !maps.Equal(inputProof.Values, expectedValues) || !maps.Equal(inputProof.Sections, expectedSections) {
			t.Fatal("exact approved source or declared inputs differ")
		}
		if actualCanonical, err := htmlmaster.CanonicalTemplate(inputProof.MasterJSON, inputProof.DefaultVarsJSON); err != nil || actualCanonical.SHA256 != canonical.SHA256 || !bytes.Equal(actualCanonical.MasterJSON, canonical.MasterJSON) || !bytes.Equal(actualCanonical.DefaultsJSON, canonical.DefaultsJSON) {
			t.Fatal("frozen approved master/defaults drifted")
		}
		changed, err := htmlsource.ChangedSections(doc)
		if err != nil || !reflect.DeepEqual(changed, []string{"delivery_terms"}) {
			t.Fatal("changed approved wording not preserved")
		}
		_, _, artifact := assertBrandedStateE2E(t, f, doc)
		if artifact.Composition.BodyPages != 1 || artifact.Composition.FinalPages != 2 {
			t.Fatal("actual body plus signing suffix differs")
		}
		commitment, err := htmlsource.Commitment(doc)
		if err != nil {
			t.Fatal("exact source commitment invalid")
		}
		materialization, err := f.q.GetHTMLDocumentMaterialization(f.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: doc.ID, OrgID: f.org, Sequence: 1})
		if err != nil || materialization.CreatedBy != invite.ID || materialization.ID == uuid.Nil || !doc.HtmlCurrentMaterializationID.Valid || uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) != materialization.ID || materialization.Sequence != 1 || materialization.PageCount != 2 || materialization.ParentID.Valid || materialization.PdfKey != doc.PdfStorageKey.String || materialization.PdfVersionID != doc.PdfStorageVersionID.String || !bytes.Equal(materialization.PdfSha256, doc.PdfSha256) || !bytes.Equal(materialization.SourceJson, doc.HtmlCurrentSourceJson) || hex.EncodeToString(materialization.SourceCommitment) != commitment {
			t.Fatal("exact first immutable history row differs")
		}
		// Join the actual UI request UUID to the original actor-scoped durable
		// creation record. The browser receipt supplies its independently observed
		// UUID for the root verifier; no request identity is synthesized here.
		var requestID uuid.UUID
		var requestCount int64
		err = f.pool.QueryRow(f.ctx, `SELECT request_id,count(*) OVER() FROM html_document_creation_requests WHERE org_id=$1 AND original_document_id=$2`, f.org, doc.ID).Scan(&requestID, &requestCount)
		if err != nil || requestID == uuid.Nil || requestCount != 1 {
			t.Fatal("one durable original creation request required")
		}
		request, err := f.q.GetHTMLDocumentCreationRequest(f.ctx, generated.GetHTMLDocumentCreationRequestParams{OrgID: f.org, ActorUserID: invite.ID, RequestID: requestID})
		if err != nil || request.OrgID != f.org || request.ActorUserID != invite.ID || request.TemplateID != template.ID || request.OriginalDocumentID != doc.ID || !request.CurrentDocumentID.Valid || uuid.UUID(request.CurrentDocumentID.Bytes) != doc.ID || request.HtmlMaterializationID != materialization.ID || request.HtmlSourceCommitment != commitment || !bytes.Equal(request.PdfSha256, doc.PdfSha256) || request.PageCount != 2 || len(request.InputDigest) != sha256.Size {
			t.Fatal("actual creation request actor/source/history/PDF tuple differs")
		}
		// Independent read-only route oracles use ONLY the real callback's original
		// sender cookie. These bypass the passive outer browser counter intentionally.
		sourceResponse := submitSessionOperationContextE2E(f.ctx, f.s, http.MethodGet, "/api/v1/documents/"+doc.ID.String()+"/html/source", "", actualCookie)
		var descriptor htmlDocumentSourceResponse
		if sourceResponse.Code != http.StatusOK || json.Unmarshal(sourceResponse.Body.Bytes(), &descriptor) != nil || descriptor.DocumentID != doc.ID || descriptor.OrgID != f.org || descriptor.HTMLSourceCommitment != commitment || descriptor.TemplateID != template.ID || descriptor.TemplateVersion != template.Version || descriptor.TemplateContentSHA256 != canonical.SHA256 || descriptor.SourceSchemaVersion != 3 || descriptor.MaterializationRevision != 1 || descriptor.PageCount != 2 || descriptor.PDFSHA256 != hex.EncodeToString(doc.PdfSha256) || !descriptor.CanEdit {
			t.Fatal("real sender source response differs from stored source")
		}
		gotValues, gotSections := map[string]string{}, map[string]string{}
		for _, value := range descriptor.Values {
			if _, exists := gotValues[value.Name]; exists {
				t.Fatal("duplicate source value")
			}
			gotValues[value.Name] = value.Text
		}
		for _, section := range descriptor.Sections {
			if _, exists := gotSections[section.Name]; exists {
				t.Fatal("duplicate source section")
			}
			gotSections[section.Name] = section.Text
		}
		if !maps.Equal(gotValues, expectedValues) || !maps.Equal(gotSections, expectedSections) || !reflect.DeepEqual(descriptor.ChangedSections, changed) {
			t.Fatal("real source text response differs")
		}
		historyResponse := submitSessionOperationContextE2E(f.ctx, f.s, http.MethodGet, "/api/v1/documents/"+doc.ID.String()+"/html/history", "", actualCookie)
		var history struct {
			Revisions []htmlDocumentHistoryResponse `json:"revisions"`
		}
		if historyResponse.Code != http.StatusOK || json.Unmarshal(historyResponse.Body.Bytes(), &history) != nil || len(history.Revisions) != 1 {
			t.Fatal("exact immutable history readback absent")
		}
		h := history.Revisions[0]
		if h.ID != materialization.ID || h.Sequence != 1 || !h.Current || h.CreatedBy != invite.ID || h.SourceCommitment != commitment || h.PDFSHA256 != descriptor.PDFSHA256 || h.PageCount != 2 {
			t.Fatal("immutable history response lost exact tuple")
		}
		pdf, err := f.s.Storage.GetVerifiedVersion(f.ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
		if err != nil || len(pdf) == 0 || len(pdf) > 4<<20 || !bytes.HasPrefix(pdf, []byte("%PDF-")) {
			t.Fatal("bounded exact stored PDF unavailable")
		}
		for _, suffix := range []string{"/pdf", "/html/revisions/1/pdf"} {
			response := submitSessionOperationContextE2E(f.ctx, f.s, http.MethodGet, "/api/v1/documents/"+doc.ID.String()+suffix, "", actualCookie)
			if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), pdf) {
				t.Fatal("current/history PDF route differs from exact stored version")
			}
		}
		var actual [7]int64
		var createdEvents, wrongActor, bound, materializations, snapshots, versions, fields int
		err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM orgs),(SELECT count(*) FROM users),(SELECT count(*) FROM documents),(SELECT count(*) FROM recipients),(SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM signatures),(SELECT count(*) FROM send_sealing_intents),(SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.created'),(SELECT count(*) FROM events WHERE document_id=$1 AND actor_user_id IS DISTINCT FROM $2),(SELECT count(*) FROM events WHERE org_id=$3 AND kind='member.identity_bound' AND actor_user_id=$2),(SELECT count(*) FROM html_document_materializations WHERE document_id=$1),(SELECT count(*) FROM html_document_materialization_snapshots WHERE document_id=$1),(SELECT count(*) FROM document_versions WHERE document_id=$1),(SELECT count(*) FROM document_fields WHERE document_id=$1)`, doc.ID, invite.ID, f.org).Scan(&actual[0], &actual[1], &actual[2], &actual[3], &actual[4], &actual[5], &actual[6], &createdEvents, &wrongActor, &bound, &materializations, &snapshots, &versions, &fields)
		wanted := baseline
		wanted[2]++
		wanted[3] += 2
		if err != nil || actual != wanted || createdEvents != 1 || wrongActor != 0 || bound != 1 || materializations != 1 || snapshots != 0 || versions != 1 || fields != 2 {
			t.Fatal("exact sender creation/history/noSend effect scope differs")
		}
		var afterTemplates string
		if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM templates x WHERE org_id=$1),(SELECT jsonb_agg(to_jsonb(x) ORDER BY template_id,version) FROM html_template_revisions x WHERE org_id=$1))::text`, f.org).Scan(&afterTemplates); err != nil || afterTemplates != beforeTemplates {
			t.Fatal("sender mutated approved design or retained revisions")
		}
		events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
		if err != nil || len(events) != len(beforeEvents)+2 {
			t.Fatal("unexpected audit effect count")
		}
		byID := map[uuid.UUID]*generated.Event{}
		for _, event := range events {
			byID[event.ID] = event
		}
		for _, event := range beforeEvents {
			if !reflect.DeepEqual(byID[event.ID], event) {
				t.Fatal("retained original audit changed")
			}
		}
		chain := audit.NewChainVerifier()
		chain.VerifyPage(events)
		if result := chain.Result(); !result.OK || !result.Complete || result.TotalChecked != len(events) {
			t.Fatal("complete actual sender audit chain invalid")
		}
		providerCounts := provider.snapshot()
		provider.mu.Lock()
		singleHandshake := len(provider.seenNonce) == 1 && len(provider.seenState) == 1 && len(provider.seenChallenge) == 1
		provider.mu.Unlock()
		if providerCounts.Discovery != 1 || providerCounts.Authorize != 1 || providerCounts.Accept != 1 || providerCounts.Token != 1 || providerCounts.JWKS < 1 || providerCounts.JWKS > 2 || providerCounts.Faults != 0 || providerCounts.PendingCodes != 0 || providerCounts.PendingTickets != 0 || !singleHandshake {
			t.Fatal("one genuine consumed OIDC handshake required")
		}
		a := authCounts.snapshot()
		if a["login"] != 1 || a["callback"] != 1 || a["logout"] != 0 || a["create"] != 0 || a["me_ok"] < 1 || a["me_ok"]+a["me_denied"] > 32 || a["login_cookie_sets"] != 1 || a["session_cookie_sets"] != 1 || a["callback_handshake_clears"] != 1 || a["logout_cookie_clears"] != 0 || a["faults"] != 0 || !reflect.DeepEqual(authCounts.sessionGenerations(), []int64{invite.SessionGeneration}) {
			t.Fatal("real native sender session/cookie inventory differs")
		}
		crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, "template-approval447.pdf"), approvalPDF)
		crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, "template-created447.pdf"), pdf)
		return doc, requestID, commitment, pdf
	}
	// The preserved444 creation oracle runs before the real review/Send UI.
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var originalDoc *generated.Document
	var requestID uuid.UUID
	var sourceCommitment string
	var originalPDF []byte
	var invitations template447Invitations
	var terminal template447Completed
	createdReady, invitationsReady, terminalReady := false, false, false
	for {
		if !time.Now().Before(waitUntil) {
			t.Fatal("447 original remaining rendezvous expired")
		}
		select {
		case <-f.ctx.Done():
			t.Fatal("447 inherited native90 deadline expired")
		case <-tick.C:
		}
		id, _, statuses, faults := observed.snapshot()
		if faults != 0 {
			t.Fatal("447 unexpected actual browser request")
		}
		if !createdReady && id != uuid.Nil && len(statuses["document"]) >= 2 && len(statuses["source"]) >= 2 && len(statuses["history_source"]) >= 1 && len(statuses["history_pdf"]) >= 1 {
			originalDoc, requestID, sourceCommitment, originalPDF = assertCreated(id)
			if err := objectsPeer.register447(originalDoc.PdfStorageKey.String); err != nil {
				t.Fatal("447 exact target object registration refused")
			}
			parties, fields, _ := assertBrandedStateE2E(t, f, originalDoc)
			if len(parties) != 2 || len(fields) != 2 {
				t.Fatal("447 two actual generated party slots required")
			}
			publicParties := make([]packageBrowserParty403, 0, 2)
			for _, party := range parties {
				publicParties = append(publicParties, packageBrowserParty403{RecipientID: party.ID, Name: party.Name, Role: party.Role, Email: party.Email})
			}
			checkpoint := map[string]any{"schema": 1, "source": "ordinary-template447-created", "rootID": originalDoc.ID, "requestID": requestID, "sourceCommitment": sourceCommitment, "templateID": template.ID, "templateVersion": template.Version, "templateContentSHA256": canonical.SHA256, "pdf": template447PDFOf(originalDoc, len(originalPDF), sourceCommitment), "parties": publicParties, "fields": ownedRealBrowserFieldGeometryV1(t, fields)}
			if err := packageBrowserPrivate256(createdPath, checkpoint); err != nil {
				t.Fatal("447 private original creation checkpoint unavailable")
			}
			createdReady = true
		}
		if createdReady && !invitationsReady && len(statuses["send"]) != 0 {
			if !reflect.DeepEqual(statuses["send"], []int{200}) || !reflect.DeepEqual(statuses["review"], []int{200}) {
				t.Fatal("447 ordinary Send/review HTTP outcome differs")
			}
			sent := packageLatest223(t, q, originalDoc.ID)
			if sent.Status != "sent" || !sent.SentAt.Valid || !sent.HtmlReviewedAt.Valid || !sent.HtmlReviewedBy.Valid || uuid.UUID(sent.HtmlReviewedBy.Bytes) != invite.ID || !bytes.Equal(sent.HtmlReviewedPdfSha256, originalDoc.PdfSha256) || sent.PdfStorageKey != originalDoc.PdfStorageKey || sent.PdfStorageVersionID != originalDoc.PdfStorageVersionID || !bytes.Equal(sent.PdfSha256, originalDoc.PdfSha256) {
				t.Fatal("447 ordinary Send lost exact actual sender review")
			}
			template447NoPackage(t, q, originalDoc.ID)
			invitations = template447InvitationsFrom(t, q, sent, len(originalPDF), sourceCommitment)
			if err := packageBrowserPrivate256(firstPath, invitations); err != nil {
				t.Fatal("447 actual ordinary invitation handoff unavailable")
			}
			invitationsReady = true
		}
		if invitationsReady && !terminalReady {
			completed := packageLatest223(t, q, originalDoc.ID)
			if completed.Status == "completed" {
				terminal = template447Terminal(t, q, originalDoc, completed, invitations, invite, strict)
				if err := template447ArmDownloads(nativeDownloads, base, terminal, filepath.Dir(input)); err != nil {
					t.Fatal("447 exact ordinary native downloads could not arm")
				}
				if err := packageBrowserPrivate256(terminalPath, terminal); err != nil {
					t.Fatal("447 actual ordinary terminal unavailable")
				}
				terminalReady = true
			}
		}
		body, readErr := oidc439ReadDone(done)
		if readErr == nil {
			var completed struct {
				Schema     int       `json:"schema"`
				ExitCode   *int      `json:"exit_code"`
				Verified   bool      `json:"verified"`
				DocumentID uuid.UUID `json:"document_id"`
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			decodeErr := decoder.Decode(&completed)
			if decodeErr == io.ErrUnexpectedEOF {
				continue
			}
			canonical, canonicalErr := json.Marshal(&completed)
			if decodeErr != nil || canonicalErr != nil || !bytes.Equal(body, canonical) || decoder.Decode(new(any)) != io.EOF || completed.Schema != 1 || completed.ExitCode == nil || *completed.ExitCode != 0 || !completed.Verified || !createdReady || !invitationsReady || !terminalReady || completed.DocumentID != originalDoc.ID {
				t.Fatal("447 external browser rejected or preceded native ordinary terminal")
			}
			break
		}
		if !os.IsNotExist(readErr) && readErr != io.ErrUnexpectedEOF {
			t.Fatal("447 private completion marker invalid")
		}
	}
	rows, err := nativeDownloads.complete419()
	if err != nil {
		t.Fatal("447 four exact native download requests incomplete")
	}
	_, actualCookie, statuses, faults := observed.snapshot()
	if faults != 0 || actualCookie == "" || !reflect.DeepEqual(statuses["create"], []int{201}) || !reflect.DeepEqual(statuses["review"], []int{200}) || !reflect.DeepEqual(statuses["send"], []int{200}) || !reflect.DeepEqual(statuses["sign"], []int{200, 200}) || !reflect.DeepEqual(statuses["view"], []int{200, 200}) {
		t.Fatal("447 exact ordinary browser mutation/status inventory differs")
	}
	final := packageLatest223(t, q, originalDoc.ID)
	if final.SenderID != invite.ID || final.PdfStorageKey != originalDoc.PdfStorageKey || final.PdfStorageVersionID != originalDoc.PdfStorageVersionID || !bytes.Equal(final.PdfSha256, originalDoc.PdfSha256) || final.HtmlCurrentMaterializationID != originalDoc.HtmlCurrentMaterializationID || final.HtmlCurrentMaterializationSequence != originalDoc.HtmlCurrentMaterializationSequence {
		t.Fatal("447 signing replaced original created source/history/PDF")
	}
	currentOriginal, err := f.s.Storage.GetVerifiedVersion(f.ctx, originalDoc.PdfStorageKey.String, originalDoc.PdfStorageVersionID.String, originalDoc.PdfSha256)
	if err != nil || !bytes.Equal(currentOriginal, originalPDF) {
		t.Fatal("447 exact original PDF version lost or overwritten")
	}
	template447NoPackage(t, q, originalDoc.ID)
	var materializations, messages int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM html_document_materializations WHERE document_id=$1 AND org_id=$2),(SELECT count(*) FROM email_deliveries)`, originalDoc.ID, f.org).Scan(&materializations, &messages); err != nil || materializations != 1 || messages != int(baseline[4])+5 {
		t.Fatal("447 repeated materialization or unexpected ordinary mail effect")
	}
	member, err := f.q.GetUser(f.ctx, invite.ID)
	if err != nil || member.OrgID != invite.OrgID || member.Role != "sender" || member.Email != invite.Email || member.Name != invite.Name || !member.ZitadelSub.Valid || member.ZitadelSub.String != provider.subject || member.SessionGeneration != invite.SessionGeneration {
		t.Fatal("447 final sender membership changed")
	}
	owner, err := f.q.GetUser(f.ctx, f.user.ID)
	if err != nil || !reflect.DeepEqual(owner, initialOwner) {
		t.Fatal("447 unrelated native owner changed")
	}
	var afterTemplates string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM templates x WHERE org_id=$1),(SELECT jsonb_agg(to_jsonb(x) ORDER BY template_id,version) FROM html_template_revisions x WHERE org_id=$1))::text`, f.org).Scan(&afterTemplates); err != nil || afterTemplates != beforeTemplates {
		t.Fatal("447 approved template/revisions changed")
	}
	events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil || len(events) >= 100 {
		t.Fatal("447 complete bounded organization chain unavailable")
	}
	byID := map[uuid.UUID]*generated.Event{}
	for _, event := range events {
		byID[event.ID] = event
	}
	for _, event := range beforeEvents {
		if !reflect.DeepEqual(byID[event.ID], event) {
			t.Fatal("447 original audit preimage changed")
		}
	}
	chain := audit.NewChainVerifier()
	chain.VerifyPage(events)
	if result := chain.Result(); !result.OK || !result.Complete || result.TotalChecked != len(events) {
		t.Fatal("447 complete organization chain invalid")
	}
	providerCounts := provider.snapshot()
	provider.mu.Lock()
	singleHandshake := len(provider.seenNonce) == 1 && len(provider.seenState) == 1 && len(provider.seenChallenge) == 1
	provider.mu.Unlock()
	if providerCounts.Discovery != 1 || providerCounts.Authorize != 1 || providerCounts.Accept != 1 || providerCounts.Token != 1 || providerCounts.JWKS < 1 || providerCounts.JWKS > 2 || providerCounts.Faults != 0 || providerCounts.PendingCodes != 0 || providerCounts.PendingTickets != 0 || !singleHandshake {
		t.Fatal("447 final one consumed OIDC handshake differs")
	}
	authSnapshot := authCounts.snapshot()
	if authSnapshot["login"] != 1 || authSnapshot["callback"] != 1 || authSnapshot["logout"] != 0 || authSnapshot["create"] != 0 || authSnapshot["me_ok"] < 1 || authSnapshot["me_ok"]+authSnapshot["me_denied"] > 32 || authSnapshot["login_cookie_sets"] != 1 || authSnapshot["session_cookie_sets"] != 1 || authSnapshot["callback_handshake_clears"] != 1 || authSnapshot["logout_cookie_clears"] != 0 || authSnapshot["faults"] != 0 || !reflect.DeepEqual(authCounts.sessionGenerations(), []int64{invite.SessionGeneration}) {
		t.Fatal("447 final ordinary OIDC session differs")
	}
	objectsPeer.mu.Lock()
	providerFailure := objectsPeer.failure
	createdKey := objectsPeer.createdKey
	registered := objectsPeer.registered
	objectsPeer.mu.Unlock()
	strict.main.mu.Lock()
	retentionFailure := strict.main.failure
	retainedUntil := strict.main.until[originalDoc.PdfStorageKey.String]
	strict.main.mu.Unlock()
	if providerFailure != nil || retentionFailure != nil || createdKey != originalDoc.PdfStorageKey.String || !registered || !final.Article13NoticeEpochAt.Valid || retainedUntil.Before(storage.EvidenceRetentionDeadline(final.Article13NoticeEpochAt.Time, article13.RetentionYearsV1)) {
		t.Fatal("447 strict ordinary source retention protocol failed")
	}
	q.reconcileV1(t)
	q.assertObserversOnlyV1(t)
	approvalSHA := sha256.Sum256(approvalPDF)
	receipt, err := json.Marshal(map[string]any{"schema": 1, "source": "ordinary-template447", "passed": true, "org_id": f.org, "user_id": invite.ID, "document_id": originalDoc.ID, "request_id": requestID, "template_id": template.ID, "template_version": template.Version, "template_content_sha256": canonical.SHA256, "source_commitment": sourceCommitment, "history_id": uuid.UUID(originalDoc.HtmlCurrentMaterializationID.Bytes), "history_sequence": 1, "exact_declared_values_and_wording": true, "exact_source_pdf_history_readback": true, "pdf_sha256": hex.EncodeToString(originalDoc.PdfSha256), "pdf_bytes": len(originalPDF), "page_count": 2, "approval_pdf_sha256": hex.EncodeToString(approvalSHA[:]), "approval_pdf_bytes": len(approvalPDF), "creation_checkpoint_unreviewed_no_send": true, "real_sender_review_of_exact_created_pdf": true, "same_draft_source_and_history_preserved": true, "sender_membership_preserved": true, "unrelated_owner_unchanged": true, "approved_template_unchanged": true, "provider": providerCounts, "single_consumed_oidc_handshake": true, "auth_routes": authSnapshot, "browser_read_statuses": statuses, "ordinary_send_status": 200, "package_attempts": 0, "package_captures": 0, "package_responses": 0, "selected_attachments": 0, "signer_package_null": true, "completed_package_null": true, "signatures": 2, "reports": 1, "deliveries": 3, "initial_invitation_outbox": 2, "controller_confirmations": 1, "terminal_artifacts": terminal.Artifacts, "report_schema": terminal.ReportSchema, "report_sha256": terminal.ReportSHA256, "report_original_events_verified": true, "report_package_members": 0, "report_package_responses": 0, "report_family_documents": 1, "native_download_requests": rows, "retention_verified": true, "organization_chain_verified": true, "detached_report_signature_verified": true, "ordinary_signature_notice_evidence_verified": true, "native_runtime_drained": true, "migration_version": migration, "server_version_num": server, "renderer_version": strings.TrimSpace(string(version)), "duration_ms": time.Since(started).Milliseconds(), "scope": "Controlled same-draft ordinary whole-SPA OIDC/template/review UI/empty-inventory Send200/two recipient signature actions/final-report downloads. Native owner approval setup, controlled issuer/storage/malware/entitlement and pending-mail outbox. Not independent human legal review, live SMTP/provider, captured annex/negotiation variants, capacity or release acceptance."})
	if err != nil || len(receipt) > 8192 {
		t.Fatal("447 closed native receipt exceeds original cap")
	}
	crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, "template-native447.json"), receipt)
}

// This test-only peer accepts one actual target creation PUT, then freezes that
// exact key into the unchanged retained provider protocol. It never synthesizes
// a source, digest, retention or completion receipt.
type template447Storage struct {
	mu         sync.Mutex
	strict     *completedPackagePeer248
	org        uuid.UUID
	createdKey string
	registered bool
	failure    error
}

func (p *template447Storage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/hash-import-fixture/")
	prefix := "org/" + p.org.String() + "/documents/"
	leaf := strings.TrimPrefix(key, prefix)
	_, parseErr := uuid.Parse(strings.TrimSuffix(leaf, ".pdf"))
	candidate := strings.HasPrefix(key, prefix) && !strings.Contains(leaf, "/") && strings.HasSuffix(leaf, ".pdf") && parseErr == nil
	if candidate && r.Method == http.MethodPut && r.URL.RawQuery == "" {
		p.strict.main.base.mu.Lock()
		_, exists := p.strict.main.base.objects[key]
		p.strict.main.base.mu.Unlock()
		if p.registered || p.createdKey != "" || exists || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || r.Header.Get("Content-Type") != "application/pdf" {
			p.failure = errors.New("447 repeated or unowned source PUT")
			http.Error(w, "owned source required", 400)
			return
		}
		status := &packageBrowserStatus403{ResponseWriter: w}
		p.strict.main.base.ServeHTTP(status, r)
		if status.code == 0 {
			status.code = 200
		}
		if status.code != 200 {
			p.failure = errors.New("447 source PUT failed")
			return
		}
		p.createdKey = key
		return
	}
	p.strict.ServeHTTP(w, r)
}
func (p *template447Storage) register447(key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failure != nil || p.registered || key == "" || p.createdKey != key {
		return errors.New("447 exact source registration required")
	}
	p.strict.mainKey = key
	p.strict.originalKeys[key] = struct{}{}
	p.registered = true
	return nil
}

type template447PDF struct {
	SHA256                  string `json:"sha256"`
	Bytes                   int64  `json:"bytes"`
	Pages                   int32  `json:"pages"`
	SourceCommitment        string `json:"sourceCommitment"`
	MaterializationRevision int32  `json:"materializationRevision"`
}

func template447PDFOf(doc *generated.Document, size int, commitment string) template447PDF {
	return template447PDF{hex.EncodeToString(doc.PdfSha256), int64(size), 2, commitment, 1}
}

type template447Invitations struct {
	Schema                  int                      `json:"schema"`
	Source                  string                   `json:"source"`
	RootID                  uuid.UUID                `json:"rootID"`
	SourceCommitment        string                   `json:"sourceCommitment"`
	MaterializationRevision int32                    `json:"materializationRevision"`
	PDF                     template447PDF           `json:"pdf"`
	Package                 *struct{}                `json:"package"`
	Parties                 []packageBrowserParty403 `json:"parties"`
	Fields                  []map[string]any         `json:"fields"`
}
type template447Completed struct {
	Schema       int                               `json:"schema"`
	Source       string                            `json:"source"`
	RootID       uuid.UUID                         `json:"rootID"`
	Package      *struct{}                         `json:"package"`
	ReportSchema string                            `json:"reportSchema"`
	ReportSHA256 string                            `json:"reportSHA256"`
	CompletionAt string                            `json:"completionAt"`
	Artifacts    []packageBrowserArtifact403       `json:"artifacts"`
	Parties      []packageBrowserCompletedParty403 `json:"parties"`
}

func template447NoPackage(t *testing.T, q *ownedPublicReadFixtureV1, root uuid.UUID) {
	t.Helper()
	var attempts, captures, responses, attachments int
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT (SELECT count(*) FROM document_package_send_attempts_v1 WHERE document_id=$1 AND org_id=$2),(SELECT count(*) FROM document_package_captures_v1 WHERE document_id=$1 AND org_id=$2),(SELECT count(*) FROM document_package_responses_v1 WHERE document_id=$1 AND org_id=$2),(SELECT count(*) FROM document_attachment_drafts_v1 a JOIN document_packages_v1 p ON p.id=a.package_id AND p.org_id=a.org_id WHERE p.document_id=$1 AND p.org_id=$2)`, root, q.f.org).Scan(&attempts, &captures, &responses, &attachments)
	if err != nil || attempts != 0 || captures != 0 || responses != 0 || attachments != 0 {
		t.Fatal("447 ordinary zero-selection path unexpectedly acquired a package capture/response")
	}
}
func template447PackageNull(t *testing.T, q *ownedPublicReadFixtureV1, token, suffix string) {
	t.Helper()
	response := q.requestV1(token, suffix)
	if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || !bytes.Equal(bytes.TrimSpace(response.Body.Bytes()), []byte(`{"package":null}`)) {
		t.Fatal("447 actual ordinary package descriptor is not exact null")
	}
}
func template447InvitationsFrom(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, size int, commitment string) template447Invitations {
	t.Helper()
	parties, fields, _ := assertBrandedStateE2E(t, q.f, doc)
	if len(parties) != 2 || len(fields) != 2 || !doc.Article13NoticeEpochAt.Valid {
		t.Fatal("447 ordinary intended parties or send epoch missing")
	}
	out := template447Invitations{Schema: 1, Source: "ordinary-template447-invitations", RootID: doc.ID, SourceCommitment: commitment, MaterializationRevision: 1, PDF: template447PDFOf(doc, size, commitment), Fields: ownedRealBrowserFieldGeometryV1(t, fields)}
	seen := map[string]bool{}
	for _, party := range parties {
		var body, htmlBody string
		var rows int
		err := q.f.pool.QueryRow(q.f.ctx, `SELECT text_body,html_body,count(*) OVER() FROM email_deliveries WHERE to_email=$1 AND status='pending' AND strpos(text_body,'/sign/')>0 AND octet_length(text_body)<=16384 AND octet_length(html_body)<=16384`, party.Email).Scan(&body, &htmlBody, &rows)
		matches := regexp.MustCompile(`/sign/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`).FindAllStringSubmatch(body, -1)
		if err != nil || rows != 1 || len(matches) != 1 || seen[matches[0][1]] {
			t.Fatal("447 unique actual ordinary pending invitation absent")
		}
		token := matches[0][1]
		seen[token] = true
		if !strings.Contains(body, q.f.s.PublicURL+"/sign/"+token) || !strings.Contains(htmlBody, q.f.s.PublicURL+"/sign/"+token) {
			t.Fatal("447 actual invitation origin differs")
		}
		rc, err := q.f.s.Sign.LookupByToken(q.f.ctx, auth.HashMagicToken(token))
		if err != nil || rc == nil {
			t.Fatal("447 actual invitation credential unavailable")
		}
		valid := rc.Recipient != nil && rc.Document != nil && rc.Recipient.ID == party.ID && rc.Document.ID == doc.ID && rc.Document.OrgID == q.f.org
		closeErr := rc.CloseReadV1()
		if !valid || closeErr != nil {
			t.Fatal("447 actual invitation credential tuple or retirement differs")
		}
		contextResponse := q.requestV1(token, "")
		var page signerContextResponse
		if contextResponse.Code != 200 || json.Unmarshal(contextResponse.Body.Bytes(), &page) != nil || page.DocumentID != doc.ID || !packageBrowserDigest403(page.Privacy.NoticeDigest) {
			t.Fatal("447 actual ordinary invitation privacy context absent")
		}
		template447PackageNull(t, q, token, "/package")
		out.Parties = append(out.Parties, packageBrowserParty403{RecipientID: party.ID, Name: party.Name, Role: party.Role, Email: party.Email, Token: token, NoticeDigest: page.Privacy.NoticeDigest})
	}
	return out
}

// Ordinary completion has no package/attempt identity. Only this arming seam
// differs from419: its actual incoming HTTP observer, four fixed filenames,
// exclusive publication, method/body/TLS/authority checks and complete419 stay
// unchanged. No fake nonzero package IDs are passed to the historical arm.
func template447ArmDownloads(o *packageBrowserNativeDownloads419, base *url.URL, terminal template447Completed, dir string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	bad := errors.New("447 exact ordinary download arm required")
	if o.armed || base == nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.ForceQuery || len(base.Host) > 256 || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || terminal.Schema != 1 || terminal.Source != "ordinary-template447-terminal" || terminal.RootID == uuid.Nil || terminal.Package != nil || len(terminal.Parties) != 2 || !packageBrowserToken403(terminal.Parties[0].Token) || !packageBrowserToken403(terminal.Parties[1].Token) || terminal.Parties[0].Token == terminal.Parties[1].Token {
		o.failed = true
		return bad
	}
	o.authority = base.Host
	o.files = packageBrowserNativeDownloadPaths419(dir)
	for i, party := range terminal.Parties {
		o.uris[2*i] = "/sign/" + party.Token + "/final-pdf"
		o.uris[2*i+1] = "/sign/" + party.Token + "/audit-cert"
	}
	o.armed = true
	return nil
}
func template447Terminal(t *testing.T, q *ownedPublicReadFixtureV1, original, completed *generated.Document, stage template447Invitations, sender *generated.User, strict *completedPackagePeer248) template447Completed {
	t.Helper()
	if completed.Status != "completed" || !completed.CompletionEffectiveAt.Valid || !completed.FinalPdfVersionID.Valid || !completed.AuditCertVersionID.Valid || !completed.AuditPayloadVersionID.Valid || !completed.AuditSignatureVersionID.Valid || completed.PdfStorageKey != original.PdfStorageKey || completed.PdfStorageVersionID != original.PdfStorageVersionID || !bytes.Equal(completed.PdfSha256, original.PdfSha256) || completed.SenderID != sender.ID || len(stage.Parties) != 2 || stage.Package != nil {
		t.Fatal("447 actual root-only terminal/version publication incomplete")
	}
	template447NoPackage(t, q, completed.ID)
	var reports, deliveries, signatures, confirmations int
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT (SELECT count(*) FROM document_participant_reports_v1 r WHERE r.document_id=$1 AND r.org_id=$2 AND r.completion_effective_at=$3 AND r.final_pdf_sha256=$4 AND r.audit_cert_sha256=$5 AND r.audit_payload_sha256=$6 AND r.audit_signature_sha256=$7),(SELECT count(*) FROM document_participant_report_deliveries_v1 WHERE document_id=$1 AND org_id=$2),(SELECT count(*) FROM signatures WHERE document_id=$1),(SELECT count(*) FROM document_lawful_basis_confirmations WHERE document_id=$1 AND org_id=$2)`, completed.ID, q.f.org, completed.CompletionEffectiveAt, completed.FinalPdfSha, completed.AuditCertSha256, completed.AuditPayloadSha256, completed.AuditSignatureSha256).Scan(&reports, &deliveries, &signatures, &confirmations)
	if err != nil || reports != 1 || deliveries != 3 || signatures != 2 || confirmations != 1 {
		t.Fatal("447 exact ordinary terminal cardinalities differ")
	}
	confirmation, err := q.f.q.GetDocumentLawfulBasisConfirmation(q.f.ctx, generated.GetDocumentLawfulBasisConfirmationParams{DocumentID: completed.ID, OrgID: q.f.org})
	if err != nil || confirmation == nil || confirmation.LawfulBasis != "contract" || !confirmation.ConfirmedBy.Valid || uuid.UUID(confirmation.ConfirmedBy.Bytes) != sender.ID || strings.TrimSpace(confirmation.ControllerName) == "" || strings.TrimSpace(confirmation.ControllerContact) == "" {
		t.Fatal("447 actual invited-sender controller instruction missing")
	}
	actualSignatures, err := q.f.q.ListSignaturesByDocument(q.f.ctx, completed.ID)
	if err != nil || len(actualSignatures) != 2 {
		t.Fatal("447 exact signature rows unavailable")
	}
	fields, err := q.f.q.ListFieldsByDocument(q.f.ctx, completed.ID)
	if err != nil || len(fields) != 2 {
		t.Fatal("447 exact generated fields unavailable")
	}
	for _, party := range stage.Parties {
		matches := 0
		for _, signature := range actualSignatures {
			if signature.RecipientID != party.RecipientID {
				continue
			}
			matched := false
			for _, field := range fields {
				if field.ID == signature.FieldID && field.RecipientID.Valid && uuid.UUID(field.RecipientID.Bytes) == party.RecipientID && field.Type == "signature" && field.Required {
					matched = true
				}
			}
			if !matched || signature.TypedName != party.Name || len(signature.ImageSha256) != 32 || !signature.ImageVersionID.Valid || !signature.ImageVersionPinRequired {
				t.Fatal("447 signature lost exact party/required field/image version")
			}
			matches++
		}
		if matches != 1 {
			t.Fatal("447 missing or duplicate intended signature")
		}
	}
	// Bind both actual public signatures to the original server-authored notice
	// and their immutable hashed audit preimages, without recording notice text.
	events, err := q.f.q.ListEventsByDocumentChronological(q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: completed.ID, Valid: true}, Limit: 1000})
	if err != nil || len(events) >= 1000 {
		t.Fatal("447 complete signature notice evidence unavailable")
	}
	seenSigned := map[uuid.UUID]bool{}
	for _, event := range events {
		if event.Kind != audit.KindDocumentSigned {
			continue
		}
		if !event.RecipientID.Valid || event.ActorUserID.Valid {
			t.Fatal("447 signer audit actor differs")
		}
		recipient := uuid.UUID(event.RecipientID.Bytes)
		var party *packageBrowserParty403
		for i := range stage.Parties {
			if stage.Parties[i].RecipientID == recipient {
				party = &stage.Parties[i]
			}
		}
		sum, e := audit.RecomputeEventRowHash(event)
		if party == nil || seenSigned[recipient] || e != nil || !bytes.Equal(sum, event.RowHash) || article13.ValidateAuditPayload(event.PayloadHashed, q.f.org, completed.ID, recipient) != nil {
			t.Fatal("447 original signer notice preimage invalid")
		}
		var payload map[string]json.RawMessage
		if json.Unmarshal(event.PayloadHashed, &payload) != nil {
			t.Fatal("447 original signed payload invalid")
		}
		var digest, name, font, imageSHA, signatureID string
		if json.Unmarshal(payload["notice_digest"], &digest) != nil || json.Unmarshal(payload["typed_name"], &name) != nil || json.Unmarshal(payload["font"], &font) != nil || json.Unmarshal(payload["image_sha256"], &imageSHA) != nil || json.Unmarshal(payload["signature_id"], &signatureID) != nil || digest != party.NoticeDigest || name != party.Name {
			t.Fatal("447 signature notice/body binding differs")
		}
		exact := false
		for _, signature := range actualSignatures {
			if signature.ID.String() == signatureID && signature.RecipientID == recipient && signature.TypedName == name && signature.Font == font && hex.EncodeToString(signature.ImageSha256) == imageSHA {
				exact = true
			}
		}
		if !exact {
			t.Fatal("447 signature audit fields differ from original signature row")
		}
		seenSigned[recipient] = true
	}
	if len(seenSigned) != 2 {
		t.Fatal("447 two original signature notice acknowledgements required")
	}
	payload, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, completed, completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID)
	if err != nil {
		t.Fatal("447 exact signed payload unavailable")
	}
	detached, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, completed, completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID)
	if err != nil || !sign.Verify(q.f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(detached)) {
		t.Fatal("447 mandatory payload detached signature invalid")
	}
	claims, err := evidence.ParseCertificateCommitments(payload)
	if err != nil || claims.DocumentID != completed.ID.String() || claims.OrgID != q.f.org.String() || claims.FinalPDFSHA256 != hex.EncodeToString(completed.FinalPdfSha) || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 {
		t.Fatal("447 current mandatory report claims disagree")
	}
	report := assertFreshParticipantReport406(t, q.f, completed, payload)
	if len(report.Members) != 0 || len(report.Responses) != 0 || len(report.Comments) != 0 || len(report.Proposals) != 0 || len(report.HistoryScope.DocumentIDs) != 1 || report.HistoryScope.DocumentIDs[0] != completed.ID.String() {
		t.Fatal("447 ordinary report invented package or negotiation facts")
	}
	if !completed.FinalizationRetainUntil.Valid || (claims.EvidenceRetainUntil != "" && claims.EvidenceRetainUntil != completed.FinalizationRetainUntil.Time.UTC().Format(time.RFC3339)) {
		t.Fatal("447 signed retention deadline differs from actual finalization")
	}
	result := template447Completed{Schema: 1, Source: "ordinary-template447-terminal", RootID: completed.ID, ReportSchema: claims.ParticipantReportSchema, ReportSHA256: claims.ParticipantReportSHA256, CompletionAt: completed.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano)}
	artifacts := []struct {
		name, key string
		digest    []byte
		version   pgtype.Text
	}{{"final-pdf", completed.FinalPdfKey.String, completed.FinalPdfSha, completed.FinalPdfVersionID}, {"evidence-report", completed.AuditCertKey.String, completed.AuditCertSha256, completed.AuditCertVersionID}, {"signed-report-payload", completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID}, {"detached-report-signature", completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID}}
	for _, artifact := range artifacts {
		raw, e := readDocumentArtifact(q.f.ctx, q.f.s.Storage, completed, artifact.key, artifact.digest, artifact.version)
		sum := sha256.Sum256(raw)
		if e != nil || len(raw) == 0 || !bytes.Equal(sum[:], artifact.digest) || ((artifact.name == "final-pdf" || artifact.name == "evidence-report") && (len(raw) > 4<<20 || !bytes.HasPrefix(raw, []byte("%PDF-")))) {
			t.Fatal("447 exact bounded terminal artifact unavailable")
		}
		// Read only the policy observed by the strict synthetic SDK peer. These
		// were set by the real finalizer PUT/retention protocol, never by an oracle.
		strict.mu.Lock()
		until := strict.until[artifact.key]
		strict.mu.Unlock()
		if until.Before(completed.FinalizationRetainUntil.Time) {
			t.Fatal("447 exact terminal artifact retention policy incomplete")
		}
		result.Artifacts = append(result.Artifacts, packageBrowserArtifact403{Name: artifact.name, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(raw))})
	}
	var senderRows int
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT count(*) FROM document_participant_report_deliveries_v1 r JOIN email_deliveries e ON e.id=r.email_delivery_id WHERE r.document_id=$1 AND r.org_id=$2 AND r.audience='sender' AND e.to_email=$3 AND e.status='pending' AND r.message_sha256=hash_package_send_message_sha256_v1(e.id) AND strpos(e.html_body,$4)>0 AND strpos(e.text_body,$4)>0 AND strpos(e.html_body,$5)>0 AND strpos(e.text_body,$5)>0`, completed.ID, q.f.org, sender.Email, "/api/v1/documents/"+completed.ID.String()+"/final-pdf", "/api/v1/documents/"+completed.ID.String()+"/audit-cert").Scan(&senderRows)
	if err != nil || senderRows != 1 {
		t.Fatal("447 invited sender completion outbox missing or duplicated")
	}
	tokenPattern := regexp.MustCompile(`/completed/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`)
	for _, party := range stage.Parties {
		var delivery uuid.UUID
		var body, htmlBody, messageSHA string
		var exact bool
		err := q.f.pool.QueryRow(q.f.ctx, `SELECT e.id,e.text_body,e.html_body,encode(r.message_sha256,'hex'),r.message_sha256=hash_package_send_message_sha256_v1(e.id) FROM document_participant_report_deliveries_v1 r JOIN email_deliveries e ON e.id=r.email_delivery_id WHERE r.document_id=$1 AND r.org_id=$2 AND r.audience='recipient' AND r.recipient_id=$3 AND e.to_email=$4 AND e.status='pending'`, completed.ID, q.f.org, party.RecipientID, party.Email).Scan(&delivery, &body, &htmlBody, &messageSHA, &exact)
		matches := tokenPattern.FindAllStringSubmatch(body, -1)
		if err != nil || !exact || delivery == uuid.Nil || len(matches) != 1 || !packageBrowserDigest403(messageSHA) {
			t.Fatal("447 actual completion outbox missing or ambiguous")
		}
		token := matches[0][1]
		for _, suffix := range []string{"/completed/" + token, "/sign/" + token + "/final-pdf", "/sign/" + token + "/audit-cert"} {
			if !strings.Contains(body, suffix) || !strings.Contains(htmlBody, suffix) {
				t.Fatal("447 completion message omitted exact artifact links")
			}
		}
		for _, old := range stage.Parties {
			if token == old.Token {
				t.Fatal("447 completion credential reused invitation")
			}
		}
		result.Parties = append(result.Parties, packageBrowserCompletedParty403{RecipientID: party.RecipientID, Token: token, EmailDeliveryID: delivery, MessageSHA256: messageSHA})
	}
	if len(result.Parties) != 2 || result.Parties[0].Token == result.Parties[1].Token {
		t.Fatal("447 distinct recipient completion credentials required")
	}
	for _, old := range stage.Parties {
		credential, e := q.f.s.Sign.LookupByToken(q.f.ctx, auth.HashMagicToken(old.Token))
		if credential != nil {
			if closeErr := credential.CloseReadV1(); closeErr != nil {
				t.Fatal("447 expired invitation lookup did not retire")
			}
		}
		if e == nil {
			t.Fatal("447 original invitation survived completion rotation")
		}
	}
	for _, signature := range actualSignatures {
		strict.mu.Lock()
		until := strict.until[signature.ImageStorageKey]
		strict.mu.Unlock()
		if until.Before(completed.FinalizationRetainUntil.Time) {
			t.Fatal("447 exact signature image retention policy incomplete")
		}
		image, e := q.f.s.Storage.GetVerifiedVersion(q.f.ctx, signature.ImageStorageKey, signature.ImageVersionID.String, signature.ImageSha256)
		if e != nil || len(image) == 0 {
			t.Fatal("447 retained original signature image version unavailable")
		}
	}
	for _, party := range result.Parties {
		template447PackageNull(t, q, party.Token, "/completed-package")
	}
	return result
}
