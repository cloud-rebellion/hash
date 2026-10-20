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
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
)

// Passive status/session observations only. The callback cookie stays in
// memory for independent read-only sender-route oracles AFTER browser completion;
// it is never handed to the browser, written or logged. No body is intercepted.
type template444HTTP struct {
	mu       sync.Mutex
	auth     *oidc439Routes
	template uuid.UUID
	document uuid.UUID
	cookie   string
	statuses map[string][]int
	faults   int
}

func (c *template444HTTP) serve(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			default:
				// The ordinary document page also loads recipients, fields,
				// comments and package metadata. Those genuine GETs remain
				// delegated, not additional selected source/PDF/history claims.
				if r.Method != http.MethodGet {
					c.faults++
				}
				return
			}
			if r.Method != http.MethodGet {
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

func (c *template444HTTP) snapshot() (uuid.UUID, string, map[string][]int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string][]int, len(c.statuses))
	for key, values := range c.statuses {
		out[key] = append([]int(nil), values...)
	}
	return c.document, c.cookie, out, c.faults
}

// Controlled first sender-template journey only. Owner creation and exact
// real-rendered preview approval below are explicit SETUP, not owner UI proof.
// The unchanged443 helpers provide real HTTPS OIDC with no cookie bootstrap.
// The inherited90s fixture owns setup+browser+oracles; no context is extended.
func TestOrdinaryOIDCSenderApprovedTemplateWithExternalBrowser444E2E(t *testing.T) {
	if os.Getenv("HASH_TEMPLATE_BROWSER_E2E") != "1" {
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
	for _, path := range []string{input, done, filepath.Join(artifacts, "template-native444.json"), filepath.Join(artifacts, "template-approval444.pdf"), filepath.Join(artifacts, "template-created444.pdf")} {
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
	q := newOwnedPublicReadFixtureProfileV1(t, false, false)
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
	observed := &template444HTTP{auth: authCounts, template: template.ID, statuses: map[string][]int{}}
	routes := observed.serve(f.s.Routes())
	oidc439Server(t, f.ctx, base, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routes.ServeHTTP(w, r.WithContext(oidc.ClientContext(r.Context(), client)))
	}))
	packet, err := json.Marshal(map[string]any{
		"schema": 1, "source": "ordinary-template444", "base": base.String(), "issuer": issuer.String(), "leaf_spki_sha256": spki,
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
	waitUntil := time.Now().Add(150 * time.Second)
	if deadline.Before(waitUntil) {
		waitUntil = deadline
	}
	var completed struct {
		Schema     int       `json:"schema"`
		ExitCode   *int      `json:"exit_code"`
		Verified   bool      `json:"verified"`
		DocumentID uuid.UUID `json:"document_id"`
	}
	for {
		body, readErr := oidc439ReadDone(done)
		if readErr == nil {
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			decodeErr := decoder.Decode(&completed)
			if decodeErr == io.ErrUnexpectedEOF {
				readErr = io.ErrUnexpectedEOF
			} else {
				canonical, canonicalErr := json.Marshal(&completed)
				if decodeErr != nil || canonicalErr != nil || !bytes.Equal(body, canonical) || decoder.Decode(new(any)) != io.EOF || completed.Schema != 1 || completed.ExitCode == nil || *completed.ExitCode != 0 || !completed.Verified || completed.DocumentID == uuid.Nil {
					t.Fatal("external browser rejected template journey")
				}
				break
			}
		}
		if !os.IsNotExist(readErr) && readErr != io.ErrUnexpectedEOF {
			t.Fatal("private completion marker invalid")
		}
		if !time.Now().Before(waitUntil) {
			t.Fatal("template rendezvous exhausted original remaining deadline")
		}
		select {
		case <-f.ctx.Done():
			t.Fatal("original native template deadline expired")
		case <-time.After(100 * time.Millisecond):
		}
	}
	documentID, actualCookie, statuses, faults := observed.snapshot()
	if faults != 0 || documentID != completed.DocumentID || actualCookie == "" || !reflect.DeepEqual(statuses["create"], []int{http.StatusCreated}) {
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
	q.reconcileV1(t)
	q.assertObserversOnlyV1(t)
	crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, "template-approval444.pdf"), approvalPDF)
	crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, "template-created444.pdf"), pdf)
	approvalSHA := sha256.Sum256(approvalPDF)
	receipt, err := json.Marshal(map[string]any{
		"schema": 1, "source": "ordinary-template444", "passed": true, "org_id": f.org, "user_id": invite.ID, "document_id": doc.ID, "request_id": requestID, "template_id": template.ID, "template_version": template.Version, "template_content_sha256": canonical.SHA256,
		"pdf_sha256": descriptor.PDFSHA256, "pdf_bytes": len(pdf), "page_count": 2, "source_commitment": commitment, "history_id": materialization.ID, "history_sequence": 1, "approval_pdf_sha256": hex.EncodeToString(approvalSHA[:]), "approval_pdf_bytes": len(approvalPDF),
		"provider": providerCounts, "single_consumed_oidc_handshake": true, "auth_routes": a, "browser_read_statuses": statuses, "sender_membership_preserved": true, "unrelated_owner_unchanged": true, "approved_template_unchanged": true, "exact_declared_values_and_wording": true, "exact_source_pdf_history_readback": true, "one_sender_pdf_draft": true, "document_review_not_acknowledged": true, "no_send_mail_signatures": true, "audit_chain_valid": true, "native_runtime_drained": true, "migration_version": migration, "server_version_num": server, "renderer_version": strings.TrimSpace(string(version)), "duration_ms": time.Since(started).Milliseconds(),
		"scope": "Controlled issuer and native owner-approved setup, production SPA and actual renderer/worker; storage/malware/entitlement peers synthetic. Not owner approval UI, document review acknowledgement, Send, live provider or capacity acceptance.",
	})
	if err != nil || len(receipt) > 8192 {
		t.Fatal("safe native template receipt exceeds cap")
	}
	crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, "template-native444.json"), receipt)
}

func mustDecodeHex444(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != sha256.Size {
		t.Fatal("invalid fixture canonical digest")
	}
	return raw
}
