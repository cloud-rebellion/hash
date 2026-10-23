//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
)

type oidc439Routes struct {
	mu             sync.Mutex
	cookies        *auth.SignedCookie
	userID         uuid.UUID
	generations    []int64
	Login          int `json:"login"`
	Callback       int `json:"callback"`
	Logout         int `json:"logout"`
	Create         int `json:"create"`
	MeOK           int `json:"me_ok"`
	MeDenied       int `json:"me_denied"`
	LoginCookies   int `json:"login_cookie_sets"`
	SessionCookies int `json:"session_cookie_sets"`
	CallbackClears int `json:"callback_handshake_clears"`
	LogoutClears   int `json:"logout_cookie_clears"`
	Faults         int `json:"faults"`
}
type oidc439StatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *oidc439StatusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *oidc439StatusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}
func (c *oidc439Routes) observe(r *http.Request, w *oidc439StatusWriter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	cookies := (&http.Response{Header: w.Header()}).Cookies()
	sessionMint, sessionClear, handshakeClear, handshakeSet := 0, 0, 0, 0
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteStrictMode {
				c.Faults++
			}
			if cookie.Value != "" && cookie.MaxAge >= 0 {
				sessionMint++
				// Observe only the real callback-issued signed cookie in memory.
				// Keep no credential, only its verified subject/generation result.
				var payload auth.SessionPayload
				if c.cookies == nil || len(c.generations) >= 3 {
					c.Faults++
				} else if raw, err := c.cookies.Verify(cookie.Value); err != nil {
					c.Faults++
				} else if json.Unmarshal(raw, &payload) != nil || payload.UserID != c.userID {
					c.Faults++
				} else {
					c.generations = append(c.generations, payload.Generation)
				}
			}
			if cookie.Value == "" && cookie.MaxAge < 0 {
				sessionClear++
			}
		}
		if cookie.Name == "hash_oauth_state" || cookie.Name == "hash_oauth_nonce" || cookie.Name == "hash_oauth_verifier" {
			if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
				c.Faults++
			}
			if cookie.Value != "" && cookie.Expires.After(time.Now()) {
				handshakeSet++
			}
			if cookie.Value == "" && cookie.MaxAge < 0 {
				handshakeClear++
			}
		}
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/auth/login":
		c.Login++
		if status != http.StatusFound || handshakeSet != 3 || sessionMint != 0 {
			c.Faults++
		}
		if handshakeSet == 3 {
			c.LoginCookies++
		}
	case r.Method == http.MethodGet && r.URL.Path == "/auth/callback":
		c.Callback++
		if status != http.StatusFound || handshakeClear != 3 || sessionMint != 1 {
			c.Faults++
		}
		if sessionMint == 1 {
			c.SessionCookies++
		}
		if handshakeClear == 3 {
			c.CallbackClears++
		}
	case r.Method == http.MethodPost && r.URL.Path == "/auth/logout":
		c.Logout++
		if status != http.StatusSeeOther || sessionClear != 1 {
			c.Faults++
		}
		if sessionClear == 1 {
			c.LogoutClears++
		}
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/documents":
		c.Create++
		if status != http.StatusCreated {
			c.Faults++
		}
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/me":
		if status == http.StatusOK {
			c.MeOK++
		} else if status == http.StatusUnauthorized {
			c.MeDenied++
		} else {
			c.Faults++
		}
	}
}
func (c *oidc439Routes) snapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]int{"login": c.Login, "callback": c.Callback, "logout": c.Logout, "create": c.Create, "me_ok": c.MeOK, "me_denied": c.MeDenied, "login_cookie_sets": c.LoginCookies, "session_cookie_sets": c.SessionCookies, "callback_handshake_clears": c.CallbackClears, "logout_cookie_clears": c.LogoutClears, "faults": c.Faults}
}
func (c *oidc439Routes) sessionGenerations() []int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int64(nil), c.generations...)
}
func oidc439Origin(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("OIDC fixture requires an exact loopback HTTPS origin")
	}
	return u
}
func oidc439Server(t *testing.T, ctx context.Context, origin *url.URL, cert tls.Certificate, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	_ = server.Listener.Close()
	listener, err := net.Listen("tcp", origin.Host)
	if err != nil {
		t.Fatal("owned OIDC TLS listener unavailable")
	}
	server.Listener = listener
	server.Config.BaseContext = func(net.Listener) context.Context { return ctx }
	server.Config.ReadHeaderTimeout = 3 * time.Second
	server.Config.ErrorLog = log.New(io.Discard, "", 0) // No raw TLS/request diagnostic strings.
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
func oidc439ReadDone(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 0 || before.Size() > 2048 {
		return nil, os.ErrInvalid
	}
	if stat, ok := before.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, os.ErrInvalid
	}
	if before.Size() == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	body, err := io.ReadAll(io.LimitReader(file, 2049))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, os.ErrInvalid
	}
	if after.Size() != before.Size() || after.ModTime() != before.ModTime() || int64(len(body)) != before.Size() {
		return nil, io.ErrUnexpectedEOF
	}
	return body, nil
}

// Selected external-browser gate. It hosts the qualified whole SPA with its
// actual inline CSP and the original Routes/auth middleware. The issuer is an
// explicit controlled protocol peer, not live Zitadel or ingress acceptance.
// No browser cookie/code/token is injected or exported. Fixture CA trust uses
// the ordinary oidc.ClientContext transport hook without changing verification.
func TestOrdinaryOIDCStaffPortalWithExternalBrowser439E2E(t *testing.T) {
	if os.Getenv("HASH_OIDC_BROWSER_E2E") != "1" {
		t.Skip("explicit ordinary OIDC external browser fixture required")
	}
	started := time.Now()
	for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_PDF_WORKER_PATH"} {
		if os.Getenv(name) == "" {
			t.Fatal("selected OIDC fixture is missing an owned native dependency")
		}
	}
	base := oidc439Origin(t, os.Getenv("HASH_OIDC_BROWSER_BASE"))
	issuer := oidc439Origin(t, os.Getenv("HASH_OIDC_BROWSER_ISSUER"))
	if base.Host != "127.0.0.1:8443" || issuer.Host != "127.0.0.1:8444" {
		t.Fatal("application and issuer must use the fixed owned loopback ports")
	}
	frontend, input, done, artifacts := os.Getenv("HASH_OIDC_BROWSER_FRONTEND"), os.Getenv("HASH_OIDC_BROWSER_INPUT"), os.Getenv("HASH_OIDC_BROWSER_DONE"), os.Getenv("HASH_OIDC_BROWSER_ARTIFACTS")
	for _, path := range []string{frontend, input, done, artifacts} {
		if !filepath.IsAbs(path) {
			t.Fatal("OIDC fixture requires absolute owned paths")
		}
	}
	if input == done || filepath.Dir(input) != filepath.Dir(done) {
		t.Fatal("OIDC private handoff paths must be distinct siblings")
	}
	for _, path := range []string{input, done, filepath.Join(artifacts, "oidc-native439.json")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("OIDC handoffs and native receipt must be fresh")
		}
	}
	info, err := os.Lstat(artifacts)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("OIDC artifact directory must be private")
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
		t.Fatal("OIDC gate requires the selected whole150-file SPA, not a component entry")
	}
	shell, err := os.ReadFile(filepath.Join(frontend, "index.html"))
	if err != nil || len(shell) == 0 || len(shell) > 1<<20 {
		t.Fatal("qualified SPA shell unavailable")
	}
	// This original constructor owns migration/runtime/pool context from birth.
	// Its inherited90s parent remains authoritative; no WithoutCancel extension.
	q := newOwnedPublicReadFixtureProfileV1(t, false, false)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	deadline, ok := f.ctx.Deadline()
	if !ok || time.Until(deadline) <= 5*time.Second {
		t.Fatal("native OIDC fixture has no useful inherited deadline")
	}
	initialOwner, err := f.q.GetUser(f.ctx, f.user.ID)
	if err != nil {
		t.Fatal("read original fixture owner")
	}
	invite, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@oidc439.example.test", Name: "Invited sender439", Role: "sender"})
	if err != nil || invite == nil || invite.ZitadelSub.Valid {
		t.Fatal("create ephemeral unbound invited sender")
	}
	var beforeOrgs, beforeUsers, beforeDocuments, beforeRecipients, beforeMail, beforeSignatures, beforeIntents int64
	if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM orgs),(SELECT count(*) FROM users),(SELECT count(*) FROM documents),(SELECT count(*) FROM recipients),(SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM signatures),(SELECT count(*) FROM send_sealing_intents)`).Scan(&beforeOrgs, &beforeUsers, &beforeDocuments, &beforeRecipients, &beforeMail, &beforeSignatures, &beforeIntents); err != nil {
		t.Fatal("read controlled initial effect counts")
	}
	cert, roots, spki, err := oidc439TLS()
	if err != nil {
		t.Fatal("create ephemeral fixture CA and certificate")
	}
	provider, err := newOIDC439Provider(issuer.String(), base.String()+"/auth/callback", invite.Email)
	if err != nil {
		t.Fatal("create owned issuer key and state")
	}
	oidc439Server(t, f.ctx, issuer, cert, provider)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	trusted := oidc.ClientContext(f.ctx, client)
	f.s.OIDC, err = auth.NewOIDC(trusted, auth.OIDCConfig{IssuerURL: issuer.String(), ClientID: provider.clientID, RedirectURL: base.String() + "/auth/callback", Cookies: f.s.Cookies})
	if err != nil || f.s.OIDC == nil {
		t.Fatal("owned HTTPS issuer discovery failed")
	}
	f.s.PublicURL = base.String()
	f.s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(frontend))
	f.s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if file, statErr := os.Stat(filepath.Join(frontend, clean)); statErr == nil && !file.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(frontend, "index.html"))
	})
	counts := &oidc439Routes{cookies: f.s.Cookies, userID: invite.ID}
	routes := f.s.Routes()
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trust only: the real callback still exchanges/verifies its original
		// code, PKCE, issuer, signature, audience, expiry and nonce.
		r = r.WithContext(oidc.ClientContext(r.Context(), client))
		tracked := r.URL.Path == "/auth/login" || r.URL.Path == "/auth/callback" || r.URL.Path == "/auth/logout" || r.URL.Path == "/api/v1/me" || r.URL.Path == "/api/v1/documents" && r.Method == http.MethodPost
		if !tracked {
			routes.ServeHTTP(w, r)
			return
		}
		observed := &oidc439StatusWriter{ResponseWriter: w}
		routes.ServeHTTP(observed, r)
		counts.observe(r, observed)
	})
	oidc439Server(t, f.ctx, base, cert, app)
	packet, err := json.Marshal(map[string]any{"schema": 1, "source": "ordinary-oidc439", "base": base.String(), "issuer": issuer.String(), "leaf_spki_sha256": spki, "org_id": f.org, "user_id": invite.ID, "email": invite.Email, "name": invite.Name, "role": invite.Role, "document_name": "OIDC439 ordinary draft", "session_generation": invite.SessionGeneration, "native_deadline_unix_ms": deadline.UnixMilli()})
	if err != nil || len(packet) > 8192 {
		t.Fatal("safe OIDC bootstrap exceeds its closed scope")
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
					t.Fatal("external browser did not accept the ordinary OIDC journey")
				}
				break
			}
		}
		if !os.IsNotExist(readErr) && readErr != io.ErrUnexpectedEOF {
			t.Fatal("OIDC completion marker is not a bounded private closed record")
		}
		if !time.Now().Before(waitUntil) {
			t.Fatal("OIDC browser rendezvous exhausted its original remaining deadline")
		}
		select {
		case <-f.ctx.Done():
			t.Fatal("ordinary OIDC native fixture deadline expired")
		case <-time.After(100 * time.Millisecond):
		}
	}
	member, err := f.q.GetUser(f.ctx, invite.ID)
	if err != nil || member.OrgID != invite.OrgID || member.Role != invite.Role || member.Email != invite.Email || member.Name != invite.Name || !member.ZitadelSub.Valid || member.ZitadelSub.String != provider.subject || member.SessionGeneration != invite.SessionGeneration+1 {
		t.Fatal("OIDC adoption/logout changed membership authority or failed one generation revocation")
	}
	owner, err := f.q.GetUser(f.ctx, f.user.ID)
	if err != nil || !reflect.DeepEqual(initialOwner, owner) {
		t.Fatal("ordinary login changed the unrelated original owner")
	}
	document, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: completed.DocumentID, OrgID: f.org})
	if err != nil || document.SenderID != invite.ID || document.Name != "OIDC439 ordinary draft" || document.SourceKind != "blocks" || document.Status != "draft" || document.SentAt.Valid || document.CompletedAt.Valid {
		t.Fatal("ordinary UI did not create exactly the invited sender's legal draft")
	}
	var blocks struct {
		Version int               `json:"version"`
		Blocks  []json.RawMessage `json:"blocks"`
	}
	var variables map[string]json.RawMessage
	if json.Unmarshal(document.BlocksJson, &blocks) != nil || blocks.Version != 1 || len(blocks.Blocks) != 0 || json.Unmarshal(document.VariablesJson, &variables) != nil || len(variables) != 0 {
		t.Fatal("ordinary draft contents escaped the UI request scope")
	}
	var orgs, users, documents, recipients, mail, signatures, intents, bound, created, wrongActor, sent int64
	if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM orgs),(SELECT count(*) FROM users),(SELECT count(*) FROM documents),(SELECT count(*) FROM recipients),(SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM signatures),(SELECT count(*) FROM send_sealing_intents),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='member.identity_bound' AND actor_user_id=$2),(SELECT count(*) FROM events WHERE document_id=$3 AND kind='document.created'),(SELECT count(*) FROM events WHERE document_id=$3 AND actor_user_id IS DISTINCT FROM $2),(SELECT count(*) FROM events WHERE document_id=$3 AND kind IN ('document.sent','recipient.invited','document.signed'))`, f.org, invite.ID, document.ID).Scan(&orgs, &users, &documents, &recipients, &mail, &signatures, &intents, &bound, &created, &wrongActor, &sent); err != nil || orgs != beforeOrgs || users != beforeUsers || documents != beforeDocuments+1 || recipients != beforeRecipients || mail != beforeMail || signatures != beforeSignatures || intents != beforeIntents || bound != 1 || created != 1 || wrongActor != 0 || sent != 0 {
		t.Fatal("ordinary authentication/draft escaped its exact durable effect scope")
	}
	events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil || len(events) > 100 {
		t.Fatal("read bounded OIDC/draft audit chain")
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	if result := verifier.Result(); !result.OK || !result.Complete || result.TotalChecked != len(events) {
		t.Fatal("ordinary OIDC/draft audit chain invalid")
	}
	providerCounts := provider.snapshot()
	if providerCounts.Discovery != 1 || providerCounts.Authorize != 3 || providerCounts.Accept != 3 || providerCounts.Token != 3 || providerCounts.JWKS < 1 || providerCounts.JWKS > 2 || providerCounts.Faults != 0 || providerCounts.PendingTickets != 0 || providerCounts.PendingCodes != 0 || !providerCounts.DistinctHandshake {
		t.Fatal("owned real OIDC protocol inventory or one-use handshake differs")
	}
	routeCounts := counts.snapshot()
	if routeCounts["login"] != 3 || routeCounts["callback"] != 3 || routeCounts["logout"] != 1 || routeCounts["create"] != 1 || routeCounts["me_ok"] < 3 || routeCounts["me_denied"] < 4 || routeCounts["me_ok"]+routeCounts["me_denied"] > 32 || routeCounts["login_cookie_sets"] != 3 || routeCounts["session_cookie_sets"] != 3 || routeCounts["callback_handshake_clears"] != 3 || routeCounts["logout_cookie_clears"] != 1 || routeCounts["faults"] != 0 {
		t.Fatal("ordinary route/session/cookie status inventory differs")
	}
	issuedGenerations := counts.sessionGenerations()
	if !reflect.DeepEqual(issuedGenerations, []int64{invite.SessionGeneration, invite.SessionGeneration, member.SessionGeneration}) {
		t.Fatal("fresh real login did not receive the exact current database session generation")
	}
	q.reconcileV1(t)
	q.assertObserversOnlyV1(t)
	receipt, err := json.Marshal(map[string]any{"schema": 1, "source": "ordinary-oidc439", "passed": true, "org_id": f.org, "user_id": invite.ID, "document_id": document.ID, "provider": providerCounts, "routes": routeCounts, "session_generation_before": invite.SessionGeneration, "session_generation_after": member.SessionGeneration, "minted_session_generations": issuedGenerations, "fresh_login_current_generation": true, "invited_membership_preserved": true, "unrelated_owner_unchanged": true, "one_blocks_draft_created": true, "no_send_mail_signatures": true, "audit_chain_valid": true, "native_runtime_drained": true, "duration_ms": time.Since(started).Milliseconds(), "scope": "controlled HTTPS issuer and hosted whole SPA; not live provider, ingress or production embed"})
	if err != nil || len(receipt) > 8192 {
		t.Fatal("safe native OIDC receipt exceeded cap")
	}
	crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, "oidc-native439.json"), receipt)
}
