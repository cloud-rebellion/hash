//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func crmBrowserRandomHex(t *testing.T) string {
	t.Helper()
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		t.Fatal("generate private disposable browser credential")
	}
	return hex.EncodeToString(bytes[:])
}

// This selected fixture uses real PG, production session/owner routes and the
// protected CRM HTTP client. Its remote CRM account and keys are disposable
// synthetic peers. No renderer, SMTP, live CRM or deployment is exercised.
func TestCRMConnectionWithExternalBrowserE2E(t *testing.T) {
	if os.Getenv("HASH_CRM_CONNECTION_BROWSER_E2E") != "1" {
		t.Skip("explicit external CRM connection browser fixture required")
	}
	if os.Getenv("HASH_E2E_DB_URL") == "" {
		t.Fatal("selected CRM browser fixture requires real PostgreSQL")
	}
	base, err := url.Parse(os.Getenv("HASH_CRM_CONNECTION_BROWSER_BASE"))
	if err != nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		t.Fatal("CRM browser requires an exact loopback HTTPS origin")
	}
	root, inputPath, donePath := os.Getenv("HASH_CRM_CONNECTION_BROWSER_FRONTEND"), os.Getenv("HASH_CRM_CONNECTION_BROWSER_INPUT"), os.Getenv("HASH_CRM_CONNECTION_BROWSER_DONE")
	for _, path := range []string{root, inputPath, donePath} {
		if !filepath.IsAbs(path) {
			t.Fatal("CRM browser requires separate absolute artifact paths")
		}
	}
	if inputPath == donePath {
		t.Fatal("private browser input and completion paths must differ")
	}
	for _, path := range []string{inputPath, donePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("CRM browser handoff paths must be fresh")
		}
	}

	f := setupLifecycleAuthorizationE2E(t, "owner", false, false)
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Minute)
	defer cancel()
	const teamID, integrationUserID = "crm_browser_team_CUID2", "crm_browser_user_CUID2"
	token, encryptionKey := crmBrowserRandomHex(t), crmBrowserRandomHex(t)
	var crmReads, unexpectedReads atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		crmReads.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/auth/me" || r.Header.Get("Authorization") != "Bearer "+token {
			unexpectedReads.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": integrationUserID, "team_id": teamID, "is_active": true, "role": "ADMIN"})
	}))
	defer peer.Close()
	client, err := crmconnection.NewClient(peer.URL, true)
	if err != nil {
		t.Fatal("create protected disposable CRM client")
	}
	keys, err := crmconnection.NewKeyring(encryptionKey, "")
	if err != nil {
		t.Fatal("create private CRM encryption keyring")
	}
	f.s.CRMOrigin, f.s.CRMClient, f.s.CRMKeys = peer.URL, client, keys
	f.s.Environment, f.s.PublicURL = "development", base.String()
	foreignOrg, err := f.q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Foreign CRM browser " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal("seed foreign browser organization")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := f.pool.Exec(cleanup, "DELETE FROM orgs WHERE id=$1", foreignOrg.ID); err != nil { //nolint:rawsql -- fixture-owned organization only
			t.Error("clean foreign browser organization")
		}
	})
	foreignOwner, err := f.q.CreateUser(ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Email: uuid.NewString() + "@crm-browser.test", Name: "Foreign browser owner", Role: "owner"})
	if err != nil {
		t.Fatal("seed foreign browser owner")
	}
	viewer, err := f.q.CreateUser(ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@crm-browser.test", Name: "Browser viewer", Role: "viewer"})
	if err != nil {
		t.Fatal("seed alternate browser viewer")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := f.pool.Exec(cleanup, "DELETE FROM users WHERE id=$1", viewer.ID); err != nil { //nolint:rawsql -- fixture-owned alternate viewer only
			t.Error("clean alternate browser viewer")
		}
	})
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	foreignCookie := dsrSessionCookieE2E(t, f.s, foreignOwner.ID, foreignOwner.SessionGeneration, time.Hour)
	viewerCookie := dsrSessionCookieE2E(t, f.s, viewer.ID, viewer.SessionGeneration, time.Hour)

	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal("CRM browser requires current built frontend")
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
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if err != nil {
		t.Fatal("CRM browser task HTTPS listener unavailable")
	}
	server.Config.Handler = f.s.Routes()
	server.StartTLS()
	defer server.Close()
	packet, err := json.Marshal(map[string]any{"base": base.String(), "cookieName": SessionCookieName, "cookie": cookie,
		"foreignCookie": foreignCookie, "viewerCookie": viewerCookie, "token": token, "orgID": f.org, "userID": f.user.ID,
		"foreignOrgID": foreignOrg.ID, "foreignUserID": foreignOwner.ID, "crmTeamID": teamID, "crmUserID": integrationUserID})
	if err != nil {
		t.Fatal("encode private CRM browser packet")
	}
	input, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("create fresh private CRM browser packet")
	}
	defer os.Remove(inputPath)
	if _, err = input.Write(packet); err != nil {
		_ = input.Close()
		t.Fatal("write private CRM browser packet")
	}
	if err = input.Close(); err != nil {
		t.Fatal("close private CRM browser packet")
	}
	deadline := time.Now().Add(150 * time.Second)
	for {
		body, err := os.ReadFile(donePath)
		if err == nil {
			var done struct {
				ExitCode int  `json:"exit_code"`
				Verified bool `json:"verified"`
			}
			if json.Unmarshal(body, &done) != nil || done.ExitCode != 0 || !done.Verified {
				t.Fatal("external browser did not accept CRM owner connection journey")
			}
			break
		}
		if !os.IsNotExist(err) || time.Now().After(deadline) {
			t.Fatal("external CRM browser acceptance timed out")
		}
		select {
		case <-ctx.Done():
			t.Fatal("CRM browser fixture deadline exceeded")
		case <-time.After(100 * time.Millisecond):
		}
	}
	row, err := f.q.GetCRMConnectionByOrg(ctx, f.org)
	if err != nil || row.Generation != 5 || row.Status != "revoked" || row.CredentialCiphertext != nil || row.CrmTeamID != teamID || row.CrmUserID != integrationUserID {
		t.Fatal("browser lost durable revoke/generation/account state")
	}
	if _, err = f.q.GetCRMConnectionByOrg(ctx, foreignOrg.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("switched browser actor created a foreign CRM connection")
	}
	if crmReads.Load() != 4 || unexpectedReads.Load() != 0 {
		t.Fatal("browser made unexpected upstream CRM requests or checked a refused actor")
	}
	var candidateEvents, enabledEvents, revokedEvents int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind='crm.connection.candidate'),count(*) FILTER (WHERE kind='crm.connection.enabled'),count(*) FILTER (WHERE kind='crm.connection.revoked') FROM events WHERE org_id=$1`, f.org).Scan(&candidateEvents, &enabledEvents, &revokedEvents); err != nil || candidateEvents != 2 || enabledEvents != 2 || revokedEvents != 1 {
		t.Fatal("browser did not commit exact audited candidate/enable/revoke operations")
	}
	receipt, err := json.MarshalIndent(map[string]any{
		"result": "pass", "actualPostgreSQL": true, "builtFrontend": true, "protectedSyntheticCRMClient": true,
		"finalStatus": row.Status, "finalGeneration": "5", "credentialCiphertextRemoved": row.CredentialCiphertext == nil,
		"retainedAccountMatched":  row.CrmTeamID == teamID && row.CrmUserID == integrationUserID,
		"foreignConnectionAbsent": true, "upstreamIdentityReads": crmReads.Load(), "unexpectedUpstreamReads": unexpectedReads.Load(),
		"candidateAuditEvents": candidateEvents, "enabledAuditEvents": enabledEvents, "revokedAuditEvents": revokedEvents,
		"liveProviderAcceptance": false, "contractProvenanceAcceptance": false, "deploymentAcceptance": false,
	}, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(filepath.Dir(donePath), "backend-receipt.json"), append(receipt, '\n'), 0600) != nil {
		t.Fatal("write safe CRM browser durable-state receipt")
	}
	t.Log("actual built owner UI/HTTPS/PostgreSQL/protected synthetic CRM peer accepted candidate1/enable2/replacement3/enable4/revoke5, actor binding and viewer refusal; no live-provider/contract-provenance/deployment acceptance")
}
