//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const crmConnectionPathE2E = "/api/v1/settings/crm/connection/"
const crmConnectionTokenE2E = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const crmConnectionKeyE2E = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
const crmConnectionTeamE2E = "f23cuid2remotecrmteam"
const crmConnectionUserE2E = "f24cuid2remotecrmuser"

type crmConnectionPauseE2E struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *crmConnectionPauseE2E) finish() { p.once.Do(func() { close(p.release) }) }

type crmConnectionPeerE2E struct {
	server     *httptest.Server
	requests   atomic.Int64
	unexpected atomic.Int64
	mu         sync.Mutex
	next       *crmConnectionPauseE2E
}

// This peer exercises the actual protected HTTP client and the inspected bare
// BrightCRM /auth/me contract, including CUID-style string identities. It does
// not bypass remote credential validation with an injected successful client.
func newCRMConnectionPeerE2E(t *testing.T) *crmConnectionPeerE2E {
	t.Helper()
	p := &crmConnectionPeerE2E{}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/auth/me" || r.Header.Get("Authorization") != "Bearer "+crmConnectionTokenE2E {
			p.unexpected.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		p.mu.Lock()
		paused := p.next
		p.next = nil
		p.mu.Unlock()
		if paused != nil {
			close(paused.entered)
			select {
			case <-paused.release:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": crmConnectionUserE2E, "team_id": crmConnectionTeamE2E, "is_active": true,
			"role": "ADMIN", "name": "CRM enrollment fixture", "email": "crm-enrollment@example.test"})
	}))
	t.Cleanup(func() {
		p.server.Close()
		if p.unexpected.Load() != 0 {
			t.Error("CRM enrollment made an unexpected credential or endpoint request")
		}
	})
	return p
}

func (p *crmConnectionPeerE2E) pauseNext(t *testing.T) *crmConnectionPauseE2E {
	t.Helper()
	paused := &crmConnectionPauseE2E{entered: make(chan struct{}), release: make(chan struct{})}
	p.mu.Lock()
	if p.next != nil {
		p.mu.Unlock()
		t.Fatal("another CRM verification pause is pending")
	}
	p.next = paused
	p.mu.Unlock()
	t.Cleanup(paused.finish)
	return paused
}

func (p *crmConnectionPauseE2E) await(t *testing.T) {
	t.Helper()
	select {
	case <-p.entered:
	case <-time.After(4 * time.Second):
		t.Fatal("CRM request did not reach actual remote verification")
	}
}

type crmConnectionFixtureE2E struct {
	lifecycleAuthorizationFixture
	peer   *crmConnectionPeerE2E
	cookie string
}

func setupCRMConnectionE2E(t *testing.T) crmConnectionFixtureE2E {
	t.Helper()
	f := setupLifecycleAuthorizationE2E(t, "owner", false, false)
	return setupCRMConnectionForFixtureE2E(t, f)
}

// Component-only connection tests keep their original pooled fixture. Source
// and Send tests supply the real native authoring/runtime fixture instead.
func setupCRMConnectionForFixtureE2E(t *testing.T, f lifecycleAuthorizationFixture) crmConnectionFixtureE2E {
	t.Helper()
	t.Setenv("HASH_ENVIRONMENT", "development")
	f.s.PublicURL, f.s.Environment = "http://localhost:39487", "development"
	if f.s.Send != nil {
		f.s.Send.PublicURL = f.s.PublicURL
	}
	if f.s.Sign != nil {
		f.s.Sign.BaseURL = f.s.PublicURL
	}
	p := newCRMConnectionPeerE2E(t)
	client, err := crmconnection.NewClient(p.server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crmconnection.NewKeyring(crmConnectionKeyE2E, "")
	if err != nil {
		t.Fatal(err)
	}
	f.s.CRMOrigin, f.s.CRMClient, f.s.CRMKeys = p.server.URL, client, keys
	return crmConnectionFixtureE2E{f, p, dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Hour)}
}

func (f crmConnectionFixtureE2E) submit(ctx context.Context, method, suffix, body, cookie string) *httptest.ResponseRecorder {
	if method != http.MethodGet {
		var input map[string]json.RawMessage
		if json.Unmarshal([]byte(body), &input) == nil && input != nil {
			if _, present := input["expected_org_id"]; !present {
				input["expected_org_id"], _ = json.Marshal(f.org)
			}
			if _, present := input["expected_user_id"]; !present {
				input["expected_user_id"], _ = json.Marshal(f.user.ID)
			}
			encoded, _ := json.Marshal(input)
			body = string(encoded)
		}
	}
	r := httptest.NewRequest(method, f.s.PublicURL+crmConnectionPathE2E+suffix, strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func crmConnectionPutBodyE2E(generation int64) string {
	return `{"expected_generation":"` + strconv.FormatInt(generation, 10) + `","token":"` + crmConnectionTokenE2E + `"}`
}

func crmConnectionEnableBodyE2E(generation int64, team, user string) string {
	return `{"expected_generation":"` + strconv.FormatInt(generation, 10) + `","crm_team_id":"` + team + `","crm_user_id":"` + user + `"}`
}

func crmConnectionRevokeBodyE2E(generation int64) string {
	return `{"expected_generation":"` + strconv.FormatInt(generation, 10) + `"}`
}

func assertCRMConnectionSafeResponseE2E(t *testing.T, w *httptest.ResponseRecorder, want int) crmConnectionResponse {
	t.Helper()
	if w.Code != want {
		t.Fatalf("CRM connection status=%d want=%d", w.Code, want)
	}
	for _, private := range []string{crmConnectionTokenE2E, crmConnectionKeyE2E, "credential_ciphertext", "ciphertext", "Bearer ", "key_hash"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("CRM response disclosed private credential material")
		}
	}
	var out crmConnectionResponse
	if want == http.StatusOK {
		if w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal("CRM settings response is cacheable or malformed")
		}
	}
	return out
}

func assertCRMConnectionActorE2E(t *testing.T, w *httptest.ResponseRecorder, org, user uuid.UUID) {
	t.Helper()
	var witness struct {
		OrgID  uuid.UUID `json:"org_id"`
		UserID uuid.UUID `json:"user_id"`
	}
	if json.Unmarshal(w.Body.Bytes(), &witness) != nil || witness.OrgID != org || witness.UserID != user {
		t.Fatal("CRM response did not retain the exact admitted Hash organization and user witness")
	}
}

func (f crmConnectionFixtureE2E) candidate(t *testing.T) *generated.CrmConnection {
	t.Helper()
	w := f.submit(f.ctx, http.MethodPut, "", crmConnectionPutBodyE2E(0), f.cookie)
	out := assertCRMConnectionSafeResponseE2E(t, w, http.StatusOK)
	assertCRMConnectionActorE2E(t, w, f.org, f.user.ID)
	if !out.Available || !out.Configured || out.Connection == nil || out.Connection.Status != "candidate" || out.Connection.Generation != "1" {
		t.Fatal("verified enrollment did not remain an explicitly disabled candidate")
	}
	row, err := f.q.GetCRMConnectionByOrg(f.ctx, f.org)
	if err != nil || row.Status != "candidate" || row.Generation != 1 {
		t.Fatal("candidate was not durably stored", err)
	}
	return row
}

func (f crmConnectionFixtureE2E) active(t *testing.T) *generated.CrmConnection {
	t.Helper()
	f.candidate(t)
	w := f.submit(f.ctx, http.MethodPost, "enable", crmConnectionEnableBodyE2E(1, crmConnectionTeamE2E, crmConnectionUserE2E), f.cookie)
	assertCRMConnectionSafeResponseE2E(t, w, http.StatusOK)
	row, err := f.q.GetCRMConnectionByOrg(f.ctx, f.org)
	if err != nil || row.Status != "active" || row.Generation != 2 {
		t.Fatal("confirmed account was not durably enabled", err)
	}
	return row
}

func (f crmConnectionFixtureE2E) inventory(t *testing.T) []byte {
	t.Helper()
	var raw []byte
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'connections',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY org_id),'[]'::jsonb) FROM crm_connections c WHERE org_id=$1),
		'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY document_id,variable_name),'[]'::jsonb) FROM document_variable_bindings b JOIN documents d ON d.id=b.document_id WHERE d.org_id=$1),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1))::text`, f.org).Scan(&raw) //nolint:rawsql -- exact disposable synthetic tenant inventory, never logged
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f crmConnectionFixtureE2E) assertUnchanged(t *testing.T, before []byte) {
	t.Helper()
	if !bytes.Equal(before, f.inventory(t)) {
		t.Fatal("refused CRM operation changed the exact connection or durable audit state")
	}
}

func TestCRMConnectionCandidateRequiresExplicitAccountConfirmationE2E(t *testing.T) {
	f := setupCRMConnectionE2E(t)
	old := f.candidate(t)
	if old.CrmTeamID != crmConnectionTeamE2E || old.CrmUserID != crmConnectionUserE2E || bytes.Contains(old.CredentialCiphertext, []byte(crmConnectionTokenE2E)) {
		t.Fatal("candidate mapping or encrypted credential is incorrect")
	}
	before, reads := f.inventory(t), f.peer.requests.Load()
	w := f.submit(f.ctx, http.MethodPost, "enable", crmConnectionEnableBodyE2E(1, "othercrmteam", crmConnectionUserE2E), f.cookie)
	assertCRMConnectionSafeResponseE2E(t, w, http.StatusConflict)
	f.assertUnchanged(t, before)
	if f.peer.requests.Load() != reads {
		t.Fatal("incorrect owner account confirmation reached external verification")
	}
	w = f.submit(f.ctx, http.MethodPost, "enable", crmConnectionEnableBodyE2E(1, crmConnectionTeamE2E, crmConnectionUserE2E), f.cookie)
	out := assertCRMConnectionSafeResponseE2E(t, w, http.StatusOK)
	assertCRMConnectionActorE2E(t, w, f.org, f.user.ID)
	if out.Connection == nil || out.Connection.Generation != "2" || out.Connection.Status != "active" || f.peer.requests.Load() != reads+1 {
		t.Fatal("explicit confirmation did not reverify the actual account and advance activation")
	}
	current, err := f.q.GetCRMConnectionByOrg(f.ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(old.CredentialCiphertext, current.CredentialCiphertext) {
		t.Fatal("enable reused ciphertext from a different authority generation")
	}
	if token, _, err := f.s.CRMKeys.Open(crmIdentity(current), current.CredentialCiphertext); err != nil || token != crmConnectionTokenE2E {
		t.Fatal("enabled ciphertext does not open under its exact current account generation")
	}
	if _, _, err := f.s.CRMKeys.Open(crmIdentity(old), current.CredentialCiphertext); err == nil {
		t.Fatal("enabled ciphertext remained valid under the obsolete candidate generation")
	}
	w = f.submit(f.ctx, http.MethodPut, "", crmConnectionPutBodyE2E(2), f.cookie)
	out = assertCRMConnectionSafeResponseE2E(t, w, http.StatusOK)
	if out.Connection == nil || out.Connection.ID != old.ID || out.Connection.Generation != "3" || out.Connection.Status != "candidate" {
		t.Fatal("credential replacement did not disable the connection for fresh account confirmation")
	}
	var events int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind IN('crm.connection.candidate','crm.connection.enabled')`, f.org).Scan(&events); err != nil || events != 3 { //nolint:rawsql
		t.Fatal("candidate/enable transitions are not exactly durably audited", err)
	}
}

func TestCRMConnectionActorWitnessRefusesCookieSubstitutionE2E(t *testing.T) {
	f := setupCRMConnectionE2E(t)
	other := setupCRMConnectionE2E(t)
	for _, mismatch := range []string{"organization", "user"} {
		t.Run(mismatch, func(t *testing.T) {
			org, user := f.org, f.user.ID
			if mismatch == "organization" {
				org = other.org
			} else {
				user = other.user.ID
			}
			body := map[string]any{"expected_generation": "0", "token": crmConnectionTokenE2E, "expected_org_id": org, "expected_user_id": user}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			before, otherBefore, reads := f.inventory(t), other.inventory(t), f.peer.requests.Load()
			assertCRMConnectionSafeResponseE2E(t, f.submit(f.ctx, http.MethodPut, "", string(raw), f.cookie), http.StatusConflict)
			f.assertUnchanged(t, before)
			other.assertUnchanged(t, otherBefore)
			if f.peer.requests.Load() != reads {
				t.Fatal("mismatched Hash actor witness reached the CRM credential")
			}
		})
	}
}

func TestCRMConnectionVerificationRechecksOriginalOwnerAuthorityE2E(t *testing.T) {
	for _, operation := range []string{"configure", "enable"} {
		for _, change := range []string{"demotion", "revocation", "expiry"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupCRMConnectionE2E(t)
				method, suffix, body := http.MethodPut, "", crmConnectionPutBodyE2E(0)
				if operation == "enable" {
					f.candidate(t)
					method, suffix, body = http.MethodPost, "enable", crmConnectionEnableBodyE2E(1, crmConnectionTeamE2E, crmConnectionUserE2E)
				}
				before := f.inventory(t)
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, ttl)
				paused := f.peer.pauseNext(t)
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- f.submit(f.ctx, method, suffix, body, cookie) }()
				paused.await(t)
				switch change {
				case "demotion":
					if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
						t.Fatal(err)
					}
				case "revocation":
					if _, err := f.q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: 0}); err != nil {
						t.Fatal(err)
					}
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
				}
				paused.finish()
				want := http.StatusForbidden
				if change == "expiry" {
					want = http.StatusUnauthorized
				}
				assertCRMConnectionSafeResponseE2E(t, receiveSessionOperationE2E(t, done), want)
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestCRMConnectionVerificationRejectsConcurrentGenerationE2E(t *testing.T) {
	for _, operation := range []string{"configure", "enable"} {
		t.Run(operation, func(t *testing.T) {
			f := setupCRMConnectionE2E(t)
			method, suffix, body, generation := http.MethodPut, "", crmConnectionPutBodyE2E(0), int64(0)
			if operation == "enable" {
				f.candidate(t)
				method, suffix, body, generation = http.MethodPost, "enable", crmConnectionEnableBodyE2E(1, crmConnectionTeamE2E, crmConnectionUserE2E), 1
			}
			paused := f.peer.pauseNext(t)
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- f.submit(f.ctx, method, suffix, body, f.cookie) }()
			paused.await(t)
			// This real second request proves enrollment holds no local owner or
			// connection lock across the remote HTTP wait. It wins the same CAS.
			winner := f.submit(f.ctx, http.MethodPut, "", crmConnectionPutBodyE2E(generation), f.cookie)
			assertCRMConnectionSafeResponseE2E(t, winner, http.StatusOK)
			before := f.inventory(t)
			paused.finish()
			assertCRMConnectionSafeResponseE2E(t, receiveSessionOperationE2E(t, done), http.StatusConflict)
			f.assertUnchanged(t, before)
		})
	}
}

func crmConnectionOperationE2E(t *testing.T, f crmConnectionFixtureE2E, operation string) (method, suffix, body string) {
	t.Helper()
	switch operation {
	case "configure":
		return http.MethodPut, "", crmConnectionPutBodyE2E(0)
	case "enable":
		f.candidate(t)
		return http.MethodPost, "enable", crmConnectionEnableBodyE2E(1, crmConnectionTeamE2E, crmConnectionUserE2E)
	case "revoke":
		f.active(t)
		return http.MethodDelete, "", crmConnectionRevokeBodyE2E(2)
	default:
		t.Fatal("unknown CRM operation fixture")
		return "", "", ""
	}
}

func TestCRMConnectionAuditWaitExpiryRollsBackE2E(t *testing.T) {
	for _, operation := range []string{"configure", "enable", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			f := setupCRMConnectionE2E(t)
			method, suffix, body := crmConnectionOperationE2E(t, f, operation)
			before := f.inventory(t)
			blocked := ownerOrgLockE2E(t, ownerOrgMutationFixture{lifecycleAuthorizationFixture: f.lifecycleAuthorizationFixture}, true)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Second)
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- f.submit(f.ctx, method, suffix, body, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, f.s, cookie)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			assertCRMConnectionSafeResponseE2E(t, receiveSessionOperationE2E(t, done), http.StatusUnauthorized)
			f.assertUnchanged(t, before)
		})
	}
}

func TestCRMConnectionAuditFailureRollsBackE2E(t *testing.T) {
	for _, operation := range []string{"configure", "enable", "revoke"} {
		for _, noRow := range []bool{false, true} {
			name := operation + "/exception"
			if noRow {
				name = operation + "/missing-row"
			}
			t.Run(name, func(t *testing.T) {
				f := setupCRMConnectionE2E(t)
				method, suffix, body := crmConnectionOperationE2E(t, f, operation)
				before := f.inventory(t)
				drop := ownerOrgAuditFaultE2E(t, ownerOrgMutationFixture{lifecycleAuthorizationFixture: f.lifecycleAuthorizationFixture}, noRow)
				w := f.submit(f.ctx, method, suffix, body, f.cookie)
				assertCRMConnectionSafeResponseE2E(t, w, http.StatusServiceUnavailable)
				if strings.Contains(w.Body.String(), "fixture private") {
					t.Fatal("private audit failure became an owner-readable CRM diagnostic")
				}
				f.assertUnchanged(t, before)
				drop()
			})
		}
	}
}

func TestCRMConnectionAuditWaitSerializesConcurrentGenerationE2E(t *testing.T) {
	f := setupCRMConnectionE2E(t)
	f.active(t)
	reads := f.peer.requests.Load()
	blocked := ownerOrgLockE2E(t, ownerOrgMutationFixture{lifecycleAuthorizationFixture: f.lifecycleAuthorizationFixture}, true)
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- f.submit(f.ctx, http.MethodPut, "", crmConnectionPutBodyE2E(2), f.cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	second := make(chan *httptest.ResponseRecorder, 1)
	go func() { second <- f.submit(f.ctx, http.MethodPut, "", crmConnectionPutBodyE2E(2), f.cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetOrgForOwnerMutation", "transactionid")
	select {
	case <-second:
		t.Fatal("competing generation crossed the original owner/audit transaction")
	default:
	}
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	assertCRMConnectionSafeResponseE2E(t, receiveSessionOperationE2E(t, first), http.StatusOK)
	assertCRMConnectionSafeResponseE2E(t, receiveSessionOperationE2E(t, second), http.StatusConflict)
	row, err := f.q.GetCRMConnectionByOrg(f.ctx, f.org)
	if err != nil || row.Generation != 3 || row.Status != "candidate" || f.peer.requests.Load() != reads+1 {
		t.Fatal("competing stale generation did not refuse before additional remote verification", err)
	}
	var events int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind='crm.connection.candidate'`, f.org).Scan(&events); err != nil || events != 2 { //nolint:rawsql
		t.Fatal("competing generation wrote a second candidate/audit transition", err)
	}
}

func TestCRMConnectionRevocationDoesNotNeedDecryptableCredentialE2E(t *testing.T) {
	for _, fault := range []string{"corrupt-ciphertext", "missing-keyring"} {
		t.Run(fault, func(t *testing.T) {
			f := setupCRMConnectionE2E(t)
			row := f.active(t)
			if fault == "corrupt-ciphertext" {
				rows, err := f.pool.Exec(f.ctx, `UPDATE crm_connections SET generation=generation+1,credential_ciphertext=$2 WHERE org_id=$1`, f.org, bytes.Repeat([]byte{0}, len(row.CredentialCiphertext))) //nolint:rawsql -- intentional owned encrypted credential damage
				if err != nil || rows.RowsAffected() != 1 {
					t.Fatal("could not seed exact credential corruption", err)
				}
				row, err = f.q.GetCRMConnectionByOrg(f.ctx, f.org)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				f.s.CRMKeys, f.s.CRMClient = nil, nil
			}
			reads := f.peer.requests.Load()
			w := f.submit(f.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(row.Generation), f.cookie)
			out := assertCRMConnectionSafeResponseE2E(t, w, http.StatusOK)
			fresh, err := f.q.GetCRMConnectionByOrg(f.ctx, f.org)
			if err != nil || fresh.Status != "revoked" || fresh.Generation != row.Generation+1 || fresh.CredentialCiphertext != nil || out.Connection == nil || out.Connection.Status != "revoked" {
				t.Fatal("credential-independent revocation did not clear ciphertext and advance authority", err)
			}
			if f.peer.requests.Load() != reads {
				t.Fatal("safe local revocation depended on a remote credential request")
			}
			var events int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind='crm.connection.revoked'`, f.org).Scan(&events); err != nil || events != 1 { //nolint:rawsql
				t.Fatal("revocation did not append exactly one durable event", err)
			}
		})
	}
}

func TestCRMConnectionTenantAndOwnerReadbackSeparationE2E(t *testing.T) {
	f := setupCRMConnectionE2E(t)
	f.active(t)
	other := setupCRMConnectionE2E(t)
	other.s.CRMOrigin, other.s.CRMClient, other.s.CRMKeys = f.s.CRMOrigin, f.s.CRMClient, f.s.CRMKeys
	before := f.inventory(t)
	w := other.submit(other.ctx, http.MethodGet, "", "", other.cookie)
	out := assertCRMConnectionSafeResponseE2E(t, w, http.StatusOK)
	assertCRMConnectionActorE2E(t, w, other.org, other.user.ID)
	if out.Configured || out.Connection != nil || !out.Available {
		t.Fatal("another Hash tenant could read a configured remote account")
	}
	w = other.submit(other.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(2), other.cookie)
	assertCRMConnectionSafeResponseE2E(t, w, http.StatusConflict)
	f.assertUnchanged(t, before)
	if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
		t.Fatal(err)
	}
	w = f.submit(f.ctx, http.MethodGet, "", "", f.cookie)
	assertCRMConnectionSafeResponseE2E(t, w, http.StatusForbidden)
	f.assertUnchanged(t, before)
}

func TestCRMConnectionDatabaseChecksAndRetainedRollbackE2E(t *testing.T) {
	f := setupCRMConnectionE2E(t)
	f.candidate(t)
	for _, mutation := range []struct{ name, set, state string }{
		{"invalid-status", "generation=generation+1,status='enabled'", "23514"},
		{"candidate-missing-cipher", "generation=generation+1,credential_ciphertext=NULL", "23514"},
		{"revoked-retained-cipher", "generation=generation+1,status='revoked'", "23514"},
		{"missing-status", "generation=generation+1,status=NULL", "23502"},
		{"missing-generation", "generation=NULL", "23502"},
		{"bad-team", "generation=generation+1,crm_team_id='../other'", "23514"},
		{"bad-user", "generation=generation+1,crm_user_id=''", "23514"},
		{"same-generation", "status='active'", "P0001"},
		{"skipped-generation", "generation=generation+2", "P0001"},
		{"changed-local-identity", "generation=generation+1,id=gen_random_uuid()", "P0001"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			before := f.inventory(t)
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			_, err = tx.Exec(f.ctx, "UPDATE crm_connections SET "+mutation.set+" WHERE org_id=$1", f.org) //nolint:rawsql -- fixed scoped synthetic mutations, no request-derived SQL
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != mutation.state {
				t.Fatalf("CRM database invariant SQLSTATE=%v want=%s", err, mutation.state)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			f.assertUnchanged(t, before)
		})
	}
	for _, retained := range []string{"connection", "company-binding"} {
		t.Run("retained-down/"+retained, func(t *testing.T) {
			if retained == "company-binding" {
				if _, err := f.pool.Exec(f.ctx, `DELETE FROM crm_connections WHERE org_id=$1`, f.org); err != nil { //nolint:rawsql -- only disposable fixture authority, deliberately retain new binding
					t.Fatal(err)
				}
				if _, err := f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{DocumentID: f.doc.ID, VariableName: "customer", SourceKind: "crm.company", SourceRef: "f25cuid2crmcompany", SourcePath: "legal_name"}); err != nil {
					t.Fatal(err)
				}
			}
			before := f.inventory(t)
			raw, err := os.ReadFile("../db/migrations/00077_crm_connections.sql")
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.SplitN(string(raw), "-- +goose Down", 2)
			if len(parts) != 2 {
				t.Fatal("CRM migration has no explicit retained-data Down guard")
			}
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			_, err = tx.Exec(f.ctx, parts[1]) //nolint:rawsql -- attempt exact migration Down only inside a disposable rolled-back transaction
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "P0001" {
				t.Fatalf("retained CRM Down did not refuse: %v", err)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			f.assertUnchanged(t, before)
			if _, err := f.q.GetCRMConnectionByOrg(f.ctx, f.org); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("retained Down removed the forward connection table", err)
			}
		})
	}
}

func TestCRMConnectionDatabaseOpaqueIdentityBoundariesE2E(t *testing.T) {
	f := setupCRMConnectionE2E(t)
	for _, field := range []string{"crm_team_id", "crm_user_id"} {
		for _, size := range []int{256, 257} {
			t.Run(field+"/"+strconv.Itoa(size), func(t *testing.T) {
				before := f.inventory(t)
				tx, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(context.Background()) }()
				team, user := crmConnectionTeamE2E, crmConnectionUserE2E
				if field == "crm_team_id" {
					team = strings.Repeat("a", size)
				} else {
					user = strings.Repeat("b", size)
				}
				_, err = tx.Exec(f.ctx, `INSERT INTO crm_connections(org_id,id,generation,status,origin,crm_team_id,crm_user_id,credential_ciphertext,verified_at) VALUES($1,$2,1,'candidate',$3,$4,$5,$6,$7)`,
					f.org, uuid.New(), f.s.CRMOrigin, team, user, bytes.Repeat([]byte{1}, 93), time.Now()) //nolint:rawsql -- exact synthetic SQL boundary, no API or credential-enrollment claim
				if size == 256 {
					if err != nil {
						t.Fatal("database refused a supported 256-byte ASCII identity", err)
					}
					row, err := generated.New(tx).GetCRMConnectionByOrg(f.ctx, f.org)
					if err != nil || row.CrmTeamID != team || row.CrmUserID != user {
						t.Fatal("database changed the accepted exact opaque identity", err)
					}
				} else {
					var pgerr *pgconn.PgError
					if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
						t.Fatal("database did not refuse the 257-byte identity at its CHECK")
					}
				}
				if err := tx.Rollback(f.ctx); err != nil {
					t.Fatal(err)
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestCRMConnectionGenerationExhaustionRetainsSafeRevocationE2E(t *testing.T) {
	for _, state := range []string{"candidate", "active"} {
		t.Run(state, func(t *testing.T) {
			f := setupCRMConnectionE2E(t)
			identity := crmconnection.Identity{ID: uuid.New(), OrgID: f.org, Generation: math.MaxInt64 - 1, Origin: f.s.CRMOrigin, CRMTeamID: crmConnectionTeamE2E, CRMUserID: crmConnectionUserE2E}
			cipher, err := f.s.CRMKeys.Seal(identity, crmConnectionTokenE2E)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.pool.Exec(f.ctx, `INSERT INTO crm_connections(org_id,id,generation,status,origin,crm_team_id,crm_user_id,credential_ciphertext,verified_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
				f.org, identity.ID, identity.Generation, state, identity.Origin, identity.CRMTeamID, identity.CRMUserID, cipher, time.Now()) //nolint:rawsql -- synthetic counter boundary unreachable by normal fixture enrollment
			if err != nil {
				t.Fatal(err)
			}
			before, reads := f.inventory(t), f.peer.requests.Load()
			w := f.submit(f.ctx, http.MethodPut, "", crmConnectionPutBodyE2E(identity.Generation), f.cookie)
			assertCRMConnectionSafeResponseE2E(t, w, http.StatusConflict)
			if state == "candidate" {
				w = f.submit(f.ctx, http.MethodPost, "enable", crmConnectionEnableBodyE2E(identity.Generation, identity.CRMTeamID, identity.CRMUserID), f.cookie)
				assertCRMConnectionSafeResponseE2E(t, w, http.StatusConflict)
			}
			f.assertUnchanged(t, before)
			if f.peer.requests.Load() != reads {
				t.Fatal("exhausted activation tried an unnecessary external verification")
			}
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(f.ctx, `UPDATE crm_connections SET generation=$2,status='active' WHERE org_id=$1`, f.org, int64(math.MaxInt64)) //nolint:rawsql -- exactly one successor, must fail status/exhaustion check rather than aliasing a trigger failure
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
				_ = tx.Rollback(context.Background())
				t.Fatalf("terminal active generation not refused by DB check: %v", err)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			w = f.submit(f.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(identity.Generation), f.cookie)
			out := assertCRMConnectionSafeResponseE2E(t, w, http.StatusOK)
			row, err := f.q.GetCRMConnectionByOrg(f.ctx, f.org)
			if err != nil || row.Generation != math.MaxInt64 || row.Status != "revoked" || row.CredentialCiphertext != nil || out.Connection == nil || out.Connection.Generation != strconv.FormatInt(math.MaxInt64, 10) {
				t.Fatal("last successor did not remain reserved for safe terminal revocation", err)
			}
		})
	}
	t.Run("candidate-reserves-enable-and-revoke", func(t *testing.T) {
		f := setupCRMConnectionE2E(t)
		identity := crmconnection.Identity{ID: uuid.New(), OrgID: f.org, Generation: math.MaxInt64 - 2, Origin: f.s.CRMOrigin, CRMTeamID: crmConnectionTeamE2E, CRMUserID: crmConnectionUserE2E}
		cipher, err := f.s.CRMKeys.Seal(identity, crmConnectionTokenE2E)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.q.SaveCRMConnectionCandidate(f.ctx, generated.SaveCRMConnectionCandidateParams{OrgID: f.org, ID: identity.ID, Generation: identity.Generation,
			Origin: identity.Origin, CrmTeamID: identity.CRMTeamID, CrmUserID: identity.CRMUserID, CredentialCiphertext: cipher,
			VerifiedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}); err != nil {
			t.Fatal(err)
		}
		before, reads := f.inventory(t), f.peer.requests.Load()
		assertCRMConnectionSafeResponseE2E(t, f.submit(f.ctx, http.MethodPut, "", crmConnectionPutBodyE2E(identity.Generation), f.cookie), http.StatusConflict)
		f.assertUnchanged(t, before)
		if f.peer.requests.Load() != reads {
			t.Fatal("candidate replacement consumed the last enable/revoke successor reserve")
		}
		w := f.submit(f.ctx, http.MethodPost, "enable", crmConnectionEnableBodyE2E(identity.Generation, identity.CRMTeamID, identity.CRMUserID), f.cookie)
		out := assertCRMConnectionSafeResponseE2E(t, w, http.StatusOK)
		if out.Connection == nil || out.Connection.Status != "active" || out.Connection.Generation != strconv.FormatInt(math.MaxInt64-1, 10) {
			t.Fatal("the last candidate could not still be confirmed and safely activated")
		}
		w = f.submit(f.ctx, http.MethodDelete, "", crmConnectionRevokeBodyE2E(math.MaxInt64-1), f.cookie)
		out = assertCRMConnectionSafeResponseE2E(t, w, http.StatusOK)
		if out.Connection == nil || out.Connection.Status != "revoked" || out.Connection.Generation != strconv.FormatInt(math.MaxInt64, 10) {
			t.Fatal("the last confirmed account lost its reserved revocation successor")
		}
	})
}

func TestCRMConnectionInvalidEnrollmentDoesNotVerifyOrWriteE2E(t *testing.T) {
	f := setupCRMConnectionE2E(t)
	for _, body := range []string{
		`{"expected_generation":"0","token":"short"}`,
		`{"expected_generation":"00","token":"` + crmConnectionTokenE2E + `"}`,
		`{"expected_generation":"-1","token":"` + crmConnectionTokenE2E + `"}`,
		`{"expected_generation":"+1","token":"` + crmConnectionTokenE2E + `"}`,
		`{"expected_generation":0,"token":"` + crmConnectionTokenE2E + `"}`,
		`{"expected_generation":"0","token":null}`,
	} {
		before, reads := f.inventory(t), f.peer.requests.Load()
		assertCRMConnectionSafeResponseE2E(t, f.submit(f.ctx, http.MethodPut, "", body, f.cookie), http.StatusBadRequest)
		f.assertUnchanged(t, before)
		if f.peer.requests.Load() != reads {
			t.Fatal("invalid enrollment input reached remote authentication")
		}
	}
	// An invalid new-row generation reaches the SQL CHECK itself, rather than
	// relying only on the update trigger's monotonic-generation refusal.
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, err = tx.Exec(f.ctx, `INSERT INTO crm_connections(org_id,id,generation,status,origin,crm_team_id,crm_user_id,credential_ciphertext,verified_at) VALUES($1,$2,0,'candidate',$3,$4,$5,$6,$7)`,
		f.org, uuid.New(), f.s.CRMOrigin, crmConnectionTeamE2E, crmConnectionUserE2E, bytes.Repeat([]byte{1}, 93), pgtype.Timestamptz{Time: time.Now(), Valid: true}) //nolint:rawsql -- invalid synthetic SQL input, requires real database guard
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
		t.Fatalf("invalid initial generation SQLSTATE=%v", err)
	}
}
