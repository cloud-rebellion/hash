//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func nativeStaff503Call(t *testing.T, s *Server, router http.Handler, path string, input any, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", s.PublicURL+path, bytes.NewReader(raw))
	request.Header.Set("Origin", s.PublicURL)
	request.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func nativeStaff503Cookie(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == SessionCookieName && cookie.Value != "" && cookie.MaxAge >= 0 && cookie.Expires.After(time.Now()) {
			if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatal("native login weakened session cookie")
			}
			return cookie.Value
		}
	}
	t.Fatal("native login did not mint a session")
	return ""
}

func nativeStaff503Token(t *testing.T, ctx context.Context, s *Server, email string) string {
	t.Helper()
	row, err := s.Queries.GetLatestStaffAuthEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	if row.HtmlBody != "" || row.TextBody != "" || len(row.StaffAuthCiphertext) == 0 {
		t.Fatal("private email bearer was not sealed in the durable outbox")
	}
	opened, err := dispatch.OpenStaffAuthEmail(s.StaffAuthMailBox, row.ID, row.ToEmail, row.Subject, row.StaffAuthCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	for _, word := range strings.Fields(opened.Text) {
		if !strings.HasPrefix(word, s.PublicURL+"/") {
			continue
		}
		parsed, err := url.Parse(word)
		if err != nil || parsed.RawQuery != "" {
			t.Fatal("auth bearer is in a query string")
		}
		fragment, err := url.ParseQuery(parsed.Fragment)
		if err != nil {
			t.Fatal(err)
		}
		token := fragment.Get("token")
		if _, err := parseStaffAuthToken(token); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(row.StaffAuthCiphertext, []byte(token)) {
			t.Fatal("outbox contains a raw bearer")
		}
		return token
	}
	t.Fatal("auth mail contains no fragment link")
	return ""
}

func nativeStaff503Setup(t *testing.T) (context.Context, *generated.Queries, *Server, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx, _, q, s, org, owner := setupDSRE2E(t)
	box, err := dispatch.NewStaffAuthMailBox(strings.Repeat("1a", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	s.StaffAuthMailBox = box
	return ctx, q, s, org, owner
}

func TestNativeStaffRegistrationVerificationLoginRecoveryE2E(t *testing.T) {
	ctx, q, s, existingOrg, _ := nativeStaff503Setup(t)
	router := s.Routes()
	email := uuid.NewString() + "@native503.test"
	password := "a long initial password  "
	registration := nativeStaff503Call(t, s, router, "/api/v1/auth/register", map[string]string{
		"email": email, "name": "Staff Owner", "company_name": "Independent Company", "password": password,
	}, "")
	if registration.Code != 202 {
		t.Fatalf("register=%d %s", registration.Code, registration.Body.String())
	}
	if _, err := q.GetUserByEmail(ctx, email); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("registration created an identity before mailbox proof", err)
	}
	token := nativeStaff503Token(t, ctx, s, email)
	for _, proof := range []map[string]string{{"token": token}, {"token": token, "password": "wrong registration password"}} {
		refused := nativeStaff503Call(t, s, router, "/api/v1/auth/verify-email", proof, "")
		if refused.Code != 400 {
			t.Fatal("missing or wrong original registration password was accepted")
		}
	}
	var responses [2]*httptest.ResponseRecorder
	var joined sync.WaitGroup
	for i := range responses {
		joined.Add(1)
		go func(i int) {
			defer joined.Done()
			responses[i] = nativeStaff503Call(t, s, router, "/api/v1/auth/verify-email", map[string]string{"token": token, "password": password}, "")
		}(i)
	}
	joined.Wait()
	var verified *httptest.ResponseRecorder
	successes := 0
	for _, response := range responses {
		if response.Code == 200 {
			successes++
			verified = response
		} else if response.Code != 400 {
			t.Fatalf("verification replay=%d %s", response.Code, response.Body.String())
		}
	}
	if successes != 1 {
		t.Fatalf("single-use token admitted %d callbacks", successes)
	}
	initialCookie := nativeStaff503Cookie(t, verified)
	user, err := q.GetUserByEmail(ctx, email)
	if err != nil || user.OrgID == existingOrg || user.Role != "owner" || user.ZitadelSub.Valid {
		t.Fatal("native bootstrap reused workspace or identity", err)
	}
	org, err := q.GetOrg(ctx, user.OrgID)
	if err != nil || org.Name != "Independent Company" || org.Plan != "starter" {
		t.Fatal("native organization bootstrap changed", err)
	}
	wrong := nativeStaff503Call(t, s, router, "/api/v1/auth/login", map[string]string{"email": email, "password": "wrong password"}, "")
	unknown := nativeStaff503Call(t, s, router, "/api/v1/auth/login", map[string]string{"email": uuid.NewString() + "@native503.test", "password": "wrong password"}, "")
	if wrong.Code != 401 || unknown.Code != 401 || wrong.Body.String() != unknown.Body.String() {
		t.Fatal("login enumerates accounts")
	}
	login := nativeStaff503Call(t, s, router, "/api/v1/auth/login", map[string]string{"email": strings.ToUpper(email), "password": password}, "")
	if login.Code != 200 {
		t.Fatalf("login=%d %s", login.Code, login.Body.String())
	}
	loginCookie := nativeStaff503Cookie(t, login)
	beforeReset, err := q.GetStaffPasswordCredential(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	forgot := nativeStaff503Call(t, s, router, "/api/v1/auth/forgot-password", map[string]string{"email": email}, "")
	missing := nativeStaff503Call(t, s, router, "/api/v1/auth/forgot-password", map[string]string{"email": uuid.NewString() + "@native503.test"}, "")
	if forgot.Code != 202 || missing.Code != 202 || forgot.Body.String() != missing.Body.String() {
		t.Fatal("recovery enumerates accounts")
	}
	recoveryToken := nativeStaff503Token(t, ctx, s, email)
	reset := nativeStaff503Call(t, s, router, "/api/v1/auth/reset-password", map[string]string{"token": recoveryToken, "password": "a new complete password"}, "")
	if reset.Code != 200 {
		t.Fatalf("reset=%d %s", reset.Code, reset.Body.String())
	}
	if _, err := q.RefreshStaffPasswordLogin(ctx, generated.RefreshStaffPasswordLoginParams{
		UserID: beforeReset.ID, SessionGeneration: beforeReset.SessionGeneration, PasswordHash: beforeReset.PasswordHash,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("old password verification snapshot survived concurrent reset freshness fence", err)
	}
	oldPassword := nativeStaff503Call(t, s, router, "/api/v1/auth/login", map[string]string{"email": email, "password": password}, "")
	if oldPassword.Code != 401 {
		t.Fatal("reset retained the old password")
	}
	for _, cookie := range reset.Result().Cookies() {
		if cookie.Name == SessionCookieName && cookie.MaxAge >= 0 {
			t.Fatal("reset automatically logged in")
		}
	}
	protected := auth.RequireSession(s.Cookies, SessionCookieName, q)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, old := range []string{initialCookie, loginCookie} {
		request := httptest.NewRequest("GET", s.PublicURL+"/private", nil)
		request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: old})
		response := httptest.NewRecorder()
		protected.ServeHTTP(response, request)
		if response.Code != 401 {
			t.Fatal("reset retained an old session generation")
		}
	}
	replay := nativeStaff503Call(t, s, router, "/api/v1/auth/reset-password", map[string]string{"token": recoveryToken, "password": "another complete password"}, "")
	if replay.Code != 400 {
		t.Fatal("password reset token replay succeeded")
	}
	after := nativeStaff503Call(t, s, router, "/api/v1/auth/login", map[string]string{"email": email, "password": "a new complete password"}, "")
	if after.Code != 200 {
		t.Fatalf("new password=%d", after.Code)
	}
}

func TestNativeStaffInvitationPreservesTenantRoleAndExistingOIDCE2E(t *testing.T) {
	ctx, q, s, org, owner := nativeStaff503Setup(t)
	router := s.Routes()
	ownerCookie := dsrSessionCookieE2E(t, s, owner, 0, time.Hour)
	email := uuid.NewString() + "@native503.test"
	invited := nativeStaff503Call(t, s, router, "/api/v1/members", map[string]string{"email": email, "name": "Invited Viewer", "role": "viewer"}, ownerCookie)
	if invited.Code != 202 {
		t.Fatalf("invite=%d %s", invited.Code, invited.Body.String())
	}
	member, err := q.GetUserByEmail(ctx, email)
	if err != nil || member.OrgID != org || member.Role != "viewer" {
		t.Fatal("invitation escaped owner's tenant or role", err)
	}
	if _, err := q.GetStaffPasswordCredentialForUser(ctx, member.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("owner set password before mailbox proof", err)
	}
	token := nativeStaff503Token(t, ctx, s, email)
	setup := nativeStaff503Call(t, s, router, "/api/v1/auth/reset-password", map[string]string{"token": token, "password": "viewer chooses own password"}, "")
	if setup.Code != 200 {
		t.Fatalf("setup=%d %s", setup.Code, setup.Body.String())
	}
	member, err = q.GetUser(ctx, member.ID)
	if err != nil || member.OrgID != org || member.Role != "viewer" {
		t.Fatal("setup changed membership", err)
	}
	login := nativeStaff503Call(t, s, router, "/api/v1/auth/login", map[string]string{"email": email, "password": "viewer chooses own password"}, "")
	viewerCookie := nativeStaff503Cookie(t, login)
	refused := nativeStaff503Call(t, s, router, "/api/v1/members", map[string]string{"email": uuid.NewString() + "@native503.test", "name": "Other", "role": "owner"}, viewerCookie)
	if refused.Code != 403 {
		t.Fatal("viewer gained owner invitation authority")
	}
	existingEmail := uuid.NewString() + "@native503.test"
	existing, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org, Email: existingEmail, Name: "Existing Sender", Role: "sender", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	registration := nativeStaff503Call(t, s, router, "/api/v1/auth/register", map[string]string{"email": existingEmail, "name": "Ignored rename", "company_name": "Ignored new company", "password": "existing sender native password"}, "")
	if registration.Code != 202 {
		t.Fatal("existing account setup refused")
	}
	existingToken := nativeStaff503Token(t, ctx, s, existingEmail)
	verification := nativeStaff503Call(t, s, router, "/api/v1/auth/verify-email", map[string]string{"token": existingToken, "password": "existing sender native password"}, "")
	if verification.Code != 400 {
		t.Fatal("existing account installed a submitter-selected registration password")
	}
	chosen := nativeStaff503Call(t, s, router, "/api/v1/auth/reset-password", map[string]string{"token": existingToken, "password": "recipient selects another password"}, "")
	if chosen.Code != 200 {
		t.Fatalf("existing setup=%d %s", chosen.Code, chosen.Body.String())
	}
	preselected := nativeStaff503Call(t, s, router, "/api/v1/auth/login", map[string]string{"email": existingEmail, "password": "existing sender native password"}, "")
	if preselected.Code != 401 {
		t.Fatal("registration submitter gained existing-account access")
	}
	retained, err := q.GetUser(ctx, existing.ID)
	if err != nil || retained.OrgID != org || retained.Role != "sender" || retained.ZitadelSub != existing.ZitadelSub || retained.Name != existing.Name {
		t.Fatal("mailbox proof replaced existing tenant, role or OIDC binding", err)
	}
}

func TestNativeStaffPendingRegistrationCannotAdoptLaterIdentityE2E(t *testing.T) {
	ctx, q, s, org, _ := nativeStaff503Setup(t)
	router := s.Routes()
	email := uuid.NewString() + "@native503.test"
	registration := nativeStaff503Call(t, s, router, "/api/v1/auth/register", map[string]string{
		"email": email, "name": "Preselected", "company_name": "Unverified company", "password": "submitter selected password",
	}, "")
	if registration.Code != 202 {
		t.Fatal("pending registration unavailable")
	}
	token := nativeStaff503Token(t, ctx, s, email)
	later, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org, Email: email, Name: "Later verified member", Role: "viewer",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	verification := nativeStaff503Call(t, s, router, "/api/v1/auth/verify-email", map[string]string{"token": token, "password": "submitter selected password"}, "")
	if verification.Code != 400 {
		t.Fatal("pending registration attached a preselected password to later membership")
	}
	if _, err := q.GetStaffPasswordCredentialForUser(ctx, later.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("later identity acquired submitter-selected credential", err)
	}
	retained, err := q.GetUser(ctx, later.ID)
	if err != nil || retained.OrgID != org || retained.Role != "viewer" || retained.ZitadelSub != later.ZitadelSub {
		t.Fatal("rejected pending registration mutated later identity", err)
	}
}
