// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
//go:build e2e

package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestCollabFrameAuthorizationTracksLiveRoleAndDraftE2E(t *testing.T) {
	ctx, pool, q, server, orgID, userID := setupDSRE2E(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	var err error
	server.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(auth.SessionPayload{UserID: userID})
	if err != nil {
		t.Fatal(err)
	}
	cookie := server.Cookies.Mint(payload, time.Hour)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: orgID, Name: "collab authorization", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`), SenderID: userID})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	apply := func(context.Context) error { calls++; return nil }
	if err := server.withCollabFrameAuthorization(ctx, cookie, doc.ID, orgID, userID, apply); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("authorized draft frame was not accepted")
	}
	if _, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: userID, OrgID: orgID, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if err := server.withCollabFrameAuthorization(ctx, cookie, doc.ID, orgID, userID, apply); err == nil {
		t.Fatal("stale socket retained demoted write permission")
	}
	if calls != 1 {
		t.Fatal("demoted frame reached mutation")
	}
	if _, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: userID, OrgID: orgID, Role: "sender"}); err != nil {
		t.Fatal(err)
	}
	seedCompleteFrozenBrandingHandlerE2E(t, ctx, pool, doc.ID)
	if _, err := pool.Exec(ctx, `UPDATE documents SET status='voided' WHERE id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	}
	if err := server.withCollabFrameAuthorization(ctx, cookie, doc.ID, orgID, userID, apply); err == nil {
		t.Fatal("voided document accepted collaborative mutation")
	}
	if calls != 1 {
		t.Fatal("non-draft frame reached mutation")
	}
	expired := server.Cookies.Mint(payload, -time.Minute)
	if err := server.withCollabFrameAuthorization(ctx, expired, doc.ID, orgID, userID, apply); err == nil {
		t.Fatal("expired socket credential accepted")
	}
}

func TestLogoutRevokesCopiedSessionAndCollabFrameE2E(t *testing.T) {
	ctx, _, q, server, orgID, userID := setupDSRE2E(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	var err error
	server.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	server.PublicURL = "https://hash.example.test"
	payload, err := json.Marshal(auth.SessionPayload{UserID: userID})
	if err != nil {
		t.Fatal(err)
	}
	cookie := server.Cookies.Mint(payload, time.Hour)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: orgID, Name: "logout fence", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`), SenderID: userID})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	apply := func(context.Context) error { called = true; return nil }
	if err := server.withCollabFrameAuthorization(ctx, cookie, doc.ID, orgID, userID, apply); err != nil || !called {
		t.Fatalf("initial session refused: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, server.PublicURL+"/auth/logout", nil)
	request.Header.Set("Origin", server.PublicURL)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	response := httptest.NewRecorder()
	server.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("logout failed: %d %s", response.Code, response.Body.String())
	}
	called = false
	if err := server.withCollabFrameAuthorization(ctx, cookie, doc.ID, orgID, userID, apply); err == nil || called {
		t.Fatal("copied logged-out socket credential retained writes")
	}
	request = httptest.NewRequest(http.MethodGet, server.PublicURL+"/api/v1/me", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	response = httptest.NewRecorder()
	server.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("copied logged-out cookie authorized HTTP: %d", response.Code)
	}
	fresh, err := q.GetUser(ctx, userID)
	if err != nil || fresh.SessionGeneration != 1 {
		t.Fatalf("logout generation: %v %v", fresh, err)
	}
	// Another old-generation logout cannot invalidate a newly minted login.
	if rows, err := q.RevokeUserSessions(ctx, generated.RevokeUserSessionsParams{ID: userID, OrgID: orgID, SessionGeneration: 0}); err != nil || rows != 0 {
		t.Fatalf("stale logout revoked new generation: %d %v", rows, err)
	}
	payload, err = json.Marshal(auth.SessionPayload{UserID: userID, Generation: fresh.SessionGeneration})
	if err != nil {
		t.Fatal(err)
	}
	called = false
	if err := server.withCollabFrameAuthorization(ctx, server.Cookies.Mint(payload, time.Hour), doc.ID, orgID, userID, apply); err != nil || !called {
		t.Fatalf("new login refused after logout: %v", err)
	}
	request = httptest.NewRequest(http.MethodPost, server.PublicURL+"/auth/logout", nil)
	request.Header.Set("Origin", server.PublicURL)
	request.Header.Set("Accept", "text/html")
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: server.Cookies.Mint(payload, time.Hour)})
	response = httptest.NewRecorder()
	server.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
		t.Fatalf("HTML logout did not return to login: %d %s", response.Code, response.Body.String())
	}
	fresh, err = q.GetUser(ctx, userID)
	if err != nil || fresh.SessionGeneration != 2 {
		t.Fatalf("HTML logout did not revoke sessions: %v %v", fresh, err)
	}
}
