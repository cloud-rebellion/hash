//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/jackc/pgx/v5"
)

type staffSelfResetLockTracer503 struct {
	armed                                     atomic.Bool
	emailOnce, userOnce                       sync.Once
	inviteAtEmail, releaseInvite, resetAtUser chan struct{}
}

func (g *staffSelfResetLockTracer503) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !g.armed.Load() {
		return ctx
	}
	if strings.HasPrefix(data.SQL, "-- name: LockStaffPasswordEmail ") {
		pause := false
		g.emailOnce.Do(func() { pause = true; close(g.inviteAtEmail) })
		if pause {
			select {
			case <-g.releaseInvite:
			case <-ctx.Done():
			}
		}
	}
	if strings.HasPrefix(data.SQL, "-- name: LockStaffPasswordUserByEmail ") {
		g.userOnce.Do(func() { close(g.resetAtUser) })
	}
	return ctx
}

func (*staffSelfResetLockTracer503) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

func TestNativeStaffSelfInvitationAndOwnResetLockOrderE2E(t *testing.T) {
	gate := &staffSelfResetLockTracer503{
		inviteAtEmail: make(chan struct{}), releaseInvite: make(chan struct{}), resetAtUser: make(chan struct{}),
	}
	ctx, _, q, s, org, owner := setupDSRE2E(t, gate)
	box, err := dispatch.NewStaffAuthMailBox(strings.Repeat("1a", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	s.StaffAuthMailBox = box
	actor, err := q.GetUser(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	router := s.Routes()
	cookie := dsrSessionCookieE2E(t, s, owner, actor.SessionGeneration, time.Hour)
	forgot := nativeStaff503Call(t, s, router, "/api/v1/auth/forgot-password", map[string]string{"email": actor.Email}, "")
	if forgot.Code != 202 {
		t.Fatalf("own recovery setup=%d", forgot.Code)
	}
	token := nativeStaff503Token(t, ctx, s, actor.Email)
	inviteBody, err := json.Marshal(map[string]string{"email": actor.Email, "name": actor.Name, "role": "owner"})
	if err != nil {
		t.Fatal(err)
	}
	resetBody, err := json.Marshal(map[string]string{"token": token, "password": "owner chooses replacement password"})
	if err != nil {
		t.Fatal(err)
	}
	calls, cancel := context.WithTimeout(ctx, 20*time.Second)
	var release sync.Once
	releaseInvite := func() { release.Do(func() { close(gate.releaseInvite) }) }
	inviteDone, resetDone := make(chan struct{}), make(chan struct{})
	inviteStarted, resetStarted := false, false
	t.Cleanup(func() {
		cancel()
		releaseInvite()
		for _, call := range []struct {
			started bool
			done    <-chan struct{}
		}{
			{inviteStarted, inviteDone}, {resetStarted, resetDone},
		} {
			if !call.started {
				continue
			}
			select {
			case <-call.done:
			case <-time.After(10 * time.Second):
				t.Error("native authentication request did not join after cancellation")
			}
		}
	})
	post := func(path string, body []byte, session string) *httptest.ResponseRecorder {
		request := httptest.NewRequest("POST", s.PublicURL+path, bytes.NewReader(body)).WithContext(calls)
		request.Header.Set("Origin", s.PublicURL)
		request.Header.Set("Content-Type", "application/json")
		if session != "" {
			request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	await := func(signal <-chan struct{}, name string) {
		t.Helper()
		select {
		case <-signal:
		case <-calls.Done():
			t.Fatalf("%s did not reach its query barrier: %v", name, calls.Err())
		}
	}
	gate.armed.Store(true)
	inviteResult, resetResult := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
	inviteStarted = true
	go func() { defer close(inviteDone); inviteResult <- post("/api/v1/members", inviteBody, cookie) }()
	await(gate.inviteAtEmail, "self-invitation")
	resetStarted = true
	go func() { defer close(resetDone); resetResult <- post("/api/v1/auth/reset-password", resetBody, "") }()
	// Reset has acquired this same email advisory lock before its user query.
	// Releasing invite now formed a user/email cycle under the original order.
	await(gate.resetAtUser, "own reset")
	releaseInvite()
	await(resetDone, "completed reset")
	await(inviteDone, "completed self-invitation")
	reset, invite := <-resetResult, <-inviteResult
	if reset.Code != 200 {
		t.Fatalf("own reset=%d %s", reset.Code, reset.Body.String())
	}
	if invite.Code != http.StatusForbidden {
		t.Fatalf("self-invitation did not recheck revoked actor generation: %d %s", invite.Code, invite.Body.String())
	}
	retained, err := q.GetUser(ctx, owner)
	if err != nil || retained.OrgID != org || retained.Role != "owner" || retained.SessionGeneration != actor.SessionGeneration+1 {
		t.Fatal("concurrent own reset changed organization/role or lost revocation", err)
	}
}
