//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestMemberDemotionCompletesAlongsideAuthorizedDSRAuditE2E(t *testing.T) {
	ctx, pool, q, s, org, user := setupDSRE2E(t)
	owner := seedSessionOwnerE2E(t, ctx, q, org)
	if _, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "sender"}); err != nil {
		t.Fatal(err)
	}
	request, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{OrgID: org, SubjectEmail: "serialized@example.test", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err = q.WithTx(blocked).AcquireOrgChainLock(ctx, org.String()); err != nil {
		t.Fatal(err)
	}
	userCookie := dsrSessionCookieE2E(t, s, user, 0, time.Hour)
	dsrResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		dsrResult <- submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/dsr/"+request.ID.String(), `{"status":"denied"}`, userCookie)
	}()
	awaitSessionOperationLockE2E(t, ctx, pool, "-- name: AcquireOrgChainLock", "advisory")
	ownerCookie := dsrSessionCookieE2E(t, s, owner, 0, time.Hour)
	memberResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		memberResult <- submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/members/"+user.String()+"/role", `{"role":"viewer"}`, ownerCookie)
	}()
	// The role change owns the org row but must wait for the DSR's live user
	// SHARE. Its org lock must permit that DSR's audit FK KEY SHARE to finish.
	awaitSessionOperationLockE2E(t, ctx, pool, "-- name: UpdateUserRole", "transactionid")
	if err = blocked.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for name, result := range map[string]<-chan *httptest.ResponseRecorder{"DSR": dsrResult, "member": memberResult} {
		response := receiveSessionOperationE2E(t, result)
		if response.Code != http.StatusOK {
			t.Fatalf("%s did not commit without deadlock: %d %s", name, response.Code, response.Body.String())
		}
	}
	freshUser, err := q.GetUser(ctx, user)
	if err != nil || freshUser.Role != "viewer" {
		t.Fatalf("demotion not durable: user=%+v err=%v", freshUser, err)
	}
	freshRequest, err := q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: request.ID, OrgID: org})
	if err != nil || freshRequest.Status != "denied" {
		t.Fatalf("serialized DSR not durable: request=%+v err=%v", freshRequest, err)
	}
	response := submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/dsr/"+request.ID.String(), `{"status":"in_progress"}`, userCookie)
	if response.Code != http.StatusForbidden {
		t.Fatalf("demoted next write=%d %s", response.Code, response.Body.String())
	}
	var events int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind IN ('data_subject.denied','member.role_changed')`, org).Scan(&events); err != nil || events != 2 {
		t.Fatalf("serialized audits=%d err=%v", events, err)
	}
}

func TestConcurrentMemberSelfDemotionsPreserveLastOwnerE2E(t *testing.T) {
	ctx, pool, q, s, org, first := setupDSRE2E(t)
	second := seedSessionOwnerE2E(t, ctx, q, org)
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	var callers sync.WaitGroup
	for _, user := range []string{first.String(), second.String()} {
		cookie := dsrSessionCookieE2E(t, s, first, 0, time.Hour)
		if user == second.String() {
			cookie = dsrSessionCookieE2E(t, s, second, 0, time.Hour)
		}
		callers.Add(1)
		go func(user, cookie string) {
			defer callers.Done()
			<-start
			results <- submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/members/"+user+"/role", `{"role":"viewer"}`, cookie)
		}(user, cookie)
	}
	close(start)
	callers.Wait()
	close(results)
	statuses := map[int]int{}
	for response := range results {
		statuses[response.Code]++
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusBadRequest] != 1 {
		t.Fatalf("concurrent self demotion statuses=%v", statuses)
	}
	owners, err := q.CountOrgOwners(ctx, org)
	if err != nil || owners != 1 {
		t.Fatalf("remaining owners=%d err=%v", owners, err)
	}
	var events int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind='member.role_changed'`, org).Scan(&events); err != nil || events != 1 {
		t.Fatalf("owner-floor audit=%d err=%v", events, err)
	}
}

func TestMemberRoleUpdateRechecksOwnerAfterOrgWaitE2E(t *testing.T) {
	for _, change := range []string{"demotion", "revocation", "expiry"} {
		t.Run(change, func(t *testing.T) {
			ctx, pool, q, s, org, user := setupDSRE2E(t)
			other := seedSessionOwnerE2E(t, ctx, q, org)
			blocked, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err = blocked.Exec(ctx, `SELECT id FROM orgs WHERE id=$1 FOR NO KEY UPDATE`, org); err != nil {
				t.Fatal(err)
			}
			ttl := time.Hour
			if change == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, s, user, 0, ttl)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/members/"+other.String()+"/role", `{"role":"sender"}`, cookie)
			}()
			awaitSessionOperationLockE2E(t, ctx, pool, "SELECT id FROM orgs", "transactionid")
			wantStatus := http.StatusForbidden
			switch change {
			case "demotion":
				_, err = q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "sender"})
			case "revocation":
				_, err = q.RevokeUserSessions(ctx, generated.RevokeUserSessionsParams{ID: user, OrgID: org, SessionGeneration: 0})
			case "expiry":
				awaitSessionCookieExpiryE2E(t, s, cookie)
				wantStatus = http.StatusUnauthorized
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = blocked.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			if response.Code != wantStatus {
				t.Fatalf("stale owner status=%d want=%d %s", response.Code, wantStatus, response.Body.String())
			}
			target, err := q.GetUser(ctx, other)
			if err != nil || target.Role != "owner" {
				t.Fatalf("unauthorized member change: target=%+v err=%v", target, err)
			}
			var events int
			if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind='member.role_changed'`, org).Scan(&events); err != nil || events != 0 {
				t.Fatalf("unauthorized member audit=%d err=%v", events, err)
			}
		})
	}
}

func TestMemberRoleUpdateExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	ctx, pool, q, s, org, user := setupDSRE2E(t)
	target := seedSessionOwnerE2E(t, ctx, q, org)
	if _, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: target, OrgID: org, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	blocked, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err = q.WithTx(blocked).AcquireOrgChainLock(ctx, org.String()); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, s, user, 0, time.Second)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/members/"+target.String()+"/role", `{"role":"owner"}`, cookie)
	}()
	awaitSessionOperationLockE2E(t, ctx, pool, "-- name: AcquireOrgChainLock", "advisory")
	awaitSessionCookieExpiryE2E(t, s, cookie)
	if err = blocked.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	response := receiveSessionOperationE2E(t, result)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired owner promotion=%d %s", response.Code, response.Body.String())
	}
	fresh, err := q.GetUser(ctx, target)
	if err != nil || fresh.Role != "viewer" {
		t.Fatalf("expired promotion escaped rollback: user=%+v err=%v", fresh, err)
	}
	var events int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind='member.role_changed'`, org).Scan(&events); err != nil || events != 0 {
		t.Fatalf("expired promotion audit=%d err=%v", events, err)
	}
}
