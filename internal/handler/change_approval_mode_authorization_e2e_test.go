//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func assertChangeApprovalStateE2E(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, mode string, events int) {
	t.Helper()
	var actualMode string
	var actualEvents int
	if err := pool.QueryRow(context.Background(), `SELECT change_approval_mode,(SELECT count(*) FROM events WHERE org_id=$1 AND kind='org.change_approval_mode_changed') FROM orgs WHERE id=$1`, org).Scan(&actualMode, &actualEvents); err != nil {
		t.Fatal(err)
	}
	if actualMode != mode || actualEvents != events {
		t.Fatalf("setting/audit = %q/%d, want %q/%d", actualMode, actualEvents, mode, events)
	}
}

func TestChangeApprovalModeRetainsOwnerAfterOrgWaitE2E(t *testing.T) {
	for _, change := range []string{"demotion", "logout", "expiry"} {
		t.Run(change, func(t *testing.T) {
			ctx, pool, q, s, org, user := setupDSRE2E(t)
			original, err := q.GetOrg(ctx, org)
			if err != nil {
				t.Fatal(err)
			}
			blocked, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err := blocked.Exec(ctx, `SELECT id FROM orgs WHERE id=$1 FOR NO KEY UPDATE`, org); err != nil {
				t.Fatal(err)
			}
			ttl := time.Hour
			if change == "expiry" {
				ttl = 2 * time.Second
			}
			cookie := dsrSessionCookieE2E(t, s, user, 0, ttl)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/settings/change-approval-mode", `{"mode":"auto_apply"}`, cookie)
			}()
			awaitSessionOperationLockE2E(t, ctx, pool, "orgs", "transactionid")
			want := http.StatusForbidden
			switch change {
			case "demotion":
				_, err = q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "sender"})
			case "logout":
				_, err = q.RevokeUserSessions(ctx, generated.RevokeUserSessionsParams{ID: user, OrgID: org, SessionGeneration: 0})
			case "expiry":
				awaitSessionCookieExpiryE2E(t, s, cookie)
				want = http.StatusUnauthorized
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := blocked.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			if response.Code != want {
				t.Fatalf("stale owner setting = %d, want %d: %s", response.Code, want, response.Body.String())
			}
			assertChangeApprovalStateE2E(t, pool, org, original.ChangeApprovalMode, 0)
		})
	}
}

func TestChangeApprovalModeExpiryDuringAuditRollsBackE2E(t *testing.T) {
	ctx, pool, q, s, org, user := setupDSRE2E(t)
	original, err := q.GetOrg(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := q.WithTx(blocked).AcquireOrgChainLock(ctx, org.String()); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, s, user, 0, 2*time.Second)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/settings/change-approval-mode", `{"mode":"auto_apply"}`, cookie)
	}()
	awaitSessionOperationLockE2E(t, ctx, pool, "-- name: AcquireOrgChainLock", "advisory")
	awaitSessionCookieExpiryE2E(t, s, cookie)
	if err := blocked.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	response := receiveSessionOperationE2E(t, result)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired audit setting = %d: %s", response.Code, response.Body.String())
	}
	assertChangeApprovalStateE2E(t, pool, org, original.ChangeApprovalMode, 0)
}

func TestChangeApprovalModeOwnerSuccessAndSenderRefusalE2E(t *testing.T) {
	ctx, pool, q, s, org, user := setupDSRE2E(t)
	cookie := dsrSessionCookieE2E(t, s, user, 0, time.Hour)
	response := submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/settings/change-approval-mode", `{"mode":"auto_apply"}`, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("owner setting = %d: %s", response.Code, response.Body.String())
	}
	assertChangeApprovalStateE2E(t, pool, org, "auto_apply", 1)
	if _, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "sender"}); err != nil {
		t.Fatal(err)
	}
	response = submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/settings/change-approval-mode", `{"mode":"accept"}`, cookie)
	if response.Code != http.StatusForbidden {
		t.Fatalf("sender setting = %d: %s", response.Code, response.Body.String())
	}
	assertChangeApprovalStateE2E(t, pool, org, "auto_apply", 1)
}
