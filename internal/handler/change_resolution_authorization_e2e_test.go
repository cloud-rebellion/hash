//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type changeResolutionAuthorizationFixture struct {
	base      changeResolutionFixture
	doc       *generated.Document
	request   *generated.ChangeRequest
	user      *generated.User
	published atomic.Int32
}

func setupChangeResolutionAuthorizationE2E(t *testing.T, role string) *changeResolutionAuthorizationFixture {
	t.Helper()
	paused := setupReviseAuthorizationE2E(t, role)
	f := &changeResolutionAuthorizationFixture{
		base: paused.changeResolutionFixture, doc: paused.doc, request: paused.request, user: paused.user,
	}
	if _, err := f.base.q.SetOrgChangeApprovalMode(f.base.ctx, generated.SetOrgChangeApprovalModeParams{ID: f.base.org, ChangeApprovalMode: "auto_apply"}); err != nil {
		t.Fatal(err)
	}
	f.base.s.Audit.Subscribe(func(_ context.Context, _ uuid.UUID, entry audit.Entry) {
		if entry.DocumentID != nil && *entry.DocumentID == f.doc.ID && entry.Payload["change_request"] == f.request.ID.String() {
			f.published.Add(1)
		}
	})
	return f
}

func (f *changeResolutionAuthorizationFixture) submit(approve bool, cookie string) *httptest.ResponseRecorder {
	action := "deny"
	if approve {
		action = "approve"
	}
	return submitSessionOperationE2E(f.base.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/change-requests/"+f.request.ID.String()+"/"+action, "", cookie)
}

func (f *changeResolutionAuthorizationFixture) snapshot(t *testing.T) string {
	t.Helper()
	return f.base.snapshot(t, f.doc.ID)
}

func (f *changeResolutionAuthorizationFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before || f.published.Load() != 0 {
		t.Fatal("refused resolution changed document/request/history/evidence/audit/outbox or published an event")
	}
}

func (f *changeResolutionAuthorizationFixture) assertCommitted(t *testing.T, approve bool, actor uuid.UUID) {
	t.Helper()
	want := "denied"
	if approve {
		want = "approved"
	}
	request, err := f.base.q.GetChangeRequest(f.base.ctx, generated.GetChangeRequestParams{ID: f.request.ID, OrgID: f.base.org})
	if err != nil || request.Status != "resolved" || !request.Resolution.Valid || request.Resolution.String != want || !request.ResolvedAt.Valid {
		t.Fatalf("authorized resolution did not commit its request: err=%v", err)
	}
	doc, err := f.base.q.GetDocument(f.base.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.base.org})
	if err != nil || doc.Status != "changes_requested" {
		t.Fatalf("authorized resolution changed ceremony status: err=%v", err)
	}
	if approve {
		if !strings.Contains(string(doc.BlocksJson), "Revised payment term") || strings.Contains(string(doc.BlocksJson), "Original payment term") {
			t.Fatal("authorized auto-apply did not commit the proposed replacement")
		}
	} else if string(doc.BlocksJson) != string(f.doc.BlocksJson) {
		t.Fatal("authorized denial changed document content")
	}
	var count, actorCount, outbox int
	if err := f.base.pool.QueryRow(f.base.ctx, `SELECT count(*),count(*) FILTER (WHERE actor_user_id=$3)
		FROM events WHERE document_id=$1 AND payload_json->>'change_request'=$2`, f.doc.ID, f.request.ID.String(), actor).Scan(&count, &actorCount); err != nil { //nolint:rawsql -- exact canonical fixture actor and subject
		t.Fatal(err)
	}
	if err := f.base.pool.QueryRow(f.base.ctx, `SELECT count(*) FROM email_deliveries
		WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1)`, f.doc.ID).Scan(&outbox); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if count != 1 || actorCount != 1 || outbox != 0 || f.published.Load() != 1 {
		t.Fatalf("authorized resolution effects: events=%d canonical=%d outbox=%d published=%d", count, actorCount, outbox, f.published.Load())
	}
}

// Correlate the observed wait with the exact synthetic blocker, rather than
// accepting a different request's similarly named query as concurrency proof.
func awaitChangeResolutionLockE2E(t *testing.T, f *changeResolutionAuthorizationFixture, holder pgx.Tx, query, event string) {
	t.Helper()
	var pid int32
	if err := holder.QueryRow(f.base.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.base.ctx, 3*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var waiting bool
		if err := f.base.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database() AND state='active' AND query LIKE $1
			AND wait_event=$2 AND $3=ANY(pg_blocking_pids(pid)))`, "%"+query+"%", event, pid).Scan(&waiting); err != nil { //nolint:rawsql
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("resolution did not wait on its exact %s %s blocker", query, event)
}

func TestChangeResolutionSessionRechecksAfterParentWaitE2E(t *testing.T) {
	for _, approve := range []bool{true, false} {
		action := "deny"
		if approve {
			action = "approve"
		}
		for _, change := range []string{"demotion", "logout", "expiry"} {
			t.Run(action+"/"+change, func(t *testing.T) {
				f := setupChangeResolutionAuthorizationE2E(t, "sender")
				owner := seedSessionOwnerE2E(t, f.base.ctx, f.base.q, f.base.org)
				before := f.snapshot(t)
				blocked, err := f.base.pool.Begin(f.base.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.base.q.WithTx(blocked).GetDocumentForUpdate(f.base.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.base.org}); err != nil {
					t.Fatal(err)
				}
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.base.s, f.user.ID, f.user.SessionGeneration, ttl)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- f.submit(approve, cookie) }()
				awaitChangeResolutionLockE2E(t, f, blocked, "-- name: GetDocumentForUpdate", "transactionid")
				want := http.StatusForbidden
				switch change {
				case "demotion":
					ownerCookie := dsrSessionCookieE2E(t, f.base.s, owner, 0, time.Hour)
					response := submitSessionOperationE2E(f.base.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, ownerCookie)
					if response.Code != http.StatusOK {
						t.Fatalf("actual sender demotion=%d %s", response.Code, response.Body.String())
					}
				case "logout":
					response := submitSessionOperationE2E(f.base.s, http.MethodPost, "/auth/logout", "", cookie)
					if response.Code != http.StatusOK {
						t.Fatalf("actual session logout=%d %s", response.Code, response.Body.String())
					}
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.base.s, cookie)
					want = http.StatusUnauthorized
				}
				if err := blocked.Commit(f.base.ctx); err != nil {
					t.Fatal(err)
				}
				if response := receiveSessionOperationE2E(t, result); response.Code != want {
					t.Fatalf("stale %s resolution=%d want=%d %s", change, response.Code, want, response.Body.String())
				}
				f.assertUnchanged(t, before)
				ownerCookie := dsrSessionCookieE2E(t, f.base.s, owner, 0, time.Hour)
				if response := f.submit(approve, ownerCookie); response.Code != http.StatusOK {
					t.Fatalf("fresh owner retry=%d %s", response.Code, response.Body.String())
				}
				f.assertCommitted(t, approve, owner)
			})
		}
	}
}

func TestChangeResolutionSessionExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	for _, approve := range []bool{true, false} {
		action := "deny"
		if approve {
			action = "approve"
		}
		t.Run(action, func(t *testing.T) {
			f := setupChangeResolutionAuthorizationE2E(t, "sender")
			before := f.snapshot(t)
			blocked, err := f.base.pool.Begin(f.base.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err := f.base.q.WithTx(blocked).AcquireOrgChainLock(f.base.ctx, f.base.org.String()); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.base.s, f.user.ID, f.user.SessionGeneration, time.Second)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit(approve, cookie) }()
			awaitChangeResolutionLockE2E(t, f, blocked, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, f.base.s, cookie)
			if err := blocked.Commit(f.base.ctx); err != nil {
				t.Fatal(err)
			}
			if response := receiveSessionOperationE2E(t, result); response.Code != http.StatusUnauthorized {
				t.Fatalf("late-expired resolution=%d %s", response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
			fresh := dsrSessionCookieE2E(t, f.base.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			if response := f.submit(approve, fresh); response.Code != http.StatusOK {
				t.Fatalf("fresh session retry=%d %s", response.Code, response.Body.String())
			}
			f.assertCommitted(t, approve, f.user.ID)
		})
	}
}

func TestChangeResolutionSenderAndOwnerCommitE2E(t *testing.T) {
	for _, role := range []string{"sender", "owner"} {
		t.Run(role, func(t *testing.T) {
			f := setupChangeResolutionAuthorizationE2E(t, role)
			cookie := dsrSessionCookieE2E(t, f.base.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			if response := f.submit(true, cookie); response.Code != http.StatusOK {
				t.Fatalf("authorized %s resolution=%d %s", role, response.Code, response.Body.String())
			}
			f.assertCommitted(t, true, f.user.ID)
		})
	}
}

func TestChangeResolutionEngineOriginalAuthorityAndLateRollbackE2E(t *testing.T) {
	t.Run("missing original authority refuses before dependencies", func(t *testing.T) {
		engine := &sign.Engine{}
		for _, missing := range []string{"callback", "actor"} {
			actor := uuid.New()
			var authorize auth.TransactionAuthorization
			if missing == "actor" {
				actor = uuid.Nil
				authorize = func(context.Context, pgx.Tx, *generated.User) error {
					t.Fatal("missing actor reached callback")
					return nil
				}
			}
			request, err := engine.ResolveChangeWithAuthorization(context.Background(), uuid.New(), uuid.New(), uuid.New(), actor, true, authorize)
			if request != nil || !errors.Is(err, auth.ErrMutationPermissionRevoked) {
				t.Fatalf("missing %s reached engine dependencies: err=%v", missing, err)
			}
		}
	})
	t.Run("live viewer cannot use authenticated engine", func(t *testing.T) {
		f := setupChangeResolutionAuthorizationE2E(t, "viewer")
		before := f.snapshot(t)
		called := false
		request, err := f.base.s.Sign.ResolveChangeWithAuthorization(f.base.ctx, f.base.org, f.doc.ID, f.request.ID, f.user.ID, true, func(context.Context, pgx.Tx, *generated.User) error {
			called = true
			return nil
		})
		if request != nil || !errors.Is(err, auth.ErrMutationPermissionRevoked) || called {
			t.Fatalf("live viewer reached resolution/callback: err=%v", err)
		}
		f.assertUnchanged(t, before)
	})
	t.Run("foreign member cannot use authenticated engine", func(t *testing.T) {
		f := setupChangeResolutionAuthorizationE2E(t, "owner")
		before := f.snapshot(t)
		foreign, err := f.base.q.CreateOrg(f.base.ctx, generated.CreateOrgParams{Name: "Foreign resolution actor " + uuid.NewString(), Plan: "pro"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = f.base.pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, foreign.ID) }) //nolint:rawsql
		user, err := f.base.q.CreateUser(f.base.ctx, generated.CreateUserParams{OrgID: foreign.ID, Email: uuid.NewString() + "@resolution.test", Name: "Foreign owner", Role: "owner"})
		if err != nil {
			t.Fatal(err)
		}
		called := false
		request, err := f.base.s.Sign.ResolveChangeWithAuthorization(f.base.ctx, f.base.org, f.doc.ID, f.request.ID, user.ID, true, func(context.Context, pgx.Tx, *generated.User) error {
			called = true
			return nil
		})
		if request != nil || !errors.Is(err, auth.ErrMutationPermissionRevoked) || called {
			t.Fatalf("foreign member reached resolution/callback: err=%v", err)
		}
		f.assertUnchanged(t, before)
	})
	t.Run("second callback fails and first cannot rewrite retained actor", func(t *testing.T) {
		f := setupChangeResolutionAuthorizationE2E(t, "owner")
		before := f.snapshot(t)
		calls := 0
		request, err := f.base.s.Sign.ResolveChangeWithAuthorization(f.base.ctx, f.base.org, f.doc.ID, f.request.ID, f.user.ID, true, func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
			calls++
			if tx == nil || user.ID != f.user.ID || user.OrgID != f.base.org || user.Role != "owner" {
				t.Error("callback did not receive the retained canonical actor and transaction")
				return auth.ErrMutationPermissionRevoked
			}
			if calls == 1 {
				user.ID, user.OrgID, user.Role = uuid.New(), uuid.New(), "viewer"
				return ctx.Err()
			}
			return auth.ErrMutationCredentialExpired
		})
		if request != nil || !errors.Is(err, auth.ErrMutationCredentialExpired) || calls != 2 {
			t.Fatalf("late callback did not refuse resolution: calls=%d err=%v", calls, err)
		}
		f.assertUnchanged(t, before)
	})
}
