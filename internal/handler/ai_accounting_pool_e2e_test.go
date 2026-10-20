//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func aiAccountingSmallPoolE2E(t *testing.T, maximum int32, blocking bool) (guardedAIAppsFixture, *atomic.Int32, *ai.Runtime) {
	t.Helper()
	f := setupGuardedAIAppsMCPE2E(t, false, blocking)
	cfg := f.pool.Config()
	cfg.MaxConns = maximum
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.pool = pool
	f.q = generated.New(pool)
	f.s.Pool = pool
	f.s.Queries = f.q
	f.s.Audit = audit.New(f.q, pool)
	shield, err := ai.NewLocalShield(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	rt := ai.New(f.q, shield, nil, f.provider)
	if _, err = f.q.UpsertOrgAISettings(f.ctx, generated.UpsertOrgAISettingsParams{OrgID: f.org, Provider: "synthetic", BaseUrl: "https://api.mistral.ai/v1", Model: f.provider.Model(), ApiKeyCt: []byte("fixture-only"), KeyLast4: "test", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	resolves := &atomic.Int32{}
	rt.ResolveOrgProvider = func(ctx context.Context, orgID uuid.UUID, q *generated.Queries) (ai.Provider, bool, error) {
		row, err := q.GetOrgAISettings(ctx, orgID)
		if err != nil {
			return nil, false, err
		}
		if row.OrgID != f.org || !row.Enabled {
			return nil, false, errors.New("unexpected BYOAI identity")
		}
		resolves.Add(1)
		return f.provider, true, nil
	}
	// Return a standalone LEGACY runtime; never route current staff HTTP/MCP
	// back through a compatibility API or promote this provider as native.
	return f, resolves, rt
}

// This file qualifies the unchanged direct LEGACY authoring coordinator and
// pool admission contract. Current staff endpoints use native ownership; their
// genuine one-application-connection/BYOAI profile is a separate test cohort.
// Admit the actual original signed session against the canonical user before
// filling the tiny pool. All later legacy transactions still recheck this exact
// retained session authorization via LockAuthor/MemberGuard; no new credential,
// fake SessionUser, constant success authorizer or native capability is supplied.
func legacyAIAccountingActor318(t *testing.T, f guardedAIAppsFixture, cookie string) authoring.Actor {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/v1/documents/"+f.doc.ID.String()+"/proposals/suggest", nil).WithContext(f.ctx)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	response := httptest.NewRecorder()
	var actor authoring.Actor
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := requireSessionUser(w, r.Context())
		if !ok {
			return
		}
		var err error
		actor, err = f.s.sessionAIAppActor(r, user)
		if err != nil {
			f.s.writeAIAppMutationError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	auth.RequireSession(f.s.Cookies, SessionCookieName, f.q)(auth.RequireRole(auth.RoleSender)(handler)).ServeHTTP(response, request)
	if response.Code != http.StatusOK || actor.Authorize == nil || actor.OrgID != f.org || actor.UserID != f.user.ID {
		t.Fatal("actual original legacy session admission failed", response.Code, response.Body.String())
	}
	return actor
}

// A fixed test adapter, not a production route replacement. It invokes the
// unchanged direct API and its real reserved pooled connection/transactions,
// actual generic runtime callback, durable request-bound usage and chain. The
// original test assertions keep their status/body facade; native admission and
// HTTP transport claims are explicitly outside this legacy profile.
func legacyAIAccountingSubmit318(f guardedAIAppsFixture, ctx context.Context, actor authoring.Actor, runtime *ai.Runtime, op staffAIActionE2E) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	var input struct {
		BlockID  string   `json:"block_id"`
		Concern  string   `json:"concern"`
		RedLines []string `json:"red_lines"`
	}
	if op.name != "suggest" || json.Unmarshal([]byte(op.body), &input) != nil {
		writeError(response, http.StatusBadRequest, "legacy suggest fixture input unavailable")
		return response
	}
	value, err := authoring.CompleteDocumentAI(ctx, authoring.AIAppDeps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit}, authoring.AIAppRequest{Actor: actor, DocumentID: f.doc.ID, Via: "rest", Action: "suggest_counter_clause"}, runtime, func(call context.Context, scoped *ai.Runtime, doc *generated.Document) (aiapps.CounterResult, error) {
		block, err := authoring.AIAppBlock(doc, input.BlockID)
		if err != nil {
			return aiapps.CounterResult{}, err
		}
		return (&aiapps.Negotiator{Runtime: scoped}).SuggestCounter(call, aiapps.CounterInput{OrgID: actor.OrgID, DocumentID: doc.ID, UserID: &actor.UserID, OriginalClause: block.Text, Concern: input.Concern, RedLines: input.RedLines})
	}, nil)
	if err != nil {
		f.s.writeAIAppMutationError(response, err)
		return response
	}
	writeJSON(response, http.StatusOK, value)
	return response
}

func TestAIAccountingSmallPoolConcurrentBYOAIRequestsPreserveCostE2E(t *testing.T) {
	for _, maximum := range []int32{2, 3} {
		t.Run(string(rune('0'+maximum)), func(t *testing.T) {
			f, resolves, runtime := aiAccountingSmallPoolE2E(t, maximum, true)
			if maximum == 3 {
				lease, err := f.pool.Acquire(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Release()
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			actor := legacyAIAccountingActor318(t, f, cookie)
			op := staffAIActionForE2E(t, f, "suggest")
			first, cancelFirst, joinedFirst := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder {
				return legacyAIAccountingSubmit318(f, ctx, actor, runtime, op)
			})
			defer guardedAICleanup264(t, nil, cancelFirst, joinedFirst)
			awaitAIProviderE2E(t, f.provider)
			if f.pool.Stat().AcquiredConns() != maximum {
				t.Fatalf("test did not occupy full pool: %+v", f.pool.Stat())
			}
			second, cancelSecond, joinedSecond := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder {
				return legacyAIAccountingSubmit318(f, ctx, actor, runtime, op)
			})
			defer guardedAICleanup264(t, nil, cancelSecond, joinedSecond)
			close(f.provider.release)
			if w := receiveSessionOperationE2E(t, first); w.Code != http.StatusOK {
				t.Fatalf("first constrained AI=%d %s", w.Code, w.Body.String())
			}
			if w := receiveSessionOperationE2E(t, second); w.Code != http.StatusOK {
				t.Fatalf("second constrained AI=%d %s", w.Code, w.Body.String())
			}
			if f.provider.calls.Load() != 2 || resolves.Load() != 2 {
				t.Fatal("BYOAI provider request lost or fell back", f.provider.calls.Load(), resolves.Load())
			}
			var count int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM ai_completion_audit a JOIN events e ON e.id=a.id AND e.org_id=a.org_id AND e.document_id=a.document_id AND e.actor_user_id=a.actor_user_id AND e.kind='ai.requested' WHERE a.org_id=$1 AND a.input_tokens=23 AND a.output_tokens=11`, f.org).Scan(&count); err != nil || count != 2 {
				t.Fatal("small-pool accounting evidence missing", count, err)
			} //nolint:rawsql -- exact fixture-owned request-bound usage
			assertStaffAIChainE2E(t, f)
		})
	}
}

func TestAIAccountingSmallPoolCancellationAndOneConnectionRefusalE2E(t *testing.T) {
	t.Run("cancel queued", func(t *testing.T) {
		f, _, runtime := aiAccountingSmallPoolE2E(t, 2, true)
		cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
		op := staffAIActionForE2E(t, f, "suggest")
		actor := legacyAIAccountingActor318(t, f, cookie)
		done, cancelDone, joinedDone := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder {
			return legacyAIAccountingSubmit318(f, ctx, actor, runtime, op)
		})
		defer guardedAICleanup264(t, nil, cancelDone, joinedDone)
		awaitAIProviderE2E(t, f.provider)
		ctx, cancel := context.WithCancel(f.ctx)
		cancel()
		queued, cancelQueued, joinedQueued := guardedAIAsync264(ctx, func(ctx context.Context) *httptest.ResponseRecorder {
			return legacyAIAccountingSubmit318(f, ctx, actor, runtime, op)
		})
		defer guardedAICleanup264(t, nil, cancelQueued, joinedQueued)
		w := receiveSessionOperationE2E(t, queued)
		if w.Code == http.StatusOK {
			t.Fatal("cancelled queued request succeeded")
		}
		close(f.provider.release)
		if w = receiveSessionOperationE2E(t, done); w.Code != http.StatusOK {
			t.Fatalf("first request lost reserved capacity=%d %s", w.Code, w.Body.String())
		}
		assertAIReceiptCostE2E(t, f, 3)
		// A subsequent request proves the refused waiter released its registry slot.
		if w = legacyAIAccountingSubmit318(f, f.ctx, actor, runtime, op); w.Code != http.StatusOK {
			t.Fatalf("AI admission leaked after cancellation=%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("one connection", func(t *testing.T) {
		f, _, runtime := aiAccountingSmallPoolE2E(t, 1, false)
		cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
		actor := legacyAIAccountingActor318(t, f, cookie)
		before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
		if w := legacyAIAccountingSubmit318(f, f.ctx, actor, runtime, staffAIActionForE2E(t, f, "suggest")); w.Code != http.StatusInternalServerError {
			t.Fatalf("max1 accounting=%d %s", w.Code, w.Body.String())
		}
		if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
			t.Fatal("one connection dispatched provider without accounting capacity")
		}
	})
}
