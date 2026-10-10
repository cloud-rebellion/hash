//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func aiAccountingSmallPoolE2E(t *testing.T, maximum int32, blocking bool) (guardedAIAppsFixture, *atomic.Int32) {
	t.Helper()
	f := setupGuardedAIAppsRESTE2E(t, false, blocking)
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
	f.s.Negotiator = &aiapps.Negotiator{Runtime: rt}
	f.s.Bilingual = &aiapps.Bilingual{Runtime: rt}
	f.s.RiskAnalyzer = &aiapps.RiskAnalyzer{Runtime: rt}
	return f, resolves
}

func TestAIAccountingSmallPoolConcurrentBYOAIRequestsPreserveCostE2E(t *testing.T) {
	for _, maximum := range []int32{2, 3} {
		t.Run(string(rune('0'+maximum)), func(t *testing.T) {
			f, resolves := aiAccountingSmallPoolE2E(t, maximum, true)
			if maximum == 3 {
				lease, err := f.pool.Acquire(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Release()
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			first := make(chan *httptest.ResponseRecorder, 1)
			second := make(chan *httptest.ResponseRecorder, 1)
			op := staffAIActionForE2E(t, f, "suggest")
			go func() { first <- staffAISubmitE2E(f, f.ctx, op, cookie) }()
			awaitAIProviderE2E(t, f.provider)
			if f.pool.Stat().AcquiredConns() != maximum {
				t.Fatalf("test did not occupy full pool: %+v", f.pool.Stat())
			}
			go func() { second <- staffAISubmitE2E(f, f.ctx, op, cookie) }()
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
		f, _ := aiAccountingSmallPoolE2E(t, 2, true)
		cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
		op := staffAIActionForE2E(t, f, "suggest")
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- staffAISubmitE2E(f, f.ctx, op, cookie) }()
		awaitAIProviderE2E(t, f.provider)
		ctx, cancel := context.WithCancel(f.ctx)
		cancel()
		queued := make(chan *httptest.ResponseRecorder, 1)
		go func() { queued <- staffAISubmitE2E(f, ctx, op, cookie) }()
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
		if w = staffAISubmitE2E(f, f.ctx, op, cookie); w.Code != http.StatusOK {
			t.Fatalf("AI admission leaked after cancellation=%d %s", w.Code, w.Body.String())
		}
	})
	t.Run("one connection", func(t *testing.T) {
		f, _ := aiAccountingSmallPoolE2E(t, 1, false)
		cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
		before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
		if w := staffAISubmitE2E(f, f.ctx, staffAIActionForE2E(t, f, "suggest"), cookie); w.Code != http.StatusInternalServerError {
			t.Fatalf("max1 accounting=%d %s", w.Code, w.Body.String())
		}
		if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
			t.Fatal("one connection dispatched provider without accounting capacity")
		}
	})
}
