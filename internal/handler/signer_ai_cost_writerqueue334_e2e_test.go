//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Pure at-birth observation of the original public request COMMIT and later dispatch statement
// and canonical rotator. No SQL is paused, replaced or granted a result here.
type signerAIWriterQueue334 struct {
	armed         atomic.Bool
	request       signerAIRequestCommit335
	dispatch      chan uint32
	rotation      chan uint32
	rotationArmed atomic.Bool
}

func (g *signerAIWriterQueue334) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if g.armed.Load() {
		g.request.observeStart(c, d)
		if g.request.dispatchRoot(c, d) && g.armed.CompareAndSwap(true, false) {
			select {
			case g.dispatch <- c.PgConn().PID():
			default:
			}
		}
	}
	if strings.HasPrefix(d.SQL, "-- name: RotateRecipientMagicToken") && g.rotationArmed.CompareAndSwap(true, false) {
		select {
		case g.rotation <- c.PgConn().PID():
		default:
		}
	}
	return ctx
}
func (g *signerAIWriterQueue334) TraceQueryEnd(_ context.Context, c *pgx.Conn, d pgx.TraceQueryEndData) {
	g.request.observeEnd(c, d)
}

// A canonical writer queued while the real provider is entered must not cut
// off independently durable cost or create a dispatch→cost→writer wait cycle.
// This regression intentionally targets the CURRENT producer; the separate331
// after-cost witness does not qualify this earlier point. No limits are raised.
func TestSignerAICanonicalWriterQueueBeforeCostPreservesAccountingE2E(t *testing.T) {
	gate := &signerAIWriterQueue334{dispatch: make(chan uint32, 1), rotation: make(chan uint32, 1)}
	f := setupSignerAIAuthWithOwned324E2E(t, true, newOwnedPublicReadFixtureProfileV1(t, false, false, gate))
	gate.armed.Store(true)
	done, cancel, joined := nativeReminderAsyncHTTP255(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return f.submitSigner(ctx, f.digest) })
	var release sync.Once
	releaseProvider := func() { release.Do(func() { close(f.provider.release) }) }
	defer func() { releaseProvider(); signerAIWorkerCleanup324(t, nil, cancel, joined) }()
	request := awaitAIProviderE2E(t, f.provider)
	if strings.Contains(request.User, "Lifecycle signer") || strings.Contains(request.User, "alice@example.com") {
		t.Fatal("writer-queue journey lost actual Shield/party context")
	}
	dispatch := awaitSignerAIBackend331(t, gate.dispatch, "real provider dispatch")
	params := signerAIRotationParams331(t, f)
	rotationCtx, rotationCancel := context.WithTimeout(f.ctx, 10*time.Second)
	rotated := make(chan error, 1)
	rotationJoined := make(chan struct{})
	// Arm only this intended worker; genuine Send setup rotations are excluded.
	gate.rotationArmed.Store(true)
	go func() { defer close(rotationJoined); rotated <- f.q.RotateRecipientMagicToken(rotationCtx, params) }()
	defer signerAIWorkerCleanup324(t, nil, rotationCancel, rotationJoined)
	rotation := awaitSignerAIBackend331(t, gate.rotation, "canonical pre-cost rotation")
	awaitSignerRotationLock331(t, f, rotation, dispatch)
	// The writer genuinely precedes the later independent cost SHARE request.
	// The real provider now returns its normal23/11 success response.
	releaseProvider()
	w := receiveSessionOperationE2E(t, done)
	var rotationErr error
	select {
	case rotationErr = <-rotated:
	case <-time.After(3 * time.Second):
		t.Fatal("pre-cost canonical rotation did not join")
	}
	var requests, usage, costs, answers int
	err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events WHERE org_id=$1 AND kind IN ('clarifier.requested','ai.requested')),(SELECT count(*) FROM ai_completion_audit WHERE org_id=$1 AND actor_user_id IS NULL AND input_tokens=23 AND output_tokens=11 AND success AND shield_active),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='ai.completed'),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='clarifier.answered')`, f.org).Scan(&requests, &usage, &costs, &answers)
	t.Logf("actual pre-cost canonical writer queue: HTTP=%d rotation_error=%v requests=%d truthful_usage=%d cost_events=%d answers=%d provider_calls=%d inventory_error=%v", w.Code, rotationErr, requests, usage, costs, answers, f.provider.calls.Load(), err)
	if w.Code != http.StatusOK || !json.Valid(w.Body.Bytes()) || !strings.Contains(w.Body.String(), "Reviewed AI suggestion") {
		t.Errorf("pre-cost queued writer interrupted authorized operation: HTTP=%d body=%s", w.Code, w.Body.String())
	}
	if rotationErr != nil {
		t.Errorf("pre-cost queued canonical rotation failed: %v", rotationErr)
	}
	if err != nil || requests != 2 || usage != 1 || costs != 1 || answers != 1 || f.provider.calls.Load() != 1 {
		t.Errorf("pre-cost writer queue lost truthful request/usage/cost/result: requests=%d usage=%d costs=%d answers=%d err=%v", requests, usage, costs, answers, err)
	}
	assertSignerAIReceiptE2E(t, f, true)
	if rotationErr == nil {
		assertSignerAIOldTokenRefuses331(t, f)
	}
	f.owned.assertObserversOnlyV1(t)
}
