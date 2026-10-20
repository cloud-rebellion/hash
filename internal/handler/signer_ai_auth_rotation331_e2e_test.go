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

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Observation only, installed at pool birth. The gap mode stops before the
// first root statement after the observed request COMMIT; answer mode stops before the real
// answer INSERT, after the actual provider and independent cost commit. Neither
// mode fabricates SQL rows, receipts, locks, input or callback authority.
type signerAIPhaseGate331 struct {
	answer        bool
	armed         atomic.Bool
	request       signerAIRequestCommit335
	entered       chan uint32
	rotation      chan uint32
	rotationArmed atomic.Bool
	release       chan struct{}
	once          sync.Once
}

func newSignerAIPhaseGate331(t *testing.T, answer bool) *signerAIPhaseGate331 {
	t.Helper()
	g := &signerAIPhaseGate331{answer: answer, entered: make(chan uint32, 1), rotation: make(chan uint32, 1), release: make(chan struct{})}
	t.Cleanup(g.unblock)
	return g
}
func (g *signerAIPhaseGate331) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(d.SQL, "-- name: RotateRecipientMagicToken") && g.rotationArmed.CompareAndSwap(true, false) {
		select {
		case g.rotation <- c.PgConn().PID():
		default:
		}
	}
	if !g.armed.Load() {
		return ctx
	}
	g.request.observeStart(c, d)
	stop := false
	if g.answer {
		if strings.HasPrefix(d.SQL, "-- name: InsertEvent") && len(d.Args) >= 5 {
			kind, ok := d.Args[4].(string)
			stop = ok && kind == "clarifier.answered"
		}
	} else if strings.HasPrefix(d.SQL, "-- name: LockDocumentAIRootV1") {
		stop = g.request.dispatchRoot(c, d)
	}
	if stop && g.armed.CompareAndSwap(true, false) {
		select {
		case g.entered <- c.PgConn().PID():
		case <-ctx.Done():
			return ctx
		}
		select {
		case <-g.release:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (g *signerAIPhaseGate331) TraceQueryEnd(_ context.Context, c *pgx.Conn, d pgx.TraceQueryEndData) {
	g.request.observeEnd(c, d)
}
func (g *signerAIPhaseGate331) unblock() { g.once.Do(func() { close(g.release) }) }
func awaitSignerAIBackend331(t *testing.T, entered <-chan uint32, label string) uint32 {
	t.Helper()
	select {
	case pid := <-entered:
		if pid == 0 {
			t.Fatal("actual signer phase omitted backend identity", label)
		}
		return pid
	case <-time.After(3 * time.Second):
		t.Fatal("actual signer phase not reached", label)
		return 0
	}
}
func signerAIRotationParams331(t *testing.T, f signerAIFixture) generated.RotateRecipientMagicTokenParams {
	t.Helper()
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	return generated.RotateRecipientMagicTokenParams{ID: f.recipient.ID, DocumentID: f.doc.ID, MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}
}
func signerAIState331(t *testing.T, f signerAIFixture) string {
	t.Helper()
	var measurements string
	if err := f.pool.QueryRow(f.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.event_id),'[]'::jsonb)::text FROM html_snapshot_event_payload_sizes_v1 m WHERE m.org_id=$1`, f.org).Scan(&measurements); err != nil {
		t.Fatal("native signer measurement snapshot", err)
	}
	return authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) + "\n" + measurements
}
func assertSignerAIOldTokenRefuses331(t *testing.T, f signerAIFixture) {
	t.Helper()
	before := signerAIState331(t, f)
	calls := f.provider.calls.Load()
	w := f.submitSigner(f.ctx, f.digest)
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "Reviewed AI suggestion") {
		t.Fatal("rotated original token accepted a fresh request or private result", w.Code, w.Body.String())
	}
	if f.provider.calls.Load() != calls || signerAIState331(t, f) != before {
		t.Fatal("rotated original token dispatched or changed usage/events/measurements")
	}
}
func awaitSignerRotationLock331(t *testing.T, f signerAIFixture, rotation, dispatch uint32) {
	t.Helper()
	ctx, stop := context.WithTimeout(f.ctx, 3*time.Second)
	defer stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var count int
		if err := f.pool.QueryRow(ctx, `SELECT count(*)::integer FROM pg_stat_activity WHERE datname=current_database() AND pid=$1 AND query LIKE '%-- name: RotateRecipientMagicToken%' AND wait_event='transactionid' AND state='active' AND $2::integer=ANY(pg_blocking_pids(pid))`, rotation, dispatch).Scan(&count); err != nil {
			t.Fatal("canonical rotation parent serialization witness", err)
		}
		if count == 1 {
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("canonical rotation did not wait behind actual dispatch owner", ctx.Err())
		}
	}
}

func signerAIRotationAfterAnswer331E2E(t *testing.T) {
	t.Helper()
	gate := newSignerAIPhaseGate331(t, true)
	f := setupSignerAIAuthWithOwned324E2E(t, false, newOwnedPublicReadFixtureProfileV1(t, false, false, gate))
	gate.armed.Store(true)
	done, cancel, joined := nativeReminderAsyncHTTP255(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return f.submitSigner(ctx, f.digest) })
	defer func() { gate.unblock(); signerAIWorkerCleanup324(t, nil, cancel, joined) }()
	dispatch := awaitSignerAIBackend331(t, gate.entered, "actual answer after cost")
	// The real provider response and its independently durable usage+cost have
	// completed. The original dispatch transaction still owns parent SHARE.
	if f.provider.calls.Load() != 1 {
		t.Fatal("answer gate did not follow actual provider completion")
	}
	assertSignerAIReceiptE2E(t, f, false)
	params := signerAIRotationParams331(t, f)
	rotationCtx, rotationCancel := context.WithTimeout(f.ctx, 10*time.Second)
	rotated := make(chan error, 1)
	rotationJoined := make(chan struct{})
	// Arm only this intended worker; genuine Send setup rotations are excluded.
	gate.rotationArmed.Store(true)
	go func() { defer close(rotationJoined); rotated <- f.q.RotateRecipientMagicToken(rotationCtx, params) }()
	defer signerAIWorkerCleanup324(t, nil, rotationCancel, rotationJoined)
	rotation := awaitSignerAIBackend331(t, gate.rotation, "canonical rotation")
	awaitSignerRotationLock331(t, f, rotation, dispatch)
	// Finish the already authorized operation before the canonical rotation can
	// acquire parent UPDATE. No raw token write bypasses M88 parent ordering.
	gate.unblock()
	w := receiveSessionOperationE2E(t, done)
	if w.Code != http.StatusOK || !json.Valid(w.Body.Bytes()) || !strings.Contains(w.Body.String(), "Reviewed AI suggestion") {
		t.Fatal("serialized authorized signer operation failed", w.Code, w.Body.String())
	}
	select {
	case err := <-rotated:
		if err != nil {
			t.Fatal("canonical queued rotation failed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canonical queued rotation did not join")
	}
	assertSignerAIReceiptE2E(t, f, true)
	assertSignerAIOldTokenRefuses331(t, f)
}

func signerAIRotationBetweenPhases331E2E(t *testing.T) {
	t.Helper()
	f, _ := signerAIRequestWithoutUsage331E2E(t)
	assertSignerAIOldTokenRefuses331(t, f)
}

func signerAIRequestWithoutUsage331E2E(t *testing.T) (signerAIFixture, uuid.UUID) {
	t.Helper()
	gate := newSignerAIPhaseGate331(t, false)
	f := setupSignerAIAuthWithOwned324E2E(t, false, newOwnedPublicReadFixtureProfileV1(t, false, false, gate))
	baseline := len(aiAppEventSnapshotE2E(t, f.lifecycleAuthorizationFixture))
	gate.armed.Store(true)
	done, cancel, joined := nativeReminderAsyncHTTP255(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return f.submitSigner(ctx, f.digest) })
	defer func() { gate.unblock(); signerAIWorkerCleanup324(t, nil, cancel, joined) }()
	awaitSignerAIBackend331(t, gate.entered, "observed request COMMIT before dispatch root")
	// The request transaction is already committed and retired; dispatch has
	// not acquired its root lock. Canonical rotation can genuinely commit here.
	var requests, usage, costs, answers int
	err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events WHERE org_id=$1 AND kind IN ('clarifier.requested','ai.requested')),(SELECT count(*) FROM ai_completion_audit WHERE org_id=$1),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='ai.completed'),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='clarifier.answered')`, f.org).Scan(&requests, &usage, &costs, &answers)
	if err != nil || requests != 2 || usage != 0 || costs != 0 || answers != 0 || f.provider.calls.Load() != 0 || len(aiAppEventSnapshotE2E(t, f.lifecycleAuthorizationFixture)) != baseline+2 {
		t.Fatal("actual request-dispatch gap state differs", requests, usage, costs, answers, err)
	}
	nativeBindingMeasurement259(t, f.lifecycleAuthorizationFixture, f.doc.ID)
	if err := f.q.RotateRecipientMagicToken(f.ctx, signerAIRotationParams331(t, f)); err != nil {
		t.Fatal("canonical phase-gap rotation", err)
	}
	before := signerAIState331(t, f)
	gate.unblock()
	w := receiveSessionOperationE2E(t, done)
	if w.Code != http.StatusGone || strings.Contains(w.Body.String(), "Reviewed AI suggestion") {
		t.Fatal("phase-gap stale signer result", w.Code, w.Body.String())
	}
	if f.provider.calls.Load() != 0 || signerAIState331(t, f) != before {
		t.Fatal("phase-gap rotation dispatched or changed committed request/usage/measurement state")
	}
	var receipt uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT id FROM events WHERE org_id=$1 AND document_id=$2 AND recipient_id=$3 AND actor_user_id IS NULL AND kind='ai.requested'`, f.org, f.doc.ID, f.recipient.ID).Scan(&receipt); err != nil || receipt == uuid.Nil {
		t.Fatal("actual unconsumed request receipt absent", receipt, err)
	}
	return f, receipt
}

func assertSignerAINativeReceiptNegatives331E2E(t *testing.T, f, other signerAIFixture, receipt uuid.UUID) {
	t.Helper()
	// Foreign-scope refusals must use a genuine request with NO usage row:
	// otherwise an existing primary-key conflict could mask a missing WHERE
	// predicate. The real phase-gap journey supplies exactly that request.
	unused, unusedReceipt := signerAIRequestWithoutUsage331E2E(t)
	params := generated.PersistSignerAIUsageV1Params{RequestEventID: unusedReceipt, OrgID: unused.org, DocumentID: unused.doc.ID, RecipientID: unused.recipient.ID, Provider: unused.nativeProvider.Name(), Model: unused.nativeProvider.Model(), PromptName: "native receipt refusal", ShieldActive: true, InputTokens: 23, OutputTokens: 11, Success: true, TransferJurisdiction: "local"}
	before, foreignBefore, unusedBefore := signerAIState331(t, f), signerAIState331(t, other), signerAIState331(t, unused)
	for _, change := range []string{"duplicate", "org", "document", "recipient", "missing"} {
		bad := params
		switch change {
		case "duplicate":
			bad.RequestEventID, bad.OrgID, bad.DocumentID, bad.RecipientID = receipt, f.org, f.doc.ID, f.recipient.ID
		case "org":
			bad.OrgID = other.org
		case "document":
			bad.DocumentID = other.doc.ID
		case "recipient":
			bad.RecipientID = other.recipient.ID
		case "missing":
			bad.RequestEventID = uuid.New()
		}
		// Every owned fixture has its own disposable database. Foreign
		// checks must execute beside the actual unused request; only the
		// duplicate executes beside its actual already-consumed receipt.
		query, queryCtx := unused.q, unused.ctx
		if change == "duplicate" {
			query, queryCtx = f.q, f.ctx
		}
		rows, err := query.PersistSignerAIUsageV1(queryCtx, bad)
		if err != nil || rows != 0 {
			t.Fatal("native foreign/duplicate signer usage receipt accepted", change, rows, err)
		}
		if signerAIState331(t, f) != before || signerAIState331(t, other) != foreignBefore || signerAIState331(t, unused) != unusedBefore {
			t.Fatal("native rejected usage receipt changed durable state", change)
		}
	}
}
