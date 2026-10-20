//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test-only observation installed at actual pool birth. It pauses just before
// the real mutation root SHARE statement, after the public route has completed
// its real token lookup/notice/input admission. It supplies no row/receipt,
// callback authority, successful SQL response or replacement public handler.
type signerAILookupGate324 struct {
	armed   atomic.Bool
	entered chan uint32
	release chan struct{}
	once    sync.Once
}

func newSignerAILookupGate324(t *testing.T) *signerAILookupGate324 {
	t.Helper()
	g := &signerAILookupGate324{entered: make(chan uint32, 1), release: make(chan struct{})}
	t.Cleanup(g.unblock)
	return g
}
func (g *signerAILookupGate324) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(d.SQL, "-- name: LockDocumentAIRootV1") && g.armed.CompareAndSwap(true, false) {
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
func (*signerAILookupGate324) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (g *signerAILookupGate324) unblock()                                                      { g.once.Do(func() { close(g.release) }) }
func (g *signerAILookupGate324) await(t *testing.T) uint32 {
	t.Helper()
	select {
	case pid := <-g.entered:
		if pid == 0 {
			t.Fatal("native source gate omitted actual backend identity")
		}
		return pid
	case <-time.After(3 * time.Second):
		t.Fatal("actual signer mutation root gate not reached after lookup")
		return 0
	}
}
func awaitSignerNativeLock324(t *testing.T, f signerAIFixture, pid uint32, query string) {
	t.Helper()
	ctx, stop := context.WithTimeout(f.ctx, 3*time.Second)
	defer stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var count int
		if err := f.pool.QueryRow(ctx, `SELECT count(*)::integer FROM pg_stat_activity WHERE datname=current_database() AND pid=$1 AND query LIKE $2 AND wait_event='transactionid' AND state='active'`, pid, "%"+query+"%").Scan(&count); err != nil {
			t.Fatal("actual signer mutation lock witness", err)
		}
		if count == 1 {
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("actual signer mutation did not wait on original row", query, ctx.Err())
		}
	}
}
func signerAIWorkerCleanup324(t *testing.T, blocked pgx.Tx, cancel context.CancelFunc, joined <-chan struct{}) {
	t.Helper()
	cancel()
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if blocked != nil {
		if err := blocked.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("original signer blocker rollback did not join", err)
		}
	}
	select {
	case <-joined:
	case <-ctx.Done():
		t.Error("original signer HTTP worker did not independently join", ctx.Err())
	}
}
func assertSignerStaffNativeOverlap324(t *testing.T, f signerAIFixture) {
	t.Helper()
	if f.pool.Config().MaxConns != 1 || !f.owned.runtime.MatchesPoolV1(f.pool) {
		t.Fatal("cross-protocol changed original one-pool allocation")
	}
	pending := f.owned.runtime.SessionsV1().PendingV1()
	snapshot, err := f.owned.runtime.SnapshotV1(f.org)
	// Same explicit funded-at-birth315 profile: two actual provider streams,
	// two reserved usage sessions and two dispatch sessions plus real observers.
	if err != nil || pending.ObserverSessions != 2 || snapshot.Global.SQLSessions != 6 || snapshot.Organisation.SQLSessions != 5 || snapshot.Global.ProviderStreams != 2 || snapshot.Organisation.ProviderStreams != 2 || snapshot.GlobalGrants > 128 || snapshot.OrganisationGrants > 64 || snapshot.Global.ParentBytes <= 0 || snapshot.Global.DBStagingBytes <= 0 {
		t.Fatal("actual recipient/staff owned overlap differs", snapshot, pending, err)
	}
}
func assertSignerStaffNativeEvents324(t *testing.T, f signerAIFixture) {
	t.Helper()
	var usages, costs, results, events int
	var exact bool
	err := f.pool.QueryRow(f.ctx, `WITH requests AS (SELECT e.* FROM events e WHERE e.org_id=$1 AND e.document_id=$2 AND e.kind='ai.requested'),tuples AS (SELECT q.id,count(DISTINCT a.id)::integer AS usages,count(DISTINCT c.id)::integer AS costs,count(DISTINCT r.id)::integer AS results FROM requests q LEFT JOIN ai_completion_audit a ON a.id=q.id AND a.org_id=q.org_id AND a.document_id=q.document_id AND a.actor_user_id IS NOT DISTINCT FROM q.actor_user_id LEFT JOIN events c ON c.org_id=q.org_id AND c.document_id=q.document_id AND c.kind='ai.completed' AND c.actor_user_id IS NOT DISTINCT FROM q.actor_user_id AND c.recipient_id IS NOT DISTINCT FROM q.recipient_id AND c.payload_json->>'request_event_id'=q.id::text AND c.payload_json->>'usage_id'=a.id::text AND c.payload_json->>'input_tokens'='23' AND c.payload_json->>'output_tokens'='11' LEFT JOIN events r ON r.org_id=q.org_id AND r.document_id=q.document_id AND r.kind=CASE WHEN q.recipient_id IS NULL THEN 'ai.result_ready' ELSE 'clarifier.answered' END AND r.actor_user_id IS NOT DISTINCT FROM q.actor_user_id AND r.recipient_id IS NOT DISTINCT FROM q.recipient_id AND r.payload_json->>'request_event_id'=q.id::text GROUP BY q.id) SELECT coalesce(sum(usages),0)::integer,coalesce(sum(costs),0)::integer,coalesce(sum(results),0)::integer,coalesce(bool_and(usages=1 AND costs=1 AND results=1),false),(SELECT count(*)::integer FROM events WHERE org_id=$1 AND document_id=$2 AND kind IN ('ai.requested','ai.completed','ai.result_ready','clarifier.requested','clarifier.answered')) FROM tuples`, f.org, f.doc.ID).Scan(&usages, &costs, &results, &exact, &events)
	if err != nil || usages != 2 || costs != 2 || results != 2 || !exact || events != 7 {
		t.Fatal("actual recipient/staff request-cost-result tuple differs", usages, costs, results, exact, events, err)
	}
	nativeBindingMeasurement259(t, f.lifecycleAuthorizationFixture, f.doc.ID)
}
