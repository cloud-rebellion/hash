//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/jackc/pgx/v5"
	"os"
	"strings"
	"testing"
	"time"
)

// Exercises the real generated query and collector timeout. Only session-local
// metadata shadows exist; this is neither migration nor worker-loop acceptance.
func TestOperationalBacklog426ActualQueryTimeoutAndBackendRetirementE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("explicit owned PostgreSQL required")
	}
	if os.Getenv("HASH_E2E_BACKLOG_OWNED_PG") != "1" {
		t.Fatal("owned backlog PostgreSQL acknowledgement required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || cfg.Host != "127.0.0.1" && cfg.Host != "localhost" && cfg.Host != "::1" || !strings.HasPrefix(cfg.Database, "hash_backlog_") {
		t.Fatal("fixed loopback owned database prefix required")
	}
	for _, fallback := range cfg.Fallbacks {
		if fallback.Host != "127.0.0.1" && fallback.Host != "localhost" && fallback.Host != "::1" {
			t.Fatal("remote fallback is not an owned loopback fixture")
		}
	}
	parent, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	connect, cancelConnect := context.WithTimeout(parent, 2*time.Second)
	conn, err := pgx.ConnectConfig(connect, cfg)
	cancelConnect()
	if err != nil {
		t.Fatal("owned collector connection failed")
	}
	// Close is idempotent: pgx may already have closed the connection while its
	// context deadline interrupted I/O. IsClosed is NOT the retirement oracle.
	closeOwned := func(c *pgx.Conn) {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c.Close(cleanup); err != nil && !c.IsClosed() {
			t.Error("owned connection close incomplete")
		}
	}
	collectorJoined := true
	defer func() {
		if collectorJoined {
			closeOwned(conn)
		} else {
			t.Error("collector ownership unresolved; no concurrent pgx close")
		}
	}()
	connect, cancelConnect = context.WithTimeout(parent, 2*time.Second)
	observer, err := pgx.ConnectConfig(connect, cfg.Copy())
	cancelConnect()
	if err != nil {
		t.Fatal("independent read-only observer connection failed")
	}
	defer closeOwned(observer)
	pid := int64(conn.PgConn().PID())
	if pid <= 0 || pid > 2147483647 {
		t.Fatal("bounded backend identity unavailable")
	}
	setup, cancelSetup := context.WithTimeout(parent, time.Second)
	_, err = conn.Exec(setup, `
 CREATE TEMP TABLE documents(id bigint,org_id bigint,status text,deleted_at timestamptz,parent_envelope_id bigint);
 CREATE TEMP TABLE document_finalization_intents(document_id bigint PRIMARY KEY,org_id bigint,created_at timestamptz);
 CREATE TEMP VIEW email_deliveries AS
 WITH delay AS MATERIALIZED (SELECT pg_sleep(5) AS slept)
 SELECT 1::bigint AS id,'pending'::text AS status,
 statement_timestamp()-interval '1 hour' AS created_at,
 statement_timestamp()-interval '1 minute' AS next_attempt_at FROM delay;`)
	cancelSetup()
	if err != nil {
		t.Fatal("owned temporary metadata setup failed")
	}
	// FROM the materialized volatile CTE must produce the view's row. The test
	// additionally requires actual PgSleep observation, so optimization-away
	// cannot become a passing synthetic timeout control.
	activity := func() (present, active, sleeping int) {
		t.Helper()
		read, cancel := context.WithTimeout(parent, 250*time.Millisecond)
		defer cancel()
		err := observer.QueryRow(read, `SELECT count(*)::integer,
   count(*) FILTER(WHERE state='active')::integer,
   count(*) FILTER(WHERE state='active' AND wait_event='PgSleep')::integer
   FROM pg_stat_activity WHERE pid=$1 AND datname=current_database()`, pid).Scan(&present, &active, &sleeping)
		if err != nil {
			t.Fatal("bounded backend-state observation failed")
		}
		if present < 0 || present > 1 || active < 0 || active > present || sleeping < 0 || sleeping > active {
			t.Fatal("backend-state projection invalid")
		}
		return
	}
	present, active, _ := activity()
	if present != 1 || active != 0 {
		t.Fatal("owned backend was not initially idle")
	}
	collectCtx, cancelCollect := context.WithCancel(parent)
	done := make(chan struct{})
	var got flarereport.OperationalBacklogSnapshotV1
	var emitted bool
	var cache operationalBacklogCacheV1
	started := time.Now()
	rawConnection := conn.PgConn().Conn() // net.Conn.Close alone is concurrent-safe fallback
	collectorJoined = false
	go func() {
		defer close(done)
		got, emitted = cache.collectV1(collectCtx, generated.New(conn).GetOperationalBacklogV1, time.Now)
	}()
	// Failure paths cancel and JOIN the actual collector before normal pgx Close
	// and observer teardown. An unresolved join fails; it is never accepted as cleanup.
	defer func() {
		cancelCollect()
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		select {
		case <-done:
			collectorJoined = true
		case <-cleanup.Done():
			// Do not race pgx methods against a still-live query. net.Conn.Close is
			// independently safe and forces transport retirement on this failure path.
			_ = rawConnection.Close()
			forced, cancelForced := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancelForced()
			select {
			case <-done:
				collectorJoined = true
			case <-forced.Done():
				t.Error("actual collector goroutine did not join")
			}
		}
		if collectorJoined {
			closeOwned(conn)
		}
	}()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	observedSleep := false
	for !observedSleep {
		_, _, sleeping := activity()
		if sleeping == 1 {
			observedSleep = true
			break
		}
		select {
		case <-done:
			t.Fatal("collector returned before actual blocking SQL was observed")
		case <-parent.Done():
			t.Fatal("parent expired before actual blocking SQL")
		case <-poll.C:
		}
	}
	completion := time.NewTimer(3 * time.Second)
	defer completion.Stop()
	select {
	case <-done:
	case <-parent.Done():
		t.Fatal("actual collector exceeded whole test owner")
	case <-completion.C:
		t.Fatal("actual collector failed finite timeout completion")
	}
	elapsed := time.Since(started)
	if !emitted || !got.ReadUnavailable || got.HasSample || got.Stale || got.Data != (flarereport.OperationalBacklogDataV1{}) || cache.hasSample {
		t.Fatal("actual timed-out query fabricated known-empty or cached success")
	}
	if elapsed >= 4*time.Second || operationalBacklogQueryBudgetV1 != time.Second {
		t.Fatal("production one-second timeout did not interrupt five-second SQL")
	}
	// BEFORE test cleanup closes conn: actual timeout must retire the active
	// backend query, rather than merely return a failed application observation.
	retirement, cancelRetirement := context.WithTimeout(parent, time.Second)
	defer cancelRetirement()
	for {
		_, active, _ := activity()
		if active == 0 {
			break
		}
		select {
		case <-retirement.Done():
			t.Fatal("active backend query outlived collector timeout")
		case <-poll.C:
		}
	}
	closeOwned(conn)
	physical, cancelPhysical := context.WithTimeout(parent, time.Second)
	defer cancelPhysical()
	select {
	case <-conn.PgConn().CleanupDone():
	case <-physical.Done():
		t.Fatal("pgx physical transport cleanup did not join")
	}
	// After explicit idempotent session close, require stable physical PID
	// absence. This also proves its temporary metadata namespace was retired.
	absent, cancelAbsent := context.WithTimeout(parent, time.Second)
	defer cancelAbsent()
	stable := 0
	for stable < 2 {
		present, _, _ := activity()
		if present == 0 {
			stable++
		} else {
			stable = 0
		}
		if stable == 2 {
			break
		}
		select {
		case <-absent.Done():
			t.Fatal("owned backend session retirement unproven")
		case <-poll.C:
		}
	}
}
