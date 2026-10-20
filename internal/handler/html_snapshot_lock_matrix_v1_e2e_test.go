//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Fixed SQL COMPONENT only: no native application grant, legal state/actor,
// producer/cache backfill, physical retirement or READY is manufactured. Root
// owns the bounded isolated PG fixture and verifies complete process disposal.
// Committed removable plain seeds permit real cross-session visibility. Every
// competing transaction/operation joins before connection release and cleanup.
type htmlSnapshotLockMatrixV1 struct {
	t             *testing.T
	f             lifecycleAuthorizationFixture
	ctx           context.Context
	cancel        context.CancelFunc
	c             [3]*pgxpool.Conn // parent actor, competing actor, independent wait witness
	pid           [3]int32
	previous      [3][3]string
	settingsKnown [3]bool
	tx            [2]pgx.Tx
	pending       chan error
	pendingCancel context.CancelFunc
	other         uuid.UUID
}

func newHTMLSnapshotLockMatrixV1(t *testing.T) *htmlSnapshotLockMatrixV1 {
	t.Helper()
	if os.Getenv("HASH_E2E_DB_URL") == "" {
		t.Fatal("selected SQL lock component requires HASH_E2E_DB_URL")
	}
	isolateHTMLTemplateDatabaseE2E(t)
	f := setupLifecycleAuthorizationE2E(t, "owner", false, false)
	ctx, cancel := context.WithTimeout(f.ctx, 25*time.Second)
	q := &htmlSnapshotLockMatrixV1{t: t, f: f, ctx: ctx, cancel: cancel}
	// Registered before any acquisition/dispatch; this runs before the existing
	// fixture pool/child-DB cleanup. Pool backends deliberately stay live until
	// that outer cleanup, not until a release of a local connection borrower.
	t.Cleanup(q.closeV1)
	other, err := f.q.CreateOrg(ctx, generated.CreateOrgParams{Name: "M94 lock component " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal("create controlled foreign org", err)
	}
	q.other = other.ID
	for i := range q.c {
		q.c[i], err = f.pool.Acquire(ctx)
		if err != nil {
			t.Fatal("acquire bounded independent component connection", err)
		}
		if err = q.c[i].QueryRow(ctx, "SELECT current_setting('statement_timeout'),current_setting('lock_timeout'),current_setting('idle_in_transaction_session_timeout')").Scan(&q.previous[i][0], &q.previous[i][1], &q.previous[i][2]); err != nil {
			t.Fatal("capture prior borrowed session settings", err)
		}
		q.settingsKnown[i] = true
		if _, err = q.c[i].Exec(ctx, "SET statement_timeout='4000ms'; SET lock_timeout='3000ms'; SET idle_in_transaction_session_timeout='10000ms'"); err != nil {
			t.Fatal("set controlled fixture timeouts", err)
		}
		if err = q.c[i].QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&q.pid[i]); err != nil {
			t.Fatal("capture actual component backend", err)
		}
	}
	if q.pid[0] == q.pid[1] || q.pid[0] == q.pid[2] || q.pid[1] == q.pid[2] {
		t.Fatal("component sessions must be independent")
	}
	return q
}
func (q *htmlSnapshotLockMatrixV1) rollbackV1(i int, ctx context.Context) error {
	if q.tx[i] == nil {
		return nil
	}
	err := q.tx[i].Rollback(ctx)
	if err == nil || errors.Is(err, pgx.ErrTxClosed) {
		q.tx[i] = nil
		return nil
	}
	return err
}
func (q *htmlSnapshotLockMatrixV1) closeV1() {
	q.cancel()
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if q.pendingCancel != nil {
		q.pendingCancel()
	}
	// Only connection0 ever runs the registered asynchronous operation; release
	// its blocker on connection1 first, then join before touching connection0.
	if err := q.rollbackV1(1, cleanup); err != nil {
		q.t.Error("fresh blocker rollback", err)
	}
	joined := true
	if q.pending != nil {
		select {
		case <-q.pending:
			q.pending = nil
		case <-cleanup.Done():
			joined = false
			q.t.Error("real component operation did not join; connection retained for outer disposal")
		}
	}
	if joined {
		if err := q.rollbackV1(0, cleanup); err != nil {
			q.t.Error("fresh parent rollback", err)
		}
	}
	if joined && q.other != uuid.Nil && q.c[2] != nil {
		if _, err := q.c[2].Exec(cleanup, "DELETE FROM orgs WHERE id=$1", q.other); err != nil {
			q.t.Error("controlled foreign org cleanup", err)
		} //nolint:rawsql -- exact owned synthetic org
	}
	for i := range q.c {
		if q.c[i] != nil && (i != 0 || joined) {
			// Restore captured actual settings, including operator startup defaults.
			restore := q.settingsKnown[i]
			if restore {
				_, err := q.c[i].Exec(cleanup, "SELECT set_config('statement_timeout',$1,false),set_config('lock_timeout',$2,false),set_config('idle_in_transaction_session_timeout',$3,false)", q.previous[i][0], q.previous[i][1], q.previous[i][2])
				restore = err == nil
			}
			if !restore {
				done := q.c[i].Conn().PgConn().CleanupDone()
				_ = q.c[i].Conn().Close(cleanup)
				select {
				case <-done:
				case <-cleanup.Done():
					q.t.Error("unrestored client cleanup did not join; borrower retained for outer disposal")
					continue
				}
			}
			q.c[i].Release()
			q.c[i] = nil
		}
	}
}
func (q *htmlSnapshotLockMatrixV1) beginV1(i int) {
	q.t.Helper()
	if q.tx[i] != nil {
		q.t.Fatal("previous component transaction still owned")
	}
	var err error
	q.tx[i], err = q.c[i].BeginTx(q.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		q.t.Fatal("begin actual component transaction", err)
	}
}
func (q *htmlSnapshotLockMatrixV1) endV1(i int) {
	q.t.Helper()
	if err := q.rollbackV1(i, q.ctx); err != nil {
		q.t.Fatal("join actual transaction rollback", err)
	}
}
func (q *htmlSnapshotLockMatrixV1) startV1(run func(context.Context) error) {
	q.t.Helper()
	if q.pending != nil {
		q.t.Fatal("one bounded actual operation at a time")
	}
	op, stop := context.WithTimeout(q.ctx, 5*time.Second)
	q.pendingCancel = stop
	q.pending = make(chan error, 1)
	done := q.pending
	go func() { done <- run(op) }()
}
func (q *htmlSnapshotLockMatrixV1) joinV1() {
	q.t.Helper()
	select {
	case err := <-q.pending:
		q.pending = nil
		q.pendingCancel()
		q.pendingCancel = nil
		if err != nil {
			q.t.Fatal("joined actual component operation", err)
		}
	case <-q.ctx.Done():
		q.t.Fatal("original component deadline while joining")
	}
}
func (q *htmlSnapshotLockMatrixV1) waitChainV1(blocker int32) {
	q.t.Helper()
	bound, stop := context.WithTimeout(q.ctx, 2*time.Second)
	defer stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked bool
		err := q.c[2].QueryRow(bound, "SELECT wait_event_type='Lock' AND wait_event='advisory' AND $2=ANY(pg_blocking_pids(pid)) FROM pg_catalog.pg_stat_activity WHERE pid=$1", q.pid[0], blocker).Scan(&blocked)
		if err != nil {
			q.t.Fatal("observe actual advisory waiter", err)
		}
		if blocked {
			return
		}
		select {
		case <-tick.C:
		case <-bound.Done():
			q.t.Fatal("exact actor never reached actual blocker advisory lock")
		}
	}
}
func (q *htmlSnapshotLockMatrixV1) busyV1(i int, run func(context.Context, pgx.Tx) error) {
	q.t.Helper()
	if q.tx[i] == nil {
		q.beginV1(i)
	}
	op, stop := context.WithTimeout(q.ctx, 2*time.Second)
	err := run(op, q.tx[i])
	alive := op.Err() == nil
	stop()
	cleanup, finish := context.WithTimeout(context.Background(), 3*time.Second)
	rollbackErr := q.rollbackV1(i, cleanup)
	finish()
	if rollbackErr != nil {
		q.t.Fatal("refused operation rollback failed", rollbackErr)
	}
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "55P03" || strings.Contains(pe.Message, "lock timeout") || !alive {
		q.t.Fatalf("require immediate55P03 with live original operation and completed rollback: code55P03=%v contextAlive=%v", errors.As(err, &pe) && pe.Code == "55P03", alive)
	}
	if q.c[i].Conn().PgConn().TxStatus() != 'I' {
		q.t.Fatal("failed operation did not return to actual idle client")
	}
}
func (q *htmlSnapshotLockMatrixV1) busySQLV1(i int, sql string, args ...any) {
	q.t.Helper()
	q.busyV1(i, func(ctx context.Context, tx pgx.Tx) error { _, err := tx.Exec(ctx, sql, args...); return err })
}
func (q *htmlSnapshotLockMatrixV1) headerV1() {
	q.t.Helper()
	q.beginV1(0)
	h, err := generated.New(q.tx[0]).GetHTMLRevisionSnapshotSizeHeaderV1(q.ctx, generated.GetHTMLRevisionSnapshotSizeHeaderV1Params{DocumentID: q.f.doc.ID, OrgID: q.f.org})
	if err != nil || h.ID != q.f.doc.ID {
		q.t.Fatal("actual complete-set scalar header", err)
	}
	// A mismatch scalar in a controlled SQL fixture is not application permission.
}

func TestHTMLSnapshotEventOrgChainWaitsE2E(t *testing.T) {
	q := newHTMLSnapshotLockMatrixV1(t)
	id := uuid.New()
	statements := []string{
		"INSERT INTO events(id,org_id,document_id,kind,payload_json)VALUES($1,$2,$3,'snapshot.wait','{}'::jsonb)",
		"UPDATE events SET ua='updated' WHERE id=$1 AND org_id=$2 AND document_id=$3",
		"DELETE FROM events WHERE id=$1 AND org_id=$2 AND document_id=$3",
	}
	for _, statement := range statements {
		q.beginV1(1)
		if err := generated.New(q.tx[1]).AcquireOrgChainLock(q.ctx, q.f.org.String()); err != nil {
			t.Fatal("hold genuine existing org-chain", err)
		}
		sql := statement
		q.startV1(func(ctx context.Context) error { _, err := q.c[0].Exec(ctx, sql, id, q.f.org, q.f.doc.ID); return err })
		q.waitChainV1(q.pid[1])
		q.endV1(1)
		q.joinV1()
	}
	var n int64
	if err := q.c[2].QueryRow(q.ctx, "SELECT count(*) FROM events WHERE id=$1", id).Scan(&n); err != nil || n != 0 {
		t.Fatal("I/U/D full chain sequence failed", err)
	}
}

func TestHTMLSnapshotOrdinaryAuditReverseOrderRetryE2E(t *testing.T) {
	q := newHTMLSnapshotLockMatrixV1(t)
	docID := q.f.doc.ID
	q.beginV1(1)
	if err := generated.New(q.tx[1]).AcquireOrgChainLock(q.ctx, q.f.org.String()); err != nil {
		t.Fatal(err)
	}
	q.beginV1(0)
	q.startV1(func(ctx context.Context) error {
		_, err := generated.New(q.tx[0]).GetHTMLRevisionSnapshotSizeHeaderV1(ctx, generated.GetHTMLRevisionSnapshotSizeHeaderV1Params{DocumentID: docID, OrgID: q.f.org})
		return err
	})
	// Exact advisory wait proves actual header has passed its subject TRY and is
	// waiting for the old ordinary appender's chain. No synthetic start gate.
	q.waitChainV1(q.pid[1])
	log := audit.New(generated.New(q.c[1]), nil)
	entry := audit.Entry{OrgID: q.f.org, DocumentID: &docID, Kind: "snapshot.audit-retry", Payload: map[string]any{"fixture": "bounded"}}
	q.busyV1(1, func(ctx context.Context, tx pgx.Tx) error { _, err := log.LogTx(ctx, tx, entry); return err })
	q.joinV1()
	q.endV1(0)
	q.beginV1(1)
	pending, err := log.LogTx(q.ctx, q.tx[1], entry)
	if err != nil || pending.ID == uuid.Nil {
		t.Fatal("fresh ordinary retry outside original locks", err)
	}
	if err = q.tx[1].Commit(q.ctx); err != nil {
		t.Fatal("actual ordinary audit retry commit", err)
	}
	q.tx[1] = nil
	log.Publish(pending)
	var n int64
	if err = q.c[2].QueryRow(q.ctx, "SELECT count(*) FROM events WHERE document_id=$1 AND kind='snapshot.audit-retry' AND octet_length(row_hash)=32", docID).Scan(&n); err != nil || n != 1 {
		t.Fatal("failed append must rollback and exactly one explicit retry commit", err)
	}
}

func TestHTMLSnapshotAllOldNewEventSubjectsRefuseE2E(t *testing.T) {
	q := newHTMLSnapshotLockMatrixV1(t)
	old, newID, orphan := uuid.New(), uuid.New(), uuid.New()
	if _, err := q.c[2].Exec(q.ctx, "INSERT INTO events(id,org_id,document_id,kind,payload_json)VALUES($1,$2,$3,'snapshot.old','{}'),($4,$2,$5,'snapshot.new','{}')", old, q.other, q.f.doc.ID, newID, orphan); err != nil {
		t.Fatal(err)
	}
	q.headerV1()
	q.busySQLV1(1, "INSERT INTO events(org_id,document_id,kind,payload_json)VALUES($1,$2,'snapshot.insert','{}')", q.other, q.f.doc.ID)
	q.busySQLV1(1, "UPDATE events SET payload_json='{\"changed\":true}' WHERE id=$1", old)
	q.busySQLV1(1, "DELETE FROM events WHERE id=$1", old)
	q.busySQLV1(1, "UPDATE events SET document_id=$2 WHERE id=$1", newID, q.f.doc.ID)
	q.busySQLV1(1, "UPDATE events SET document_id=$2 WHERE id=$1", old, orphan)
	q.endV1(0)
	var n int64
	if err := q.c[2].QueryRow(q.ctx, "SELECT count(*) FROM events WHERE(id=$1 AND document_id=$2 AND payload_json='{}'::jsonb)OR(id=$3 AND document_id=$4 AND payload_json='{}'::jsonb)", old, q.f.doc.ID, newID, orphan).Scan(&n); err != nil || n != 2 {
		t.Fatal("OLD/NEW refusal changed committed sources", err)
	}
}

func TestHTMLSnapshotUUIDBirthMoveDeleteRefuseE2E(t *testing.T) {
	q := newHTMLSnapshotLockMatrixV1(t)
	orphan := uuid.New()
	q.beginV1(1)
	if _, err := q.tx[1].Exec(q.ctx, "INSERT INTO events(org_id,document_id,kind,payload_json)VALUES($1,$2,'snapshot.orphan','{}')", q.other, orphan); err != nil {
		t.Fatal(err)
	}
	q.busySQLV1(0, "INSERT INTO documents(id,org_id,sender_id,name,status,source_kind)VALUES($1,$2,$3,'snapshot birth','draft','pdf')", orphan, q.f.org, q.f.user.ID)
	q.endV1(1)
	q.beginV1(0)
	if _, err := q.tx[0].Exec(q.ctx, "INSERT INTO documents(id,org_id,sender_id,name,status,source_kind)VALUES($1,$2,$3,'snapshot birth','draft','pdf')", orphan, q.f.org, q.f.user.ID); err != nil {
		t.Fatal(err)
	}
	q.busySQLV1(1, "INSERT INTO events(org_id,document_id,kind,payload_json)VALUES($1,$2,'snapshot.birth-race','{}')", q.other, orphan)
	q.endV1(0)
	q.beginV1(1)
	if _, err := q.tx[1].Exec(q.ctx, "INSERT INTO events(org_id,document_id,kind,payload_json)VALUES($1,$2,'snapshot.identity','{}')", q.other, q.f.doc.ID); err != nil {
		t.Fatal(err)
	}
	q.busySQLV1(0, "UPDATE documents SET org_id=$2 WHERE id=$1", q.f.doc.ID, q.other)
	q.busySQLV1(0, "UPDATE documents SET id=$2 WHERE id=$1", q.f.doc.ID, uuid.New())
	q.busySQLV1(0, "DELETE FROM documents WHERE id=$1", q.f.doc.ID)
	q.endV1(1)
}

func TestHTMLSnapshotEventSourceCacheNOWAITInversionsE2E(t *testing.T) {
	q := newHTMLSnapshotLockMatrixV1(t)
	event := uuid.New()
	if _, err := q.c[2].Exec(q.ctx, "INSERT INTO events(id,org_id,document_id,kind,payload_json)VALUES($1,$2,$3,'snapshot.cache','{}')", event, q.f.org, q.f.doc.ID); err != nil {
		t.Fatal(err)
	}
	q.beginV1(1)
	if _, err := q.tx[1].Exec(q.ctx, "SELECT id FROM events WHERE id=$1 FOR UPDATE", event); err != nil {
		t.Fatal(err)
	}
	q.busyV1(0, func(ctx context.Context, tx pgx.Tx) error {
		_, err := generated.New(tx).MeasureHTMLSnapshotEventPayloadV1(ctx, generated.MeasureHTMLSnapshotEventPayloadV1Params{EventID: event, DocumentID: q.f.doc.ID, OrgID: q.f.org})
		return err
	})
	q.endV1(1)
	if _, err := generated.New(q.c[2]).MeasureHTMLSnapshotEventPayloadV1(q.ctx, generated.MeasureHTMLSnapshotEventPayloadV1Params{EventID: event, DocumentID: q.f.doc.ID, OrgID: q.f.org}); err != nil {
		t.Fatal("explicit bounded SQL fixture measurement", err)
	}
	q.beginV1(1)
	if _, err := q.tx[1].Exec(q.ctx, "SELECT event_id FROM html_snapshot_event_payload_sizes_v1 WHERE event_id=$1 FOR UPDATE", event); err != nil {
		t.Fatal(err)
	}
	q.headerV1()
	q.busyV1(0, func(ctx context.Context, tx pgx.Tx) error {
		_, err := generated.New(tx).LockHTMLRevisionSnapshotSizeCachesV1(ctx, generated.LockHTMLRevisionSnapshotSizeCachesV1Params{DocumentID: q.f.doc.ID, OrgID: q.f.org})
		return err
	})
	q.endV1(1)
}

func TestHTMLSnapshotCascadeAndOldHeaderCutoverE2E(t *testing.T) {
	q := newHTMLSnapshotLockMatrixV1(t)
	if _, err := q.c[2].Exec(q.ctx, "INSERT INTO events(org_id,document_id,kind,payload_json)VALUES($1,$2,'snapshot.cascade','{}')", q.other, q.f.doc.ID); err != nil {
		t.Fatal(err)
	}
	q.headerV1()
	q.busySQLV1(1, "DELETE FROM orgs WHERE id=$1", q.other)
	q.endV1(0)
	q.beginV1(1)
	if _, err := q.tx[1].Exec(q.ctx, "DELETE FROM orgs WHERE id=$1", q.other); err != nil {
		t.Fatal("uncontended same-Tx org-absence cascade", err)
	}
	var remains bool
	if err := q.tx[1].QueryRow(q.ctx, "SELECT EXISTS(SELECT 1 FROM events WHERE org_id=$1)", q.other).Scan(&remains); err != nil || remains {
		t.Fatal("actual org cascade left its events", err)
	}
	q.endV1(1) // retain removable seed only until outer cleanup
	q.beginV1(0)
	if _, err := q.tx[0].Exec(q.ctx, "SELECT id FROM documents WHERE id=$1 FOR UPDATE", q.f.doc.ID); err != nil {
		t.Fatal(err)
	}
	q.busySQLV1(1, "LOCK TABLE documents,events IN EXCLUSIVE MODE NOWAIT")
	q.endV1(0)
}
