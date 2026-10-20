//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These tests use the real isolated PostgreSQL242 owner and embedded migration
// runner. Explicit synthetic mail rows are not SMTP delivery, a running worker,
// configured Flare alerting, or production migration-lock acceptance.
const failedMailCreationEpoch114 int64 = 1577836800000000

type failedMailState114 struct {
	Rows       json.RawMessage `json:"rows"`
	OldIndexes json.RawMessage `json:"old_indexes"`
	TableShape json.RawMessage `json:"table_shape"`
	Index      json.RawMessage `json:"index"`
	History    json.RawMessage `json:"history"`
}

func failedMailSnapshot114(t *testing.T, f migrationPGFixture242) failedMailState114 {
	t.Helper()
	snapshotCtx, stop := context.WithTimeout(f.ctx, 250*time.Millisecond)
	defer stop()
	tx, err := f.admin.BeginTx(snapshotCtx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("begin bounded same-state mail witness", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("read-only mail witness rollback", err)
		}
	}()
	var state failedMailState114
	// Preserve all five original JSONB expressions. A SQL NULL becomes the
	// same JSON null that the previous jsonb_build_object produced. One read-
	// only repeatable snapshot covers every complete, separately bounded part.
	for _, item := range []struct {
		phase      string
		expression string
		target     *json.RawMessage
	}{
		{"rows", `COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM public.email_deliveries e),'[]'::jsonb)`, &state.Rows},
		{"old_indexes", `COALESCE((SELECT jsonb_agg(jsonb_build_array(c.relname,pg_get_indexdef(i.indexrelid)) ORDER BY c.relname) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.email_deliveries'::regclass AND c.relname<>'email_deliveries_failed_observation_v1'),'[]'::jsonb)`, &state.OldIndexes},
		{"table_shape", `(SELECT jsonb_agg(jsonb_build_array(a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.email_deliveries'::regclass AND a.attnum>0 AND NOT a.attisdropped)`, &state.TableShape},
		{"index", `(SELECT jsonb_build_object('schema',n.nspname,'table_schema',pn.nspname,'table',p.relname,'method',am.amname,'unique',i.indisunique,'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,'key_count',i.indnkeyatts,'column_count',i.indnatts,'names',(SELECT jsonb_agg(a.attname ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'predicate',pg_get_expr(i.indpred,i.indrelid),'definition',pg_get_indexdef(i.indexrelid)) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_index i ON i.indexrelid=c.oid JOIN pg_class p ON p.oid=i.indrelid JOIN pg_namespace pn ON pn.oid=p.relnamespace JOIN pg_am am ON am.oid=c.relam WHERE n.nspname='public' AND c.relname='email_deliveries_failed_observation_v1')`, &state.Index},
		{"history", `(SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM public.goose_db_version v)`, &state.History},
	} {
		call, cancel := context.WithTimeout(snapshotCtx, 250*time.Millisecond)
		started := time.Now()
		var raw string
		err := tx.QueryRow(call, "SELECT COALESCE("+item.expression+",'null'::jsonb)::text").Scan(&raw)
		cancel()
		t.Logf("M114 witness phase=%s elapsed_ms=%d bytes=%d", item.phase, time.Since(started).Milliseconds(), len(raw))
		if err != nil {
			t.Fatal("bounded real mail witness component", item.phase, err)
		}
		if !json.Valid([]byte(raw)) {
			t.Fatal("decode exact real mail witness component", item.phase)
		}
		*item.target = json.RawMessage([]byte(raw))
	}
	return state
} //nolint:rawsql -- complete same-state read-only witness in this uniquely owned database

func failedMailRowsUnchanged114(t *testing.T, before, after failedMailState114) {
	t.Helper()
	if !reflect.DeepEqual(before.Rows, after.Rows) || !reflect.DeepEqual(before.OldIndexes, after.OldIndexes) || !reflect.DeepEqual(before.TableShape, after.TableShape) {
		t.Fatal("M114 changed full mail rows, original queue indexes, or table shape")
	}
}

func failedMailIndexState114(t *testing.T, state failedMailState114, present bool) {
	t.Helper()
	if !present {
		if string(state.Index) != "null" {
			t.Fatal("M114 index survived Down or preceded Up")
		}
		return
	}
	var index struct {
		Schema      string   `json:"schema"`
		TableSchema string   `json:"table_schema"`
		Table       string   `json:"table"`
		Method      string   `json:"method"`
		Unique      bool     `json:"unique"`
		Valid       bool     `json:"valid"`
		Ready       bool     `json:"ready"`
		Live        bool     `json:"live"`
		KeyCount    int      `json:"key_count"`
		ColumnCount int      `json:"column_count"`
		Names       []string `json:"names"`
		Predicate   string   `json:"predicate"`
		Definition  string   `json:"definition"`
	}
	if string(state.Index) == "null" || json.Unmarshal(state.Index, &index) != nil || index.Schema != "public" || index.TableSchema != "public" || index.Table != "email_deliveries" || index.Method != "btree" || index.Unique || !index.Valid || !index.Ready || !index.Live || index.KeyCount != 1 || index.ColumnCount != 2 || !reflect.DeepEqual(index.Names, []string{"id", "created_at"}) || index.Predicate != "(status = 'failed'::text)" || index.Definition != "CREATE INDEX email_deliveries_failed_observation_v1 ON public.email_deliveries USING btree (id) INCLUDE (created_at) WHERE (status = 'failed'::text)" {
		t.Fatal("M114 actual public nonunique key/include/predicate definition differs")
	}
}

func failedMailHead114(t *testing.T, f migrationPGFixture242, want int64) {
	t.Helper()
	migrationHead242(t, f, want, true)
	call, stop := context.WithTimeout(f.ctx, 250*time.Millisecond)
	defer stop()
	var rows, applied int
	if err := f.admin.QueryRow(call, "SELECT count(*)::integer,count(*) FILTER(WHERE is_applied)::integer FROM public.goose_db_version WHERE version_id=114").Scan(&rows, &applied); err != nil || rows != map[bool]int{true: 1, false: 0}[want == 114] || applied != rows {
		t.Fatal("M114 committed history differs", rows, applied, err)
	}
} //nolint:rawsql -- exact applied114 row, no history repair

func failedMailSeed114(t *testing.T, f migrationPGFixture242) {
	t.Helper()
	_, err := f.admin.Exec(f.ctx, `WITH seed(n,status,created_at,next_attempt_at,sent_at) AS (VALUES
 (1,'failed',TIMESTAMPTZ '2020-01-01 00:00:00+00',TIMESTAMPTZ '2020-01-01 00:00:00+00',NULL::timestamptz),
 (2,'failed',TIMESTAMPTZ 'infinity',TIMESTAMPTZ '2020-01-01 00:00:00+00',NULL::timestamptz),
 (3,'failed',statement_timestamp()+interval '1 day',TIMESTAMPTZ '2020-01-01 00:00:00+00',NULL::timestamptz),
 (4,'pending',TIMESTAMPTZ '2020-01-01 00:00:00+00',TIMESTAMPTZ '2020-01-01 00:00:00+00',NULL::timestamptz),
 (5,'retrying',TIMESTAMPTZ '2020-01-01 00:00:00+00',TIMESTAMPTZ 'infinity',NULL::timestamptz),
 (6,'sent',TIMESTAMPTZ '2020-01-01 00:00:00+00',TIMESTAMPTZ '2020-01-01 00:00:00+00',TIMESTAMPTZ '2020-01-01 00:00:00+00'))
 INSERT INTO public.email_deliveries(id,to_email,subject,html_body,text_body,status,created_at,next_attempt_at,sent_at)
 SELECT ('11400000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'fixed@example.invalid','fixed synthetic M114','<p>fixed M114</p>','fixed M114',status,created_at,next_attempt_at,sent_at FROM seed`)
	if err != nil {
		t.Fatal("seed legal real mail status/clock rows", err)
	}
} //nolint:rawsql -- six fixed synthetic rows, all required actual columns

func TestFailedMailIndex114FreshOccupiedReplayDownAndCollisionE2E(t *testing.T) {
	t.Run("fresh current114 and repeated Up", func(t *testing.T) {
		f := migrationPG242(t)
		if err := mdb.RunMigrationsContext(f.ctx, f.db); err != nil {
			t.Fatal("fresh embedded114", err)
		}
		failedMailHead114(t, f, 114)
		before := failedMailSnapshot114(t, f)
		failedMailIndexState114(t, before, true)
		if err := mdb.RunMigrationsContext(f.ctx, f.db); err != nil {
			t.Fatal("current114 replay", err)
		}
		if after := failedMailSnapshot114(t, f); !reflect.DeepEqual(before, after) {
			t.Fatal("repeated Up changed exact state/history")
		}
		migrationPoolRetired242(t, f, f.db, f.name)
	})
	t.Run("occupied113 upgrade Down replay and collision", func(t *testing.T) {
		f := migrationPG242(t)
		if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 113); err != nil {
			t.Fatal("actual113 predecessor", err)
		}
		failedMailSeed114(t, f)
		before := failedMailSnapshot114(t, f)
		failedMailIndexState114(t, before, false)
		if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 114); err != nil {
			t.Fatal("occupied113 to114", err)
		}
		failedMailHead114(t, f, 114)
		up := failedMailSnapshot114(t, f)
		failedMailRowsUnchanged114(t, before, up)
		failedMailIndexState114(t, up, true)
		if err := mdb.RunMigrationsContext(f.ctx, f.db); err != nil {
			t.Fatal("occupied replay", err)
		}
		if after := failedMailSnapshot114(t, f); !reflect.DeepEqual(up, after) {
			t.Fatal("occupied repeated Up changed history/data/catalog")
		}
		if err := mdb.RunMigrationsDownToContext(f.ctx, f.db, 113); err != nil {
			t.Fatal("occupied114 Down113", err)
		}
		failedMailHead114(t, f, 113)
		down := failedMailSnapshot114(t, f)
		failedMailRowsUnchanged114(t, before, down)
		failedMailIndexState114(t, down, false)
		if _, err := f.admin.Exec(f.ctx, "CREATE INDEX email_deliveries_failed_observation_v1 ON public.email_deliveries(next_attempt_at)"); err != nil {
			t.Fatal("seed explicitly owned conflicting index", err)
		}
		collision := failedMailSnapshot114(t, f)
		err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 114)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42P07" {
			t.Fatal("collision was accepted or lost duplicate-object identity", err)
		}
		failedMailHead114(t, f, 113)
		if after := failedMailSnapshot114(t, f); !reflect.DeepEqual(collision, after) {
			t.Fatal("refused collision changed existing index/history/data")
		}
		if _, err := f.admin.Exec(f.ctx, "DROP INDEX public.email_deliveries_failed_observation_v1"); err != nil {
			t.Fatal("remove only owned synthetic collision", err)
		}
		if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 114); err != nil {
			t.Fatal("lawful Up after collision removal", err)
		}
		failedMailHead114(t, f, 114)
		replayed := failedMailSnapshot114(t, f)
		failedMailRowsUnchanged114(t, before, replayed)
		failedMailIndexState114(t, replayed, true)
		if !reflect.DeepEqual(up.Index, replayed.Index) {
			t.Fatal("replay changed approved index definition")
		}
		migrationPoolRetired242(t, f, f.db, f.name)
	})
}

// The generated query is executed in a real READ ONLY transaction. Read-only
// server-clock probes bracket its statement, so changing creation-age seconds
// are checked honestly before normalization across before/after statements.
func failedMailRead114(t *testing.T, f migrationPGFixture242, failedAge, activeAge, dueAge bool) generated.GetOperationalBacklogV1Row {
	t.Helper()
	begin, stop := context.WithTimeout(f.ctx, 250*time.Millisecond)
	tx, err := f.admin.BeginTx(begin, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	stop()
	if err != nil {
		t.Fatal("begin real read-only observation", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("read-only observation rollback", err)
		}
	}()
	setup, cancel := context.WithTimeout(f.ctx, 250*time.Millisecond)
	_, err = tx.Exec(setup, "SET LOCAL statement_timeout='1s'")
	cancel()
	if err != nil {
		t.Fatal("set original1s query budget", err)
	}
	clock := func() int64 {
		call, cancel := context.WithTimeout(f.ctx, 250*time.Millisecond)
		defer cancel()
		var epoch int64
		if err := tx.QueryRow(call, "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint").Scan(&epoch); err != nil {
			t.Fatal("bounded server-clock witness", err)
		}
		return epoch
	}
	before := clock()
	call, cancel := context.WithTimeout(f.ctx, time.Second)
	row, err := generated.New(tx).GetOperationalBacklogV1(call)
	cancel()
	if err != nil || row == nil {
		t.Fatal("actual generated17-scalar read-only query", err)
	}
	after := clock()
	if after < before {
		t.Fatal("server clock moved backwards during observation")
	}
	minAge := (before - failedMailCreationEpoch114) / 1000000
	maxAge := (after - failedMailCreationEpoch114) / 1000000
	for _, a := range []struct {
		value    int64
		positive bool
	}{{row.MailFailedOldestObservedCreationAgeSeconds, failedAge}, {row.MailOldestObservedAgeSeconds, activeAge}, {row.MailOldestObservedOverdueSeconds, dueAge}} {
		if a.positive {
			if a.value < minAge || a.value > maxAge {
				t.Fatal("finite creation/due age escaped actual statement clock window")
			}
		} else if a.value != 0 {
			t.Fatal("unknown/absent clock fabricated a positive age")
		}
	}
	row.MailFailedOldestObservedCreationAgeSeconds = 0
	row.MailOldestObservedAgeSeconds = 0
	row.MailOldestObservedOverdueSeconds = 0
	return *row
}

func TestFailedMailIndex114ActualGeneratedMetadataReadOnlyE2E(t *testing.T) {
	f := migrationPG242(t)
	if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 113); err != nil {
		t.Fatal("real113 query predecessor", err)
	}
	if row := failedMailRead114(t, f, false, false, false); row != (generated.GetOperationalBacklogV1Row{}) {
		t.Fatal("real known-empty17scalars differ", row)
	}
	failedMailSeed114(t, f)
	before := failedMailSnapshot114(t, f)
	sparse := failedMailRead114(t, f, true, true, true)
	expected := generated.GetOperationalBacklogV1Row{MailCount: 2, MailDueCount: 1, MailUnknownDueCount: 1, MailFailedCount: 3, MailFailedUnknownCreatedCount: 2}
	if sparse != expected {
		t.Fatal("real status/backoff/unknown-clock semantics differ", sparse)
	}
	if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 114); err != nil {
		t.Fatal("index before generated-query comparison", err)
	}
	if row := failedMailRead114(t, f, true, true, true); row != sparse {
		t.Fatal("index changed actual17-scalar semantics")
	}
	if after := failedMailSnapshot114(t, f); !reflect.DeepEqual(before.Rows, after.Rows) {
		t.Fatal("observation or index changed mail rows")
	}
	if _, err := f.admin.Exec(f.ctx, "UPDATE public.email_deliveries SET status='retrying',next_attempt_at=statement_timestamp()+interval '5 minutes' WHERE status='failed'"); err != nil {
		t.Fatal("explicit owned durable requeue", err)
	}
	requeued := failedMailRead114(t, f, false, true, true)
	if requeued != (generated.GetOperationalBacklogV1Row{MailCount: 5, MailDueCount: 1, MailUnknownCreatedCount: 2, MailUnknownDueCount: 1}) {
		t.Fatal("durable requeue did not clear only terminal rows", requeued)
	}
	if _, err := f.admin.Exec(f.ctx, "UPDATE public.email_deliveries SET status='sent',sent_at=statement_timestamp() WHERE id IN ('11400000-0000-4000-8000-000000000001'::uuid,'11400000-0000-4000-8000-000000000002'::uuid,'11400000-0000-4000-8000-000000000003'::uuid)"); err != nil {
		t.Fatal("explicit synthetic sent transition", err)
	}
	if _, err := f.admin.Exec(f.ctx, `INSERT INTO public.email_deliveries(id,to_email,subject,html_body,text_body,status,created_at,next_attempt_at)
 SELECT ('11400000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'fixed@example.invalid','fixed cap','<p>fixed</p>','fixed','failed',TIMESTAMPTZ '2020-01-01 00:00:00+00',TIMESTAMPTZ '2020-01-01 00:00:00+00' FROM generate_series(1000,2000) n`); err != nil {
		t.Fatal("real bounded cap rows", err)
	}
	cappedBefore := failedMailSnapshot114(t, f)
	capped := failedMailRead114(t, f, true, true, true)
	if capped != (generated.GetOperationalBacklogV1Row{MailCount: 2, MailDueCount: 1, MailUnknownDueCount: 1, MailFailedCount: 1000, MailFailedLimitReached: true}) {
		t.Fatal("real observed cap is not exact lower-bound sample", capped)
	}
	if err := mdb.RunMigrationsDownToContext(f.ctx, f.db, 113); err != nil {
		t.Fatal("query-compatible Down", err)
	}
	if row := failedMailRead114(t, f, true, true, true); row != capped {
		t.Fatal("removing index changed bounded reader semantics")
	}
	down := failedMailSnapshot114(t, f)
	failedMailRowsUnchanged114(t, cappedBefore, down)
	failedMailIndexState114(t, down, false)
	if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 114); err != nil {
		t.Fatal("read-compatible replay", err)
	}
	if row := failedMailRead114(t, f, true, true, true); row != capped {
		t.Fatal("replayed index changed read-only semantics")
	}
	after := failedMailSnapshot114(t, f)
	failedMailRowsUnchanged114(t, cappedBefore, after)
	failedMailIndexState114(t, after, true)
	failedMailHead114(t, f, 114)
	migrationPoolRetired242(t, f, f.db, f.name)
} //nolint:rawsql -- explicit owned synthetic status transitions, not worker/SMTP success

func failedMailMigrationStart114(ctx context.Context, database *sql.DB, down bool) (<-chan error, <-chan struct{}) {
	result := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		if down {
			result <- mdb.RunMigrationsDownToContext(ctx, database, 113)
		} else {
			result <- mdb.RunMigrationsUpToContext(ctx, database, 114)
		}
	}()
	return result, joined
}

func TestFailedMailIndex114ActualObservedLockCancellationE2E(t *testing.T) {
	for _, down := range []bool{false, true} {
		name := "Up writer lock"
		if down {
			name = "Down reader lock"
		}
		t.Run(name, func(t *testing.T) {
			f := migrationPG242(t)
			start := int64(113)
			if down {
				start = 114
			}
			if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, start); err != nil {
				t.Fatal("actual lock predecessor", err)
			}
			failedMailSeed114(t, f)
			before := failedMailSnapshot114(t, f)
			failedMailIndexState114(t, before, down)
			lockSQL := "LOCK TABLE public.email_deliveries IN ROW EXCLUSIVE MODE"
			fragment := "CREATE INDEX email_deliveries_failed_observation_v1"
			if down {
				lockSQL = "LOCK TABLE public.email_deliveries IN ACCESS SHARE MODE"
				fragment = "DROP INDEX public.email_deliveries_failed_observation_v1"
			}
			holder := manualProposalMigrationHolder268(t, f, lockSQL)
			holderPID := int32(holder.Conn().PgConn().PID())
			call, cancel := context.WithCancel(f.ctx)
			result, joined := failedMailMigrationStart114(call, f.db, down)
			defer migrationDeferredJoin242(t, cancel, joined)
			pid := migrationBlocked242(t, f, f.name, fragment)
			migrationOwnsLock242(t, f, pid, true)
			probe, stop := context.WithTimeout(f.ctx, 250*time.Millisecond)
			var exactBlocker bool
			err := f.admin.QueryRow(probe, "SELECT $2::integer=ANY(pg_blocking_pids($1))", pid, holderPID).Scan(&exactBlocker)
			stop()
			if err != nil || !exactBlocker {
				t.Fatal("actual relation wait is not owned holder", err)
			}
			cancel()
			if err := migrationJoin242(t, f.ctx, result); !errors.Is(err, context.Canceled) {
				t.Fatal("actual blocked migration lost caller cancellation", err)
			}
			migrationDeferredJoin242(t, cancel, joined)
			migrationWait242(t, f.ctx, func(probe context.Context) (bool, error) {
				var retired bool
				err := f.admin.QueryRow(probe, `SELECT NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND granted AND ((classid::bigint<<32)|objid::bigint)=$2)
 AND NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND (state IS DISTINCT FROM 'idle' OR backend_xid IS NOT NULL))`, pid, migrationFixtureLock242).Scan(&retired)
				return retired, err
			})
			migrationOwnsLock242(t, f, pid, false)
			if after := failedMailSnapshot114(t, f); !reflect.DeepEqual(before, after) {
				t.Fatal("canceled actualDDL changed index/history/data/catalog")
			}
			var one int
			if err := f.db.QueryRowContext(f.ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
				t.Fatal("migration API closed caller pool", err)
			}
			failedMailHead114(t, f, start)
			manualProposalMigrationRelease268(t, holder)
			if down {
				if err := mdb.RunMigrationsDownToContext(f.ctx, f.db, 113); err != nil {
					t.Fatal("lawful Down after actual canceled wait", err)
				}
				failedMailHead114(t, f, 113)
				failedMailIndexState114(t, failedMailSnapshot114(t, f), false)
			}
			if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 114); err != nil {
				t.Fatal("lawful Up/replay after holder release", err)
			}
			failedMailHead114(t, f, 114)
			after := failedMailSnapshot114(t, f)
			failedMailRowsUnchanged114(t, before, after)
			failedMailIndexState114(t, after, true)
			migrationPoolRetired242(t, f, f.db, f.name)
		})
	}
} //nolint:rawsql -- actual observed owned relation/advisory-lock and retirement witnesses
