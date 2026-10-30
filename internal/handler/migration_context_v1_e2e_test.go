//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

const migrationFixtureLock242 int64 = 792310457018

type migrationPGFixture242 struct {
	ctx    context.Context
	admin  *pgx.Conn
	db     *sql.DB
	config *pgx.ConnConfig
	name   string
}

func migrationPG242(t *testing.T) migrationPGFixture242 {
	t.Helper()
	isolateEmptyHTMLTemplateDatabaseE2E(t)
	ctx := migrationFixtureContext242(t)
	cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
	if err != nil {
		t.Fatal("invalid disposable migration fixture configuration")
	}
	cfg.RuntimeParams["application_name"] = "hash-migration242-" + uuid.NewString()
	cfg.RuntimeParams["statement_timeout"] = "5000"
	cfg.RuntimeParams["lock_timeout"] = "3000"
	cfg.RuntimeParams["idle_in_transaction_session_timeout"] = "15000"
	witness := cfg.Copy()
	witness.RuntimeParams["application_name"] = "hash-migration242-witness-" + uuid.NewString()
	admin, err := pgx.ConnectConfig(ctx, witness)
	if err != nil {
		t.Fatal("connect independent migration witness", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := admin.Close(cleanup); err != nil {
			t.Error("close migration witness", err)
		}
	})
	database := stdlib.OpenDB(*cfg)
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Error("close migration fixture pool", err)
		}
	})
	return migrationPGFixture242{ctx: ctx, admin: admin, db: database, config: cfg, name: cfg.RuntimeParams["application_name"]}
}
func migrationDDLBlock242(t *testing.T, f migrationPGFixture242) pgx.Tx {
	t.Helper()
	cfg := f.config.Copy()
	cfg.RuntimeParams["application_name"] = f.name + "-ddlholder"
	conn, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal("connect exact DDL blocker", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := conn.Close(cleanup); err != nil {
			t.Error("close exact DDL blocker", err)
		}
	})
	tx, err := conn.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	})
	if _, err := tx.Exec(f.ctx, "LOCK TABLE documents IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	return tx
} //nolint:rawsql -- deliberate exact disposable-schema migration lock barrier

func migrationWait242(t *testing.T, ctx context.Context, probe func(context.Context) (bool, error)) {
	t.Helper()
	wait, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		ok, err := probe(wait)
		if err != nil {
			t.Fatal("migration witness failed", err)
		}
		if ok {
			return
		}
		select {
		case <-wait.Done():
			t.Fatal("migration witness did not establish its condition", wait.Err())
		case <-ticker.C:
		}
	}
}
func migrationBlocked242(t *testing.T, f migrationPGFixture242, name, fragment string) int32 {
	t.Helper()
	var pid int32
	migrationWait242(t, f.ctx, func(call context.Context) (bool, error) {
		err := f.admin.QueryRow(call, "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND state='active' AND wait_event_type='Lock' AND position($2 in query)>0", name, fragment).Scan(&pid)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return err == nil, err
	}) //nolint:rawsql -- unique disposable DB and exact migration application witness
	return pid
}
func migrationOwnsLock242(t *testing.T, f migrationPGFixture242, pid int32, want bool) {
	t.Helper()
	var owns bool
	err := f.admin.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND granted AND ((classid::bigint<<32)|objid::bigint)=$2)", pid, migrationFixtureLock242).Scan(&owns)
	if err != nil || owns != want {
		t.Fatal("migration lock/session association differs", err, owns, want)
	}
} //nolint:rawsql -- original fixed lock identity and actual waiting backend
func migrationHead242(t *testing.T, f migrationPGFixture242, want int64, recipientExists bool) {
	t.Helper()
	version, err := mdb.GetMigrationVersionContext(f.ctx, f.db)
	if err != nil || version != want {
		t.Fatal("migration version changed unexpectedly", version, want, err)
	}
	var present bool
	if err := f.admin.QueryRow(f.ctx, "SELECT to_regclass('recipients') IS NOT NULL").Scan(&present); err != nil || present != recipientExists {
		t.Fatal("migration SQL was partial or unexpectedly applied", present, recipientExists, err)
	}
} //nolint:rawsql -- exact controlled schema rollback observation
func migrationStart242(ctx context.Context, database *sql.DB, version int64) (<-chan error, <-chan struct{}) {
	result := make(chan error, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); result <- mdb.RunMigrationsUpToContext(ctx, database, version) }()
	return result, joined
}
func migrationJoin242(t *testing.T, ctx context.Context, result <-chan error) error {
	t.Helper()
	wait, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	select {
	case err := <-result:
		return err
	case <-wait.Done():
		t.Fatal("actual migration did not join", wait.Err())
		return wait.Err()
	}
}
func migrationDeferredJoin242(t *testing.T, cancel context.CancelFunc, joined <-chan struct{}) {
	t.Helper()
	cancel()
	wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	select {
	case <-joined:
	case <-wait.Done():
		t.Error("actual migration cleanup did not join")
	}
}
func migrationPoolRetired242(t *testing.T, f migrationPGFixture242, database *sql.DB, name string) {
	t.Helper()
	if err := database.Close(); err != nil {
		t.Fatal("close migrated pool", err)
	}
	migrationWait242(t, f.ctx, func(call context.Context) (bool, error) {
		var count int
		err := f.admin.QueryRow(call, "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1", name).Scan(&count)
		return count == 0, err
	})
	t.Log("unique migration pool/backend retirement witnessed")
} //nolint:rawsql -- only the exact synthetic application name in this owned DB

func TestMigrationContextActualPostgresLockAndSQLCancellationV1E2E(t *testing.T) {
	t.Run("version getter is read only and preserves legacy false shadows", func(t *testing.T) {
		f := migrationPG242(t)
		_, err := mdb.GetMigrationVersionContext(f.ctx, f.db)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
			t.Fatal("fresh version observation did not refuse absent metadata", err)
		}
		var absent bool
		if err := f.admin.QueryRow(f.ctx, "SELECT to_regclass('goose_db_version') IS NULL AND to_regclass('documents') IS NULL").Scan(&absent); err != nil || !absent {
			t.Fatal("version getter created schema", absent, err)
		}
		if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 3); err != nil {
			t.Fatal("genuine migration before legacy-history observation", err)
		}
		if _, err := f.admin.Exec(f.ctx, "INSERT INTO goose_db_version (version_id,is_applied) VALUES (3,false)"); err != nil {
			t.Fatal("insert genuine legacy false version shadow", err)
		}
		history := func() string {
			t.Helper()
			var result string
			if err := f.admin.QueryRow(f.ctx, "SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version AS v").Scan(&result); err != nil {
				t.Fatal("observe exact version history", err)
			}
			return result
		}
		before := history()
		migrationHead242(t, f, 2, true)
		if after := history(); after != before {
			t.Fatal("version observation mutated legacy history")
		}
		migrationPoolRetired242(t, f, f.db, f.name)
	})
	for _, kind := range []string{"false row", "duplicate version", "negative version"} {
		t.Run("unsupported "+kind+" history refuses Up and Down without mutation", func(t *testing.T) {
			f := migrationPG242(t)
			if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 3); err != nil {
				t.Fatal("genuine migration before unsupported-history fixture", err)
			}
			statement := "UPDATE goose_db_version SET is_applied=false WHERE version_id=3"
			switch kind {
			case "duplicate version":
				statement = "INSERT INTO goose_db_version (version_id,is_applied) VALUES (2,true)"
			case "negative version":
				statement = "INSERT INTO goose_db_version (version_id,is_applied) VALUES (-1,true)"
			}
			if _, err := f.admin.Exec(f.ctx, statement); err != nil {
				t.Fatal("seed real unsupported history row", err)
			}
			snapshot := func() string {
				t.Helper()
				var state string
				if err := f.admin.QueryRow(f.ctx, `SELECT jsonb_build_array(
     (SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM goose_db_version AS v),
     to_regclass('documents')::text,to_regclass('recipients')::text,
     to_regclass('document_fields')::text)::text`).Scan(&state); err != nil {
					t.Fatal("snapshot actual metadata and transition schema", err)
				}
				return state
			}
			before := snapshot()
			for _, down := range []bool{false, true} {
				if down {
					if err := mdb.RunMigrationsDownToContext(f.ctx, f.db, 2); !errors.Is(err, mdb.ErrMigrationHistoryUnsupportedV1) {
						t.Fatal("unsupported history reached Down", err)
					}
				} else if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 4); !errors.Is(err, mdb.ErrMigrationHistoryUnsupportedV1) {
					t.Fatal("unsupported history reached Up", err)
				}
				if f.db.Stats().Idle != 0 {
					t.Fatal("refused writer returned its locked session to pool")
				}
				migrationWait242(t, f.ctx, func(call context.Context) (bool, error) {
					var absent bool
					err := f.admin.QueryRow(call, "SELECT NOT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1)", f.name).Scan(&absent)
					return absent, err
				})
				var acquired bool
				if err := f.admin.QueryRow(f.ctx, "SELECT pg_try_advisory_lock($1)", migrationFixtureLock242).Scan(&acquired); err != nil || !acquired {
					t.Fatal("refused backend retained the actual migration lock", err, acquired)
				}
				var released bool
				if err := f.admin.QueryRow(f.ctx, "SELECT pg_advisory_unlock($1)", migrationFixtureLock242).Scan(&released); err != nil || !released {
					t.Fatal("release independent lock-absence witness", err, released)
				}
				if after := snapshot(); after != before {
					t.Fatal("refused writer changed exact metadata or transition schema")
				}
			}
			migrationPoolRetired242(t, f, f.db, f.name)
		})
	}
	t.Run("cancel advisory wait does not migrate or retain its session", func(t *testing.T) {
		f := migrationPG242(t)
		if _, err := f.admin.Exec(f.ctx, "SELECT pg_advisory_lock($1)", migrationFixtureLock242); err != nil {
			t.Fatal(err)
		}
		held := true
		defer func() {
			if held {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				var unlocked bool
				if err := f.admin.QueryRow(cleanup, "SELECT pg_advisory_unlock($1)", migrationFixtureLock242).Scan(&unlocked); err != nil || !unlocked {
					t.Error("holder lock cleanup", err, unlocked)
				}
			}
		}()
		call, cancel := context.WithCancel(f.ctx)
		result, joined := migrationStart242(call, f.db, 2)
		defer migrationDeferredJoin242(t, cancel, joined)
		pid := migrationBlocked242(t, f, f.name, "pg_advisory_lock")
		migrationOwnsLock242(t, f, pid, false)
		cancel()
		if err := migrationJoin242(t, f.ctx, result); !errors.Is(err, context.Canceled) {
			t.Fatal("advisory wait lost caller cancellation", err)
		}
		var untouched bool
		if err := f.admin.QueryRow(f.ctx, "SELECT to_regclass('goose_db_version') IS NULL AND to_regclass('documents') IS NULL").Scan(&untouched); err != nil || !untouched {
			t.Fatal("cancelled lock wait reached schema mutation", untouched, err)
		}
		migrationWait242(t, f.ctx, func(call context.Context) (bool, error) {
			var exists bool
			err := f.admin.QueryRow(call, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid=$1 AND application_name=$2)", pid, f.name).Scan(&exists)
			return !exists, err
		})
		var unlocked bool
		if err := f.admin.QueryRow(f.ctx, "SELECT pg_advisory_unlock($1)", migrationFixtureLock242).Scan(&unlocked); err != nil || !unlocked {
			t.Fatal("release actual holder", err, unlocked)
		}
		held = false
		if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 2); err != nil {
			t.Fatal("fresh retry after cancelled lock", err)
		}
		migrationHead242(t, f, 2, false)
		migrationPoolRetired242(t, f, f.db, f.name)
	})
	t.Run("cancel blocked migration rolls back and unlocks original backend", func(t *testing.T) {
		f := migrationPG242(t)
		if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 2); err != nil {
			t.Fatal(err)
		}
		blocker := migrationDDLBlock242(t, f)
		call, cancel := context.WithCancel(f.ctx)
		result, joined := migrationStart242(call, f.db, 3)
		defer migrationDeferredJoin242(t, cancel, joined)
		pid := migrationBlocked242(t, f, f.name, "CREATE TABLE recipients")
		migrationOwnsLock242(t, f, pid, true)
		cancel()
		if err := migrationJoin242(t, f.ctx, result); !errors.Is(err, context.Canceled) {
			t.Fatal("migration SQL lost caller cancellation", err)
		}
		// pgx may finish closing a cancelled connection asynchronously. Error
		// return and pool eviction are not remote-retirement acknowledgements.
		// Observe the original backend/key read-only before retrying; never
		// terminate that backend or release its lock through this witness.
		retirementStarted := time.Now()
		migrationWait242(t, f.ctx, func(call context.Context) (bool, error) {
			var retired bool
			err := f.admin.QueryRow(call, `SELECT
 NOT EXISTS (SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND granted
  AND ((classid::bigint<<32)|objid::bigint)=$2)
 AND NOT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1
  AND (state IS DISTINCT FROM 'idle' OR backend_xid IS NOT NULL))`, pid, migrationFixtureLock242).Scan(&retired)
			return retired, err
		})
		t.Logf("original cancelled backend lock/transaction retirement observed after %s", time.Since(retirementStarted))
		migrationOwnsLock242(t, f, pid, false)
		migrationHead242(t, f, 2, false)
		if err := blocker.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
		if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 3); err != nil {
			t.Fatal("fresh migration retry after original rollback", err)
		}
		migrationHead242(t, f, 3, true)
		migrationPoolRetired242(t, f, f.db, f.name)
	})
	t.Run("concurrent migrators serialize on the same SQL owning session", func(t *testing.T) {
		f := migrationPG242(t)
		if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 2); err != nil {
			t.Fatal(err)
		}
		blocker := migrationDDLBlock242(t, f)
		cfg := f.config.Copy()
		cfg.RuntimeParams["application_name"] = "hash-migration242-second-" + uuid.NewString()
		second := stdlib.OpenDB(*cfg)
		second.SetMaxOpenConns(1)
		second.SetMaxIdleConns(1)
		t.Cleanup(func() { _ = second.Close() })
		call, cancel := context.WithCancel(f.ctx)
		defer cancel()
		firstResult, firstJoined := migrationStart242(call, f.db, 3)
		defer migrationDeferredJoin242(t, cancel, firstJoined)
		firstPID := migrationBlocked242(t, f, f.name, "CREATE TABLE recipients")
		migrationOwnsLock242(t, f, firstPID, true)
		secondResult, secondJoined := migrationStart242(call, second, 3)
		defer migrationDeferredJoin242(t, cancel, secondJoined)
		secondPID := migrationBlocked242(t, f, cfg.RuntimeParams["application_name"], "pg_advisory_lock")
		if firstPID == secondPID {
			t.Fatal("independent pools shared a backend identity")
		}
		migrationOwnsLock242(t, f, secondPID, false)
		if err := blocker.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
		if err := migrationJoin242(t, f.ctx, firstResult); err != nil {
			t.Fatal("first actual migrator failed", err)
		}
		if err := migrationJoin242(t, f.ctx, secondResult); err != nil {
			t.Fatal("serialized actual migrator failed", err)
		}
		migrationHead242(t, f, 3, true)
		var count int
		if err := f.admin.QueryRow(f.ctx, "SELECT count(*) FROM goose_db_version WHERE version_id=3 AND is_applied").Scan(&count); err != nil || count != 1 {
			t.Fatal("concurrent migration history duplicated", count, err)
		}
		migrationPoolRetired242(t, f, second, cfg.RuntimeParams["application_name"])
		migrationPoolRetired242(t, f, f.db, f.name)
	})
}

// This file intentionally uses no contract source, tokens, storage or send
// fixtures. It qualifies actual migration lock/cancel/rollback retirement only.
