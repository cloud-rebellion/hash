//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These are schema-only controls in the existing owned migration harness.
// Direct source/cache rows below are deliberately synthetic; they establish no
// native body admission, signing evidence, historical backfill or legacy API.
func TestManualProposalWireMigrationUpDownAndRefusalsV1E2E(t *testing.T) {
	t.Run("empty Up and empty Down", func(t *testing.T) {
		f := migrationPG242(t)
		manualProposalMigrationVersion268(t, f, 111, false)
		manualProposalMigrationApply268(t, f)
		var proposals, measurements int
		if err := f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM document_proposals),(SELECT count(*) FROM manual_proposal_wire_sizes_v1)`).Scan(&proposals, &measurements); err != nil || proposals != 0 || measurements != 0 {
			t.Fatal("empty Up invented source or measurements", proposals, measurements, err)
		}
		if err := mdb.RunMigrationsDownToContext(f.ctx, f.db, 111); err != nil {
			t.Fatal("empty actual M112 Down failed", err)
		}
		manualProposalMigrationSchema268(t, f, false)
		manualProposalMigrationHead268(t, f, 111)
		manualProposalMigrationUnlocked268(t, f)
		migrationPoolRetired242(t, f, f.db, f.name)
	})
	t.Run("source cache locks and retained Down preserve data", func(t *testing.T) {
		f := migrationPG242(t)
		manualProposalMigrationVersion268(t, f, 111, false)
		proposal, sibling, document, org := manualProposalMigrationSeed268(t, f)
		beforeUp := manualProposalMigrationState268(t, f)
		holder := manualProposalMigrationHolder268(t, f, "LOCK TABLE public.document_proposals IN SHARE MODE")
		manualProposalMigrationSQLState268(t, mdb.RunMigrationsUpToContext(f.ctx, f.db, 112), "55P03")
		if after := manualProposalMigrationState268(t, f); after != beforeUp {
			t.Fatal("locked Up changed original rows, history or schema")
		}
		manualProposalMigrationUnlocked268(t, f)
		manualProposalMigrationRelease268(t, holder)
		manualProposalMigrationApply268(t, f)
		afterUp := manualProposalMigrationState268(t, f)
		if beforeUp.source != afterUp.source || afterUp.cache != "[]" {
			t.Fatal("M112 Up changed old proposals or fabricated a measurement")
		}

		for _, tc := range []struct {
			name                    string
			proposal, document, org any
		}{
			{"null proposal", nil, document, org},
			{"null document", proposal, nil, org},
			{"null organisation", proposal, document, nil},
			{"missing source", uuid.New(), document, org},
			{"wrong document", proposal, uuid.New(), org},
			{"wrong organisation", proposal, document, uuid.New()},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before := manualProposalMigrationState268(t, f)
				_, err := f.admin.Exec(f.ctx, manualProposalMigrationInsert268, tc.proposal, tc.document, tc.org)
				manualProposalMigrationSQLState268(t, err, "23514")
				if after := manualProposalMigrationState268(t, f); after != before {
					t.Fatal("invalid measurement scope changed source, cache or schema")
				}
			})
		}
		manualProposalMigrationMeasure268(t, f, proposal, document, org)
		for _, tc := range []struct {
			name, statement string
			args            []any
			code            string
		}{
			{"identity rewrite", "UPDATE manual_proposal_wire_sizes_v1 SET proposal_id=$2 WHERE proposal_id=$1", []any{proposal, sibling}, "23514"},
			{"document rewrite", "UPDATE manual_proposal_wire_sizes_v1 SET document_id=$2 WHERE proposal_id=$1", []any{proposal, uuid.New()}, "23514"},
			{"organisation rewrite", "UPDATE manual_proposal_wire_sizes_v1 SET org_id=$2 WHERE proposal_id=$1", []any{proposal, uuid.New()}, "23514"},
			{"duplicate cache", manualProposalMigrationInsert268, []any{proposal, document, org}, "23505"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before := manualProposalMigrationState268(t, f)
				_, err := f.admin.Exec(f.ctx, tc.statement, tc.args...)
				manualProposalMigrationSQLState268(t, err, tc.code)
				if after := manualProposalMigrationState268(t, f); after != before {
					t.Fatal("invalid cache mutation changed retained source, proof or schema")
				}
			})
		}
		// Caller values are never authority on UPDATE either: the actual source
		// replaces forged negative lengths/version and nonfinite timestamps.
		if _, err := f.admin.Exec(f.ctx, `UPDATE manual_proposal_wire_sizes_v1 SET diff_wire_bytes=-777,measurement_server_version_num=-1,proposal_created_at='infinity',proposal_updated_at='infinity',measured_at='infinity' WHERE proposal_id=$1`, proposal); err != nil {
			t.Fatal("cache UPDATE failed to derive real source values", err)
		}
		manualProposalMigrationExact268(t, f, proposal)
		before := manualProposalMigrationState268(t, f)
		holder = manualProposalMigrationHolder268(t, f, "SELECT id FROM document_proposals WHERE id=$1 FOR UPDATE", proposal)
		_, err := f.admin.Exec(f.ctx, `UPDATE manual_proposal_wire_sizes_v1 SET diff_wire_bytes=-1 WHERE proposal_id=$1`, proposal)
		manualProposalMigrationSQLState268(t, err, "55P03")
		if after := manualProposalMigrationState268(t, f); after != before {
			t.Fatal("cache to source NOWAIT refusal changed retained data or schema")
		}
		manualProposalMigrationRelease268(t, holder)
		for _, column := range []string{"created_at", "updated_at"} {
			var original time.Time
			if err := f.admin.QueryRow(f.ctx, "SELECT "+column+" FROM document_proposals WHERE id=$1", sibling).Scan(&original); err != nil {
				t.Fatal("read exact synthetic source timestamp", err)
			}
			if _, err := f.admin.Exec(f.ctx, "UPDATE document_proposals SET "+column+"='infinity' WHERE id=$1", sibling); err != nil {
				t.Fatal("set explicit invalid schema-control source timestamp", err)
			}
			before := manualProposalMigrationState268(t, f)
			_, err := f.admin.Exec(f.ctx, manualProposalMigrationInsert268, sibling, document, org)
			manualProposalMigrationSQLState268(t, err, "23514")
			if after := manualProposalMigrationState268(t, f); after != before {
				t.Fatal("nonfinite source refusal changed source, cache or schema")
			}
			if _, err := f.admin.Exec(f.ctx, "UPDATE document_proposals SET "+column+"=$2 WHERE id=$1", sibling, original); err != nil {
				t.Fatal("restore exact synthetic source timestamp", err)
			}
		}
		// A no-op UPDATE also invalidates. There is no content comparison or
		// automatic repair; the explicit test measurement below is not an API.
		if _, err := f.admin.Exec(f.ctx, "UPDATE document_proposals SET proposed_text=proposed_text WHERE id=$1", proposal); err != nil {
			t.Fatal("same-value source update", err)
		}
		manualProposalMigrationCount268(t, f, proposal, 0)
		manualProposalMigrationMeasure268(t, f, proposal, document, org)
		if _, err := f.admin.Exec(f.ctx, `UPDATE document_proposals SET diff_json='{"changed":"å exact source"}'::jsonb,updated_at=clock_timestamp() WHERE id=$1`, proposal); err != nil {
			t.Fatal("actual source rewrite", err)
		}
		manualProposalMigrationCount268(t, f, proposal, 0)
		manualProposalMigrationMeasure268(t, f, proposal, document, org)
		manualProposalMigrationMeasure268(t, f, sibling, document, org)
		if _, err := f.admin.Exec(f.ctx, "DELETE FROM document_proposals WHERE id=$1", sibling); err != nil {
			t.Fatal("delete explicit synthetic sibling", err)
		}
		manualProposalMigrationCount268(t, f, sibling, 0)
		manualProposalMigrationExact268(t, f, proposal)

		before = manualProposalMigrationState268(t, f)
		manualProposalMigrationSQLState268(t, mdb.RunMigrationsDownToContext(f.ctx, f.db, 111), "23514")
		if after := manualProposalMigrationState268(t, f); after != before {
			t.Fatal("retained-cache Down refusal removed rows, history or schema")
		}
		manualProposalMigrationUnlocked268(t, f)
		for _, table := range []string{"document_proposals", "manual_proposal_wire_sizes_v1"} {
			holder = manualProposalMigrationHolder268(t, f, "LOCK TABLE public."+table+" IN SHARE MODE")
			manualProposalMigrationSQLState268(t, mdb.RunMigrationsDownToContext(f.ctx, f.db, 111), "55P03")
			if after := manualProposalMigrationState268(t, f); after != before {
				t.Fatal("locked Down left partial schema or changed retained rows", table)
			}
			manualProposalMigrationUnlocked268(t, f)
			manualProposalMigrationRelease268(t, holder)
		}
		// Explicit disposal of this synthetic cache qualifies the supported empty
		// rollback only. The original source proposal must survive byte-exact.
		if tag, err := f.admin.Exec(f.ctx, "DELETE FROM manual_proposal_wire_sizes_v1 WHERE proposal_id=$1", proposal); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("dispose only the explicit synthetic proof", err)
		}
		beforeDown := manualProposalMigrationState268(t, f)
		if err := mdb.RunMigrationsDownToContext(f.ctx, f.db, 111); err != nil {
			t.Fatal("empty-cache Down with retained source failed", err)
		}
		manualProposalMigrationSchema268(t, f, false)
		manualProposalMigrationHead268(t, f, 111)
		if after := manualProposalMigrationState268(t, f); after.source != beforeDown.source {
			t.Fatal("successful Down changed retained source proposals")
		}
		manualProposalMigrationUnlocked268(t, f)
		migrationPoolRetired242(t, f, f.db, f.name)
	})
}

const manualProposalMigrationInsert268 = `INSERT INTO manual_proposal_wire_sizes_v1(proposal_id,document_id,org_id,proposal_created_at,proposal_updated_at,diff_wire_bytes,measurement_server_version_num,measured_at) VALUES($1,$2,$3,'infinity','infinity',-777,-1,'infinity')`

type manualProposalMigrationStateV1268 struct{ source, cache, schema, history string }

func manualProposalMigrationState268(t *testing.T, f migrationPGFixture242) manualProposalMigrationStateV1268 {
	t.Helper()
	var state manualProposalMigrationStateV1268
	if err := f.admin.QueryRow(f.ctx, `SELECT
 (SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.id),'[]'::jsonb)::text FROM document_proposals p),
 (SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.id),'[]'::jsonb)::text FROM goose_db_version v),
 jsonb_build_object('table',to_regclass('public.manual_proposal_wire_sizes_v1')::text,'index',to_regclass('public.manual_proposal_wire_scope_v1')::text,
 'columns',(SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull) ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=to_regclass('public.manual_proposal_wire_sizes_v1') AND a.attnum>0 AND NOT a.attisdropped),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(c.conname,pg_get_constraintdef(c.oid,true)) ORDER BY c.conname) FROM pg_constraint c WHERE c.conrelid=to_regclass('public.manual_proposal_wire_sizes_v1')),
 'functions',(SELECT jsonb_agg(pg_get_functiondef(p.oid) ORDER BY p.proname) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('hash_derive_manual_proposal_wire_v1','hash_invalidate_manual_proposal_wire_v1')),
 'triggers',(SELECT jsonb_agg(pg_get_triggerdef(t.oid,true) ORDER BY t.tgname) FROM pg_trigger t WHERE t.tgname IN ('derive_manual_proposal_wire_v1','invalidate_manual_proposal_wire_v1') AND NOT t.tgisinternal))::text`).Scan(&state.source, &state.history, &state.schema); err != nil {
		t.Fatal("snapshot actual M112 source, metadata and schema", err)
	}
	var present bool
	if err := f.admin.QueryRow(f.ctx, "SELECT to_regclass('public.manual_proposal_wire_sizes_v1') IS NOT NULL").Scan(&present); err != nil {
		t.Fatal(err)
	}
	state.cache = "absent"
	if present {
		if err := f.admin.QueryRow(f.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.proposal_id),'[]'::jsonb)::text FROM manual_proposal_wire_sizes_v1 m`).Scan(&state.cache); err != nil {
			t.Fatal("snapshot actual M112 cache", err)
		}
	}
	return state
}
func manualProposalMigrationVersion268(t *testing.T, f migrationPGFixture242, version int64, present bool) {
	t.Helper()
	if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, version); err != nil {
		t.Fatal("apply genuine pre-M112 migration tree", err)
	}
	manualProposalMigrationHead268(t, f, version)
	manualProposalMigrationSchema268(t, f, present)
}
func manualProposalMigrationApply268(t *testing.T, f migrationPGFixture242) {
	t.Helper()
	if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 112); err != nil {
		t.Fatal("apply actual embedded M112", err)
	}
	manualProposalMigrationHead268(t, f, 112)
	manualProposalMigrationSchema268(t, f, true)
}
func manualProposalMigrationHead268(t *testing.T, f migrationPGFixture242, want int64) {
	t.Helper()
	if got, err := mdb.GetMigrationVersionContext(f.ctx, f.db); err != nil || got != want {
		t.Fatal("M112 migration head differs", got, want, err)
	}
}
func manualProposalMigrationSchema268(t *testing.T, f migrationPGFixture242, present bool) {
	t.Helper()
	var objects int
	if err := f.admin.QueryRow(f.ctx, `SELECT
 (to_regclass('public.manual_proposal_wire_sizes_v1') IS NOT NULL)::int+
 (to_regclass('public.manual_proposal_wire_scope_v1') IS NOT NULL)::int+
 (to_regprocedure('public.hash_derive_manual_proposal_wire_v1()') IS NOT NULL)::int+
 (to_regprocedure('public.hash_invalidate_manual_proposal_wire_v1()') IS NOT NULL)::int+
 (SELECT count(*)::int FROM pg_trigger WHERE tgname IN ('derive_manual_proposal_wire_v1','invalidate_manual_proposal_wire_v1') AND NOT tgisinternal)`).Scan(&objects); err != nil || (!present && objects != 0) || (present && objects != 6) {
		t.Fatal("M112 objects partial or unexpectedly present", objects, present, err)
	}
}
func manualProposalMigrationSeed268(t *testing.T, f migrationPGFixture242) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	var org, user, document, proposal, sibling uuid.UUID
	if err := f.admin.QueryRow(f.ctx, "INSERT INTO orgs(name,plan) VALUES('M112 schema control','pro') RETURNING id").Scan(&org); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.QueryRow(f.ctx, "INSERT INTO users(org_id,email,name,role,zitadel_sub) VALUES($1,$2,'Schema control','owner',$3) RETURNING id", org, uuid.NewString()+"@m112.test", uuid.NewString()).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.QueryRow(f.ctx, `INSERT INTO documents(org_id,name,source_kind,blocks_json,variables_json,sender_id) VALUES($1,'M112 schema control','blocks','{"version":1,"blocks":[]}'::jsonb,'{}'::jsonb,$2) RETURNING id`, org, user).Scan(&document); err != nil {
		t.Fatal(err)
	}
	for _, target := range []*uuid.UUID{&proposal, &sibling} {
		if err := f.admin.QueryRow(f.ctx, `INSERT INTO document_proposals(document_id,org_id,proposed_by,block_id,proposal_kind,proposed_text,rationale,diff_json) VALUES($1,$2,$3,'schema-control','counter','Preserved original text','Preserved rationale','{"nested":{"unicode":"å中文","escaped":"a\nb"},"array":[1,true,null]}'::jsonb) RETURNING id`, document, org, user).Scan(target); err != nil {
			t.Fatal("insert explicit synthetic pre-M112 proposal", err)
		}
	}
	return proposal, sibling, document, org
}
func manualProposalMigrationSQLState268(t *testing.T, err error, code string) {
	t.Helper()
	var server *pgconn.PgError
	if !errors.As(err, &server) || server.Code != code {
		t.Fatal("M112 refusal did not retain exact server SQLSTATE", code, err)
	}
}
func manualProposalMigrationCount268(t *testing.T, f migrationPGFixture242, proposal uuid.UUID, want int) {
	t.Helper()
	var got int
	if err := f.admin.QueryRow(f.ctx, "SELECT count(*) FROM manual_proposal_wire_sizes_v1 WHERE proposal_id=$1", proposal).Scan(&got); err != nil || got != want {
		t.Fatal("M112 cache invalidation/cascade differs", got, want, err)
	}
}
func manualProposalMigrationMeasure268(t *testing.T, f migrationPGFixture242, proposal, document, org uuid.UUID) {
	t.Helper()
	if _, err := f.admin.Exec(f.ctx, manualProposalMigrationInsert268, proposal, document, org); err != nil {
		t.Fatal("derive actual synthetic source measurement", err)
	}
	manualProposalMigrationExact268(t, f, proposal)
}
func manualProposalMigrationExact268(t *testing.T, f migrationPGFixture242, proposal uuid.UUID) {
	t.Helper()
	var exact bool
	if err := f.admin.QueryRow(f.ctx, `SELECT m.document_id=p.document_id AND m.org_id=p.org_id AND m.proposal_created_at=p.created_at AND m.proposal_updated_at=p.updated_at AND m.diff_wire_bytes=octet_length(p.diff_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer AND isfinite(m.measured_at) AND m.measured_at>=p.created_at AND m.measured_at<=clock_timestamp() AND current_setting('server_encoding')='UTF8' FROM manual_proposal_wire_sizes_v1 m JOIN document_proposals p ON p.id=m.proposal_id WHERE p.id=$1`, proposal).Scan(&exact); err != nil || !exact {
		t.Fatal("M112 derived values differ from exact actual source", exact, err)
	}
}
func manualProposalMigrationHolder268(t *testing.T, f migrationPGFixture242, statement string, args ...any) pgx.Tx {
	t.Helper()
	cfg := f.config.Copy()
	cfg.RuntimeParams["application_name"] = "hash-m112-holder-" + uuid.NewString()
	conn, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal("connect M112 exact source/DDL holder", err)
	}
	t.Cleanup(func() {
		call, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := conn.Close(call); err != nil {
			t.Error("close exact M112 holder", err)
		}
	})
	tx, err := conn.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		call, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := tx.Rollback(call); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("rollback exact M112 holder", err)
		}
	})
	if _, err := tx.Exec(f.ctx, statement, args...); err != nil {
		t.Fatal("establish actual M112 holder", err)
	}
	return tx
}
func manualProposalMigrationRelease268(t *testing.T, tx pgx.Tx) {
	t.Helper()
	call, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := tx.Rollback(call); err != nil {
		t.Fatal("release actual M112 holder", err)
	}
}
func manualProposalMigrationUnlocked268(t *testing.T, f migrationPGFixture242) {
	t.Helper()
	var retired bool
	if err := f.admin.QueryRow(f.ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.datname=current_database() AND a.application_name=$1 AND l.locktype='advisory' AND l.granted AND ((l.classid::bigint<<32)|l.objid::bigint)=$2) AND NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND (state='idle in transaction' OR backend_xid IS NOT NULL))`, f.name, migrationFixtureLock242).Scan(&retired); err != nil || !retired {
		t.Fatal("completed M112 operation retained its advisory lock or transaction", retired, err)
	}
}
