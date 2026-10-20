//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
	"os"
	"strings"
	"testing"
	"time"
)

// Real PostgreSQL QUERY semantics against transaction-local metadata-only
// shadow tables. Not production-schema/migration/finalization acceptance.
func TestOperationalBacklog426MetadataSQLSemanticsE2E(t *testing.T) {
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
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := conn.Close(cleanup); err != nil {
			t.Error("owned connection close failed")
		}
	}()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil {
			t.Error("owned temporary fixture rollback failed")
		}
	}()
	exec := func(sql string) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE TEMP TABLE email_deliveries(id bigint,status text,created_at timestamptz,next_attempt_at timestamptz) ON COMMIT DROP;
 CREATE TEMP TABLE documents(id bigint,org_id bigint,status text,deleted_at timestamptz,parent_envelope_id bigint) ON COMMIT DROP;
 CREATE TEMP TABLE document_finalization_intents(document_id bigint PRIMARY KEY,org_id bigint,created_at timestamptz) ON COMMIT DROP;`)
	q := generated.New(tx)
	row, err := q.GetOperationalBacklogV1(ctx)
	if err != nil || row.MailCount != 0 || row.FinalizingRootCount != 0 || row.MailLimitReached || row.FinalizingLimitReached {
		t.Fatal("known empty query differs", err, row)
	}
	exec(`INSERT INTO email_deliveries VALUES
 (1,'pending',statement_timestamp()-interval '1 hour',statement_timestamp()-interval '30 seconds'),
 (2,'retrying',statement_timestamp()-interval '2 hours',statement_timestamp()+interval '5 minutes'),
 (3,'retrying','infinity','infinity'),(4,'sent',statement_timestamp()-interval '1 day',statement_timestamp()),(5,'failed',statement_timestamp()-interval '1 day',statement_timestamp());
 INSERT INTO documents VALUES (1,1,'finalizing',NULL,NULL),(2,1,'finalizing',NULL,NULL),(3,1,'finalizing',NULL,NULL),(4,1,'finalizing',NULL,NULL),(5,1,'completed',NULL,NULL),(6,1,'finalizing',NULL,1),(7,1,'finalizing',statement_timestamp(),NULL);
 INSERT INTO document_finalization_intents VALUES (1,1,statement_timestamp()-interval '1 hour'),(3,1,statement_timestamp()+interval '1 hour'),(4,2,statement_timestamp()-interval '1 day'),(5,1,statement_timestamp()-interval '1 day');`)
	row, err = q.GetOperationalBacklogV1(ctx)
	if err != nil || row.MailCount != 3 || row.MailDueCount != 1 || row.MailUnknownCreatedCount != 1 || row.MailUnknownDueCount != 1 || row.MailOldestObservedAgeSeconds < 7200 || row.MailOldestObservedOverdueSeconds < 30 || row.FinalizingRootCount != 4 || row.FinalizingIntentCount != 2 || row.FinalizingMissingIntentCount != 2 || row.FinalizingUnknownIntentAgeCount != 1 || row.FinalizingOldestObservedIntentAgeSeconds < 3600 {
		t.Fatal("leased/backoff, unknown clocks, root filters or org join changed", err, row)
	}
	var before string
	if err := tx.QueryRow(ctx, `SELECT string_agg(row(id,status,created_at,next_attempt_at)::text,',' ORDER BY id) FROM email_deliveries`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = q.GetOperationalBacklogV1(ctx); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := tx.QueryRow(ctx, `SELECT string_agg(row(id,status,created_at,next_attempt_at)::text,',' ORDER BY id) FROM email_deliveries`).Scan(&after); err != nil || before != after {
		t.Fatal("observation mutated queue", err)
	}
	exec(`INSERT INTO email_deliveries SELECT n,'pending',statement_timestamp(),statement_timestamp() FROM generate_series(100,1200)n;
 INSERT INTO documents SELECT n,1,'finalizing',NULL,NULL FROM generate_series(100,1200)n;`)
	row, err = q.GetOperationalBacklogV1(ctx)
	if err != nil || row.MailCount != 1000 || !row.MailLimitReached || row.FinalizingRootCount != 1000 || !row.FinalizingLimitReached || row.FinalizingIntentCount+row.FinalizingMissingIntentCount != row.FinalizingRootCount {
		t.Fatal("cap or overlapping-record semantics changed", err, row)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = q.GetOperationalBacklogV1(canceled); err == nil {
		t.Fatal("canceled query succeeded")
	}
}
