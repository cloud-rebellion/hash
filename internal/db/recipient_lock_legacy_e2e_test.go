//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package db_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// A current document cannot jump straight to completed: M109 requires native
// frozen/published finalization evidence. These two direct-query lock tests use
// genuine legacy state instead. Seed at the earliest schema with recipients,
// then apply the entire caller-pinned current tree before executing any query.
// This fixture proves migration-compatible token/query ordering, not a signing
// ceremony, finalization-producer acceptance or immutable storage evidence.
func legacyCompletedRecipientLock(t *testing.T, ctx context.Context, parent *pgxpool.Pool) (*pgxpool.Pool, *generated.Queries, recipientLockFixture) {
	t.Helper()
	name := "hash_recipient_lock_legacy_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := parent.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("create owned legacy recipient database failed")
	}
	var child *pgxpool.Pool
	t.Cleanup(func() {
		if child != nil {
			child.Close()
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		// Pool/database/sql closure precedes normal exact-name DROP. Never terminate
		// unknown sessions or FORCE-drop the caller's fixture to obtain cleanup.
		for {
			var active int
			if err := parent.QueryRow(cleanup, "SELECT count(*) FROM pg_stat_activity WHERE datname=$1", name).Scan(&active); err != nil {
				t.Error("observe owned legacy database retirement failed")
				return
			}
			if active == 0 {
				break
			}
			select {
			case <-cleanup.Done():
				t.Error("owned legacy database sessions did not settle")
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
		if _, err := parent.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("drop exact owned legacy recipient database failed")
		}
	})
	cfg := parent.Config().Copy()
	cfg.ConnConfig.Database = name
	migrationDB := stdlib.OpenDB(*cfg.ConnConfig.Copy())
	defer migrationDB.Close()
	if err := mdb.RunMigrationsUpToContext(ctx, migrationDB, 3); err != nil {
		t.Fatal("migrate owned legacy recipient prefix failed")
	}
	f := recipientLockFixture{org: uuid.New(), doc: uuid.New(), recipient: uuid.New()}
	owner := uuid.New()
	sent := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	signed := sent.Add(time.Minute)
	completed := signed.Add(time.Minute)
	// Explicit historical columns only. No present-day measurement cache, intent,
	// hash-chain entry or evidence body is fabricated to masquerade as a producer.
	statements := []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO orgs(id,name,plan) VALUES($1,'Synthetic legacy lock organization','pro')", []any{f.org}},
		{"INSERT INTO users(id,org_id,email,name,role) VALUES($1,$2,$3,'Synthetic legacy owner','owner')", []any{owner, f.org, uuid.NewString() + "@recipient-lock.test"}},
		{"INSERT INTO documents(id,org_id,sender_id,name,status,source_kind,blocks_json,variables_json,sent_at,completed_at,created_at,updated_at) VALUES($1,$2,$3,'Synthetic legacy completed lock document','completed','blocks','[]','{}',$4,$5,$4::timestamptz-interval '1 minute',$5)", []any{f.doc, f.org, owner, sent, completed}},
		{"INSERT INTO recipients(id,document_id,email,name,role,status,magic_token_hash,sent_at,signed_at,created_at) VALUES($1,$2,$3,'Synthetic legacy signed party','signer','signed',$4,$5,$6,$5::timestamptz-interval '30 seconds')", []any{f.recipient, f.doc, uuid.NewString() + "@recipient-lock.test", bytes.Repeat([]byte{1}, 32), sent, signed}},
	}
	for _, statement := range statements {
		if _, err := migrationDB.ExecContext(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal("seed explicit historical recipient query state failed")
		}
	} //nolint:rawsql -- owned pre109 history, before normal forward migration
	// M65 correctly refuses historical non-draft rows without the branding
	// snapshot that Send already required in that release. Install that explicit
	// historical configuration at M64, before its lifecycle guard exists. This
	// remains synthetic legacy state, not a modern producer/evidence receipt.
	if err := mdb.RunMigrationsUpToContext(ctx, migrationDB, 64); err != nil {
		t.Fatal("migrate owned legacy recipient to branding boundary failed", err)
	}
	if _, err := migrationDB.ExecContext(ctx, `INSERT INTO document_branding_override
		(document_id,primary_hex,accent_hex,surface_hex,text_hex,muted_hex,logo_url,logo_alt,font_heading,font_body,signature_color)
		VALUES($1,'#111111','#222222','#ffffff','#111111','#666666','','','Inter','Inter','#111111')`, f.doc); err != nil { //nolint:rawsql -- explicit pre65 legacy configuration
		t.Fatal("seed complete historical branding snapshot failed", err)
	}
	if err := mdb.RunMigrationsContext(ctx, migrationDB); err != nil {
		t.Fatal("forward migrate legacy recipient fixture to bound current tree failed", err)
	}
	if err := migrationDB.Close(); err != nil {
		t.Fatal("close legacy migration connection failed")
	}
	var err error
	child, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("open migrated legacy recipient fixture failed")
	}
	// Reuse every normal profile guard: literal loopback, owned prefix, exact
	// compiled tree pin/current version and real enabled M88 parent trigger.
	digest, versions, err := mdb.EmbeddedMigrationsIdentity()
	if err != nil || digest != os.Getenv("HASH_E2E_RECIPIENT_LOCK_MIGRATION_SHA256") || len(versions) == 0 {
		t.Fatal("read bound migration identity failed")
	}
	var applied, count int64
	var trigger bool
	if err := child.QueryRow(ctx, "SELECT max(version_id),count(*) FROM goose_db_version WHERE is_applied AND version_id>0").Scan(&applied, &count); err != nil || applied != versions[len(versions)-1] || count != int64(len(versions)) {
		t.Fatal("legacy fixture did not reach entire bound current migration history")
	}
	if err := child.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='recipients'::regclass AND tgname='pdf_admission_invalidate_parties' AND tgenabled='O')").Scan(&trigger); err != nil || !trigger {
		t.Fatal("migrated legacy parent trigger missing")
	}
	var status string
	var bound bool
	if err := child.QueryRow(ctx, "SELECT status,completion_effective_at_bound FROM documents WHERE id=$1 AND org_id=$2", f.doc, f.org).Scan(&status, &bound); err != nil || status != "completed" || bound {
		t.Fatal("legacy completed-state migration provenance changed")
	}
	var frozenBranding bool
	if err := child.QueryRow(ctx, "SELECT hash_document_has_valid_frozen_branding($1)", f.doc).Scan(&frozenBranding); err != nil || !frozenBranding {
		t.Fatal("historical branding snapshot did not survive the unchanged migration guards")
	}
	q := generated.New(child)
	f.initial, err = q.GetRecipient(ctx, generated.GetRecipientParams{ID: f.recipient, OrgID: f.org})
	if err != nil || f.initial.Status != "signed" || !f.initial.SignedAt.Valid {
		t.Fatal("legacy signed recipient was not preserved")
	}
	return child, q, f
}
