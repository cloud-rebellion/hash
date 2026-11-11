//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package handler

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// The current seed and its empty M128 Down establish a real M127 database. The
// canonical runner then upgrades that historical schema; no Goose rows, applied
// SQL files, package consent or retained settings are rewritten by the fixture.
func TestSigningLanguages128Native127UpgradeAndRetainedDownRefusalE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	factory := testfixture.NewOwnedPostgresFactory(dsn)
	t.Cleanup(func() {
		if err := factory.Close(); err != nil {
			t.Error(err)
		}
	})
	database := factory.Clone(t, "hash_languages128_")
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse owned PostgreSQL configuration")
	}
	cfg.Database = database
	sqlDB := stdlib.OpenDB(*cfg)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := mdb.RunMigrationsDownToContext(ctx, sqlDB, 127); err != nil {
		t.Fatal("empty M128 could not restore its exact prior schema", err)
	}
	if version, err := mdb.GetMigrationVersionContext(ctx, sqlDB); err != nil || version != 127 {
		t.Fatal("Down did not retain the actual M127 history", version, err)
	}
	org := uuid.New()
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO orgs(id,name,plan) VALUES($1,'Synthetic language migration','pro')`, org); err != nil {
		t.Fatal("seed synthetic migration organization", err)
	}
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO org_email_template_revisions_v1(org_id,kind,revision,subject_template,html_template,text_template)
 VALUES($1,'email.invite',1,'Retained English source','<p>Retained literal source</p>','Retained literal source')`, org); err != nil {
		t.Fatal("seed retained M119 edition", err)
	}
	var before, englishText, englishSHA string
	if err := sqlDB.QueryRowContext(ctx, `SELECT to_jsonb(r)::text,hash_package_incorporation_text_v1(),encode(hash_package_incorporation_sha256_v1(),'hex')
 FROM org_email_template_revisions_v1 r WHERE org_id=$1 AND kind='email.invite' AND revision=1`, org).Scan(&before, &englishText, &englishSHA); err != nil {
		t.Fatal(err)
	}
	if englishText != documentpackage.IncorporationTextV1 || englishSHA != documentpackage.IncorporationSHA256V1 {
		t.Fatal("historical English package statement differs")
	}
	if err := mdb.RunMigrationsContext(ctx, sqlDB); err != nil {
		t.Fatal("actual M127-to-M128 upgrade refused", err)
	}
	if version, err := mdb.GetMigrationVersionContext(ctx, sqlDB); err != nil || version != 128 {
		t.Fatal("M128 was not actually applied", version, err)
	}
	var after string
	if err := sqlDB.QueryRowContext(ctx, `SELECT to_jsonb(r)::text FROM org_email_template_revisions_v1 r WHERE org_id=$1 AND kind='email.invite' AND revision=1`, org).Scan(&after); err != nil || after != before {
		t.Fatal("upgrade changed the retained literal edition", err)
	}
	for _, copy := range []documentpackage.IncorporationV1{documentpackage.IncorporationCopyV1(), documentpackage.IncorporationCopyForLocaleV1("sv")} {
		var text, sha string
		if err := sqlDB.QueryRowContext(ctx, `SELECT hash_package_incorporation_text_for_version_v128($1),encode(hash_package_incorporation_sha256_for_version_v128($1),'hex')`, copy.Version).Scan(&text, &sha); err != nil || text != copy.Text || sha != copy.SHA256 {
			t.Fatal("SQL and application canonical package bytes disagree", copy.Version, err)
		}
	}
	var unknownRefused bool
	if err := sqlDB.QueryRowContext(ctx, `SELECT hash_package_incorporation_text_for_version_v128('unknown') IS NULL
 AND hash_package_incorporation_sha256_for_version_v128('unknown') IS NULL`).Scan(&unknownRefused); err != nil || !unknownRefused {
		t.Fatal("unknown package language gained a canonical statement", err)
	}
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO org_email_preferences_v1(org_id,revision,locale) VALUES($1,1,'sv')`, org); err != nil {
		t.Fatal(err)
	}
	err = mdb.RunMigrationsDownToContext(ctx, sqlDB, 127)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("Down discarded retained M128 preferences", err)
	}
	if version, err := mdb.GetMigrationVersionContext(ctx, sqlDB); err != nil || version != 128 {
		t.Fatal("refused Down changed applied migration history", version, err)
	}
	var locale string
	if err := sqlDB.QueryRowContext(ctx, `SELECT locale FROM org_email_preferences_v1 WHERE org_id=$1`, org).Scan(&locale); err != nil || locale != "sv" {
		t.Fatal("refused Down changed retained language", err)
	}
}
