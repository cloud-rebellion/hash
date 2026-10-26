//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"os"
	"testing"
	"time"

	hashdb "github.com/bright-interaction/hash/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// This requires a dedicated, initially empty owned database. It never resets an
// existing schema, and the caller owns removal of its isolated test container.
func TestFirstInstallFresh117ResourceBaseline(t *testing.T) {
	dsn := os.Getenv("HASH_FIRST_INSTALL_TEST_DB_URL")
	if dsn == "" {
		t.Skip("HASH_FIRST_INSTALL_TEST_DB_URL is required for real PostgreSQL qualification")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || cfg.Database != "hash_first_install_test" || (cfg.Host != "127.0.0.1" && cfg.Host != "localhost") {
		t.Fatal("a dedicated local first-install test database is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid owned PostgreSQL configuration")
	}
	poolCfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatal("could not open owned PostgreSQL database")
	}
	defer pool.Close()
	initial, err := verifyFirstInstallDatabase(ctx, pool)
	if err != nil || !initial.Complete || !initial.Safe {
		t.Fatal("test database is not empty; refusing to modify it")
	}
	sqlDB := stdlib.OpenDB(*cfg)
	sqlDB.SetMaxOpenConns(1)
	defer sqlDB.Close()
	if err := hashdb.RunMigrationsContext(ctx, sqlDB); err != nil {
		t.Fatal("actual embedded migrations failed")
	}
	digest, versions, err := hashdb.EmbeddedMigrationsIdentity()
	if err != nil || len(versions) == 0 || versions[len(versions)-1] != 117 {
		t.Fatal("qualification requires the actual complete migration117 tree")
	}

	t.Run("untouched migration rows are unused scaffolding", func(t *testing.T) {
		// The old generic EXISTS rule rejected these exact migration-owned rows.
		var oldNonempty int
		if err := pool.QueryRow(ctx, `SELECT
		  (EXISTS (SELECT 1 FROM signing_resource_control))::int
		+ (EXISTS (SELECT 1 FROM signing_resource_accounts))::int`).Scan(&oldNonempty); err != nil || oldNonempty != 2 {
			t.Fatal("real migration89 baseline was not installed")
		}
		got, err := verifyFirstInstallSchema(ctx, pool, digest, true)
		if err != nil || !got.Complete || !got.Safe || !got.GooseStateExact || !got.StaticSeedExact || got.NonemptyBusinessTables != 0 {
			t.Fatalf("fresh complete schema refused: result=%+v query_failed=%t", got, err != nil)
		}
	})

	t.Run("unknown future business table still refuses", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `CREATE TABLE bootstrap_business_probe (id integer PRIMARY KEY); INSERT INTO bootstrap_business_probe VALUES (1)`); err != nil {
			t.Fatal("could not install owned business-data probe")
		}
		got, err := verifyFirstInstallSchema(ctx, pool, digest, true)
		if err != nil || !got.Complete || got.Safe || got.NonemptyBusinessTables != 1 {
			t.Fatalf("unknown business row did not refuse: result=%+v query_failed=%t", got, err != nil)
		}
		if _, err := pool.Exec(ctx, `DROP TABLE bootstrap_business_probe`); err != nil {
			t.Fatal("could not remove owned business-data probe")
		}
	})

	t.Run("real workspace requires candidate cutover", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(name,plan) VALUES ('First-install synthetic company','starter')`); err != nil {
			t.Fatal("could not create owned workspace probe")
		}
		before, err := verifyFirstInstallSchema(ctx, pool, digest, true)
		if err != nil || !before.Complete || before.Safe || before.NonemptyBusinessTables == 0 {
			t.Fatal("pre-candidate phase accepted an actual workspace")
		}
		after, err := verifyFirstInstallSchema(ctx, pool, digest, false)
		if err != nil || !after.Complete || !after.Safe {
			t.Fatal("authorized candidate-cutover retry rejected legitimate workspace rows")
		}
	})
}
