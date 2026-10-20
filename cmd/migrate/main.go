// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Command migrate applies Hash's embedded database migrations and exits. The
// production release workflow runs this exact candidate-image binary only
// after its fresh-backup/old-image compatibility gate has passed, allowing the
// complete audit chain to be verified before any traffic moves to the release.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	mdb "github.com/bright-interaction/hash/internal/db"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv("HASH_DB_URL")); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "hash-migrate:", err)
		os.Exit(1)
	}
}

func run(parent context.Context, dsn string) error {
	if parent == nil {
		return fmt.Errorf("migration context is required")
	}
	ctx, cancel := context.WithTimeout(parent, mdb.DefaultMigrationTimeout)
	defer cancel()
	if dsn == "" {
		return fmt.Errorf("HASH_DB_URL is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// A parser error can quote its input. Do not copy a credential-bearing
		// URL into release logs.
		return fmt.Errorf("HASH_DB_URL is invalid")
	}
	db := stdlib.OpenDB(*cfg.ConnConfig)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if err := mdb.RunMigrationsContext(ctx, db); err != nil {
		return fmt.Errorf("apply embedded migrations: %w", err)
	}
	return nil
}
