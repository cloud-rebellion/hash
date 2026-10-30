//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package testfixture

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestOwnedPostgresFactoryRequiresExplicitScopeBeforeConnecting(t *testing.T) {
	t.Setenv("HASH_E2E_OWNED_PG", "")
	f := NewOwnedPostgresFactory("postgres://synthetic-private-value@invalid.invalid/private")
	if err := f.initialize(t.Context()); err == nil || strings.Contains(err.Error(), "synthetic-private-value") || f.config != nil || f.seed != "" {
		t.Fatal("unacknowledged fixture connected or exposed configuration")
	}
	for _, prefix := range []string{"production_", "hash_../", "hash_BAD_", strings.Repeat("hash_", 7)} {
		if ownedFixturePrefix(prefix) {
			t.Fatal("unowned or noncanonical prefix accepted")
		}
	}
}

func TestOwnedPostgresClonesPreserveIndependentCurrentEstatesE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL for owned PostgreSQL fixture integration")
	}
	f := NewOwnedPostgresFactory(dsn)
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	left, right := f.Clone(t, "hash_factory_left_"), f.Clone(t, "hash_factory_right_")
	if left == right || left == f.seed || right == f.seed {
		t.Fatal("fixture estates alias their seed or another case")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	connect := func(database string) *pgx.Conn {
		cfg := f.config.Copy()
		cfg.Database = database
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal("connect independent owned clone")
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := closeFixtureConn(cleanup, conn); err != nil {
				t.Error(err)
			}
		})
		return conn
	}
	a, b := connect(left), connect(right)
	id := uuid.New()
	if _, err := a.Exec(ctx, `INSERT INTO orgs(id,name) VALUES($1,'Synthetic clone isolation')`, id); err != nil {
		t.Fatal("write left independent estate")
	}
	var count int
	if err := b.QueryRow(ctx, `SELECT count(*)::integer FROM orgs WHERE id=$1`, id).Scan(&count); err != nil || count != 0 {
		t.Fatal("clone case state leaked")
	}
	if err := a.QueryRow(ctx, `SELECT count(*)::integer FROM orgs WHERE id=$1`, id).Scan(&count); err != nil || count != 1 {
		t.Fatal("original clone state lost")
	}
	seedConfig := f.config.Copy()
	seedConfig.Database = f.seed
	if unexpected, err := pgx.ConnectConfig(ctx, seedConfig); err == nil {
		_ = closeFixtureConn(ctx, unexpected)
		t.Fatal("sealed migrated seed accepted a case connection")
	}
}
