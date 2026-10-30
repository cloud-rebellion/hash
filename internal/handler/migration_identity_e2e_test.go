//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"os"
	"slices"
	"testing"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Full current Up must match every embedded applied version and the caller's
// source digest. Explicit historical UpTo/DownTo boundary oracles stay separate.
func assertCurrentHandlerMigrationHistoryE2E(t *testing.T, ctx context.Context, database generated.DBTX) int64 {
	t.Helper()
	digest, versions, err := mdb.EmbeddedMigrationsIdentity()
	if err != nil || len(versions) == 0 || digest != os.Getenv("HASH_E2E_EXPECT_MIGRATIONS_SHA256") {
		t.Fatal("current migration fixture does not match the caller-pinned embedded source")
	}
	var applied []int64
	var rows, invalid int64
	err = database.QueryRow(ctx, `SELECT
 coalesce(array_agg(version_id ORDER BY version_id) FILTER(WHERE version_id>0 AND is_applied),'{}'::bigint[]),
 count(*) FILTER(WHERE version_id>0),
 count(*) FILTER(WHERE version_id IS NULL OR version_id<0 OR is_applied IS DISTINCT FROM TRUE)
 FROM goose_db_version`).Scan(&applied, &rows, &invalid)
	if err != nil || rows != int64(len(versions)) || invalid != 0 || !slices.Equal(applied, versions) {
		t.Fatalf("current migration history mismatch: applied=%d total=%d expected=%d invalid=%d query_failed=%t", len(applied), rows, len(versions), invalid, err != nil)
	}
	return versions[len(versions)-1]
}
