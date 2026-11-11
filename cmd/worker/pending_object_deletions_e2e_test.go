//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/objectretire"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// The worker loop's tick drains pending object deletions: a storage failure keeps
// the row and backs it off, a recovered store deletes the exact version and then
// the row, and an absent version counts as done.
func TestPendingObjectDeletionSweepRetriesUntilTheVersionIsGoneE2E(t *testing.T) {
	ctx, pool, w, orgID, _, _ := setupSoftDeletePurgeE2E(t)
	digest := sha256.Sum256([]byte("pending deletion fixture"))
	key := "org/" + orgID.String() + "/documents/" + uuid.NewString() + ".pdf"
	documentID := uuid.New()
	rows, err := objectretire.Record(ctx, w.queries, orgID, documentID, nil, []objectretire.Object{{Key: key, VersionID: "fixture-version-1", SHA256: digest[:]}})
	if err != nil || len(rows) != 1 {
		t.Fatalf("record rows=%d err=%v", len(rows), err)
	}
	pending := func() []*generated.PendingObjectDeletionsV1 {
		t.Helper()
		got, err := w.queries.ListPendingObjectDeletionsForDocumentV1(ctx, generated.ListPendingObjectDeletionsForDocumentV1Params{OrgID: orgID, DocumentID: documentID})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	makeDue := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE pending_object_deletions_v1 SET next_attempt_at = clock_timestamp() - interval '1 second'`); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	var calls []string
	failing := true
	w.storage = purgeDeleteFunc(func(_ context.Context, k, version string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, k+"@"+version)
		if failing {
			return errors.New("storage unavailable")
		}
		return nil
	})

	// The request's grace period holds the sweep off a fresh row.
	w.runPendingObjectDeletionsOnce(ctx)
	if len(calls) != 0 || len(pending()) != 1 {
		t.Fatalf("the sweep ran inside the first-attempt grace period: calls=%v", calls)
	}

	makeDue()
	w.runPendingObjectDeletionsOnce(ctx)
	got := pending()
	if len(calls) != 1 || len(got) != 1 || got[0].Attempts != 1 || got[0].LastError != "storage unavailable" {
		t.Fatalf("failed attempt: calls=%v rows=%+v", calls, got)
	}

	// Backed off: an immediate tick leaves it alone.
	w.runPendingObjectDeletionsOnce(ctx)
	if len(calls) != 1 {
		t.Fatalf("the sweep retried inside the backoff: calls=%v", calls)
	}

	mu.Lock()
	failing = false
	mu.Unlock()
	makeDue()
	w.runPendingObjectDeletionsOnce(ctx)
	if len(calls) != 2 || calls[1] != key+"@fixture-version-1" || len(pending()) != 0 {
		t.Fatalf("recovered attempt: calls=%v rows=%d", calls, len(pending()))
	}
}

// M127's Down is reversible, but never silently drops an owed deletion: it refuses
// while any row remains, drops the table once the queue is drained, and the
// migration applies again afterwards.
func TestPendingObjectDeletionMigrationDownRefusesWhileObligationsRemainE2E(t *testing.T) {
	ctx, pool, w, orgID, _, _ := setupSoftDeletePurgeE2E(t)
	db := stdlib.OpenDB(*pool.Config().ConnConfig)
	t.Cleanup(func() { _ = db.Close() })
	digest := sha256.Sum256([]byte("pending deletion down fixture"))
	documentID := uuid.New()
	if _, err := objectretire.Record(ctx, w.queries, orgID, documentID, nil, []objectretire.Object{{Key: "org/" + orgID.String() + "/documents/" + uuid.NewString() + ".pdf", VersionID: "v1", SHA256: digest[:]}}); err != nil {
		t.Fatal(err)
	}
	err := mdb.RunMigrationsDownToContext(ctx, db, 126)
	var pgErr *pgconn.PgError
	if err == nil || !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("Down with an owed deletion must be refused with 23514, got %v", err)
	}
	var tables int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name='pending_object_deletions_v1'`).Scan(&tables); err != nil || tables != 1 {
		t.Fatalf("the refused Down must keep the table: tables=%d err=%v", tables, err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM pending_object_deletions_v1`); err != nil {
		t.Fatal(err)
	}
	if err := mdb.RunMigrationsDownToContext(ctx, db, 126); err != nil {
		t.Fatalf("Down of a drained queue: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name='pending_object_deletions_v1'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("Down must drop the table: tables=%d err=%v", tables, err)
	}
	if err := mdb.RunMigrationsContext(ctx, db); err != nil {
		t.Fatalf("re-applying M127: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name='pending_object_deletions_v1'`).Scan(&tables); err != nil || tables != 1 {
		t.Fatalf("re-applied M127 must recreate the table: tables=%d err=%v", tables, err)
	}
}
