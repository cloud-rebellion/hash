//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestSoftDeletePurgeSkipsPrivacyHoldsContentionAndStaleLeaseE2E(t *testing.T) {
	ctx, pool, w, orgID, userID, cutoff := setupSoftDeletePurgeE2E(t)
	objects := &purgeDeleterStub{}
	purge := func(doc *generated.Document) {
		t.Helper()
		rows, err := purgeClaimedSoftDeletedDocument(ctx, doc, cutoff, objects, w.beginSoftDeletePurge)
		if err != nil || rows != 0 || objects.calls != 0 {
			t.Fatalf("unsafe admission rows=%d objects=%d err=%v", rows, objects.calls, err)
		}
		assertSoftDeletePurgeRowE2E(t, ctx, pool, doc, true)
	}
	linked := seedSoftDeletePurgeClaimE2E(t, ctx, w, orgID, userID, cutoff)
	_, err := pool.Exec(ctx, `INSERT INTO data_subject_requests(org_id,document_id,subject_email,kind,requested_via)
VALUES($1,$2,'linked@example.test','access','dpo')`, orgID, linked.ID)
	checkSoftDeletePurgeE2E(t, err, "create linked hold after claiming")
	purge(linked)

	global := seedSoftDeletePurgeClaimE2E(t, ctx, w, orgID, userID, cutoff)
	var globalRequest uuid.UUID
	checkSoftDeletePurgeE2E(t, pool.QueryRow(ctx, `INSERT INTO data_subject_requests(org_id,subject_email,kind,requested_via)
VALUES($1,'global@example.test','access','dpo') RETURNING id`, orgID).Scan(&globalRequest), "create global hold after claiming")
	purge(global)
	_, err = pool.Exec(ctx, `UPDATE data_subject_requests SET status='withdrawn' WHERE id=$1`, globalRequest)
	checkSoftDeletePurgeE2E(t, err, "release global hold fixture")

	contested := seedSoftDeletePurgeClaimE2E(t, ctx, w, orgID, userID, cutoff)
	globalTx, err := pool.Begin(ctx)
	checkSoftDeletePurgeE2E(t, err, "begin uncommitted global hold")
	defer globalTx.Rollback(context.Background())
	_, err = globalTx.Exec(ctx, `INSERT INTO data_subject_requests(org_id,subject_email,kind,requested_via)
VALUES($1,'pending@example.test','restriction','dpo')`, orgID)
	checkSoftDeletePurgeE2E(t, err, "hold exclusive global writer fence")
	purge(contested)
	checkSoftDeletePurgeE2E(t, globalTx.Rollback(ctx), "release contested organization fence")

	locked := seedSoftDeletePurgeClaimE2E(t, ctx, w, orgID, userID, cutoff)
	parentTx, err := pool.Begin(ctx)
	checkSoftDeletePurgeE2E(t, err, "begin contested parent")
	defer parentTx.Rollback(context.Background())
	var lockedID uuid.UUID
	checkSoftDeletePurgeE2E(t, parentTx.QueryRow(ctx, `SELECT id FROM documents WHERE id=$1 FOR UPDATE`, locked.ID).Scan(&lockedID), "hold exact parent")
	purge(locked)
	checkSoftDeletePurgeE2E(t, parentTx.Rollback(ctx), "release contested parent")

	stale := seedSoftDeletePurgeClaimE2E(t, ctx, w, orgID, userID, cutoff)
	_, err = pool.Exec(ctx, `UPDATE documents SET name='updated lease' WHERE id=$1`, stale.ID)
	checkSoftDeletePurgeE2E(t, err, "advance claimed lease")
	purge(stale)
}

func TestSoftDeletePurgeHoldsPrivacyFenceThroughoutObjectIOE2E(t *testing.T) {
	ctx, pool, w, orgID, userID, cutoff := setupSoftDeletePurgeE2E(t)
	doc := seedSoftDeletePurgeClaimE2E(t, ctx, w, orgID, userID, cutoff)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var objectCalls atomic.Int32
	storageErr := errors.New("forced source-version cleanup failure")
	objects := purgeDeleteFunc(func(ctx context.Context, key, version string) error {
		objectCalls.Add(1)
		if key != doc.PdfStorageKey.String || version != doc.PdfStorageVersionID.String {
			return errors.New("wrong exact source version")
		}
		entered <- struct{}{}
		select {
		case <-release:
			return storageErr
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	purgeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	purgeDone := make(chan error, 1)
	go func() {
		_, err := purgeClaimedSoftDeletedDocument(purgeCtx, doc, cutoff, objects, w.beginSoftDeletePurge)
		purgeDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("purge never reached protected object cleanup")
	}
	requestTx, err := pool.Begin(purgeCtx)
	checkSoftDeletePurgeE2E(t, err, "begin global request during object cleanup")
	requestPID := requestTx.Conn().PgConn().PID()
	requestDone := make(chan error, 1)
	go func() {
		defer requestTx.Rollback(context.Background())
		if _, err := requestTx.Exec(purgeCtx, `INSERT INTO data_subject_requests(org_id,subject_email,kind,requested_via)
VALUES($1,'during-delete@example.test','access','sender')`, orgID); err != nil {
			requestDone <- err
			return
		}
		requestDone <- requestTx.Commit(purgeCtx)
	}()
	waitSoftDeletePurgeLockE2E(t, ctx, pool, requestPID)
	select {
	case err := <-requestDone:
		t.Fatalf("global request bypassed object cleanup fence: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-purgeDone:
		if !errors.Is(err, storageErr) {
			t.Fatalf("protected storage failure=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("purge did not release its transaction after source cleanup failure")
	}
	select {
	case err := <-requestDone:
		checkSoftDeletePurgeE2E(t, err, "global request commits after purge rollback")
	case <-time.After(3 * time.Second):
		t.Fatal("global request remained blocked after purge rollback")
	}
	assertSoftDeletePurgeRowE2E(t, ctx, pool, doc, true)
	rows, err := purgeClaimedSoftDeletedDocument(ctx, doc, cutoff, objects, w.beginSoftDeletePurge)
	if err != nil || rows != 0 || objectCalls.Load() != 1 {
		t.Fatalf("retry with committed global hold rows=%d objects=%d err=%v", rows, objectCalls.Load(), err)
	}
}

func TestSoftDeletePurgePreservesSharedSourceAndRetriesDatabaseFailureE2E(t *testing.T) {
	ctx, pool, w, orgID, userID, cutoff := setupSoftDeletePurgeE2E(t)
	shared := seedSoftDeletePurgeClaimE2E(t, ctx, w, orgID, userID, cutoff)
	other, err := w.queries.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{
		OrgID: orgID, Name: "shared source", SenderID: userID, PdfStorageKey: shared.PdfStorageKey,
		PdfStorageVersionID: shared.PdfStorageVersionID, PdfSha256: shared.PdfSha256, EvidenceVersionPinsRequired: true,
	})
	checkSoftDeletePurgeE2E(t, err, "create other durable source reference")
	objects := &purgeDeleterStub{}
	rows, err := purgeClaimedSoftDeletedDocument(ctx, shared, cutoff, objects, w.beginSoftDeletePurge)
	if err != nil || rows != 1 || objects.calls != 0 {
		t.Fatalf("shared source purge rows=%d objects=%d err=%v", rows, objects.calls, err)
	}
	assertSoftDeletePurgeRowE2E(t, ctx, pool, shared, false)
	assertSoftDeletePurgeRowE2E(t, ctx, pool, other, true)

	doc := seedSoftDeletePurgeClaimE2E(t, ctx, w, orgID, userID, cutoff)
	functionName := "hash_purge_test_delete_failure_" + strings.ReplaceAll(doc.ID.String(), "-", "")
	triggerName := functionName + "_trg"
	_, err = pool.Exec(ctx, `CREATE FUNCTION "`+functionName+`"() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN IF OLD.id='`+doc.ID.String()+`'::uuid THEN RAISE EXCEPTION 'forced source cleanup row failure'; END IF; RETURN OLD; END $body$`)
	checkSoftDeletePurgeE2E(t, err, "create deliberate row-delete failure")
	_, err = pool.Exec(ctx, `CREATE TRIGGER "`+triggerName+`" BEFORE DELETE ON documents FOR EACH ROW EXECUTE FUNCTION "`+functionName+`"()`)
	checkSoftDeletePurgeE2E(t, err, "enable deliberate row-delete failure")
	rows, err = purgeClaimedSoftDeletedDocument(ctx, doc, cutoff, objects, w.beginSoftDeletePurge)
	if err == nil || rows != 0 || objects.calls != 1 {
		t.Fatalf("failed row cleanup rows=%d objects=%d err=%v", rows, objects.calls, err)
	}
	assertSoftDeletePurgeRowE2E(t, ctx, pool, doc, true)
	_, err = pool.Exec(ctx, `DROP TRIGGER "`+triggerName+`" ON documents`)
	checkSoftDeletePurgeE2E(t, err, "remove row-delete failure")
	_, err = pool.Exec(ctx, `DROP FUNCTION "`+functionName+`"()`)
	checkSoftDeletePurgeE2E(t, err, "remove failure function")
	rows, err = purgeClaimedSoftDeletedDocument(ctx, doc, cutoff, objects, w.beginSoftDeletePurge)
	if err != nil || rows != 1 || objects.calls != 2 || objects.key != doc.PdfStorageKey.String || objects.version != doc.PdfStorageVersionID.String {
		t.Fatalf("exact-version cleanup retry rows=%d objects=%d key/version=%q/%q err=%v", rows, objects.calls, objects.key, objects.version, err)
	}
	assertSoftDeletePurgeRowE2E(t, ctx, pool, doc, false)
}

func TestSoftDeletePurgeConcurrentClosedRequestsDoNotUpgradeOrgFenceE2E(t *testing.T) {
	ctx, pool, w, orgID, userID, cutoff := setupSoftDeletePurgeE2E(t)
	docs := []*generated.Document{
		seedSoftDeletePurgeClaimE2E(t, ctx, w, orgID, userID, cutoff),
		seedSoftDeletePurgeClaimE2E(t, ctx, w, orgID, userID, cutoff),
	}
	for i, status := range []string{"denied", "withdrawn"} {
		_, err := pool.Exec(ctx, `INSERT INTO data_subject_requests(org_id,document_id,subject_email,kind,status,requested_via)
VALUES($1,$2,'closed@example.test','access',$3,'dpo')`, orgID, docs[i].ID, status)
		checkSoftDeletePurgeE2E(t, err, "seed closed linked request")
	}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	objects := purgeDeleteFunc(func(ctx context.Context, _, _ string) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	purgeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	type result struct {
		rows int64
		err  error
	}
	done := make(chan result, 2)
	for _, doc := range docs {
		go func(doc *generated.Document) {
			rows, err := purgeClaimedSoftDeletedDocument(purgeCtx, doc, cutoff, objects, w.beginSoftDeletePurge)
			done <- result{rows: rows, err: err}
		}(doc)
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("same-organization purges did not both reach source cleanup under shared fences")
		}
	}
	releaseOnce.Do(func() { close(release) })
	for range 2 {
		select {
		case result := <-done:
			if result.err != nil || result.rows != 1 {
				t.Fatalf("concurrent closed-request purge rows=%d err=%v", result.rows, result.err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("closed request FK SET NULL attempted a shared-to-exclusive organization lock upgrade")
		}
	}
	for _, doc := range docs {
		assertSoftDeletePurgeRowE2E(t, ctx, pool, doc, false)
	}
	var preserved int
	checkSoftDeletePurgeE2E(t, pool.QueryRow(ctx, `SELECT count(*) FROM data_subject_requests
WHERE org_id=$1 AND document_id IS NULL AND status IN ('denied','withdrawn')`, orgID).Scan(&preserved), "preserved closed request inventory")
	if preserved != 2 {
		t.Fatalf("closed requests after parent deletion=%d", preserved)
	}
}

func setupSoftDeletePurgeE2E(t *testing.T) (context.Context, *pgxpool.Pool, *worker, uuid.UUID, uuid.UUID, pgtype.Timestamptz) {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(dsn)
	checkSoftDeletePurgeE2E(t, err, "parse fixture database configuration")
	admin := stdlib.OpenDB(*cfg.ConnConfig)
	t.Cleanup(func() { _ = admin.Close() })
	databaseName := "hash_soft_purge_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+databaseName)
	checkSoftDeletePurgeE2E(t, err, "create isolated purge database")
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(cleanupCtx, "DROP DATABASE IF EXISTS "+databaseName+" WITH (FORCE)"); err != nil {
			t.Logf("purge fixture database cleanup failed: %v", err)
		}
	})
	cfg.ConnConfig.Database = databaseName
	pool, err = pgxpool.NewWithConfig(ctx, cfg)
	checkSoftDeletePurgeE2E(t, err, "open purge database")
	migrationDB := stdlib.OpenDB(*cfg.ConnConfig)
	checkSoftDeletePurgeE2E(t, mdb.RunMigrations(migrationDB), "migrate purge fixture")
	checkSoftDeletePurgeE2E(t, migrationDB.Close(), "close migration connection")
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "soft deletion privacy fence", Plan: "pro"})
	checkSoftDeletePurgeE2E(t, err, "create purge organization")
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@purge.test", Name: "Owner", Role: "owner"})
	checkSoftDeletePurgeE2E(t, err, "create purge owner")
	cutoff := pgtype.Timestamptz{Time: time.Now().Add(-softDeleteGraceWindow), Valid: true}
	return ctx, pool, &worker{pool: pool, queries: q}, org.ID, user.ID, cutoff
}

func seedSoftDeletePurgeClaimE2E(t *testing.T, ctx context.Context, w *worker, orgID, userID uuid.UUID, cutoff pgtype.Timestamptz) *generated.Document {
	t.Helper()
	key := "org/" + orgID.String() + "/documents/" + uuid.NewString() + ".pdf"
	digest := sha256.Sum256([]byte("soft-delete source fixture"))
	_, err := w.pool.Exec(ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind,pdf_storage_key,pdf_sha256,pdf_storage_version_id,deleted_at,created_at,updated_at)
VALUES($1,$2,'old deleted draft','pdf',$3,$4,'fixture-source-version-1',now()-interval '100 days',now()-interval '200 days',now()-interval '1 hour')`, orgID, userID, key, digest[:])
	checkSoftDeletePurgeE2E(t, err, "seed old deleted source")
	claimed, err := w.queries.ClaimSoftDeletedDocumentsForPurge(ctx, generated.ClaimSoftDeletedDocumentsForPurgeParams{Cutoff: cutoff, BatchLimit: 100})
	checkSoftDeletePurgeE2E(t, err, "claim actual cleanup lease")
	if len(claimed) != 1 || claimed[0].PdfStorageKey.String != key {
		t.Fatalf("purge fixture claims=%d, want exactly the new source", len(claimed))
	}
	if claimed[0].ID == uuid.Nil {
		t.Fatal("purge fixture has no document identity")
	}
	return claimed[0]
}

func assertSoftDeletePurgeRowE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, doc *generated.Document, retained bool) {
	t.Helper()
	var count int
	checkSoftDeletePurgeE2E(t, pool.QueryRow(ctx, `SELECT count(*) FROM documents WHERE id=$1 AND pdf_storage_key=$2 AND pdf_storage_version_id=$3`, doc.ID, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String).Scan(&count), "inspect durable cleanup reference")
	if (count == 1) != retained {
		t.Fatalf("source key/version retained=%v, want %v", count == 1, retained)
	}
}

func waitSoftDeletePurgeLockE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, pid uint32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		checkSoftDeletePurgeE2E(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, pid).Scan(&waiting), "observe privacy writer waiting on real fence")
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("privacy writer never reached an actual PostgreSQL fence wait")
}

func checkSoftDeletePurgeE2E(t *testing.T, err error, action string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
}
