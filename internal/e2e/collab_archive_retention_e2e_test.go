//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package e2e

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCollabArchiveRetentionIsBoundedAndProtectsRequestsE2E(t *testing.T) {
	ctx, pool, orgID, userID := setupCollabArchiveRetentionE2E(t)
	for range 8 {
		docID := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
		for range 16 {
			seedCollabArchiveRetentionRecord(t, ctx, pool, docID, true)
		}
	}
	openDoc := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
	seedCollabArchiveRetentionRecord(t, ctx, pool, openDoc, true)
	seedCollabArchiveRetentionRequest(t, ctx, pool, orgID, openDoc, "open")
	inProgressDoc := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
	seedCollabArchiveRetentionRecord(t, ctx, pool, inProgressDoc, true)
	seedCollabArchiveRetentionRequest(t, ctx, pool, orgID, inProgressDoc, "in_progress")
	freshDoc := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
	seedCollabArchiveRetentionRecord(t, ctx, pool, freshDoc, false)
	deniedDoc := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
	seedCollabArchiveRetentionRecord(t, ctx, pool, deniedDoc, true)
	seedCollabArchiveRetentionRequest(t, ctx, pool, orgID, deniedDoc, "denied")

	// A long-lived repeatable snapshot cannot safely see global requests
	// committed before the purge's organization fence. Reject it without loss.
	staleSnapshotTx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	must(t, err, "begin unsupported isolation")
	defer staleSnapshotTx.Rollback(context.Background())
	var rejectedCount int64
	err = staleSnapshotTx.QueryRow(ctx, `SELECT hash_purge_expired_collab_archives()`).Scan(&rejectedCount)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "25000" {
		t.Fatalf("unsupported purge isolation error=%v", err)
	}
	must(t, staleSnapshotTx.Rollback(ctx), "rollback unsupported isolation")
	assertCollabArchiveRetentionCount(t, ctx, pool, uuid.Nil, 132)

	// The function participates in its caller's transaction: a rollback must
	// preserve archives even after it reports a full deletion batch.
	tx, err := pool.Begin(ctx)
	must(t, err, "begin purge rollback")
	defer tx.Rollback(context.Background())
	var deleted int64
	must(t, tx.QueryRow(ctx, `SELECT hash_purge_expired_collab_archives()`).Scan(&deleted), "purge in transaction")
	if deleted != 100 {
		t.Fatalf("prospective purge=%d, want 100 total archives", deleted)
	}
	must(t, tx.Rollback(ctx), "rollback archive purge")
	assertCollabArchiveRetentionCount(t, ctx, pool, uuid.Nil, 132)

	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 100 {
		t.Fatalf("first purge=%d, want 100 total archives across documents", deleted)
	}
	assertCollabArchiveRetentionCount(t, ctx, pool, uuid.Nil, 32)
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 29 {
		t.Fatalf("second purge=%d, want remaining 29 eligible archives", deleted)
	}
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatalf("protected/fresh archives purged=%d", deleted)
	}
	assertCollabArchiveRetentionCount(t, ctx, pool, uuid.Nil, 3)
	for _, docID := range []uuid.UUID{openDoc, inProgressDoc, freshDoc} {
		assertCollabArchiveRetentionCount(t, ctx, pool, docID, 1)
	}
	assertCollabArchiveRetentionCount(t, ctx, pool, deniedDoc, 0)
}

func TestCollabArchiveRetentionSerializesRequestsAndSkipsLocksE2E(t *testing.T) {
	ctx, pool, orgID, userID := setupCollabArchiveRetentionE2E(t)
	docID := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
	seedCollabArchiveRetentionRecord(t, ctx, pool, docID, true)
	parentTx, err := pool.Begin(ctx)
	must(t, err, "begin held document")
	defer parentTx.Rollback(context.Background())
	var lockedID uuid.UUID
	must(t, parentTx.QueryRow(ctx, `SELECT id FROM documents WHERE id=$1 FOR UPDATE`, docID).Scan(&lockedID), "hold document before request")

	requestCtx, cancelRequest := context.WithTimeout(ctx, 10*time.Second)
	defer cancelRequest()
	requestTx, err := pool.Begin(requestCtx)
	must(t, err, "begin waiting privacy request")
	requestPID := requestTx.Conn().PgConn().PID()
	done := make(chan error, 1)
	go func() {
		defer requestTx.Rollback(context.Background())
		var observedID uuid.UUID
		if err := requestTx.QueryRow(requestCtx, `SELECT id FROM documents WHERE id=$1 FOR UPDATE`, docID).Scan(&observedID); err != nil {
			done <- err
			return
		}
		if _, err := requestTx.Exec(requestCtx, `INSERT INTO data_subject_requests
(org_id,document_id,subject_email,kind,requested_via) VALUES($1,$2,'retention@example.test','access','sender')`, orgID, docID); err != nil {
			done <- err
			return
		}
		done <- requestTx.Commit(requestCtx)
	}()
	deadline := time.Now().Add(3 * time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		must(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, requestPID).Scan(&waiting), "observe real request lock wait")
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("privacy request never reached the held document lock")
	}
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatal("purge did not skip a document with a waiting privacy request")
	}
	assertCollabArchiveRetentionCount(t, ctx, pool, docID, 1)
	must(t, parentTx.Commit(ctx), "release held document for privacy request")
	select {
	case err := <-done:
		must(t, err, "commit request after actual lock wait")
	case <-time.After(3 * time.Second):
		t.Fatal("privacy request remained blocked after releasing document")
	}
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatal("request committed after lock wait failed to protect expired history")
	}
	assertCollabArchiveRetentionCount(t, ctx, pool, docID, 1)

	// The document FK also protects an uncommitted linked request even when
	// a non-HTTP caller omits the application's explicit parent lock.
	fkDoc := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
	seedCollabArchiveRetentionRecord(t, ctx, pool, fkDoc, true)
	fkTx, err := pool.Begin(ctx)
	must(t, err, "begin FK request")
	defer fkTx.Rollback(context.Background())
	_, err = fkTx.Exec(ctx, `INSERT INTO data_subject_requests
(org_id,document_id,subject_email,kind,requested_via) VALUES($1,$2,'fk@example.test','restriction','dpo')`, orgID, fkDoc)
	must(t, err, "insert uncommitted FK request")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatal("purge ignored the request's parent FK lock")
	}
	must(t, fkTx.Commit(ctx), "commit FK request")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatal("purge ignored committed restriction request")
	}
	assertCollabArchiveRetentionCount(t, ctx, pool, fkDoc, 1)

	// Archive row locks are skipped after the parent lock, allowing unrelated
	// expired rows to make progress without blocking the entire invocation.
	rowDoc := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
	lockedArchive := seedCollabArchiveRetentionRecord(t, ctx, pool, rowDoc, true)
	seedCollabArchiveRetentionRecord(t, ctx, pool, rowDoc, true)
	rowTx, err := pool.Begin(ctx)
	must(t, err, "begin held archive")
	defer rowTx.Rollback(context.Background())
	must(t, rowTx.QueryRow(ctx, `SELECT id FROM collab_recovery_archives WHERE id=$1 FOR UPDATE`, lockedArchive).Scan(&lockedID), "hold archive row")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 1 {
		t.Fatalf("purge with one locked archive=%d, want one unlocked sibling", deleted)
	}
	assertCollabArchiveRetentionCount(t, ctx, pool, rowDoc, 1)
	must(t, rowTx.Rollback(ctx), "release archive row")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 1 {
		t.Fatalf("purge after archive unlock=%d", deleted)
	}
}

func TestCollabArchiveRetentionPreservesConcurrentRecoveryE2E(t *testing.T) {
	ctx, pool, orgID, userID := setupCollabArchiveRetentionE2E(t)
	docID := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
	seedCollabArchiveRetentionRecord(t, ctx, pool, docID, true)
	persisted := []byte("persisted recovery bytes")
	active := []byte("active recovery bytes")
	_, err := pool.Exec(ctx, `INSERT INTO collab_doc_states(document_id,ydoc_state,state_size,update_count) VALUES($1,$2,$3,1)`, docID, persisted, len(persisted))
	must(t, err, "seed pending persisted history")
	var at pgtype.Timestamptz
	must(t, pool.QueryRow(ctx, `SELECT updated_at FROM documents WHERE id=$1`, docID).Scan(&at), "observe canonical document")
	tx, err := pool.Begin(ctx)
	must(t, err, "begin recovery")
	defer tx.Rollback(context.Background())
	var nextGeneration int64
	must(t, tx.QueryRow(ctx, `SELECT hash_recover_canonical_collab($1,$2,1,$3,$4,true,$5,1)`, docID, orgID, at, userID, active).Scan(&nextGeneration), "recover without committing")
	if nextGeneration != 2 {
		t.Fatalf("recovery generation=%d", nextGeneration)
	}
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatal("expiry purge entered a document with uncommitted recovery")
	}
	must(t, tx.Commit(ctx), "commit recovery archives")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 1 {
		t.Fatalf("post-recovery purge=%d, want only the old expired archive", deleted)
	}
	assertCollabArchiveRetentionCount(t, ctx, pool, docID, 2)
	rows, err := pool.Query(ctx, `SELECT origin,ydoc_state FROM collab_recovery_archives WHERE document_id=$1`, docID)
	must(t, err, "read preserved new recovery bytes")
	defer rows.Close()
	seen := map[string][]byte{}
	for rows.Next() {
		var origin string
		var replay []byte
		must(t, rows.Scan(&origin, &replay), "read new archive")
		seen[origin] = replay
	}
	must(t, rows.Err(), "read recovery rows")
	if !bytes.Equal(seen["persisted"], persisted) || !bytes.Equal(seen["active_room"], active) {
		t.Fatal("expiry purge changed newly archived persisted or active replay")
	}
}

func TestCollabArchiveRetentionFencesGlobalRequestsAndReopenE2E(t *testing.T) {
	ctx, pool, orgID, userID := setupCollabArchiveRetentionE2E(t)
	docID := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
	seedCollabArchiveRetentionRecord(t, ctx, pool, docID, true)
	var otherOrg, otherUser uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO orgs(name,plan) VALUES('other retention org','pro') RETURNING id`).Scan(&otherOrg), "other org")
	must(t, pool.QueryRow(ctx, `INSERT INTO users(org_id,email,name,role) VALUES($1,$2,'Other Owner','owner') RETURNING id`, otherOrg, uuid.NewString()+"@retention.test").Scan(&otherUser), "other owner")
	otherDoc := seedCollabArchiveRetentionDocument(t, ctx, pool, otherOrg, otherUser)
	seedCollabArchiveRetentionRecord(t, ctx, pool, otherDoc, true)

	globalTx, err := pool.Begin(ctx)
	must(t, err, "begin global privacy request")
	defer globalTx.Rollback(context.Background())
	var requestID uuid.UUID
	must(t, globalTx.QueryRow(ctx, `INSERT INTO data_subject_requests
(org_id,subject_email,kind,requested_via) VALUES($1,'global@example.test','access','sender') RETURNING id`, orgID).Scan(&requestID), "uncommitted global request")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 1 {
		t.Fatalf("purge during global request=%d, want only other organization's archive", deleted)
	}
	assertCollabArchiveRetentionCount(t, ctx, pool, docID, 1)
	assertCollabArchiveRetentionCount(t, ctx, pool, otherDoc, 0)
	must(t, globalTx.Commit(ctx), "commit global request")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatal("committed global request failed to protect organization history")
	}
	_, err = pool.Exec(ctx, `UPDATE data_subject_requests SET status='denied' WHERE id=$1`, requestID)
	must(t, err, "deny global request fixture")

	// Reopening has no changed document FK, so the UPDATE trigger must fence
	// the global writer before its new status becomes visible to another txn.
	reopenTx, err := pool.Begin(ctx)
	must(t, err, "begin global reopen")
	defer reopenTx.Rollback(context.Background())
	_, err = reopenTx.Exec(ctx, `UPDATE data_subject_requests SET status='in_progress' WHERE id=$1`, requestID)
	must(t, err, "uncommitted global reopen")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatal("uncommitted global reopen did not fence expiry")
	}
	must(t, reopenTx.Commit(ctx), "commit global reopen")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatal("reopened global request did not protect history")
	}
	_, err = pool.Exec(ctx, `UPDATE data_subject_requests SET status='withdrawn' WHERE id=$1`, requestID)
	must(t, err, "withdraw global request fixture")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 1 {
		t.Fatalf("purge after withdrawing global request=%d", deleted)
	}

	// Linked status transitions must use the same document-before-request
	// lock order as creation; updating status alone does not retake the FK.
	linkedDoc := seedCollabArchiveRetentionDocument(t, ctx, pool, orgID, userID)
	seedCollabArchiveRetentionRecord(t, ctx, pool, linkedDoc, true)
	seedCollabArchiveRetentionRequest(t, ctx, pool, orgID, linkedDoc, "denied")
	linkedTx, err := pool.Begin(ctx)
	must(t, err, "begin linked reopen")
	defer linkedTx.Rollback(context.Background())
	var lockedID uuid.UUID
	must(t, linkedTx.QueryRow(ctx, `SELECT id FROM documents WHERE id=$1 FOR UPDATE`, linkedDoc).Scan(&lockedID), "lock document before linked reopen")
	_, err = linkedTx.Exec(ctx, `UPDATE data_subject_requests SET status='in_progress' WHERE document_id=$1`, linkedDoc)
	must(t, err, "uncommitted linked reopen")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatal("uncommitted document-locked reopen failed to protect history")
	}
	must(t, linkedTx.Commit(ctx), "commit linked reopen")
	if deleted := purgeCollabArchiveRetention(t, ctx, pool); deleted != 0 {
		t.Fatal("committed linked reopen failed to protect history")
	}
	assertCollabArchiveRetentionCount(t, ctx, pool, linkedDoc, 1)
}

func setupCollabArchiveRetentionE2E(t *testing.T) (context.Context, *pgxpool.Pool, uuid.UUID, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	t.Cleanup(cleanup)
	conn := stdlibConn(t, pool)
	must(t, mdb.RunMigrationsUpTo(conn, 72), "migrate archive expiry fixture")
	must(t, conn.Close(), "close migration connection")
	var orgID, userID uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO orgs(name,plan) VALUES('archive retention','pro') RETURNING id`).Scan(&orgID), "retention org")
	must(t, pool.QueryRow(ctx, `INSERT INTO users(org_id,email,name,role) VALUES($1,$2,'Owner','owner') RETURNING id`, orgID, uuid.NewString()+"@retention.test").Scan(&userID), "retention owner")
	return ctx, pool, orgID, userID
}

func seedCollabArchiveRetentionDocument(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, userID uuid.UUID) uuid.UUID {
	t.Helper()
	var docID uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind,blocks_json,variables_json)
VALUES($1,$2,'archive retention','blocks','{"version":1,"blocks":[]}','{}') RETURNING id`, orgID, userID).Scan(&docID), "retention document")
	return docID
}

func seedCollabArchiveRetentionRecord(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID uuid.UUID, expired bool) uuid.UUID {
	t.Helper()
	var archiveID uuid.UUID
	if expired {
		must(t, pool.QueryRow(ctx, `INSERT INTO collab_recovery_archives
(document_id,observed_canonical_generation,origin,ydoc_state,created_at,expires_at)
VALUES($1,1,'persisted',$2,now()-interval '100 days',now()-interval '10 days') RETURNING id`, docID, []byte("retained recovery")).Scan(&archiveID), "expired archive")
	} else {
		must(t, pool.QueryRow(ctx, `INSERT INTO collab_recovery_archives
(document_id,observed_canonical_generation,origin,ydoc_state)
VALUES($1,1,'persisted',$2) RETURNING id`, docID, []byte("fresh recovery")).Scan(&archiveID), "unexpired archive")
	}
	return archiveID
}

func seedCollabArchiveRetentionRequest(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, docID uuid.UUID, status string) {
	t.Helper()
	_, err := pool.Exec(ctx, `INSERT INTO data_subject_requests
(org_id,document_id,subject_email,kind,status,requested_via) VALUES($1,$2,'retention@example.test','access',$3,'dpo')`, orgID, docID, status)
	must(t, err, "pending retention request")
}

func purgeCollabArchiveRetention(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var deleted int64
	must(t, pool.QueryRow(ctx, `SELECT hash_purge_expired_collab_archives()`).Scan(&deleted), "purge expired archive batch")
	return deleted
}

func assertCollabArchiveRetentionCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID uuid.UUID, want int) {
	t.Helper()
	var count int
	if docID == uuid.Nil {
		must(t, pool.QueryRow(ctx, `SELECT count(*) FROM collab_recovery_archives`).Scan(&count), "count all archives")
	} else {
		must(t, pool.QueryRow(ctx, `SELECT count(*) FROM collab_recovery_archives WHERE document_id=$1`, docID).Scan(&count), "count document archives")
	}
	if count != want {
		t.Fatalf("document %s archives=%d, want %d", docID, count, want)
	}
}
