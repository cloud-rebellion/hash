//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestDSRReopeningFencesRecoveryArchiveExpiryE2E(t *testing.T) {
	ctx, pool, q, s, org, user := setupDSRE2E(t)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: user, Name: "privacy reopen", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO collab_recovery_archives(document_id,observed_canonical_generation,origin,ydoc_state,created_at,expires_at) VALUES($1,1,'persisted',$2,clock_timestamp()-interval '100 days',clock_timestamp()-interval '10 days')`, doc.ID, []byte{1, 42})
	if err != nil {
		t.Fatal(err)
	}
	dsr, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{OrgID: org, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, SubjectEmail: "fixture@example.test", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res := transitionDSRE2E(s, org, user, dsr.ID, "denied"); res.Code != 200 {
		t.Fatalf("deny %d", res.Code)
	}
	locked, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Rollback(ctx)
	if _, err = q.WithTx(locked).GetDocumentForPrivacyUpdate(ctx, generated.GetDocumentForPrivacyUpdateParams{DocumentID: doc.ID, OrgID: org}); err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- transitionDSRE2E(s, org, user, dsr.ID, "in_progress") }()
	deadline := time.Now().Add(3 * time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		var count int
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event='transactionid' AND state='active'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			waiting = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("reopen did not wait on document fence")
	}
	if _, err = q.PurgeExpiredCollabRecoveryArchives(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM collab_recovery_archives WHERE document_id=$1`, doc.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("purge discarded locked history", err)
	}
	if err = locked.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-done:
		if res.Code != 200 {
			t.Fatalf("reopen %d %s", res.Code, res.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reopen did not finish")
	}
	if _, err = q.PurgeExpiredCollabRecoveryArchives(ctx); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM collab_recovery_archives WHERE document_id=$1`, doc.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("reopen did not protect expired history", err)
	}
	// Closing review must remain possible during the draft soft-delete grace.
	if _, err = pool.Exec(ctx, `UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	}
	if res := transitionDSRE2E(s, org, user, dsr.ID, "denied"); res.Code != 200 {
		t.Fatalf("soft-deleted review close %d %s", res.Code, res.Body.String())
	}
}
