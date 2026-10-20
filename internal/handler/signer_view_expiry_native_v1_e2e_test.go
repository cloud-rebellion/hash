//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOwnedSignerViewExpiryDuringNativeAuditWaitRollsBackE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	party := parties[0]
	deadline := time.Now().Add(1500 * time.Millisecond)
	if _, err := f.pool.Exec(f.ctx, "UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1 AND document_id=$3", party.RecipientID, deadline, doc.ID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- controlled genuine-token expiry boundary, not source/measurement repair
	rc := q.lookupV1(t, party.Token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	if err = rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	var originalStatus string
	if err = f.pool.QueryRow(f.ctx, "SELECT status FROM recipients WHERE id=$1", party.RecipientID).Scan(&originalStatus); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- rollback oracle
	held, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Rollback(context.Background()) }()
	if err = f.q.WithTx(held).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	var holder int32
	if err = held.QueryRow(f.ctx, "SELECT pg_backend_pid()").Scan(&holder); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- actual blocker identity
	call, cancel := context.WithCancel(f.ctx)
	defer cancel()
	r := httptest.NewRequest(http.MethodPost, "/sign/"+party.Token+"/view", strings.NewReader(`{}`)).WithContext(call)
	r.Header.Set(signerNoticeDigestHeader, notice.NoticeDigest)
	result := make(chan *httptest.ResponseRecorder, 1)
	joined := false
	joinDeadline := deadline.Add(4030 * time.Millisecond)
	go func() { w := httptest.NewRecorder(); f.s.Routes().ServeHTTP(w, r); result <- w }()
	defer func() {
		if joined {
			return
		}
		cancel()
		_ = held.Rollback(context.Background())
		timer := time.NewTimer(max(time.Until(joinDeadline), time.Nanosecond))
		defer timer.Stop()
		select {
		case <-result:
			joined = true
		case <-timer.C:
			t.Error("native view request did not join its original cleanup deadline")
		}
	}()
	waiting := false
	observeUntil := time.Now().Add(time.Second)
	for time.Now().Before(observeUntil) {
		select {
		case w := <-result:
			joined = true
			t.Fatalf("native view returned before the held audit wait: %d", w.Code)
		default:
		}
		if err = f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE datname=current_database() AND position('AcquireOrgChainLock' in query)>0 AND wait_event='advisory' AND $1=ANY(pg_blocking_pids(a.pid)))`, holder).Scan(&waiting); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- independent actual native SQL wait observation
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("view did not enter its original native audit-chain wait")
	}
	time.Sleep(time.Until(deadline) + 30*time.Millisecond)
	if err = held.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-result:
		joined = true
		if w.Code != http.StatusGone || w.Header().Get("X-Hash-PDF-SHA256") != "" {
			t.Fatalf("late native view expiry status=%d", w.Code)
		}
	case <-time.After(max(time.Until(joinDeadline), time.Nanosecond)):
		t.Fatal("native view did not join after its audit lock was released")
	}
	q.assertObserversOnlyV1(t)
	var status string
	var events int
	if err = f.pool.QueryRow(f.ctx, `SELECT r.status,(SELECT count(*) FROM events WHERE document_id=$2 AND recipient_id=r.id AND kind='document.viewed') FROM recipients r WHERE r.id=$1`, party.RecipientID, doc.ID).Scan(&status, &events); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- actual rollback witness, no cache writes
	if status != originalStatus || events != 0 {
		t.Fatal("expired native view committed status or evidence")
	}
}
