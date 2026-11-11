//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Fix verification f021b9d..8621ab3, findings N2 and N3: lock contention on the
// erasure path is a retryable answer, never a 500, and a transition that cannot be
// valid does not queue for the organization lock.

// holdErasureOrgLockE2E stands in for a concurrent erasure fulfilment of the same
// organization that is still running: it holds the advisory key that
// LockDSRErasureFulfilmentV1 waits on until the returned transaction ends.
func (f *dsrHistoryFixtureV1) holdErasureOrgLockE2E() pgx.Tx {
	f.t.Helper()
	outside, err := f.srv.Pool.Begin(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = outside.Rollback(f.ctx) })
	if _, err := outside.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hashtextextended('hash-dsr-erasure:' || $1::text, 0))`, f.org.String()); err != nil { //nolint:rawsql -- stands in for a running erasure of the same org
		f.t.Fatal(err)
	}
	return outside
}

// N2: a package or amendment transaction holds the shared privacy fence on the
// linked document, so RedactDSRSubjectIdentifiers raises 55P03 while the request
// is still in_progress. That is the privacy-contention 409, not a 500, and the
// rolled-back request converges once the fence is released.
func TestDSRRedactFenceContentionIsRetryableE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	a := f.seed(f.owner, "ann@corp.test", 1)
	ra := f.erasure(a, "ann@corp.test")
	f.start(ra, f.ownerCookie)

	outside, err := f.srv.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outside.Rollback(f.ctx) })
	var held bool
	if err := outside.QueryRow(f.ctx, `SELECT hash_try_document_package_privacy_fence_v1($1,$2)`, f.org, a.id).Scan(&held); err != nil || !held { //nolint:rawsql -- a package transaction holding the shared fence
		t.Fatalf("fence held=%v err=%v", held, err)
	}

	w := f.patch(ra, `{"status":"fulfilled","confirm":true}`, f.ownerCookie)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "privacy review is changing") {
		t.Fatalf("erasure against a held fence=%d %s, want the retryable privacy-contention 409", w.Code, w.Body.String())
	}
	if f.status(ra) != "in_progress" || f.revisions(a) != 1 || f.recipientEmail(a) != "ann@corp.test" || len(f.pending(a)) != 0 {
		t.Fatal("the contended erasure changed state")
	}

	// Positive control: with the fence released the repeat converges.
	if err := outside.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if w := f.patch(ra, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("repeat after the fence was released=%d %s", w.Code, w.Body.String())
	}
	if f.status(ra) != "fulfilled" || f.revisions(a) != 0 {
		t.Fatal("the repeat did not erase the history")
	}
}

// N3: a valid fulfilment that waits on the organization lock past the 10 s
// transaction deadline is a retryable 503 with Retry-After, not a 500, and it
// converges once the lock is free.
func TestDSRErasureOrgLockWaitDeadlineIsRetryable503E2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	a := f.seed(f.owner, "ann@corp.test", 1)
	ra := f.erasure(a, "ann@corp.test")
	f.start(ra, f.ownerCookie)
	outside := f.holdErasureOrgLockE2E()

	started := time.Now()
	w := f.patch(ra, `{"status":"fulfilled","confirm":true}`, f.ownerCookie)
	waited := time.Since(started)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" || !strings.Contains(w.Body.String(), "retry") {
		t.Fatalf("erasure behind a held org lock=%d Retry-After=%q %s after %s, want a retryable 503", w.Code, w.Header().Get("Retry-After"), w.Body.String(), waited)
	}
	if waited < sessionTransactionTimeout/2 {
		t.Fatalf("answered after %s: the request did not actually wait on the lock", waited)
	}
	if f.status(ra) != "in_progress" || f.revisions(a) != 1 {
		t.Fatal("the timed-out erasure changed state")
	}

	if err := outside.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if w := f.patch(ra, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("repeat after the lock was released=%d %s", w.Code, w.Body.String())
	}
}

// N3: an invalid transition is refused by the pre-lock check, so it neither waits
// for a held organization lock nor changes its answer because of it.
func TestDSRInvalidTransitionIsRefusedWithoutWaitingForTheOrgLockE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	b := f.seed(f.owner, "bob@corp.test", 1)
	rb := f.erasure(b, "bob@corp.test")
	f.start(rb, f.ownerCookie)
	if w := f.patch(rb, `{"status":"withdrawn"}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("withdraw=%d %s", w.Code, w.Body.String())
	}
	// Control with the lock free.
	free := f.patch(rb, `{"status":"fulfilled","confirm":true}`, f.ownerCookie)
	if free.Code != http.StatusConflict || !strings.Contains(free.Body.String(), "invalid transition withdrawn") {
		t.Fatalf("invalid transition, lock free=%d %s", free.Code, free.Body.String())
	}

	f.holdErasureOrgLockE2E()
	started := time.Now()
	held := f.patch(rb, `{"status":"fulfilled","confirm":true}`, f.ownerCookie)
	waited := time.Since(started)
	if waited > 3*time.Second {
		t.Fatalf("an invalid transition waited %s for the org lock", waited)
	}
	if held.Code != free.Code || held.Body.String() != free.Body.String() {
		t.Fatalf("invalid transition with the lock held=%d %s, lock free=%d %s", held.Code, held.Body.String(), free.Code, free.Body.String())
	}
	if f.status(rb) != "withdrawn" || f.revisions(b) != 1 {
		t.Fatal("the refused transition changed state")
	}
}
