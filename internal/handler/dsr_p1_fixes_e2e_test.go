//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/objectretire"
	"github.com/google/uuid"
)

// Fix verification 556db8c..f021b9d, findings M1, L1 and L2: a durable record of
// the object deletions an erasure owes, the subject bound to the linked recipient,
// and a retryable answer instead of a 500 when erasures collide.

func (f *dsrHistoryFixtureV1) pending(d dsrHistoryDocV1) []*generated.PendingObjectDeletionsV1 {
	f.t.Helper()
	rows, err := f.srv.Queries.ListPendingObjectDeletionsForDocumentV1(f.ctx, generated.ListPendingObjectDeletionsForDocumentV1Params{OrgID: f.org, DocumentID: d.id})
	if err != nil {
		f.t.Fatal(err)
	}
	return rows
}

// makeDue moves every pending row's retry time into the past, standing in for the
// backoff elapsing.
func (f *dsrHistoryFixtureV1) makeDue() {
	f.t.Helper()
	if _, err := f.srv.Pool.Exec(f.ctx, `UPDATE pending_object_deletions_v1 SET next_attempt_at = clock_timestamp() - interval '1 second' WHERE org_id=$1`, f.org); err != nil { //nolint:rawsql -- test stands in for the backoff elapsing
		f.t.Fatal(err)
	}
}

func (f *dsrHistoryFixtureV1) setObject(key string, body []byte) {
	f.peer.mu.Lock()
	f.peer.objects[key] = body
	f.peer.mu.Unlock()
}

func (f *dsrHistoryFixtureV1) object(key string) []byte {
	f.peer.mu.Lock()
	defer f.peer.mu.Unlock()
	return append([]byte(nil), f.peer.objects[key]...)
}

// M1: a storage fault after commit must leave a durable record, not an orphan. The
// fault is the exact-version check failing (the stored bytes do not match the
// committed SHA-256), the same branch an outage or a retention lock takes.
func TestDSRRetireFailureLeavesDurableRecordAndSweepDrainsItE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)

	// Positive control: healthy storage deletes the objects after commit and leaves
	// no pending row behind.
	healthy := f.seed(f.owner, "bob@corp.test", 2)
	healthyDSR := f.erasure(healthy, "bob@corp.test")
	f.start(healthyDSR, f.ownerCookie)
	if w := f.patch(healthyDSR, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("healthy erasure=%d %s", w.Code, w.Body.String())
	}
	if f.presentCount(healthy.keys) != 1 || len(f.pending(healthy)) != 0 {
		t.Fatalf("healthy erasure left present=%d pending=%d, want 1 (the current PDF) and 0", f.presentCount(healthy.keys), len(f.pending(healthy)))
	}

	doc := f.seed(f.owner, "ann@corp.test", 2)
	dsr := f.erasure(doc, "ann@corp.test")
	f.start(dsr, f.ownerCookie)
	original := f.object(doc.keys[0])
	f.setObject(doc.keys[0], []byte("%PDF-1.4 drifted bytes"))

	if w := f.patch(dsr, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("erasure under a storage fault=%d %s", w.Code, w.Body.String())
	}
	if f.status(dsr) != "fulfilled" || f.revisions(doc) != 0 {
		t.Fatalf("status=%s revisions=%d", f.status(dsr), f.revisions(doc))
	}
	// The object the fault protected is still stored, and the database says so.
	if !f.present(doc.keys[0]) {
		t.Fatal("the faulted object vanished without a delete")
	}
	if f.present(doc.keys[1]) {
		t.Fatal("the healthy revision object was not deleted")
	}
	rows := f.pending(doc)
	if len(rows) != 1 {
		t.Fatalf("pending rows=%d, want exactly the faulted object", len(rows))
	}
	row := rows[0]
	if row.StorageKey != doc.keys[0] || row.VersionID != "import-version-1" || len(row.Sha256) != 32 || row.OrgID != f.org || row.DocumentID != doc.id {
		t.Fatalf("pending row does not name the exact version: %+v", row)
	}
	if !row.DsrID.Valid || uuid.UUID(row.DsrID.Bytes) != dsr {
		t.Fatal("pending row does not name the erasure request")
	}
	if row.Attempts != 1 || row.LastError == "" || strings.Contains(strings.ToLower(row.LastError), "ann@") {
		t.Fatalf("attempts=%d last_error=%q", row.Attempts, row.LastError)
	}

	// The retry token is gone from the revision rows, so a repeat is still refused.
	if w := f.patch(dsr, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusConflict {
		t.Fatalf("repeat of a fulfilled erasure=%d", w.Code)
	}

	// Backoff holds: the sweep right away leases nothing.
	if claimed, deleted, err := objectretire.Sweep(f.ctx, f.srv.Queries, f.srv.Storage); err != nil || claimed != 0 || deleted != 0 {
		t.Fatalf("sweep inside the backoff claimed=%d deleted=%d err=%v", claimed, deleted, err)
	}
	// Still faulted: the sweep retries, counts the attempt and keeps the row.
	f.makeDue()
	if claimed, deleted, err := objectretire.Sweep(f.ctx, f.srv.Queries, f.srv.Storage); err != nil || claimed != 1 || deleted != 0 {
		t.Fatalf("sweep during the fault claimed=%d deleted=%d err=%v", claimed, deleted, err)
	}
	if rows := f.pending(doc); len(rows) != 1 || rows[0].Attempts != 2 || !f.present(doc.keys[0]) {
		t.Fatalf("a failed sweep must keep the row and count the attempt: %+v", rows)
	}

	// Storage recovers: the sweep deletes the object, then the row.
	f.setObject(doc.keys[0], original)
	f.makeDue()
	if claimed, deleted, err := objectretire.Sweep(f.ctx, f.srv.Queries, f.srv.Storage); err != nil || claimed != 1 || deleted != 1 {
		t.Fatalf("sweep after recovery claimed=%d deleted=%d err=%v", claimed, deleted, err)
	}
	if f.present(doc.keys[0]) || len(f.pending(doc)) != 0 {
		t.Fatalf("after the sweep original present=%v pending=%d, want gone and 0", f.present(doc.keys[0]), len(f.pending(doc)))
	}
	if !f.present(doc.keys[2]) {
		t.Fatal("the sweep deleted the document's current PDF")
	}
	// Nothing left to do.
	if claimed, _, err := objectretire.Sweep(f.ctx, f.srv.Queries, f.srv.Storage); err != nil || claimed != 0 {
		t.Fatalf("idle sweep claimed=%d err=%v", claimed, err)
	}
}

// M1: a request that rolls back records no pending deletion. The obligation exists
// only if the erasure committed.
func TestDSRRolledBackErasureRecordsNoPendingDeletionE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	doc := f.seed(f.owner, "ann@corp.test", 2)
	dsr := f.erasure(doc, "ann@corp.test")
	f.start(dsr, f.ownerCookie)

	fn := "dsr_pending_fail_" + strings.ReplaceAll(dsr.String(), "-", "")
	if _, err := f.srv.Pool.Exec(f.ctx, `CREATE FUNCTION `+fn+`() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected terminal failure'; END; $$ LANGUAGE plpgsql`); err != nil { //nolint:rawsql -- failure injection for this test's request only
		t.Fatal(err)
	}
	if _, err := f.srv.Pool.Exec(f.ctx, `CREATE TRIGGER `+fn+` BEFORE UPDATE ON data_subject_requests FOR EACH ROW WHEN (NEW.id = '`+dsr.String()+`' AND NEW.status = 'fulfilled') EXECUTE FUNCTION `+fn+`()`); err != nil { //nolint:rawsql -- failure injection for this test's request only
		t.Fatal(err)
	}
	if w := f.patch(dsr, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusInternalServerError {
		t.Fatalf("injected failure=%d %s", w.Code, w.Body.String())
	}
	if len(f.pending(doc)) != 0 || f.revisions(doc) != 2 || f.presentCount(doc.keys) != len(doc.keys) {
		t.Fatalf("a rolled-back erasure left pending=%d revisions=%d present=%d", len(f.pending(doc)), f.revisions(doc), f.presentCount(doc.keys))
	}
}

type dsrMismatchBodyV1 struct {
	Code      string `json:"code"`
	WillErase struct {
		Documents    int    `json:"pdf_revision_documents"`
		SubjectEmail string `json:"subject_email"`
	} `json:"will_erase"`
}

// L1: the owner approves a request by its subject_email, so the data erased must
// belong to that person. A request naming someone else is refused whole, and a
// request whose subject matches the linked recipient (case and padding aside)
// goes through, naming the matched email in its confirmation.
func TestDSRErasureRefusesSubjectThatIsNotTheLinkedRecipientE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	victim := f.seed(f.owner, "victim@corp.test", 1)
	mismatched := f.erasure(victim, "requester@corp.test")
	f.start(mismatched, f.ownerCookie)

	for _, body := range []string{`{"status":"fulfilled"}`, `{"status":"fulfilled","confirm":true}`} {
		wantDSRCodedV1(t, "mismatched subject "+body, f.patch(mismatched, body, f.ownerCookie), http.StatusConflict, "dsr_subject_mismatch")
	}
	if f.revisions(victim) != 1 || f.markers(victim) != 0 || f.historyEvents(victim) != 0 || len(f.pending(victim)) != 0 {
		t.Fatal("the refused request erased or recorded something")
	}
	if f.recipientEmail(victim) != "victim@corp.test" || f.status(mismatched) != "in_progress" || f.presentCount(victim.keys) != len(victim.keys) {
		t.Fatal("the refused request anonymized the recipient, closed the request or deleted objects")
	}

	// Positive control: the recipient's own request, with case and padding that the
	// scope query ignores, reaches the confirmation and then succeeds.
	ann := f.seed(f.owner, "ann@corp.test", 1)
	matching := f.erasure(ann, "  ANN@Corp.Test ")
	f.start(matching, f.ownerCookie)
	w := f.patch(matching, `{"status":"fulfilled"}`, f.ownerCookie)
	var body dsrMismatchBodyV1
	if w.Code != http.StatusConflict || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != "confirmation_required" {
		t.Fatalf("matching subject, unconfirmed: %d %s", w.Code, w.Body.String())
	}
	if body.WillErase.SubjectEmail != "ann@corp.test" || body.WillErase.Documents != 1 {
		t.Fatalf("the confirmation must name the matched email: %s", w.Body.String())
	}
	if w := f.patch(matching, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("matching subject, confirmed=%d %s", w.Code, w.Body.String())
	}
	if f.revisions(ann) != 0 || f.historyEvents(ann) != 1 {
		t.Fatal("the matching request did not erase the history")
	}
	// The mismatched request's target is still untouched after the other one ran.
	if f.revisions(victim) != 1 || f.recipientEmail(victim) != "victim@corp.test" {
		t.Fatal("the matching request reached the other recipient")
	}
}

// L2: two erasures for the same subject, linked to different documents, used to
// deadlock (one got a 500). They now take turns; if the first erasure changes
// the second request's reviewed scope, that request needs a fresh confirmation.
func TestDSRCrossLinkedErasuresDoNotDeadlockE2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	a := f.seed(f.owner, "ann@corp.test", 1)
	b := f.seed(f.owner, "ann@corp.test", 1)
	ra, rb := f.erasure(a, "ann@corp.test"), f.erasure(b, "ann@corp.test")
	f.start(ra, f.ownerCookie)
	f.start(rb, f.ownerCookie)
	var before int64
	if err := f.srv.Pool.QueryRow(f.ctx, `SELECT deadlocks FROM pg_stat_database WHERE datname=current_database()`).Scan(&before); err != nil { //nolint:rawsql -- deadlock counter oracle
		t.Fatal(err)
	}
	// Park both requests inside the transaction (authorize takes the user row FOR
	// SHARE), then release them together so they contend.
	blocker, err := f.srv.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(f.ctx, `SELECT 1 FROM users WHERE id=$1 FOR UPDATE`, f.owner); err != nil { //nolint:rawsql -- parks both requests
		t.Fatal(err)
	}
	type result struct {
		name string
		id   uuid.UUID
		code int
		body string
	}
	out := make(chan result, 2)
	for name, id := range map[string]uuid.UUID{"A": ra, "B": rb} {
		go func() {
			w := f.patch(id, `{"status":"fulfilled","confirm":true}`, f.ownerCookie)
			out <- result{name, id, w.Code, w.Body.String()}
		}()
	}
	waiting := 0
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if err := f.srv.Pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_locks WHERE NOT granted`).Scan(&waiting); err != nil { //nolint:rawsql -- waiter oracle
			t.Fatal(err)
		}
		if waiting >= 2 {
			break
		}
	}
	_ = blocker.Rollback(f.ctx)
	r1, r2 := <-out, <-out
	time.Sleep(1500 * time.Millisecond) // the server logs a deadlock after deadlock_timeout
	var after int64
	if err := f.srv.Pool.QueryRow(f.ctx, `SELECT deadlocks FROM pg_stat_database WHERE datname=current_database()`).Scan(&after); err != nil { //nolint:rawsql -- deadlock counter oracle
		t.Fatal(err)
	}
	t.Logf("parked_waiters=%d %s=%d | %s=%d | deadlocks %d->%d", waiting, r1.name, r1.code, r2.name, r2.code, before, after)
	if waiting < 2 {
		t.Fatalf("the fixture did not park both requests (waiters=%d); the test would prove nothing", waiting)
	}
	if after != before || (r1.code != http.StatusOK && r2.code != http.StatusOK) {
		t.Fatalf("concurrent erasures: %s=%d %s=%d deadlocks %d->%d", r1.name, r1.code, r2.name, r2.code, before, after)
	}
	for _, result := range []result{r1, r2} {
		if result.code == http.StatusOK {
			continue
		}
		var body dsrCodedBodyV1
		if result.code != http.StatusConflict || json.Unmarshal([]byte(result.body), &body) != nil || body.Code != "confirmation_required" || body.ConfirmationReceipt == "" {
			t.Fatalf("changed concurrent scope must request a fresh review, got %d %s", result.code, safeDSRResponseE2E(result.body))
		}
		input, _ := json.Marshal(dsrTransitionInput{Status: "fulfilled", Confirm: true, ConfirmationReceipt: body.ConfirmationReceipt})
		if w := f.patch(result.id, string(input), f.ownerCookie); w.Code != http.StatusOK {
			t.Fatalf("freshly reviewed concurrent scope=%d %s", w.Code, safeDSRResponseE2E(w.Body.String()))
		}
	}
	if f.revisions(a) != 0 || f.revisions(b) != 0 || f.status(ra) != "fulfilled" || f.status(rb) != "fulfilled" {
		t.Fatal("both erasures should have completed")
	}
}

// L2: a deadlock that still happens, here against a writer outside the erasure
// path, is a retryable 503 with Retry-After and leaves the request open. A repeat
// converges.
func TestDSRErasureDeadlockAgainstOtherWriterIsRetryable503E2E(t *testing.T) {
	f := newDSRHistoryFixtureV1(t)
	a := f.seed(f.owner, "ann@corp.test", 1)
	b := f.seed(f.owner, "ann@corp.test", 1)
	ra := f.erasure(a, "ann@corp.test")
	f.start(ra, f.ownerCookie)

	// An outside transaction holds the in-scope document b, then asks for the
	// linked document a that the erasure holds while it waits for b.
	outside, err := f.srv.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outside.Rollback(f.ctx) })
	if _, err := outside.Exec(f.ctx, `SELECT 1 FROM documents WHERE id=$1 FOR UPDATE`, b.id); err != nil { //nolint:rawsql -- outside writer holding an in-scope document
		t.Fatal(err)
	}
	type result struct {
		code   int
		header string
		body   string
	}
	erased := make(chan result, 1)
	go func() {
		w := f.patch(ra, `{"status":"fulfilled","confirm":true}`, f.ownerCookie)
		erased <- result{w.Code, w.Header().Get("Retry-After"), w.Body.String()}
	}()
	waitForWaiters := func(n int) {
		t.Helper()
		var waiting int
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if err := f.srv.Pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_locks WHERE NOT granted`).Scan(&waiting); err != nil { //nolint:rawsql -- waiter oracle
				t.Fatal(err)
			}
			if waiting >= n {
				return
			}
		}
		t.Fatalf("expected %d lock waiters, saw %d", n, waiting)
	}
	waitForWaiters(1) // the erasure is queued behind the outside transaction on b
	var wg sync.WaitGroup
	wg.Add(1)
	var outsideErr error
	go func() {
		defer wg.Done()
		_, outsideErr = outside.Exec(f.ctx, `SELECT 1 FROM documents WHERE id=$1 FOR UPDATE`, a.id) //nolint:rawsql -- closes the lock cycle
	}()
	// The erasure queued first, so its deadlock check runs first and it is the victim.
	got := <-erased
	if got.code != http.StatusServiceUnavailable || got.header == "" || !strings.Contains(got.body, "retry") {
		t.Fatalf("deadlocked erasure=%d Retry-After=%q %s, want a retryable 503", got.code, got.header, got.body)
	}
	wg.Wait()
	if outsideErr != nil {
		t.Fatalf("the outside writer was the victim instead: %v", outsideErr)
	}
	if err := outside.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.status(ra) != "in_progress" || f.revisions(a) != 1 || f.revisions(b) != 1 || f.recipientEmail(a) != "ann@corp.test" {
		t.Fatal("the deadlocked erasure changed state")
	}

	// Positive control: the repeat converges.
	if w := f.patch(ra, `{"status":"fulfilled","confirm":true}`, f.ownerCookie); w.Code != http.StatusOK {
		t.Fatalf("repeat after the deadlock=%d %s", w.Code, w.Body.String())
	}
	if f.revisions(a) != 0 || f.revisions(b) != 0 {
		t.Fatal("the repeat did not erase both documents")
	}
}
