//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5"
)

const nativeCommentBody163V1 = "Synthetic native comment ÅÄÖ: complete ownership and atomic rollback"

type nativeCommentState163V1 struct {
	document                               *generated.Document
	recipients                             []*generated.Recipient
	comments, events, measurements, outbox string
}

func captureNativeCommentState163V1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document) nativeCommentState163V1 {
	t.Helper()
	f := q.f
	var s nativeCommentState163V1
	var err error
	s.document, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	s.recipients, err = f.q.ListRecipientsByDocument(f.ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(s.recipients, func(i, j int) bool { return s.recipients[i].ID.String() < s.recipients[j].ID.String() })
	for _, item := range []struct {
		sql  string
		out  *string
		args []any
	}{
		{"SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.id),'[]'::jsonb)::text FROM document_comments x WHERE x.document_id=$1", &s.comments, []any{doc.ID}},
		{"SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.id),'[]'::jsonb)::text FROM events x WHERE x.document_id=$1 AND x.org_id=$2", &s.events, []any{doc.ID, f.org}},
		{"SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.event_id),'[]'::jsonb)::text FROM html_snapshot_event_payload_sizes_v1 x WHERE x.document_id=$1 AND x.org_id=$2", &s.measurements, []any{doc.ID, f.org}},
		{"SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.id),'[]'::jsonb)::text FROM email_deliveries x WHERE x.subject=$1", &s.outbox, []any{"New comment on " + doc.Name}},
	} {
		if err = f.pool.QueryRow(f.ctx, item.sql, item.args...).Scan(item.out); err != nil {
			t.Fatal(err)
		}
	} //nolint:rawsql -- exact whole fresh synthetic rollback witnesses only
	return s
}
func assertNativeCommentUnchanged163V1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, before nativeCommentState163V1) {
	t.Helper()
	after := captureNativeCommentState163V1(t, q, doc)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("native refusal changed complete document, recipients, comments, audit measurements or comment outbox")
	}
	ownedRevisionConsumedV1(t, q)
	if got := q.runtime.SessionsV1().PendingV1(); got != (pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 2}) {
		t.Fatal("joined response retained an input/canonical/other consumer", got)
	}
}
func nativeCommentNotice163V1(t *testing.T, q *ownedPublicReadFixtureV1, token string) string {
	t.Helper()
	w := q.requestV1(token, "")
	var page signerContextResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Privacy.NoticeDigest == "" {
		t.Fatal("actual current notice unavailable")
	}
	ownedRevisionConsumedV1(t, q)
	return page.Privacy.NoticeDigest
}
func nativeCommentRequest163V1(t *testing.T, q *ownedPublicReadFixtureV1, ctx context.Context, doc *generated.Document, side, token, notice, cookie string) *http.Request {
	t.Helper()
	body, err := json.Marshal(createCommentInput{Body: nativeCommentBody163V1})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/documents/" + doc.ID.String() + "/comments"
	if side == "signer" {
		path = "/sign/" + token + "/comments"
	} else if side != "sender" {
		t.Fatal("unknown closed comment side")
	}
	r := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+path, bytes.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", q.f.s.PublicURL)
	if side == "signer" {
		r.Header.Set(signerNoticeDigestHeader, notice)
	} else {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	return r
}
func nativeCommentAuditHolder163V1(t *testing.T, q *ownedPublicReadFixtureV1) (pgx.Tx, int32) {
	t.Helper()
	tx, err := q.f.pool.Begin(q.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Register bounded release before a request can ever borrow this blocker.
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = tx.Rollback(ctx)
	})
	if err = q.f.q.WithTx(tx).AcquireOrgChainLock(q.f.ctx, q.f.org.String()); err != nil {
		t.Fatal(err)
	}
	var pid int32
	if err = tx.QueryRow(q.f.ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- actual independent blocker identity
	return tx, pid
}

type nativeCommentJob163V1 struct {
	done   chan struct{}
	cancel context.CancelFunc
	w      *httptest.ResponseRecorder
}

func startNativeCommentJob163V1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, side, token, notice, cookie string, held pgx.Tx) *nativeCommentJob163V1 {
	t.Helper()
	ctx, cancel := context.WithCancel(q.f.ctx)
	j := &nativeCommentJob163V1{done: make(chan struct{}), cancel: cancel, w: httptest.NewRecorder()}
	r := nativeCommentRequest163V1(t, q, ctx, doc, side, token, notice, cookie)
	joinUntil := time.Now().Add(7 * time.Second)
	t.Cleanup(func() {
		cancel()
		if held != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			_ = held.Rollback(cleanup)
			stop()
		}
		select {
		case <-j.done:
		case <-time.After(max(time.Until(joinUntil), time.Nanosecond)):
			t.Error("actual native comment goroutine did not join its bounded cleanup")
		}
	})
	go func() { defer close(j.done); q.f.s.Routes().ServeHTTP(j.w, r) }()
	return j
}
func (j *nativeCommentJob163V1) joinV1(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case <-j.done:
		return j.w
	case <-time.After(4 * time.Second):
		t.Fatal("native comment did not join after actual blocker release")
		return nil
	}
}

// This writer deliberately does NOT unblock on request cancellation. Its
// independent finite lifetime is a test failure escape, never release proof.
type nativeCommentResponseWriter163V1 struct {
	*httptest.ResponseRecorder
	entered  chan struct{}
	release  <-chan struct{}
	life     context.Context
	once     sync.Once
	timedOut atomic.Bool
}

func (w *nativeCommentResponseWriter163V1) Write(p []byte) (int, error) {
	if w.Code == http.StatusCreated && len(p) > 0 {
		w.once.Do(func() { close(w.entered) })
		select {
		case <-w.release:
		case <-w.life.Done():
			w.timedOut.Store(true)
			return 0, w.life.Err()
		}
	}
	return w.ResponseRecorder.Write(p)
}

func TestOwnedCommentResponseWriteRetainsDebtAfterCancellationE2E(t *testing.T) {
	for _, side := range []string{"signer", "sender"} {
		t.Run(side, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			notice := nativeCommentNotice163V1(t, q, parties[0].Token)
			before := captureNativeCommentState163V1(t, q, doc)
			ctx, cancel := context.WithCancel(q.f.ctx)
			joinUntil := time.Now().Add(8 * time.Second)
			life, stop := context.WithDeadline(context.Background(), joinUntil)
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			w := &nativeCommentResponseWriter163V1{ResponseRecorder: httptest.NewRecorder(), entered: entered, release: release, life: life}
			r := nativeCommentRequest163V1(t, q, ctx, doc, side, parties[0].Token, notice, q.cookie)
			// Cleanup is registered before launch and precedes fixture teardown.
			t.Cleanup(func() {
				unblock()
				cancel()
				defer stop()
				select {
				case <-done:
				case <-time.After(max(time.Until(joinUntil), time.Nanosecond)):
					t.Error("actual blocked comment writer did not join")
				}
			})
			go func() { defer close(done); q.f.s.Routes().ServeHTTP(w, r) }()
			select {
			case <-entered:
			case <-done:
				t.Fatal("native comment ended before actual201 body Write", w.Code)
			case <-time.After(5 * time.Second):
				t.Fatal("native comment did not reach real body Write")
			}
			// Independent current DB witnesses prove this is postcommit, not merely a
			// charged request stopped before Create/audit/notification.
			rows, err := q.f.q.ListComments(q.f.ctx, doc.ID)
			if err != nil || len(rows) != 1 || rows[0].Body != nativeCommentBody163V1 || rows[0].AuthorSide != side {
				t.Fatal("actual201 write lacks committed comment", err)
			}
			after := captureNativeCommentState163V1(t, q, doc)
			if !reflect.DeepEqual(before.document, after.document) || !reflect.DeepEqual(before.recipients, after.recipients) {
				t.Fatal("comment changed source or recipient state")
			}
			var audits, measured int
			var payload []byte
			err = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer,count(*) FILTER(WHERE m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer)::integer FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.comment_posted'", doc.ID, q.f.org).Scan(&audits, &measured)
			if err != nil || audits != 1 || measured != 1 {
				t.Fatal("actual201 write lacks exact intrinsic audit measurement", err)
			} //nolint:rawsql -- actual event/measurement witness only
			if err = q.f.pool.QueryRow(q.f.ctx, "SELECT payload_json FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.comment_posted'", doc.ID, q.f.org).Scan(&payload); err != nil {
				t.Fatal(err)
			} //nolint:rawsql
			if side == "signer" && article13.ValidateAuditPayload(payload, q.f.org, doc.ID, parties[0].RecipientID) != nil {
				t.Fatal("committed public comment lost full notice evidence")
			}
			recs, err := q.f.q.ListRecipientsByDocument(q.f.ctx, doc.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, email := range []string{q.f.user.Email, recs[0].Email, recs[1].Email} {
				want := 0
				if (side == "signer" && email == q.f.user.Email) || (side == "sender" && email != q.f.user.Email) {
					want = 1
				}
				var count int
				if err = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM email_deliveries WHERE to_email=$1 AND subject=$2", email, "New comment on "+doc.Name).Scan(&count); err != nil || count != want {
					t.Fatal("actual201 notification fanout differs", count, want, err)
				}
			} //nolint:rawsql
			q.reconcileV1(t)
			want := pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 2, HTMLAdmissions: 1, HTMLInputProducers: 1}
			if side == "signer" {
				want.HTMLAdmissions = 2
				want.SignerReaders = 1
				want.SignerScopes = 1
			}
			pending, snapshot := q.runtime.SessionsV1().PendingV1(), q.snapshotV1(t)
			if pending != want {
				t.Fatal("actual blocked201 consumer topology differs", pending, want)
			}
			if snapshot.Global.SQLSessions != 2 || snapshot.Organisation.SQLSessions != 1 || snapshot.Organisation.ParentBytes <= 0 || snapshot.Organisation.DBStagingBytes <= 0 {
				t.Fatal("committed body lost actual result debt", snapshot)
			}
			global, org := snapshot.Global, snapshot.Organisation
			global.ParentBytes, global.DBStagingBytes, global.SQLSessions = 0, 0, 0
			org.ParentBytes, org.DBStagingBytes, org.SQLSessions = 0, 0, 0
			if global != (workguard.VectorV1{}) || org != (workguard.VectorV1{}) {
				t.Fatal("unrelated worker/dial/renderer debt survived postcommit")
			}
			extra, grants := int64(0), int64(1)
			if side == "signer" {
				extra = 8 << 20
				grants = 2
			}
			if snapshot.Global.ParentBytes-snapshot.Organisation.ParentBytes != extra || snapshot.Global.DBStagingBytes-snapshot.Organisation.DBStagingBytes != extra || snapshot.GlobalGrants-snapshot.OrganisationGrants != grants {
				t.Fatal("actual process/tenant debt split differs", snapshot)
			}
			cancel()
			q.reconcileV1(t)
			select {
			case <-done:
				t.Fatal("request cancellation ended a still-running body consumer")
			default:
			}
			if got := q.runtime.SessionsV1().PendingV1(); got != pending {
				t.Fatal("cancellation/reconcile refunded real consumers", got, pending)
			}
			if got := q.snapshotV1(t); got != snapshot {
				t.Fatal("cancellation/reconcile refunded actual body debt", got, snapshot)
			}
			unblock()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("actual body writer did not join after explicit release")
			}
			if w.timedOut.Load() || w.Code != http.StatusCreated {
				t.Fatal("writer required its independent failure timeout", w.Code)
			}
			var response commentResponse
			if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.ID != rows[0].ID.String() || response.Body != nativeCommentBody163V1 {
				t.Fatal("actual last-use bytes lost original comment")
			}
			ownedRevisionConsumedV1(t, q)
			if q.runtime.SessionsV1().PendingV1() != (pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 2}) {
				t.Fatal("joined actual body retained consumers")
			}
		})
	}
}

func TestOwnedPublicCommentExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	deadline := time.Now().Add(1500 * time.Millisecond)
	if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_expires_at=$1 WHERE id=$2 AND document_id=$3", deadline, parties[0].RecipientID, doc.ID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- genuine original-token natural expiry boundary, not authority/measurement repair
	notice := nativeCommentNotice163V1(t, q, parties[0].Token)
	before := captureNativeCommentState163V1(t, q, doc)
	held, pid := nativeCommentAuditHolder163V1(t, q)
	job := startNativeCommentJob163V1(t, q, doc, "signer", parties[0].Token, notice, "", held)
	ownedReadWaitV1(t, q, pid, "AcquireOrgChainLock")
	if delay := time.Until(deadline) + 30*time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}
	if err := held.Commit(q.f.ctx); err != nil {
		t.Fatal(err)
	}
	w := job.joinV1(t)
	if w.Code != http.StatusGone {
		t.Fatal("expired native comment did not retain final credential gate", w.Code)
	}
	assertNativeCommentUnchanged163V1(t, q, doc, before)
}

func TestOwnedStaffCommentAuthorizationAfterDocumentWaitE2E(t *testing.T) {
	for _, change := range []string{"demotion", "logout", "expiry"} {
		t.Run(change, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			_ = nativeCommentNotice163V1(t, q, parties[0].Token)
			other := seedSessionOwnerE2E(t, q.f.ctx, q.f.q, q.f.org)
			owner, err := q.f.q.GetUser(q.f.ctx, other)
			if err != nil {
				t.Fatal(err)
			}
			cookie := q.cookie
			if change == "expiry" {
				cookie = dsrSessionCookieE2E(t, q.f.s, q.f.user.ID, q.f.user.SessionGeneration, 2*time.Second)
			}
			before := captureNativeCommentState163V1(t, q, doc)
			held, pid := ownedReadHolderV1(t, q, doc.ID, false)
			job := startNativeCommentJob163V1(t, q, doc, "sender", "", "", cookie, held)
			ownedReadWaitV1(t, q, pid, "GetHTMLSendDocumentStateHeaderV1")
			status := http.StatusForbidden
			switch change {
			case "demotion":
				otherCookie := dsrSessionCookieE2E(t, q.f.s, other, owner.SessionGeneration, time.Hour)
				w := submitSessionOperationContextE2E(q.f.ctx, q.f.s, http.MethodPatch, "/api/v1/members/"+q.f.user.ID.String()+"/role", "{\"role\":\"viewer\"}", otherCookie)
				if w.Code != http.StatusOK {
					t.Fatal("actual member demotion failed", w.Code)
				}
			case "logout":
				w := submitSessionOperationContextE2E(q.f.ctx, q.f.s, http.MethodPost, "/auth/logout", "", cookie)
				if w.Code != http.StatusOK {
					t.Fatal("actual logout failed", w.Code)
				}
			case "expiry":
				awaitSessionCookieExpiryE2E(t, q.f.s, cookie)
				status = http.StatusUnauthorized
			}
			if err = held.Commit(q.f.ctx); err != nil {
				t.Fatal(err)
			}
			w := job.joinV1(t)
			if w.Code != status {
				t.Fatal("native comment used stale staff authorization", change, w.Code, status)
			}
			assertNativeCommentUnchanged163V1(t, q, doc, before)
		})
	}
}

func TestOwnedStaffCommentExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	for _, mode := range []string{"queue", "direct-adapter"} {
		t.Run(mode, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			_ = nativeCommentNotice163V1(t, q, parties[0].Token)
			spy := &senderCommentDeliverySpy{}
			if mode == "direct-adapter" {
				q.f.s.Sign.Mailer = spy
			}
			before := captureNativeCommentState163V1(t, q, doc)
			held, pid := nativeCommentAuditHolder163V1(t, q)
			cookie := dsrSessionCookieE2E(t, q.f.s, q.f.user.ID, q.f.user.SessionGeneration, 2*time.Second)
			job := startNativeCommentJob163V1(t, q, doc, "sender", "", "", cookie, held)
			ownedReadWaitV1(t, q, pid, "AcquireOrgChainLock")
			awaitSessionCookieExpiryE2E(t, q.f.s, cookie)
			if err := held.Commit(q.f.ctx); err != nil {
				t.Fatal(err)
			}
			w := job.joinV1(t)
			if w.Code != http.StatusUnauthorized {
				t.Fatal("native comment lost original final cookie check", w.Code)
			}
			if spy.calls.Load() != 0 {
				t.Fatal("rejected native comment invoked synchronous delivery")
			}
			assertNativeCommentUnchanged163V1(t, q, doc, before)
		})
	}
}

// Sequences intentionally observe a negative injection despite transaction
// rollback. They confer no permission and never repair source/size measurements.
func nativeCommentFault163V1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, side, stage string) (func() int64, int64) {
	t.Helper()
	tag := "cmt163_" + strings.ReplaceAll(doc.ID.String(), "-", "")
	fn, trig, seq := tag+"_fn", tag+"_trg", tag+"_seq"
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }
	table, condition := "document_comments", "NEW.document_id="+quote(doc.ID.String())+"::uuid"
	want := int64(1)
	if stage == "audit" || stage == "audit-no-row" {
		table = "events"
		condition += " AND NEW.kind='document.comment_posted'"
	}
	failure := "RAISE EXCEPTION 'private native comment fault163'"
	if stage == "audit-no-row" {
		failure = "RETURN NULL"
	}
	action := failure
	if stage == "outbox" {
		table = "email_deliveries"
		recs, err := q.f.q.ListRecipientsByDocument(q.f.ctx, doc.ID)
		if err != nil || len(recs) != 2 {
			t.Fatal("actual notification targets missing", err)
		}
		if side == "signer" {
			condition = "NEW.subject=" + quote("New comment on "+doc.Name) + " AND NEW.to_email=" + quote(q.f.user.Email)
		} else {
			first, last := quote(recs[0].Email), quote(recs[1].Email)
			condition = "NEW.subject=" + quote("New comment on "+doc.Name) + " AND NEW.to_email IN (" + first + "," + last + ")"
			action = "IF NEW.to_email=" + last + " THEN " + failure + "; END IF"
			want = 2 // First actual recipient insert precedes the second recipient fault.
		}
	}
	sql := fmt.Sprintf("CREATE SEQUENCE %s; CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF %s THEN PERFORM nextval('%s'); %s; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION %s()", seq, fn, condition, seq, action, trig, table, fn)
	// Pre-register exact bounded cleanup before exposing the trigger.
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := q.f.pool.Exec(ctx, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s(); DROP SEQUENCE IF EXISTS %s", trig, table, fn, seq)); err != nil {
			t.Error(err)
		}
	})
	if _, err := q.f.pool.Exec(q.f.ctx, sql); err != nil {
		t.Fatal(err)
	} //nolint:rawsql,gosec -- only generated UUID identifiers/closed table names and escaped fixture literals
	read := func() int64 {
		var last int64
		var called bool
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT last_value,is_called FROM "+seq).Scan(&last, &called); err != nil {
			t.Fatal(err)
		}
		if !called {
			return 0
		}
		return last
	} //nolint:rawsql,gosec -- isolated nontransactional negative-fault observation
	return read, want
}
func TestOwnedCommentInjectedFailuresAreAtomicAndPrivateE2E(t *testing.T) {
	for _, side := range []string{"signer", "sender"} {
		for _, stage := range []string{"comment", "audit", "audit-no-row", "outbox"} {
			t.Run(side+"-"+stage, func(t *testing.T) {
				q := newOwnedPublicReadFixtureV1(t)
				doc, parties := q.createSentV1(t)
				notice := nativeCommentNotice163V1(t, q, parties[0].Token)
				before := captureNativeCommentState163V1(t, q, doc)
				hits, want := nativeCommentFault163V1(t, q, doc, side, stage)
				w := httptest.NewRecorder()
				q.f.s.Routes().ServeHTTP(w, nativeCommentRequest163V1(t, q, q.f.ctx, doc, side, parties[0].Token, notice, q.cookie))
				if w.Code != http.StatusServiceUnavailable {
					t.Fatal("native internal failure classification changed", side, stage, w.Code)
				}
				if got := hits(); got != want {
					t.Fatal("request did not reach exact actual injected SQL boundary", stage, got, want)
				}
				for _, private := range []string{"private native comment fault163", "cmt163_", "SQLSTATE", "PL/pgSQL", nativeCommentBody163V1} {
					if strings.Contains(w.Body.String(), private) {
						t.Fatal("native failure leaked private cause/body")
					}
				}
				assertNativeCommentUnchanged163V1(t, q, doc, before)
			})
		}
	}
}
