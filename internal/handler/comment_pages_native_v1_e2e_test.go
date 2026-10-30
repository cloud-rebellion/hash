//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/commentwindow"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func ownedCommentPageRequest166V1(q *ownedPublicReadFixtureV1, ctx context.Context, doc *generated.Document, token, query string) *http.Request {
	path := "/api/v1/documents/" + doc.ID.String() + "/comments"
	if token != "" {
		path = "/sign/" + token + "/comments"
	}
	if query != "" {
		path += "?" + query
	}
	r := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+path, nil).WithContext(ctx)
	if token == "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
	}
	return r
}

func ownedCommentPage166V1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, token, query string) pdfadmission.CommentPageResponseV1 {
	t.Helper()
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, ownedCommentPageRequest166V1(q, q.f.ctx, doc, token, query))
	var page pdfadmission.CommentPageResponseV1
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Comments) > commentwindow.Limit || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("actual bounded comment GET failed status%d: %.200s", w.Code, w.Body.String())
	}
	nativeCommentDrained164V1(t, q)
	return page
}

// These are deliberately stored historical text rows, including values beyond
// today's POST limit. This fixture grants no signing/event/measurement authority.
// Later in the test a genuine native POST proves the ordinary Latest refresh.
func ownedHistoricalCommentRows166V1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document) (time.Time, string, string) {
	t.Helper()
	var at time.Time
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT clock_timestamp()").Scan(&at); err != nil {
		t.Fatal(err)
	}
	large := strings.Repeat("Å<&\u2028\x01", 6500)
	sentinel := strings.Repeat("S\x01", 65536)
	_, err := q.f.pool.Exec(q.f.ctx, `INSERT INTO document_comments
		(id,document_id,user_id,author_name,author_side,body,created_at)
		SELECT ('16600000-0000-4000-8000-'||lpad(to_hex(n),12,'0'))::uuid,$1,$3,
		       'Historical author Å<&','sender',
		       CASE WHEN n=100 THEN $4 WHEN n=55 THEN $5 ELSE format('Historical message %s Å<&',n) END,
		       $2::timestamptz+((n-1)/35)*interval '1 microsecond'
		FROM generate_series(1,105) AS n`, doc.ID, at, q.f.user.ID, large, sentinel)
	if err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- bounded actual historical fixtures, not an application write substitute
	return at, large, sentinel
}

func assertOwnedCommentRange166V1(t *testing.T, page pdfadmission.CommentPageResponseV1, first, last int, at time.Time) {
	t.Helper()
	if len(page.Comments) != last-first+1 {
		t.Fatal("wrong visible comment count", len(page.Comments), first, last)
	}
	for i, row := range page.Comments {
		n := first + i
		if row.ID != fmt.Sprintf("16600000-0000-4000-8000-%012x", n) {
			t.Fatal("comment tie-break position skipped/repeated", n, row.ID)
		}
		actual, err := time.Parse(time.RFC3339Nano, row.CreatedAt)
		if err != nil || !actual.Equal(at.Add(time.Duration((n-1)/35)*time.Microsecond)) {
			t.Fatal("stored microsecond lost in DTO", row.CreatedAt, err)
		}
	}
}

func TestOwnedCommentPagesPreserveWholeHistoryAndAccessE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	at, large, sentinel := ownedHistoricalCommentRows166V1(t, q, doc)
	before := captureNativeCommentState163V1(t, q, doc)
	for _, side := range []string{"public", "staff"} {
		t.Run(side, func(t *testing.T) {
			token := ""
			if side == "public" {
				token = parties[0].Token
			}
			latest := ownedCommentPage166V1(t, q, doc, token, "")
			assertOwnedCommentRange166V1(t, latest, 56, 105, at)
			if latest.OlderCursor == nil || latest.NewerCursor != nil || latest.Comments[44].Body != large {
				t.Fatal("latest omitted old large body or wrong edge")
			}
			middle := ownedCommentPage166V1(t, q, doc, token, "before="+*latest.OlderCursor)
			assertOwnedCommentRange166V1(t, middle, 6, 55, at)
			if middle.OlderCursor == nil || middle.NewerCursor == nil || middle.Comments[49].Body != sentinel {
				t.Fatal("older page truncated historical body or lost edge")
			}
			oldest := ownedCommentPage166V1(t, q, doc, token, "before="+*middle.OlderCursor)
			assertOwnedCommentRange166V1(t, oldest, 1, 5, at)
			if oldest.OlderCursor != nil || oldest.NewerCursor == nil {
				t.Fatal("oldest page lost forward navigation")
			}
			forward := ownedCommentPage166V1(t, q, doc, token, "after="+*oldest.NewerCursor)
			if !reflect.DeepEqual(forward, middle) {
				t.Fatal("newer did not restore exact tied-timestamp middle window")
			}
			forward = ownedCommentPage166V1(t, q, doc, token, "after="+*forward.NewerCursor)
			if !reflect.DeepEqual(forward, latest) {
				t.Fatal("newer did not restore latest window")
			}
			foreign, err := commentwindow.Cursor(uuid.New(), doc.ID, uuid.New(), at)
			if err != nil {
				t.Fatal(err)
			}
			for _, query := range []string{"limit=1000", "before=x", "before=" + *latest.OlderCursor + "&after=" + *latest.OlderCursor, "before=" + foreign} {
				w := httptest.NewRecorder()
				q.f.s.Routes().ServeHTTP(w, ownedCommentPageRequest166V1(q, q.f.ctx, doc, token, query))
				if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "Historical") {
					t.Fatal("ambiguous/foreign selector was accepted or disclosed stored data", w.Code)
				}
				nativeCommentDrained164V1(t, q)
			}
		})
	}
	assertNativeCommentUnchanged163V1(t, q, doc, before)
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, nativeCommentRequest163V1(t, q, q.f.ctx, doc, "sender", "", "", q.cookie))
	if w.Code != http.StatusCreated {
		t.Fatalf("native new message failed%d:%.200s", w.Code, w.Body.String())
	}
	var posted commentResponse
	if err := json.Unmarshal(w.Body.Bytes(), &posted); err != nil {
		t.Fatal(err)
	}
	nativeCommentDrained164V1(t, q)
	latest := ownedCommentPage166V1(t, q, doc, parties[0].Token, "")
	if len(latest.Comments) != 50 || latest.Comments[49].ID != posted.ID || latest.Comments[49].Body != nativeCommentBody163V1 {
		t.Fatal("Latest refresh lost newly confirmed native message")
	}
	viewer, err := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	q.cookie = dsrSessionCookieE2E(t, q.f.s, viewer.ID, viewer.SessionGeneration, time.Hour)
	viewerPage := ownedCommentPage166V1(t, q, doc, "", "")
	if !reflect.DeepEqual(latest, viewerPage) {
		t.Fatal("staff viewer lost existing history read permission")
	}
	t.Log("actual public/staff Latest/Older/Newer visit all105 historical rows with35-way microsecond ties; >POST-limit text intact, malformed/foreign selectors refused without changes, nativePOST→Latest and staffviewer preserved")
}

func TestOwnedCommentWindowIndexMigrationPreservesHistoryE2E(t *testing.T) {
	// Qualify the real97↔98 goose boundary independently. Today's native
	// signer cannot run against schema97, and M111 rightly forbids rolling an
	// active ceremony back through its later clock disposition guard.
	qualifyHistoricalCommentIndex98E2E(t)
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	ownedHistoricalCommentRows166V1(t, q, doc)
	want := ownedCommentPage166V1(t, q, doc, parties[0].Token, "")
	before := captureNativeCommentState163V1(t, q, doc)
	current := assertCurrentHandlerMigrationHistoryE2E(t, q.f.ctx, q.f.pool)
	raw, err := os.ReadFile("../db/migrations/00098_comment_window_order.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(raw), "-- +goose Down", 2)
	if len(parts) != 2 {
		t.Fatal("M98 requires actual Up/Down")
	}
	var definition string
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT pg_get_indexdef('idx_document_comments_window'::regclass)").Scan(&definition); err != nil || !strings.Contains(definition, "(document_id, created_at, id)") {
		t.Fatal("normal98 did not create exact seek-order index", definition, err)
	} //nolint:rawsql -- actual migration shape, not a planner/capacity claim
	// Current native API compatibility with exactly the authored index Down.
	// Migration history stays current; the independent phase above owns the
	// historical version assertions. No newer ceremony guard is bypassed.
	if _, err := q.f.pool.Exec(q.f.ctx, parts[1]); err != nil {
		t.Fatal("actual98 index Down on current native history", err)
	}
	var absent bool
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT to_regclass('idx_document_comments_window') IS NULL").Scan(&absent); err != nil || !absent {
		t.Fatal("rollback retained new index", err)
	} //nolint:rawsql -- actual bounded index absence only
	if got := ownedCommentPage166V1(t, q, doc, parties[0].Token, ""); !reflect.DeepEqual(got, want) {
		t.Fatal("index rollback changed history semantics")
	}
	if _, err := q.f.pool.Exec(q.f.ctx, parts[0]); err != nil {
		t.Fatal("actual98 index Up on current native history", err)
	}
	if got := assertCurrentHandlerMigrationHistoryE2E(t, q.f.ctx, q.f.pool); got != current {
		t.Fatal("index-only compatibility changed current migration history")
	}
	var restored string
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT pg_get_indexdef('idx_document_comments_window'::regclass)").Scan(&restored); err != nil || restored != definition {
		t.Fatal("index reapply changed definition", restored, err)
	} //nolint:rawsql -- exact normal-up index identity
	if got := ownedCommentPage166V1(t, q, doc, parties[0].Token, ""); !reflect.DeepEqual(got, want) {
		t.Fatal("index reapply changed history semantics")
	}
	assertNativeCommentUnchanged163V1(t, q, doc, before)
}

type ownedCommentPageWriter166V1 struct {
	*httptest.ResponseRecorder
	entered, release chan struct{}
	life             context.Context
	once             sync.Once
	timedOut         atomic.Bool
}

func (w *ownedCommentPageWriter166V1) Write(body []byte) (int, error) {
	if len(body) > 0 {
		w.once.Do(func() { close(w.entered) })
		select {
		case <-w.release:
		case <-w.life.Done():
			w.timedOut.Store(true)
			return 0, w.life.Err()
		}
	}
	return w.ResponseRecorder.Write(body)
}

func TestOwnedCommentPageResponseRetainsNativeDebtE2E(t *testing.T) {
	var staffPageDB int64
	for _, side := range []string{"staff", "public"} {
		t.Run(side, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			ownedHistoricalCommentRows166V1(t, q, doc)
			token := ""
			if side == "public" {
				token = parties[0].Token
			}
			ctx, cancel := context.WithCancel(q.f.ctx)
			w := &ownedCommentPageWriter166V1{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{}), life: q.f.ctx}
			done := make(chan struct{})
			var release sync.Once
			defer func() {
				release.Do(func() { close(w.release) })
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("actual comment GET response did not join")
				}
			}()
			r := ownedCommentPageRequest166V1(q, ctx, doc, token, "")
			go func() { defer close(done); q.f.s.Routes().ServeHTTP(w, r) }()
			select {
			case <-w.entered:
			case <-done:
				t.Fatal("response returned before controlled write")
			case <-time.After(5 * time.Second):
				t.Fatal("actual GET never reached response write")
			}
			if w.Code != http.StatusOK {
				t.Fatal("controlled write was an error response", w.Code)
			}
			wantObservers := 1
			wantPending := pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 1, HTMLAdmissions: 1, HTMLInputProducers: 1}
			if side == "public" {
				wantObservers = 2
				wantPending.ObserverSessions = 2
				wantPending.HTMLAdmissions = 2
				wantPending.SignerReaders = 1
				wantPending.SignerScopes = 1
			}
			pending := q.runtime.SessionsV1().PendingV1()
			snapshot, err := q.runtime.SnapshotV1(q.f.org)
			if err != nil || pending != wantPending || snapshot.Global.ParentBytes <= 0 || snapshot.Global.SQLSessions != int64(wantObservers) || snapshot.Organisation.SQLSessions != 1 {
				t.Fatal("response lost native input/body ownership", pending, err)
			}
			if side == "staff" {
				staffPageDB = snapshot.Organisation.DBStagingBytes
			} else if staffPageDB < 16*54679 || staffPageDB >= 32<<20 || snapshot.Organisation.DBStagingBytes <= staffPageDB+32<<20 || snapshot.Global.DBStagingBytes-snapshot.Organisation.DBStagingBytes != 8<<20 {
				// Identical rows share independent JSON DB costs after the
				// staff actor/public credential producer has retired. The additional
				// nonempty original model body must retain its own >=32MiB loan;
				// only its8MiB process scope is charged globally rather than here.
				t.Fatal("actual response-purpose GET lost its original model body during Write", snapshot, staffPageDB)
			}
			cancel()
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			err = q.runtime.ReconcileCleanupV1(cleanup)
			stop()
			after, afterErr := q.runtime.SnapshotV1(q.f.org)
			if afterErr != nil || after != snapshot || q.runtime.SessionsV1().PendingV1() != pending {
				t.Fatal("cancellation/reconciliation retired still-writing page", err, afterErr)
			}
			release.Do(func() { close(w.release) })
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("real comment GET did not join after write release")
			}
			if w.timedOut.Load() {
				t.Fatal("synthetic writer used timeout as release")
			}
			var page pdfadmission.CommentPageResponseV1
			if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Comments) != 50 {
				t.Fatal("controlled real GET omitted bounded JSON")
			}
			textBytes := 0
			for _, row := range page.Comments {
				textBytes += len(row.AuthorName) + len(row.AuthorSide) + len(row.Body)
			}
			if textBytes != 54679 {
				t.Fatal("staff/public page actor cost control did not use the exact same bounded text fixture", textBytes)
			}
			q.reconcileV1(t)
			drained := q.runtime.SessionsV1().PendingV1()
			observed, err := q.runtime.SnapshotV1(q.f.org)
			if err != nil || drained != (pdfadmission.ApplicationSessionPendingV1{ObserverSessions: wantObservers}) || observed.Global != (workguard.VectorV1{SQLSessions: int64(wantObservers)}) || observed.GlobalGrants != int64(wantObservers) || observed.Organisation != (workguard.VectorV1{SQLSessions: 1}) || observed.OrganisationGrants != 1 {
				t.Fatal("page last use did not drain to its exact genuine observer topology", drained, observed, err)
			}
		})
	}
}

// Real historical goose application/rollback is distinct from exercising the
// current native signer above. Both use the same authored M98 index migration.
func qualifyHistoricalCommentIndex98E2E(t *testing.T) {
	t.Helper()
	f := migrationPG242(t)
	if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 98); err != nil {
		t.Fatal("actual empty98 Up", err)
	}
	var before string
	if err := f.admin.QueryRow(f.ctx, "SELECT pg_get_indexdef('idx_document_comments_window'::regclass)").Scan(&before); err != nil || !strings.Contains(before, "(document_id, created_at, id)") {
		t.Fatal("historical98 seek index", before, err)
	}
	if err := mdb.RunMigrationsDownToContext(f.ctx, f.db, 97); err != nil {
		t.Fatal("actual98 Down97", err)
	}
	migrationHead242(t, f, 97, true)
	var absent bool
	if err := f.admin.QueryRow(f.ctx, "SELECT to_regclass('idx_document_comments_window') IS NULL").Scan(&absent); err != nil || !absent {
		t.Fatal("historical98 index survived Down", err)
	}
	if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, 98); err != nil {
		t.Fatal("actual98 replay", err)
	}
	migrationHead242(t, f, 98, true)
	var after string
	if err := f.admin.QueryRow(f.ctx, "SELECT pg_get_indexdef('idx_document_comments_window'::regclass)").Scan(&after); err != nil || before != after {
		t.Fatal("historical98 replay changed index", after, err)
	}
	migrationPoolRetired242(t, f, f.db, f.name)
}
