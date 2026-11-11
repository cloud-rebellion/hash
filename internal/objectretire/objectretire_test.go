// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package objectretire

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type fakeStore struct {
	deleted  []uuid.UUID
	failures []generated.RecordPendingObjectDeletionFailureV1Params
	delErr   error
	// detached records whether bookkeeping ran on a context that outlives the caller's.
	detached bool
}

func (s *fakeStore) InsertPendingObjectDeletionV1(context.Context, generated.InsertPendingObjectDeletionV1Params) (*generated.PendingObjectDeletionsV1, error) {
	return nil, errors.New("unused")
}
func (s *fakeStore) ClaimDuePendingObjectDeletionsV1(context.Context, generated.ClaimDuePendingObjectDeletionsV1Params) ([]*generated.PendingObjectDeletionsV1, error) {
	return nil, errors.New("unused")
}
func (s *fakeStore) DeletePendingObjectDeletionV1(ctx context.Context, arg generated.DeletePendingObjectDeletionV1Params) (int64, error) {
	s.detached = ctx.Err() == nil
	if s.delErr != nil {
		return 0, s.delErr
	}
	s.deleted = append(s.deleted, arg.ID)
	return 1, nil
}
func (s *fakeStore) RecordPendingObjectDeletionFailureV1(ctx context.Context, arg generated.RecordPendingObjectDeletionFailureV1Params) (int64, error) {
	s.detached = ctx.Err() == nil
	s.failures = append(s.failures, arg)
	return 1, nil
}

type fakeDeleter struct {
	err   error
	calls int
}

func (d *fakeDeleter) DeleteVersion(context.Context, string, string, []byte) error {
	d.calls++
	return d.err
}

func testRow(attempts int32) *generated.PendingObjectDeletionsV1 {
	return &generated.PendingObjectDeletionsV1{ID: uuid.New(), OrgID: uuid.New(), StorageKey: "org/x/documents/y.pdf", VersionID: "v1", Sha256: make([]byte, 32), Attempts: attempts}
}

func TestAttemptDeletesTheRowOnlyAfterTheObjectIsGone(t *testing.T) {
	row := testRow(0)
	store, deleter := &fakeStore{}, &fakeDeleter{}
	if !Attempt(context.Background(), store, deleter, row) || len(store.deleted) != 1 || store.deleted[0] != row.ID || len(store.failures) != 0 {
		t.Fatalf("success: deleted=%v failures=%v", store.deleted, store.failures)
	}

	row = testRow(2)
	store, deleter = &fakeStore{}, &fakeDeleter{err: errors.New("access denied")}
	if Attempt(context.Background(), store, deleter, row) || len(store.deleted) != 0 || len(store.failures) != 1 {
		t.Fatalf("failure must keep the row: deleted=%v failures=%v", store.deleted, store.failures)
	}
	if got := store.failures[0]; got.ID != row.ID || got.OrgID != row.OrgID || got.LastError != "access denied" || got.BackoffSeconds != Backoff(2).Seconds() {
		t.Fatalf("failure record=%+v", got)
	}
}

func TestAttemptWithoutStorageIsAFailureNotACrash(t *testing.T) {
	store := &fakeStore{}
	if Attempt(context.Background(), store, nil, testRow(0)) || len(store.failures) != 1 || store.failures[0].LastError == "" {
		t.Fatalf("nil deleter: %+v", store.failures)
	}
}

func TestAttemptSurvivesACanceledCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &fakeStore{}
	if !Attempt(ctx, store, &fakeDeleter{}, testRow(0)) || len(store.deleted) != 1 || !store.detached {
		t.Fatalf("a canceled request must still finish its cleanup: deleted=%v detached=%v", store.deleted, store.detached)
	}
}

func TestAttemptAllStopsStartingAttemptsPastItsBudget(t *testing.T) {
	store, deleter := &fakeStore{}, &fakeDeleter{}
	rows := []*generated.PendingObjectDeletionsV1{testRow(0), testRow(0), testRow(0)}
	if got := AttemptAll(context.Background(), store, deleter, rows, 0); got != 3 || deleter.calls != 3 {
		t.Fatalf("no budget: done=%d calls=%d", got, deleter.calls)
	}
	store, deleter = &fakeStore{}, &fakeDeleter{}
	if got := AttemptAll(context.Background(), store, deleter, rows, time.Nanosecond); got > 1 || deleter.calls > 1 {
		t.Fatalf("an exhausted budget must leave the rest to the sweep: done=%d calls=%d", got, deleter.calls)
	}
}

// hangingDeleter blocks until its context ends, the way a hung object store does.
type hangingDeleter struct{ calls int }

func (d *hangingDeleter) DeleteVersion(ctx context.Context, _, _ string, _ []byte) error {
	d.calls++
	<-ctx.Done()
	return ctx.Err()
}

func TestAttemptAllBudgetCapsAHungDeleteNotOnlyTheNextStart(t *testing.T) {
	store, deleter := &fakeStore{}, &hangingDeleter{}
	rows := []*generated.PendingObjectDeletionsV1{testRow(0), testRow(0), testRow(0)}
	budget := 150 * time.Millisecond
	started := time.Now()
	done := AttemptAll(context.Background(), store, deleter, rows, budget)
	elapsed := time.Since(started)
	if done != 0 || deleter.calls != 1 {
		t.Fatalf("one attempt consumes the whole budget and the rest wait for the sweep: done=%d calls=%d", done, deleter.calls)
	}
	// Without the per-attempt cap this would take AttemptTimeout (15 s).
	if elapsed > 3*time.Second {
		t.Fatalf("a hung delete held the caller for %s, budget was %s", elapsed, budget)
	}
	if len(store.failures) != 0 {
		t.Fatalf("a delete cut short by the budget is not a failed attempt: %+v", store.failures)
	}
}

// goneThenHangingDeleter removes the object and then blocks on the store's
// confirmation reads, the way RemoveObject followed by two context-bound checks
// does when the budget ends between them.
type goneThenHangingDeleter struct{ gone bool }

func (d *goneThenHangingDeleter) DeleteVersion(ctx context.Context, _, _ string, _ []byte) error {
	d.gone = true
	<-ctx.Done()
	return ctx.Err()
}

// R3: a budget cut must not add an attempt or overwrite last_error, even when the
// object is already gone. The row keeps its grace and the sweep finds the
// version absent and removes it.
func TestAttemptAllBudgetCutIsNotACountedFailure(t *testing.T) {
	store, deleter := &fakeStore{}, &goneThenHangingDeleter{}
	rows := []*generated.PendingObjectDeletionsV1{testRow(3)}
	rows[0].LastError = "AccessDenied: earlier real cause"
	if done := AttemptAll(context.Background(), store, deleter, rows, 100*time.Millisecond); done != 0 {
		t.Fatalf("done=%d, the budget cut leaves the row for the sweep", done)
	}
	if !deleter.gone {
		t.Fatal("setup: the delete never ran")
	}
	if len(store.failures) != 0 || len(store.deleted) != 0 {
		t.Fatalf("budget cut recorded a failure or removed the row: failures=%+v deleted=%v", store.failures, store.deleted)
	}
}

// A deadline that is not the budget's (the full per-attempt timeout, or one the
// store reports itself) is a real failure and is still counted.
func TestAttemptCountsADeadlineThatIsNotTheBudgetsV1(t *testing.T) {
	store := &fakeStore{}
	Attempt(context.Background(), store, &fakeDeleter{err: context.DeadlineExceeded}, testRow(0))
	if len(store.failures) != 1 {
		t.Fatalf("a deadline at the full attempt timeout must be counted: %+v", store.failures)
	}
	store = &fakeStore{}
	AttemptAll(context.Background(), store, &fakeDeleter{err: errors.New("AccessDenied")}, []*generated.PendingObjectDeletionsV1{testRow(0)}, time.Minute)
	if len(store.failures) != 1 {
		t.Fatalf("a real error inside the budget must be counted: %+v", store.failures)
	}
}

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestAttemptLogsAnErrorPerRowOnceAttemptsReachTheThreshold(t *testing.T) {
	buf := captureSlog(t)
	failing := &fakeDeleter{err: errors.New("object lock denies delete")}

	Attempt(context.Background(), &fakeStore{}, failing, testRow(AlertAttempts-2))
	if strings.Contains(buf.String(), "level=ERROR") {
		t.Fatalf("below the threshold must not log at Error: %s", buf.String())
	}

	row := testRow(AlertAttempts - 1)
	row.DocumentID = uuid.New()
	Attempt(context.Background(), &fakeStore{}, failing, row)
	out := buf.String()
	for _, want := range []string{"level=ERROR", "id=" + row.ID.String(), "org_id=" + row.OrgID.String(), "document_id=" + row.DocumentID.String(), "attempts=5", "object lock denies delete"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}

	buf.Reset()
	Attempt(context.Background(), &fakeStore{}, &fakeDeleter{}, testRow(AlertAttempts+3))
	if buf.Len() != 0 {
		t.Fatalf("a successful delete must not log: %s", buf.String())
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	if Backoff(0) != 30*time.Second || Backoff(1) != time.Minute || Backoff(2) != 2*time.Minute {
		t.Fatalf("backoff 0/1/2 = %v %v %v", Backoff(0), Backoff(1), Backoff(2))
	}
	if Backoff(100) != maxBackoff || Backoff(1<<30) != maxBackoff {
		t.Fatalf("backoff must cap at %v, got %v", maxBackoff, Backoff(100))
	}
}

func TestDescribeErrorIsBoundedSingleLineValidText(t *testing.T) {
	if DescribeError(nil) != "" {
		t.Fatal("nil error must describe as empty")
	}
	got := DescribeError(errors.New("line one\nline two\r\x00tail"))
	if strings.ContainsAny(got, "\n\r\x00") {
		t.Fatalf("control characters survived: %q", got)
	}
	long := DescribeError(errors.New(strings.Repeat("e", 1000)))
	if len(long) != maxErrorBytes {
		t.Fatalf("length=%d, want %d", len(long), maxErrorBytes)
	}
	// A multibyte rune straddling the cut must not leave invalid UTF-8.
	straddle := DescribeError(errors.New(strings.Repeat("e", maxErrorBytes-1) + "åå"))
	if !utf8.ValidString(straddle) || len(straddle) > maxErrorBytes {
		t.Fatalf("truncation broke UTF-8: %q", straddle)
	}
}
