// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/bright-interaction/hash/internal/auth"
)

// commitNotSentV1 returns the error pgx gives for a COMMIT whose context was
// already done: a real *pgconn errTimeout wrapping contextAlreadyDoneError, which
// pgconn.SafeToRetry and pgconn.Timeout both report. It is built by a real
// pgconn.PgConn over an in-memory fake backend that only completes startup.
func commitNotSentV1(t *testing.T) error {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		be := pgproto3.NewBackend(server, server)
		if _, err := be.ReceiveStartupMessage(); err != nil {
			return
		}
		be.Send(&pgproto3.AuthenticationOk{})
		be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = be.Flush()
		for {
			if _, err := be.Receive(); err != nil {
				return
			}
		}
	}()
	cfg, err := pgconn.ParseConfig("host=fake user=u dbname=d sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.DialFunc = func(context.Context, string, string) (net.Conn, error) { return client, nil }
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	conn, err := pgconn.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = conn.Exec(ctx, "commit").ReadAll()
	if !pgconn.SafeToRetry(err) || !pgconn.Timeout(err) {
		t.Fatalf("fixture drifted from pgx: %T SafeToRetry=%v Timeout=%v", err, pgconn.SafeToRetry(err), pgconn.Timeout(err))
	}
	return err
}

// commitConnLostV1 returns the error pgx gives for a connection lost after
// COMMIT was sent: a *pgconn.connLockError, whose SafeToRetry is hard-coded true
// but which is not a timeout.
func commitConnLostV1(t *testing.T) error {
	t.Helper()
	err := (&pgconn.PgConn{}).Exec(context.Background(), "commit").Close()
	if !pgconn.SafeToRetry(err) || pgconn.Timeout(err) {
		t.Fatalf("fixture drifted from pgx: %T SafeToRetry=%v Timeout=%v", err, pgconn.SafeToRetry(err), pgconn.Timeout(err))
	}
	return err
}

// R1: a retry hint at COMMIT is given only when the commit was never sent or the
// server answered and rolled back before the commit record. A deadline or a lost
// connection after COMMIT was sent, and a 57014 (which can follow an applied
// commit), leave the outcome unknown and must not tell the client to repeat the
// write.
func TestClassifyDSRCommitErrorOnlyRetriesWhatCannotHaveCommittedV1(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		status     int
		retryAfter bool
		code       string
	}{
		{"deadline after COMMIT was sent", fmt.Errorf("commit: %w", context.DeadlineExceeded), http.StatusInternalServerError, false, "dsr_commit_outcome_unknown"},
		{"bare deadline", context.DeadlineExceeded, http.StatusInternalServerError, false, "dsr_commit_outcome_unknown"},
		{"client gone", context.Canceled, http.StatusInternalServerError, false, "dsr_commit_outcome_unknown"},
		{"connection lost", errors.New("write: broken pipe"), http.StatusInternalServerError, false, "dsr_commit_outcome_unknown"},
		{"connection lost after send (pgx connLockError)", commitConnLostV1(t), http.StatusInternalServerError, false, "dsr_commit_outcome_unknown"},
		{"statement canceled (may follow an applied commit)", &pgconn.PgError{Code: "57014"}, http.StatusInternalServerError, false, "dsr_commit_outcome_unknown"},
		{"statement canceled, wrapped", fmt.Errorf("commit: %w", &pgconn.PgError{Code: "57014"}), http.StatusInternalServerError, false, "dsr_commit_outcome_unknown"},
		{"deferred constraint", &pgconn.PgError{Code: "23514"}, http.StatusInternalServerError, false, "dsr_commit_outcome_unknown"},
		{"commit never sent", fmt.Errorf("commit: %w", commitNotSentV1(t)), http.StatusServiceUnavailable, true, ""},
		{"serialization", &pgconn.PgError{Code: "40001"}, http.StatusServiceUnavailable, true, ""},
		{"deadlock", &pgconn.PgError{Code: "40P01"}, http.StatusServiceUnavailable, true, ""},
		{"fence contention", &pgconn.PgError{Code: "55P03"}, http.StatusConflict, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if !classifyDSRCommitErrorV1(w, tc.err) {
				t.Fatal("a commit error must always get an answer")
			}
			if w.Code != tc.status || (w.Header().Get("Retry-After") != "") != tc.retryAfter {
				t.Fatalf("status=%d Retry-After=%q, want %d retryAfter=%v", w.Code, w.Header().Get("Retry-After"), tc.status, tc.retryAfter)
			}
			if tc.code != "" && !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) {
				t.Fatalf("body %q lacks code %s", w.Body.String(), tc.code)
			}
		})
	}
	w := httptest.NewRecorder()
	if classifyDSRCommitErrorV1(w, nil) || w.Body.Len() != 0 {
		t.Fatal("nil must write nothing")
	}
}

// failingTxV1 fails the role lock query with err; any other method would panic.
type failingTxV1 struct {
	pgx.Tx
	err error
}

type failingRowV1 struct{ err error }

func (r failingRowV1) Scan(...any) error { return r.err }

func (t failingTxV1) QueryRow(context.Context, string, ...any) pgx.Row { return failingRowV1{t.err} }

// R2: the role lock inside the transaction maps a deadline through the caller's
// classifier instead of answering 500, and the hook changes nothing else.
func TestAuthorizeTransactionSessionClassifiedMapsRoleLockDeadlineV1(t *testing.T) {
	s := &Server{}
	deadline := fmt.Errorf("lock role: %w", context.DeadlineExceeded)
	r := httptest.NewRequest(http.MethodPatch, "/", nil)

	w := httptest.NewRecorder()
	if s.authorizeTransactionSessionClassified(w, r, failingTxV1{err: deadline}, auth.SessionUser{}, auth.SessionPayload{}, "", auth.RoleSender, classifyDSRDBErrorV1) {
		t.Fatal("a failed role lock must not authorize")
	}
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("with the DSR classifier: status=%d Retry-After=%q", w.Code, w.Header().Get("Retry-After"))
	}

	w = httptest.NewRecorder()
	s.authorizeTransactionSession(w, r, failingTxV1{err: deadline}, auth.SessionUser{}, auth.SessionPayload{}, "", auth.RoleSender)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("callers without a classifier keep the 500: %d", w.Code)
	}

	w = httptest.NewRecorder()
	s.authorizeTransactionSessionClassified(w, r, failingTxV1{err: errors.New("boom")}, auth.SessionUser{}, auth.SessionPayload{}, "", auth.RoleSender, classifyDSRDBErrorV1)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("an unclassified error stays a 500: %d", w.Code)
	}

	w = httptest.NewRecorder()
	s.authorizeTransactionSessionClassified(w, r, failingTxV1{err: pgx.ErrNoRows}, auth.SessionUser{}, auth.SessionPayload{}, "", auth.RoleSender, classifyDSRDBErrorV1)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a missing user stays a 403: %d", w.Code)
	}
}
