//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// holdCommitReplyProxyE2E forwards to upstream and, once the client has sent
// COMMIT, delays every server reply by hold. That is the shape of a deadline
// that fires after COMMIT left the client: the server applies it, the client
// never reads the answer.
func holdCommitReplyProxyE2E(t *testing.T, upstream string, hold time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", upstream)
			if err != nil {
				_ = client.Close()
				continue
			}
			var sent atomic.Bool
			go func() {
				buf := make([]byte, 32<<10)
				for {
					n, err := client.Read(buf)
					if n > 0 {
						if bytes.Contains(bytes.ToLower(buf[:n]), []byte("commit")) {
							sent.Store(true)
						}
						_, _ = server.Write(buf[:n])
					}
					if err != nil {
						_ = server.Close()
						return
					}
				}
			}()
			go func() {
				buf := make([]byte, 32<<10)
				for {
					n, err := server.Read(buf)
					if n > 0 {
						if sent.Load() {
							time.Sleep(hold)
						}
						_, _ = client.Write(buf[:n])
					}
					if err != nil {
						_ = client.Close()
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// R1 against a real server: the transaction commits, the deadline fires before
// the reply is read, and the handler must not answer "503, retry".
func TestDSRCommitDeadlineAfterSendIsOutcomeUnknownNotRetryE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	dbName := fmt.Sprintf("hash_r1_commit_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+dbName); err != nil { //nolint:rawsql -- scratch database for this probe
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// The deferred admin.Close has already run by now, so use a fresh connection.
		c, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Errorf("drop %s: %v", dbName, err)
			return
		}
		defer c.Close(ctx)
		if _, err := c.Exec(ctx, `DROP DATABASE IF EXISTS `+dbName+` WITH (FORCE)`); err != nil { //nolint:rawsql -- scratch database cleanup
			t.Errorf("drop %s: %v", dbName, err)
		}
	})

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	direct := *u
	direct.Path = "/" + dbName
	proxied := direct
	proxied.Host = holdCommitReplyProxyE2E(t, u.Host, 1500*time.Millisecond)

	check, err := pgx.Connect(ctx, direct.String())
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close(ctx)
	if _, err := check.Exec(ctx, `CREATE TABLE erasure_probe (id int PRIMARY KEY)`); err != nil { //nolint:rawsql -- scratch table for this probe
		t.Fatal(err)
	}

	conn, err := pgx.Connect(ctx, proxied.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO erasure_probe VALUES (1)`); err != nil { //nolint:rawsql -- the write the commit applies
		t.Fatal(err)
	}
	commitCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	commitErr := tx.Commit(commitCtx)
	if !errors.Is(commitErr, context.DeadlineExceeded) || pgconn.SafeToRetry(commitErr) {
		t.Fatalf("setup: want a deadline after COMMIT was sent, got %v (safe to retry=%v)", commitErr, pgconn.SafeToRetry(commitErr))
	}
	time.Sleep(2 * time.Second)
	var n int
	if err := check.QueryRow(ctx, `SELECT count(*) FROM erasure_probe`).Scan(&n); err != nil || n != 1 { //nolint:rawsql -- reads back what the commit applied
		t.Fatalf("the commit must have been applied: n=%d err=%v", n, err)
	}

	w := httptest.NewRecorder()
	classifyDSRCommitErrorV1(w, commitErr)
	if w.Code == http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "" {
		t.Fatalf("a committed write answered %d with Retry-After %q: %s", w.Code, w.Header().Get("Retry-After"), w.Body.String())
	}
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "dsr_commit_outcome_unknown") {
		t.Fatalf("status=%d body=%s, want the outcome-unknown 500", w.Code, w.Body.String())
	}
}
