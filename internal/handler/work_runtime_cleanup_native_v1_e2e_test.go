//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package handler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A genuine TCP cancellation must not strand the shared signer owner forever.
// The blocker outlives CloseV1's five-second budget. Only the production cleanup
// scheduler runs before recovery: no fixture Reconcile call supplies the result.
func TestWorkRuntimeCleanupRecoversCancelledSignerHTTPV1E2E(t *testing.T) {
	isolateMigratedHTMLTemplateDatabaseE2E(t)
	u, err := url.Parse(os.Getenv("HASH_E2E_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	params := u.Query()
	// This new isolated fixture must keep its real backend alive beyond the
	// native close budget. It changes no existing fixture or product timeout.
	for _, name := range []string{"statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout"} {
		params.Set(name, "30000")
	}
	u.RawQuery = params.Encode()
	t.Setenv("HASH_E2E_DB_URL", u.String())
	ctx, pool, queries, s, _, _ := setupDSRPoolBirth315E2E(t, 0)
	limits := workguard.LimitsV1{
		Global:       workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 1},
		Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 1},
		MaxGrants:    128, MaxOrganisationGrants: 96,
	}
	runtime, err := pdfadmission.NewWorkRuntimeV1(pool, limits, int64(pool.Config().MaxConns)+8)
	if err != nil {
		t.Fatal(err)
	}
	s.Sign = &sign.Engine{Pool: pool, Queries: queries, WorkRuntime: runtime}
	if err := s.Sign.InitializeWorkRuntimeV1(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.Sign.CloseWorkRuntimeRequestsV1(cleanup); err != nil {
			t.Error("journal cleanup", err)
		}
		observers := runtime.SessionsV1().PendingV1().ObserverSessions
		err := runtime.CloseV1(cleanup)
		pending := runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.SignerScopes != 0 || pending.SignerReaders != 0 {
			t.Errorf("unretired signer work: %+v", pending)
		}
		if observers > 0 && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			t.Errorf("last observer was falsely credited: %v", err)
		} else if observers == 0 && err != nil {
			t.Error(err)
		}
		// Socket close is not physical backend proof. Independently join this
		// unique pool/application before the isolated database cleanup runs.
		cfg := pool.Config().ConnConfig.Copy()
		application := cfg.RuntimeParams["application_name"]
		cfg.RuntimeParams["application_name"] = "hash_cleanup_independent_witness"
		witness, err := pgx.ConnectConfig(cleanup, cfg)
		if err != nil {
			t.Error("independent retirement witness", err)
			return
		}
		defer func() {
			closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := witness.Close(closeCtx); err != nil {
				t.Error("close witness", err)
			}
		}()
		pool.Close()
		for {
			var count int
			if err := witness.QueryRow(cleanup, "SELECT count(*)::integer FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1", application).Scan(&count); err != nil {
				t.Error("backend retirement witness", err)
				return
			} //nolint:rawsql -- exact disposable fixture application, never retirement authority
			if count == 0 {
				return
			}
			select {
			case <-cleanup.Done():
				t.Error("fixture backend retirement did not join", count)
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	})
	stopCleanup := runtime.StartCleanupV1()
	t.Cleanup(stopCleanup) // LIFO: join before runtime/pool close.
	server := httptest.NewServer(s.Routes())
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{}}
	t.Cleanup(client.CloseIdleConnections)
	path := "/sign/" + strings.Repeat("cafebabe", 8)
	status := func(suffix string) int {
		t.Helper()
		response, err := client.Get(server.URL + path + suffix)
		if err != nil {
			t.Fatal("actual signer HTTP request", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(body) > 4096 {
			t.Fatal("bounded signer response", readErr, closeErr)
		}
		return response.StatusCode
	}
	if a, b := status("/fields"), status(""); a != http.StatusNotFound || b != http.StatusNotFound {
		t.Fatalf("cold unissued token: fields=%d context=%d", a, b)
	}
	baseline, err := runtime.SnapshotV1(uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rollback := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := holder.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("join original holder rollback", err)
		}
	}
	t.Cleanup(rollback)
	if _, err := holder.Exec(ctx, "LOCK TABLE recipients IN ACCESS EXCLUSIVE MODE"); err != nil { //nolint:rawsql -- exact isolated fixture table
		t.Fatal(err)
	}
	var holderPID int32
	if err := holder.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&holderPID); err != nil { //nolint:rawsql -- own blocker identity
		t.Fatal(err)
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, server.URL+path+"/fields", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		response, err := client.Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		done <- err
	}()
	joined := false
	t.Cleanup(func() {
		cancelRequest()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("own HTTP client did not join")
			}
		}
	})
	var backendPID int32
	var backendStart time.Time
	application := pool.Config().ConnConfig.RuntimeParams["application_name"]
	until := time.Now().Add(1500 * time.Millisecond)
	for {
		err := pool.QueryRow(ctx, "SELECT a.pid,a.backend_start FROM pg_stat_activity a WHERE a.datname=current_database() AND a.application_name=$1 AND a.state='active' AND a.wait_event_type='Lock' AND position('-- name: ProbeSignerScopeByTokenHashV1' in a.query)>0 AND $2=ANY(pg_blocking_pids(a.pid))", application, holderPID).Scan(&backendPID, &backendStart)
		if err == nil {
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) || time.Now().After(until) {
			t.Fatal("actual HTTP probe did not reach exact owned blocker", err)
		}
		time.Sleep(10 * time.Millisecond)
	} //nolint:rawsql -- autocommit live witness; no stale observer transaction snapshot
	select {
	case err := <-done:
		joined = true
		var timeout interface{ Timeout() bool }
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal("expected actual TCP client deadline", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP cancellation did not join")
	}
	// The scheduler must not credit a socket-close while the same SQL backend
	// is still alive behind the original lock, beyond the native close budget.
	time.Sleep(6 * time.Second)
	var live bool
	if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2 AND $3=ANY(pg_blocking_pids(pid)))", backendPID, backendStart, holderPID).Scan(&live); err != nil || !live {
		t.Fatal("original native backend was not still held", err)
	} //nolint:rawsql -- exact PID/start and actual blocker; no synthetic retirement proof
	if code := status("/fields"); code != http.StatusServiceUnavailable {
		t.Fatal("live quarantined owner was prematurely reused", code)
	}
	held, err := runtime.SnapshotV1(uuid.Nil)
	if err != nil || held.Global.SQLSessions <= baseline.Global.SQLSessions || runtime.SessionsV1().PendingV1().WorkSessions == 0 {
		t.Fatal("live original SQL ownership was prematurely credited", held, err)
	}
	rollback()
	until = time.Now().Add(5 * time.Second)
	for {
		if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2)", backendPID, backendStart).Scan(&live); err != nil {
			t.Fatal("physical retirement witness", err)
		} //nolint:rawsql -- exact original PID/start, independent of scheduler state
		if !live {
			break
		}
		if time.Now().After(until) {
			t.Fatal("original native backend did not physically retire")
		}
		time.Sleep(10 * time.Millisecond)
	}
	until = time.Now().Add(6 * time.Second)
	for {
		a, b := status("/fields"), status("")
		if a == http.StatusNotFound && b == http.StatusNotFound && time.Now().Before(until) {
			break
		}
		if (a != http.StatusServiceUnavailable && a != http.StatusNotFound) || (b != http.StatusServiceUnavailable && b != http.StatusNotFound) || time.Now().After(until) {
			t.Fatalf("no scheduler-only recovery after physical retirement: fields=%d context=%d", a, b)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if pending := runtime.SessionsV1().PendingV1(); pending.WorkSessions != 0 || pending.SignerScopes != 0 {
		t.Fatalf("recovered HTTP left original work unretired: %+v", pending)
	}
	if recovered, err := runtime.SnapshotV1(uuid.Nil); err != nil || recovered != baseline {
		t.Fatal("recovery lost original observer debt or retained cancelled work", recovered, baseline, err)
	}
}
