// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestApplicationObserverProbeCancellationDoesNotOwnControlLifetimeV1(t *testing.T) {
	type scopeKey struct{}
	parent := context.WithValue(context.Background(), scopeKey{}, "synthetic observer scope")
	caller, stop := context.WithTimeout(parent, 20*time.Millisecond)
	defer stop()
	probe, finish, err := applicationObserverProbeContextV1(caller)
	if err != nil {
		t.Fatal("valid caller could not own a bounded control probe")
	}
	defer finish()
	stop()
	if probe.Err() != nil || probe.Value(scopeKey{}) != "synthetic observer scope" {
		t.Fatal("caller cancellation interrupted control ownership or lost scope")
	}
	deadline, bounded := probe.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > applicationObserverProbeBudgetV1 {
		t.Fatal("dispatched control observation lacks its fixed lifetime bound")
	}
	finish()
	if !errors.Is(probe.Err(), context.Canceled) {
		t.Fatal("control owner could not end its own probe")
	}
	if denied, cancel, err := applicationObserverProbeContextV1(caller); err == nil || denied != nil || cancel != nil {
		t.Fatal("already cancelled caller dispatched a new control probe")
	}
}

func applicationSessionResourcesTestV1(t *testing.T, n int64) (*workguard.CoordinatorV1, *WorkAdmissionV1) {
	t.Helper()
	c, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{SQLSessions: n}, Organisation: workguard.VectorV1{SQLSessions: n}, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal("construct session test coordinator")
	}
	a, err := NewWorkAdmissionV1(c)
	if err != nil {
		t.Fatal("construct session test cost adapter")
	}
	return c, a
}
func applicationSessionConfigTestV1(t *testing.T) *pgx.ConnConfig {
	t.Helper()
	c, err := pgx.ParseConfig("postgres://synthetic:synthetic@127.0.0.1:9/synthetic?sslmode=disable")
	if err != nil {
		t.Fatal("parse synthetic test profile")
	}
	return c
}
func TestApplicationSessionFixedProfilePreservesEffectiveConfigV1(t *testing.T) {
	_, work := applicationSessionResourcesTestV1(t, 2)
	c := applicationSessionConfigTestV1(t)
	c.Password = "private override"
	c.Database = "effective override"
	c.RuntimeParams["statement_timeout"] = "4321"
	c.ConnectTimeout = 3 * time.Second
	c.TLSConfig = &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "declared.internal", MinVersion: tls.VersionTLS12}
	f, err := NewApplicationSessionFactoryV1(c, work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal("effective supported configuration refused")
	}
	got := f.state.config
	if got == c || got.Password != c.Password || got.Database != c.Database || got.RuntimeParams["statement_timeout"] != "4321" || got.ConnectTimeout != c.ConnectTimeout || got.TLSConfig == c.TLSConfig || got.TLSConfig.RootCAs != c.TLSConfig.RootCAs || got.TLSConfig.ServerName != c.TLSConfig.ServerName {
		t.Fatal("effective credentials/TLS/runtime/timeout configuration silently discarded")
	}
	c.RuntimeParams["statement_timeout"] = "mutated"
	if got.RuntimeParams["statement_timeout"] != "4321" {
		t.Fatal("factory did not own configuration copy")
	}
	c = applicationSessionConfigTestV1(t)
	c.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	if _, err := NewApplicationSessionFactoryV1(c, work, ApplicationSessionDirectProfileV1); err == nil {
		t.Fatal("custom resolver hook accepted as fixed transport")
	}
	c = applicationSessionConfigTestV1(t)
	c.TLSConfig = &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return nil, errors.New("private TLS hook")
	}}
	if _, err := NewApplicationSessionFactoryV1(c, work, ApplicationSessionDirectProfileV1); err == nil {
		t.Fatal("unaccounted TLS callback accepted")
	}
	if _, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, "unsupported"); err == nil {
		t.Fatal("unsupported transport profile accepted")
	}
	coordinator, hookWork := applicationSessionResourcesTestV1(t, 2)
	var invoked atomic.Int32
	cases := []struct {
		name      string
		configure func(*pgx.ConnConfig)
	}{
		{"notice", func(c *pgx.ConnConfig) { c.OnNotice = func(*pgconn.PgConn, *pgconn.Notice) { invoked.Add(1) } }},
		{"notification", func(c *pgx.ConnConfig) {
			c.OnNotification = func(*pgconn.PgConn, *pgconn.Notification) { invoked.Add(1) }
		}},
		{"postgres-error", func(c *pgx.ConnConfig) {
			c.OnPgError = func(*pgconn.PgConn, *pgconn.PgError) bool { invoked.Add(1); return true }
		}},
		{"missing-fatal-error-handler", func(c *pgx.ConnConfig) { c.OnPgError = nil }},
		{"ech-rejection", func(c *pgx.ConnConfig) {
			c.TLSConfig = &tls.Config{EncryptedClientHelloConfigList: []byte{0, 1}, EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { invoked.Add(1); return nil }}
		}},
		{"ech-server-keys", func(c *pgx.ConnConfig) {
			c.TLSConfig = &tls.Config{GetEncryptedClientHelloKeys: func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) { invoked.Add(1); return nil, nil }}
		}},
		{"unwrap-session", func(c *pgx.ConnConfig) {
			c.TLSConfig = &tls.Config{UnwrapSession: func([]byte, tls.ConnectionState) (*tls.SessionState, error) { invoked.Add(1); return nil, nil }}
		}},
		{"wrap-session", func(c *pgx.ConnConfig) {
			c.TLSConfig = &tls.Config{WrapSession: func(tls.ConnectionState, *tls.SessionState) ([]byte, error) { invoked.Add(1); return nil, nil }}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := applicationSessionConfigTestV1(t)
			tc.configure(bad)
			factory, err := NewApplicationSessionFactoryV1(bad, hookWork, ApplicationSessionDirectProfileV1)
			if factory != nil || !errors.Is(err, ErrApplicationSessionV1) || invoked.Load() != 0 || coordinator.SnapshotV1(uuid.Nil).Global.SQLSessions != 0 {
				t.Fatal("unsupported executable protocol hook escaped pre-dispatch refusal")
			}
		})
	}
}
func TestApplicationSessionDeniedObserverLeavesRetryableZeroDispatchV1(t *testing.T) {
	c, work := applicationSessionResourcesTestV1(t, 1)
	org := uuid.New()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	held, err := work.SQLSessionV1(ctx, org)
	if err != nil {
		t.Fatal("admit held capacity")
	}
	defer held()
	f, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal("construct fixed profile")
	}
	h, err := f.OpenV1(ctx, org, uuid.New())
	if err == nil || h != nil {
		t.Fatal("capacity denial did not refuse before connection creation")
	}
	p := f.PendingV1()
	if p.ObserverSessions != 0 || p.WorkSessions != 0 || p.UnknownStarts != 0 || f.state.organisations[org].observer != nil {
		t.Fatal("never-dispatched observer left a permanent unknown registry entry")
	}
	held()
	if c.SnapshotV1(org).Global.SQLSessions != 0 {
		t.Fatal("capacity did not recover")
	}
	again, err := work.SQLSessionV1(ctx, org)
	if err != nil {
		t.Fatal("known zero-dispatch denial prevented capacity recovery")
	}
	again()
	// Actual factory reconnect after capacity recovery is proved by the real PG
	// suite; this native case intentionally performs no PostgreSQL/network I/O.
}

// Private native seams below are explicitly synthetic, never issued by the
// public fixed factory. They exercise call/consumer conjunction, not backend proof.
type applicationSessionTxTestV1 struct {
	pgx.Tx
	row     pgx.Row
	rows    pgx.Rows
	commits atomic.Int32
}

func (t *applicationSessionTxTestV1) QueryRow(context.Context, string, ...any) pgx.Row { return t.row }
func (t *applicationSessionTxTestV1) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return t.rows, nil
}
func (t *applicationSessionTxTestV1) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("SELECT 1"), nil
}
func (t *applicationSessionTxTestV1) Commit(context.Context) error { t.commits.Add(1); return nil }

type applicationSessionScanTestV1 struct {
	entered, finish chan struct{}
	once            sync.Once
}

func (r *applicationSessionScanTestV1) Scan(...any) error {
	r.once.Do(func() { close(r.entered) })
	<-r.finish
	return nil
}
func TestApplicationSessionOwnedScanJoinsAndCopiesCannotCreditEarlyV1(t *testing.T) {
	c, work := applicationSessionResourcesTestV1(t, 2)
	org := uuid.New()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	grant, err := work.SQLSessionV1(ctx, org)
	if err != nil {
		t.Fatal("admit synthetic work owner")
	}
	p := &applicationSessionFactoryStateV1{work: work, sessions: make(map[*applicationOwnedSessionV1]struct{})}
	done := make(chan struct{})
	close(done)
	row := &applicationSessionScanTestV1{entered: make(chan struct{}), finish: make(chan struct{})}
	var observed atomic.Int32
	s := &applicationOwnedSessionV1{factory: p, org: org, document: uuid.New(), grant: grant, changed: make(chan struct{}), dialed: true, tx: &applicationSessionTxTestV1{row: row}, fence: &applicationSessionFenceV1{clientDone: done, observe: func(context.Context, applicationBackendIdentityV1) (bool, error) { observed.Add(1); return true, nil }}}
	p.sessions[s] = struct{}{}
	h := &ApplicationSessionV1{state: s}
	copyHandle := *h
	scanDone := make(chan struct{})
	var finish sync.Once
	go func() {
		defer close(scanDone)
		_ = (&applicationOwnedDBTXV1{session: s}).QueryRow(ctx, "synthetic admitted body load").Scan()
	}()
	t.Cleanup(func() {
		finish.Do(func() { close(row.finish) })
		select {
		case <-scanDone:
		case <-time.After(time.Second):
			t.Error("synthetic admitted Scan did not join")
		}
		grant()
	})
	select {
	case <-row.entered:
	case <-time.After(time.Second):
		t.Fatal("actual Scan call seam not witnessed")
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if err := copyHandle.ReconcileCleanupV1(ctx); !errors.Is(err, ErrApplicationSessionUnknownV1) || observed.Load() != 0 || c.SnapshotV1(org).Global.SQLSessions != 1 {
		t.Fatal("active body Scan was credited before its call joined")
	}
	finish.Do(func() { close(row.finish) })
	select {
	case <-scanDone:
	case <-time.After(time.Second):
		t.Fatal("body Scan did not join")
	}
	if err := h.ReconcileCleanupV1(ctx); err != nil {
		t.Fatal("joined synthetic conjunction could not retire")
	}
	if err := copyHandle.ReconcileCleanupV1(ctx); err != nil || observed.Load() != 1 || c.SnapshotV1(org).Global.SQLSessions != 0 {
		t.Fatal("copied handle duplicated credit or discarded completion")
	}
}
func TestApplicationSessionBorrowCannotExposeRawOrInterleaveCommitV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tx := &applicationSessionTxTestV1{}
	s := &applicationOwnedSessionV1{tx: tx, changed: make(chan struct{})}
	h := &ApplicationSessionV1{state: s}
	err := h.WithTxV1(ctx, func(owned context.Context, db generated.DBTX) error {
		if _, raw := db.(pgx.Tx); raw {
			t.Fatal("unchecked transaction/connection escaped owned borrow")
		}
		if err := h.CommitV1(ctx); err == nil {
			t.Fatal("another completion call interleaved a borrowed transaction")
		}
		_, err := db.Exec(owned, "synthetic ordinary mutation")
		return err
	})
	if err != nil || tx.commits.Load() != 0 {
		t.Fatal("owned nested statement failed or commit dispatched")
	}
	if err := h.CommitV1(ctx); err != nil || tx.commits.Load() != 1 {
		t.Fatal("joined callback prevented normal completion")
	}
	if err := h.WithTxV1(ctx, func(context.Context, generated.DBTX) error { return nil }); err == nil {
		t.Fatal("completed session admitted another transaction borrow")
	}
}

func TestApplicationSessionErrorsPreserveSQLDecisionsWithoutPrivateTextV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failure := applicationSessionErrorV1(ctx, ErrApplicationSessionCommitUnknownV1, errors.Join(pgx.ErrNoRows, errors.New("private DSN credential detail")))
	if !errors.Is(failure, ErrApplicationSessionV1) || !errors.Is(failure, ErrApplicationSessionCommitUnknownV1) || !errors.Is(failure, pgx.ErrNoRows) || failure.Error() != ErrApplicationSessionV1.Error() {
		t.Fatal("generic session error lost the SQL/commit decision contract or exposed private error text")
	}
	cancel()
	failure = applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, nil)
	if !errors.Is(failure, context.Canceled) || !errors.Is(failure, ErrApplicationSessionUnknownV1) {
		t.Fatal("cancelled cleanup lost retained-session disposition")
	}
}

func TestApplicationSessionBusyObserverRefusesWithoutExposingControlOwnerV1(t *testing.T) {
	for _, mode := range []string{"busy", "unknown", "closed"} {
		t.Run(mode, func(t *testing.T) {
			coordinator, work := applicationSessionResourcesTestV1(t, 2)
			org := uuid.New()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			grant, err := work.SQLSessionV1(ctx, org)
			if err != nil {
				t.Fatal("admit synthetic control owner")
			}
			defer grant()
			p := &applicationSessionFactoryStateV1{work: work, organisations: make(map[uuid.UUID]*applicationSessionOrganisationV1), sessions: make(map[*applicationOwnedSessionV1]struct{})}
			o := &applicationSessionOrganisationV1{factory: p, org: org, guard: make(chan struct{}, 1)}
			s := applicationSessionNewOwnerV1(o, uuid.Nil, true)
			s.grant = grant
			s.active = 0
			s.unknown = mode == "unknown"
			s.closed = mode == "closed"
			if mode == "busy" {
				s.active = 1
			}
			o.observer = s
			p.organisations[org] = o
			before := coordinator.SnapshotV1(org)
			handle, err := (&ApplicationSessionFactoryV1{state: p}).OpenV1(ctx, org, uuid.New())
			if err == nil || handle != nil || o.observer != s || s.grant == nil || len(p.sessions) != 0 ||
				s.closed != (mode == "closed") || s.retired || s.retiring != 0 || s.closingClient ||
				coordinator.SnapshotV1(org) != before || before.Global.SQLSessions != 1 ||
				s.unknown != (mode != "busy") || (mode == "busy" && s.active != 1) || (mode != "busy" && s.active != 0) ||
				p.organisations[org] != o || len(p.organisations) != 1 {
				t.Fatal("busy observer was exposed as an uncertain work cleanup handle or credited")
			}
		})
	}
}

func TestApplicationSessionShutdownGateRefusesUnregisteredObserverV1(t *testing.T) {
	coordinator, work := applicationSessionResourcesTestV1(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	org := uuid.New()
	factory, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal("construct shutdown fixture")
	}
	organisation, err := factory.organisationV1(ctx, org)
	if err != nil {
		t.Fatal("create bounded undialed organisation")
	}
	if err := factory.CloseV1(ctx); err != nil {
		t.Fatal("never-dispatched factory could not close")
	}
	if err := organisation.ensureObserverV1(ctx); err == nil || organisation.observer != nil || coordinator.SnapshotV1(org).Global.SQLSessions != 0 {
		t.Fatal("observer creation escaped terminal dispatch gate")
	}
}

type applicationSessionRowsTestV1 struct {
	pgx.Rows
	closes atomic.Int32
}

func (r *applicationSessionRowsTestV1) Close()          { r.closes.Add(1) }
func (r *applicationSessionRowsTestV1) Conn() *pgx.Conn { return &pgx.Conn{} }
func TestApplicationSessionHeldRowsLoanAndCopiedCloseV1(t *testing.T) {
	coordinator, work := applicationSessionResourcesTestV1(t, 2)
	org := uuid.New()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	grant, err := work.SQLSessionV1(ctx, org)
	if err != nil {
		t.Fatal("admit synthetic Rows owner")
	}
	defer grant()
	factory := &applicationSessionFactoryStateV1{work: work, sessions: make(map[*applicationOwnedSessionV1]struct{})}
	clientDone := make(chan struct{})
	close(clientDone)
	raw := &applicationSessionRowsTestV1{}
	var observed atomic.Int32
	owner := &applicationOwnedSessionV1{factory: factory, org: org, document: uuid.New(), grant: grant, changed: make(chan struct{}), dialed: true, tx: &applicationSessionTxTestV1{rows: raw}, fence: &applicationSessionFenceV1{clientDone: clientDone, observe: func(context.Context, applicationBackendIdentityV1) (bool, error) { observed.Add(1); return true, nil }}}
	factory.sessions[owner] = struct{}{}
	session := &ApplicationSessionV1{state: owner}
	var borrowed pgx.Rows
	err = session.WithTxV1(ctx, func(owned context.Context, db generated.DBTX) error {
		var e error
		borrowed, e = db.Query(owned, "synthetic Rows loan")
		return e
	})
	if err != nil || borrowed == nil {
		t.Fatal("create owned Rows loan")
	}
	defer borrowed.Close()
	if borrowed.Conn() != nil {
		t.Fatal("Rows exposed a private connection")
	}
	if err = session.CommitV1(ctx); err == nil {
		t.Fatal("commit interleaved a live Rows loan")
	}
	owner.mu.Lock()
	owner.closed = true
	owner.mu.Unlock()
	if err = session.ReconcileCleanupV1(ctx); !errors.Is(err, ErrApplicationSessionUnknownV1) || observed.Load() != 0 || coordinator.SnapshotV1(org).Global.SQLSessions != 1 {
		t.Fatal("held Rows loan credited before caller close")
	}
	copyRows := *borrowed.(*applicationOwnedRowsV1)
	var closers sync.WaitGroup
	closers.Add(2)
	go func() { defer closers.Done(); borrowed.Close() }()
	go func() { defer closers.Done(); copyRows.Close() }()
	closers.Wait()
	if raw.closes.Load() != 1 {
		t.Fatal("copied Rows handles dispatched duplicate physical close")
	}
	if err = session.ReconcileCleanupV1(ctx); err != nil || observed.Load() != 1 || coordinator.SnapshotV1(org).Global.SQLSessions != 0 {
		t.Fatal("joined Rows loan did not retire exactly once")
	}
	if err = session.ReconcileCleanupV1(ctx); err != nil || observed.Load() != 1 {
		t.Fatal("retired Rows loan repeated server proof or credit")
	}
}
