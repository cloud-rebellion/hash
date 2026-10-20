// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This fixed observer proves only retirement of the exact original PostgreSQL
// backend. Client CleanupDone alone does not prove server work has stopped.
// Backend absence does NOT prove COMMIT/rollback, original row disposition or
// permission to release durable retained DB/provider debt, replay or regenerate.
// Durable unknown debt requires a separate fresh scoped journal reconciliation.
type applicationBackendIdentityV1 struct {
	pid                  int32
	backendStart         time.Time
	databaseOID, userOID int64
	address              string
	port                 int32
	postmasterStart      time.Time
}
type applicationSessionFenceV1 struct {
	mu                 sync.Mutex
	clientDone         <-chan struct{}
	identity           applicationBackendIdentityV1
	observe            func(context.Context, applicationBackendIdentityV1) (bool, error)
	retired, observing bool
}

func (f *applicationSessionFenceV1) retiredV1() bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.retired
}
func (f *applicationSessionFenceV1) proveV1(ctx context.Context) (bool, error) {
	if f == nil || f.observe == nil || !applicationContextV1(ctx) {
		return false, applicationErrorV1(ctx, nil)
	}
	f.mu.Lock()
	if f.retired {
		f.mu.Unlock()
		return true, nil
	}
	if f.observing || !applicationDoneV1(f.clientDone) {
		f.mu.Unlock()
		return false, nil
	}
	f.observing = true
	identity := f.identity
	f.mu.Unlock()
	gone, err := f.observe(ctx, identity)
	f.mu.Lock()
	f.observing = false
	if err == nil && ctx.Err() == nil && gone {
		f.retired = true
	}
	retired := f.retired
	f.mu.Unlock()
	if err != nil || ctx.Err() != nil {
		return false, applicationErrorV1(ctx, err)
	}
	return retired, nil
}

const applicationBackendIdentitySQLV1 = "SELECT a.pid,a.backend_start,a.datid::bigint,a.usesysid::bigint,COALESCE(pg_catalog.inet_server_addr()::text,''),COALESCE(pg_catalog.inet_server_port(),0),pg_catalog.pg_postmaster_start_time() FROM pg_catalog.pg_stat_activity a WHERE a.pid=pg_catalog.pg_backend_pid()"

// Query by PID ONLY. A masked/null backend_start must remain unknown instead of
// disappearing behind an exact-start WHERE predicate and resembling absence.
const applicationBackendObservationSQLV1 = "SELECT own.pid,own.backend_start,own.datid::bigint,own.usesysid::bigint,COALESCE(pg_catalog.inet_server_addr()::text,''),COALESCE(pg_catalog.inet_server_port(),0),pg_catalog.pg_postmaster_start_time(),target.pid,target.backend_start,target.datid::bigint,target.usesysid::bigint FROM pg_catalog.pg_stat_activity own LEFT JOIN pg_catalog.pg_stat_activity target ON target.pid=$1::integer WHERE own.pid=pg_catalog.pg_backend_pid()"

func applicationIdentityValidV1(v applicationBackendIdentityV1) bool {
	return v.pid > 0 && v.databaseOID > 0 && v.databaseOID <= 4294967295 && v.userOID > 0 && v.userOID <= 4294967295 && !v.backendStart.IsZero() && !v.postmasterStart.IsZero() &&
		v.backendStart.Year() >= 1 && v.backendStart.Year() <= 9999 && v.postmasterStart.Year() >= 1 && v.postmasterStart.Year() <= 9999 && len(v.address) <= 128 && v.port >= 0 && v.port <= 65535
}
func applicationServerSameV1(a, b applicationBackendIdentityV1) bool {
	return a.databaseOID == b.databaseOID && a.userOID == b.userOID && a.address == b.address && a.port == b.port && a.postmasterStart.Equal(b.postmasterStart)
}
func applicationTLSVerifySameV1(a, b *tls.Config) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	// Compare only public verification settings. Do not reflect certificate private
	// keys, passwords or callback internals. Uninspectable custom verification
	// callbacks refuse; the runtime must supply a supported same-origin observer.
	// RootCAs pointer equality deliberately requires dedicated sessions constructed
	// from observer.Config().ConnConfig.Copy(), whose TLS clone shares the verifier.
	return a.ServerName == b.ServerName && a.InsecureSkipVerify == b.InsecureSkipVerify && a.MinVersion == b.MinVersion && a.MaxVersion == b.MaxVersion && a.RootCAs == b.RootCAs &&
		a.VerifyConnection == nil && b.VerifyConnection == nil && a.VerifyPeerCertificate == nil && b.VerifyPeerCertificate == nil
}
func applicationObserverConfigSameV1(a, b *pgx.ConnConfig) bool {
	return a != nil && b != nil && a.Host == b.Host && a.Port == b.Port && a.Database == b.Database && a.User == b.User && applicationTLSVerifySameV1(a.TLSConfig, b.TLSConfig)
}
func applicationCaptureSessionFenceV1(ctx context.Context, tx pgx.Tx, observer *pgxpool.Pool) (*applicationSessionFenceV1, error) {
	if !applicationContextV1(ctx) || tx == nil || tx.Conn() == nil || tx.Conn().IsClosed() || observer == nil || !applicationObserverConfigSameV1(tx.Conn().Config(), observer.Config().ConnConfig) {
		return nil, applicationErrorV1(ctx, nil)
	}
	var original applicationBackendIdentityV1
	// Only scalar own-session metadata; no private fields, source bytes or JSON.
	if err := tx.QueryRow(ctx, applicationBackendIdentitySQLV1).Scan(&original.pid, &original.backendStart, &original.databaseOID, &original.userOID, &original.address, &original.port, &original.postmasterStart); err != nil || ctx.Err() != nil || !applicationIdentityValidV1(original) || uint32(original.pid) != tx.Conn().PgConn().PID() {
		return nil, applicationErrorV1(ctx, err)
	}
	fence := &applicationSessionFenceV1{clientDone: tx.Conn().PgConn().CleanupDone(), identity: original}
	fence.observe = func(ctx context.Context, old applicationBackendIdentityV1) (bool, error) {
		// Acquire/SQL are deadline bounded and called only outside entity locks. The
		// monitor pool belongs to the same trusted application; never widen its role.
		conn, err := observer.Acquire(ctx)
		if err != nil {
			return false, applicationErrorV1(ctx, err)
		}
		defer conn.Release()
		if conn.Conn().PgConn().TxStatus() != 'I' || !applicationObserverConfigSameV1(tx.Conn().Config(), conn.Conn().Config()) {
			return false, applicationErrorV1(ctx, nil)
		}
		// This is a fresh autocommit stats snapshot, independent of any old writer tx.
		if _, err := conn.Exec(ctx, "SELECT pg_catalog.pg_stat_clear_snapshot()"); err != nil {
			return false, applicationErrorV1(ctx, err)
		}
		var current applicationBackendIdentityV1
		var targetPID *int32
		var started *time.Time
		var databaseOID, userOID *int64
		// The own-server fingerprint and target PID row MUST come from ONE statement.
		// A routing/transaction-pooling proxy cannot validate server A then make an
		// absent target on server B appear to retire the original server A backend.
		err = conn.QueryRow(ctx, applicationBackendObservationSQLV1, old.pid).Scan(&current.pid, &current.backendStart, &current.databaseOID, &current.userOID, &current.address, &current.port, &current.postmasterStart, &targetPID, &started, &databaseOID, &userOID)
		if err != nil || ctx.Err() != nil {
			return false, applicationErrorV1(ctx, err)
		}
		return applicationObservedRetiredV1(ctx, old, current, targetPID, started, databaseOID, userOID)

	}
	return fence, nil
}

func applicationObservedRetiredV1(ctx context.Context, old, current applicationBackendIdentityV1, pid *int32, started *time.Time, databaseOID, userOID *int64) (bool, error) {
	if !applicationIdentityValidV1(current) || !applicationServerSameV1(old, current) {
		return false, applicationErrorV1(ctx, nil)
	}
	if pid == nil {
		if started != nil || databaseOID != nil || userOID != nil {
			return false, applicationErrorV1(ctx, nil)
		}
		return true, nil
	}
	if *pid != old.pid || started == nil || databaseOID == nil || userOID == nil || started.IsZero() || started.Year() < 1 || started.Year() > 9999 || *databaseOID < 1 || *databaseOID > 4294967295 || *userOID < 1 || *userOID > 4294967295 {
		return false, applicationErrorV1(ctx, nil)
	}
	if started.Equal(old.backendStart) {
		return false, nil
	}
	// A readable different incarnation of the same PID on that exact server means
	// the old backend has gone. This never resolves durable transaction outcome.
	return true, nil
}
