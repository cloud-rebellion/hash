//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package testfixture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	hashdb "github.com/bright-interaction/hash/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// OwnedPostgresFactory belongs to one test process. It migrates one empty,
// uniquely owned seed and gives every case an independent physical database.
// The original parent is captured before tests can temporarily change the DSN.
// Empty-database migration/legacy tests must retain their original fixture.
type OwnedPostgresFactory struct {
	mu                  sync.Mutex
	dsn                 string
	config              *pgx.ConnConfig
	parentOID, ownerOID uint32
	seed                string
	seedOID             uint32
	deadline            time.Time
	ready               bool
	initErr             error
}

func NewOwnedPostgresFactory(parentDSN string) *OwnedPostgresFactory {
	return &OwnedPostgresFactory{dsn: parentDSN}
}

func fixtureError(phase string, err error) error {
	state := "none"
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		state = pg.Code
	}
	return fmt.Errorf("owned PostgreSQL fixture %s (type=%T sqlstate=%s deadline=%t)", phase, err, state, errors.Is(err, context.DeadlineExceeded))
}

func (f *OwnedPostgresFactory) connect(ctx context.Context) (*pgx.Conn, error) {
	cfg := f.config.Copy()
	cfg.RuntimeParams["application_name"] = "hash_owned_fixture_admin"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fixtureError("administrator connect", err)
	}
	var database, user string
	var oid, owner uint32
	err = conn.QueryRow(ctx, `SELECT current_database(),current_user,d.oid,r.oid FROM pg_database d JOIN pg_roles r ON r.rolname=current_user WHERE d.datname=current_database()`).Scan(&database, &user, &oid, &owner)
	if err != nil || database != f.config.Database || user != f.config.User || (f.parentOID != 0 && (oid != f.parentOID || owner != f.ownerOID)) {
		_ = conn.Close(ctx)
		return nil, fixtureError("parent identity changed", err)
	}
	if f.parentOID == 0 {
		f.parentOID, f.ownerOID = oid, owner
	}
	return conn, nil
}

func closeFixtureConn(ctx context.Context, conn *pgx.Conn) error {
	if err := conn.Close(ctx); err != nil {
		return fixtureError("connection close", err)
	}
	select {
	case <-conn.PgConn().CleanupDone():
		return nil
	case <-ctx.Done():
		return fixtureError("connection cleanup join", ctx.Err())
	}
}

func observeFixtureRetired(ctx context.Context, admin *pgx.Conn, name string) error {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*)::integer FROM pg_stat_activity WHERE datname=$1`, name).Scan(&count); err != nil {
			return fixtureError("backend witness", err)
		}
		if count == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fixtureError("backend retirement", ctx.Err())
		case <-tick.C:
		}
	}
}

func (f *OwnedPostgresFactory) initialize(ctx context.Context) (retErr error) {
	if f.initErr != nil {
		return f.initErr
	}
	if f.ready {
		return nil
	}
	defer func() {
		if retErr != nil {
			f.initErr = retErr
		}
	}()
	if os.Getenv("HASH_E2E_OWNED_PG") != "1" {
		return fmt.Errorf("owned PostgreSQL fixture requires HASH_E2E_OWNED_PG=1")
	}
	digest, versions, err := hashdb.EmbeddedMigrationsIdentity()
	if err != nil || len(versions) == 0 || os.Getenv("HASH_E2E_EXPECT_MIGRATIONS_SHA256") != digest {
		return fmt.Errorf("owned PostgreSQL fixture requires the exact caller-pinned migration digest")
	}
	f.config, err = pgx.ParseConfig(f.dsn)
	if err != nil || f.config.Database == "" || f.config.User == "" {
		return fmt.Errorf("owned PostgreSQL fixture requires its original PostgreSQL configuration")
	}
	admin, err := f.connect(ctx)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeFixtureConn(ctx, admin)) }()
	name := "hash_e2e_seed_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		return fixtureError("seed creation", err)
	}
	f.seed = name
	if err := admin.QueryRow(ctx, `SELECT oid FROM pg_database WHERE datname=$1 AND datdba=$2`, name, f.ownerOID).Scan(&f.seedOID); err != nil {
		return fixtureError("seed ownership", err)
	}
	cfg := f.config.Copy()
	cfg.Database = name
	cfg.RuntimeParams["application_name"] = "hash_owned_seed_migration"
	bridge := stdlib.OpenDB(*cfg)
	bridge.SetMaxOpenConns(1)
	bridge.SetMaxIdleConns(1)
	defer bridge.Close()
	if err := hashdb.RunMigrationsContext(ctx, bridge); err != nil {
		return fixtureError("seed migration", err)
	}
	version, err := hashdb.GetMigrationVersionContext(ctx, bridge)
	if err != nil || version != versions[len(versions)-1] {
		return fixtureError("seed migration identity", err)
	}
	if err := bridge.Close(); err != nil {
		return fixtureError("migration bridge close", err)
	}
	if err := observeFixtureRetired(ctx, admin, name); err != nil {
		return err
	}
	// Block accidental case connections to the immutable migrated seed. Clones
	// still have their normal independent connections and writable schema.
	if _, err := admin.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{name}.Sanitize()+" ALLOW_CONNECTIONS false"); err != nil {
		return fixtureError("seal seed connections", err)
	}
	f.ready = true
	return nil
}

func ownedFixturePrefix(prefix string) bool {
	if !strings.HasPrefix(prefix, "hash_") || !strings.HasSuffix(prefix, "_") || len(prefix) > 30 {
		return false
	}
	return strings.Trim(prefix, "abcdefghijklmnopqrstuvwxyz0123456789_") == ""
}

// Clone registers disposal before callers create any pools, runtimes or peers;
// their normal joined cleanup therefore runs before the independent DROP.
func (f *OwnedPostgresFactory) Clone(t testing.TB, prefix string) string {
	t.Helper()
	if !ownedFixturePrefix(prefix) {
		t.Fatal("invalid owned PostgreSQL fixture prefix")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	deadline := time.Now().Add(90 * time.Second)
	if owner, ok := t.(interface{ Deadline() (time.Time, bool) }); ok {
		if end, exists := owner.Deadline(); exists {
			f.deadline = end.Add(-5 * time.Second)
			if f.deadline.Before(deadline) {
				deadline = f.deadline
			}
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := f.initialize(ctx); err != nil {
		t.Fatal(err)
	}
	admin, err := f.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeFixtureConn(ctx, admin); err != nil {
			t.Error(err)
		}
	}()
	if err := observeFixtureRetired(ctx, admin, f.seed); err != nil {
		t.Fatal(err)
	}
	var seedOID uint32
	if err := admin.QueryRow(ctx, `SELECT oid FROM pg_database WHERE datname=$1 AND datdba=$2 AND NOT datallowconn AND NOT datistemplate`, f.seed, f.ownerOID).Scan(&seedOID); err != nil || seedOID != f.seedOID {
		t.Fatal("owned PostgreSQL seed identity changed")
	}
	name := prefix + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE "+pgx.Identifier{f.seed}.Sanitize()); err != nil {
		t.Fatal(fixtureError("independent clone creation", err))
	}
	var oid uint32
	if err := admin.QueryRow(ctx, `SELECT oid FROM pg_database WHERE datname=$1 AND datdba=$2 AND NOT datistemplate`, name, f.ownerOID).Scan(&oid); err != nil {
		t.Fatal(fixtureError("clone ownership", err))
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := f.drop(cleanup, name, oid); err != nil {
			t.Error(err)
		}
	})
	return name
}

func (f *OwnedPostgresFactory) drop(ctx context.Context, name string, oid uint32) (retErr error) {
	if (!strings.HasPrefix(name, "hash_e2e_seed_") && !strings.HasPrefix(name, "hash_")) || oid == 0 {
		return fmt.Errorf("refuse unknown PostgreSQL fixture disposal")
	}
	admin, err := f.connect(ctx)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeFixtureConn(ctx, admin)) }()
	var actual uint32
	if err := admin.QueryRow(ctx, `SELECT oid FROM pg_database WHERE datname=$1 AND datdba=$2 AND NOT datistemplate`, name, f.ownerOID).Scan(&actual); err != nil || actual != oid {
		return fixtureError("disposal identity changed", err)
	}
	if err := observeFixtureRetired(ctx, admin, name); err != nil {
		return err
	}
	start := time.Now()
	if _, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		return fixtureError(fmt.Sprintf("drop after zero-backend witness elapsed=%s", time.Since(start).Round(time.Millisecond)), err)
	}
	return nil
}

// Close is called from TestMain, within the original test-process deadline.
// Failed child cleanup remains a test failure; it is never force-dropped here.
func (f *OwnedPostgresFactory) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seed == "" {
		return nil
	}
	deadline := time.Now().Add(10 * time.Second)
	if !f.deadline.IsZero() && f.deadline.Before(deadline) {
		deadline = f.deadline
	}
	ctx, stop := context.WithDeadline(context.Background(), deadline)
	defer stop()
	return f.drop(ctx, f.seed, f.seedOID)
}
