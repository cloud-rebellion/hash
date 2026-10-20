// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package db wires the embedded goose migrations and exposes a runner.
package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// EmbeddedMigrationsIdentity returns the release identity of the SQL tree
// compiled into this exact application image. The digest intentionally uses
// the same canonical filename-NUL-content-NUL encoding as CI' release
// manifest, so release-only database checks can prove that the image, the
// approved manifest, and Goose's applied state all describe one migration
// tree. The returned versions are sorted and are a defensive copy.
func EmbeddedMigrationsIdentity() (digest string, versions []int64, err error) {
	var names []string
	err = fs.WalkDir(embeddedMigrations, "migrations", func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("embedded migration %s is not a regular file", filePath)
		}
		name := strings.TrimPrefix(filePath, "migrations/")
		if name == filePath || name == "" || strings.HasPrefix(name, "../") {
			return fmt.Errorf("resolve embedded migration name")
		}
		names = append(names, name)
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if len(names) == 0 {
		return "", nil, fmt.Errorf("embedded migration tree is empty")
	}
	sort.Strings(names)
	h := sha256.New()
	seenVersions := make(map[int64]struct{}, len(names))
	versions = make([]int64, 0, len(names))
	for _, name := range names {
		prefix, _, ok := strings.Cut(path.Base(name), "_")
		version, parseErr := strconv.ParseInt(prefix, 10, 64)
		if !ok || parseErr != nil || version <= 0 {
			return "", nil, fmt.Errorf("embedded migration has an invalid versioned filename")
		}
		if _, duplicate := seenVersions[version]; duplicate {
			return "", nil, fmt.Errorf("embedded migration version is duplicated")
		}
		seenVersions[version] = struct{}{}
		versions = append(versions, version)
		raw, readErr := embeddedMigrations.ReadFile(path.Join("migrations", name))
		if readErr != nil {
			return "", nil, readErr
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(raw)
		_, _ = h.Write([]byte{0})
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return hex.EncodeToString(h.Sum(nil)), append([]int64(nil), versions...), nil
}

// DefaultMigrationTimeout bounds compatibility callers and startup even when the
// supplied parent has no deadline. An earlier caller deadline always wins.
const DefaultMigrationTimeout = 2 * time.Minute
const migrationCleanupTimeout = 5 * time.Second
const migrationLockKey int64 = 792310457018 // Preserve the existing database-scoped lock identity.

// ErrMigrationHistoryUnsupportedV1 refuses migration writes over history whose
// false or ambiguous rows the pinned Goose provider would silently misinterpret.
// Read-only version observation remains available; this runner never repairs it.
var ErrMigrationHistoryUnsupportedV1 = errors.New("migration history is unsupported by the migration writer")

// RunMigrations applies the exact embedded SQL migrations with a finite default.
func RunMigrations(db *sql.DB) error { return RunMigrationsContext(context.Background(), db) }

// RunMigrationsContext propagates cancellation through pool acquisition, the
// session advisory lock, migration SQL and transactions. It never closes the
// caller's pool. Context cancellation is not successful migration or retirement.
func RunMigrationsContext(ctx context.Context, db *sql.DB) error {
	return runMigrationOperationContext(ctx, db, "up", 0)
}

// RunMigrationsUpTo preserves the historical embedded-version setup API.
func RunMigrationsUpTo(db *sql.DB, version int64) error {
	return RunMigrationsUpToContext(context.Background(), db, version)
}
func RunMigrationsUpToContext(ctx context.Context, db *sql.DB, version int64) error {
	if version < 0 {
		return fmt.Errorf("migration target must not be negative")
	}
	return runMigrationOperationContext(ctx, db, "up", version)
}

// GetMigrationVersionContext observes existing version history without creating
// metadata or using package-global Goose state. Like the legacy version getter,
// each version's newest ID decides whether it remains applied; the newest such
// applied row is the result. This does not normalize old migration histories.
func GetMigrationVersionContext(parent context.Context, db *sql.DB) (int64, error) {
	if parent == nil || db == nil {
		return -1, fmt.Errorf("migration version requires a context and database")
	}
	ctx, cancel := context.WithTimeout(parent, DefaultMigrationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	var version int64
	err := db.QueryRowContext(ctx, `SELECT version_id FROM (
  SELECT DISTINCT ON (version_id) id,version_id,is_applied
  FROM goose_db_version ORDER BY version_id,id DESC
 ) AS latest_versions WHERE is_applied ORDER BY id DESC LIMIT 1`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		err = goose.ErrNoNextVersion
	}
	if err != nil {
		return -1, fmt.Errorf("read existing migration version: %w", errors.Join(err, ctx.Err()))
	}
	if err = ctx.Err(); err != nil {
		return -1, err
	}
	return version, nil
}

// Rollback uses the same embedded SQL, caller deadline and same-session lock.
// Individual migrations retain their own occupied-history refusal guards.
func RunMigrationsDownContext(ctx context.Context, db *sql.DB) error {
	return runMigrationOperationContext(ctx, db, "down", -1)
}
func RunMigrationsDownToContext(ctx context.Context, db *sql.DB, version int64) error {
	if version < 0 {
		return fmt.Errorf("migration target must not be negative")
	}
	return runMigrationOperationContext(ctx, db, "down", version)
}

func runMigrationOperationContext(parent context.Context, db *sql.DB, direction string, version int64) error {
	if parent == nil || db == nil {
		return fmt.Errorf("migration requires a context and database")
	}
	ctx, cancel := context.WithTimeout(parent, DefaultMigrationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	migrations, err := fs.Sub(embeddedMigrations, "migrations")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}
	// Each locking Goose operation pins ONE *sql.Conn for its locker, metadata
	// and SQL transactions. Pooled db.Exec locks cannot provide that guarantee.
	// Avoid package-global FS/dialect mutation.
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations,
		goose.WithSessionLocker(migrationSessionLocker{}), goose.WithDisableGlobalRegistry(true), goose.WithVerbose(true))
	if err != nil {
		return fmt.Errorf("construct embedded migration provider: %w", err)
	}
	// Up/UpTo first call HasPending, which does not use a SessionLocker. Initialize
	// this exact provider via its locking GetDBVersion first, solely to initialize
	// version metadata. Discard its MAX value; it is not the public legacy-history
	// version observation above. The cached initialization leaves HasPending reads
	// unlocked and read-only; actual migration writes are rechecked/applied under
	// Up's separate pinned-session lock. Abandon this provider on any warm-up error
	// because Goose caches its first initialization attempt.
	if direction == "up" {
		if _, err = provider.GetDBVersion(ctx); err != nil {
			return fmt.Errorf("initialize embedded migration metadata: %w", errors.Join(err, ctx.Err()))
		}
	}
	switch {
	case direction == "down" && version < 0:
		_, err = provider.Down(ctx)
	case direction == "down":
		_, err = provider.DownTo(ctx, version)
	case direction == "up" && version > 0:
		_, err = provider.UpTo(ctx, version)
	case direction == "up":
		_, err = provider.Up(ctx)
	default:
		return fmt.Errorf("invalid migration direction")
	}
	if err != nil {
		return fmt.Errorf("run embedded migrations %s: %w", direction, errors.Join(err, ctx.Err()))
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	slog.Info("migrations applied", "direction", direction, "target", version)
	return nil
}

// Goose invokes both methods on its same pinned connection. Its cleanup gives
// SessionUnlock a detached context; add an explicit bound to that cleanup too.
// A failed or ambiguous lock operation must never return a possibly locked
// session to the pool. driver.ErrBadConn evicts that exact connection, rather
// than issuing an unlock on some other pooled backend or terminating a peer.
type migrationSessionLocker struct{}

func (migrationSessionLocker) SessionLock(ctx context.Context, conn *sql.Conn) error {
	if ctx == nil || conn == nil {
		return fmt.Errorf("migration lock requires its session")
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return errors.Join(fmt.Errorf("acquire migration advisory lock: %w", err), discardMigrationSession(conn))
	}
	// This runs before Goose initializes its version table, on the actual locked
	// session. Goose does not invoke SessionUnlock when SessionLock refuses, so
	// a failed inspection or unsupported history must evict this exact session.
	if err := checkMigrationWriterHistory(ctx, conn); err != nil {
		return errors.Join(err, discardMigrationSession(conn))
	}
	return nil
}

// checkMigrationWriterHistory returns only bounded scalars. The caller deadline
// bounds the fixed metadata queries; no historical rows are loaded into Go. This
// is provider-shape validation, not a compiled-version ceiling or history repair.
func checkMigrationWriterHistory(ctx context.Context, conn *sql.Conn) error {
	var present bool
	if err := conn.QueryRowContext(ctx, "SELECT to_regclass('goose_db_version') IS NOT NULL").Scan(&present); err != nil {
		return errors.Join(ErrMigrationHistoryUnsupportedV1, ctx.Err())
	}
	if !present {
		return nil
	}
	var supported bool
	err := conn.QueryRowContext(ctx, `SELECT
  NOT EXISTS (SELECT 1 FROM goose_db_version
   WHERE is_applied IS DISTINCT FROM TRUE OR version_id IS NULL OR version_id<0)
  AND NOT EXISTS (SELECT version_id FROM goose_db_version
   GROUP BY version_id HAVING count(*)>1)`).Scan(&supported)
	if err != nil || !supported {
		return errors.Join(ErrMigrationHistoryUnsupportedV1, ctx.Err())
	}
	return nil
}
func (migrationSessionLocker) SessionUnlock(parent context.Context, conn *sql.Conn) error {
	if parent == nil || conn == nil {
		return fmt.Errorf("migration unlock requires its session")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), migrationCleanupTimeout)
	defer cancel()
	var unlocked bool
	err := conn.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", migrationLockKey).Scan(&unlocked)
	if err == nil && unlocked {
		return nil
	}
	if err == nil {
		err = fmt.Errorf("migration advisory lock was not held by its owning session")
	}
	return errors.Join(fmt.Errorf("release migration advisory lock: %w", err), discardMigrationSession(conn))
}
func discardMigrationSession(conn *sql.Conn) error {
	err := conn.Raw(func(any) error { return driver.ErrBadConn })
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) {
		return nil
	}
	return err
}
