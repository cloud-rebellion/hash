// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Command e2eprofile checks caller-owned integration fixtures before any test
// or migration writes. It creates no database and never prints configuration.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/jackc/pgx/v5"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "audit" {
		err = auditRun(os.Args[2:])
	} else {
		err = run()
	}
	if err != nil {
		// PostgreSQL/parser errors may contain credential-bearing connection
		// strings. Only the fixed phase errors constructed below are printed.
		fmt.Fprintln(os.Stderr, "e2e profiles:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("module root and source-built PDF worker are required")
	}
	for _, name := range []string{"HASH_E2E_OWNED_PG", "HASH_E2E_BACKLOG_OWNED_PG", "HASH_E2E_RECIPIENT_LOCK_OWNED_PG", "HASH_E2E_ORIGINALS_OWNED_PG"} {
		if os.Getenv(name) != "1" {
			return fmt.Errorf("explicit disposable PostgreSQL ownership acknowledgement required: %s", name)
		}
	}
	for _, entry := range optionalAcceptanceCatalog {
		if os.Getenv(entry.Flag) != "" {
			return fmt.Errorf("separate acceptance flag must be unset in this runner: %s", entry.Flag)
		}
	}
	want := os.Getenv("HASH_E2E_EXPECT_MIGRATIONS_SHA256")
	raw, err := hex.DecodeString(want)
	if err != nil || len(raw) != sha256.Size || want != strings.ToLower(want) {
		return fmt.Errorf("caller-pinned migration SHA-256 is required")
	}
	embedded, versions, err := db.EmbeddedMigrationsIdentity()
	if err != nil || embedded != want || len(versions) == 0 {
		return fmt.Errorf("caller migration pin differs from this compiled source")
	}
	for i, version := range versions {
		if version != int64(i+1) {
			return fmt.Errorf("embedded migration versions are not contiguous")
		}
	}
	onDisk, err := migrationTreeDigest(filepath.Join(os.Args[1], "internal", "db", "migrations"))
	if err != nil || onDisk != embedded {
		return fmt.Errorf("migration source changed or differs from the compiled tree")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seen := make(map[string]bool)
	for _, profile := range []struct{ name, env, prefix string }{
		{"ordinary", "HASH_E2E_DB_URL", ""},
		{"backlog", "HASH_E2E_BACKLOG_DB_URL", "hash_backlog_"},
		{"recipient-lock", "HASH_E2E_RECIPIENT_LOCK_DB_URL", "hash_recipient_lock_"},
	} {
		identity, err := inspectDatabase(ctx, profile.env, profile.prefix)
		if err != nil {
			return fmt.Errorf("%s profile: %s", profile.name, err)
		}
		if seen[identity] {
			return fmt.Errorf("each profile must have a distinct disposable database")
		}
		seen[identity] = true
	}
	if err := sanitize.ConfigurePDFWorker(ctx, os.Args[2], "production"); err != nil {
		return fmt.Errorf("source-built isolated PDF worker failed its production probe")
	}
	fmt.Println(embedded)
	return nil
}

func inspectDatabase(parent context.Context, env, prefix string) (string, error) {
	config, err := profileConfiguration(os.Getenv(env), prefix)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	config.RuntimeParams["application_name"] = "hash-e2e-profile-preflight"
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return "", fmt.Errorf("cannot connect to the owned fixture")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = conn.Close(cleanup)
	}()
	var database, address string
	var port int32
	var writable, createdb, empty bool
	err = conn.QueryRow(ctx, `SELECT current_database(),coalesce(inet_server_addr()::text,''),
 coalesce(inet_server_port(),0),NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off',
 (SELECT rolcreatedb OR rolsuper FROM pg_roles WHERE rolname=current_user),
 NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S'))`).Scan(&database, &address, &port, &writable, &createdb, &empty)
	if err != nil || database != config.Database || !writable || !createdb || !empty {
		return "", fmt.Errorf("require the exact fresh writable fixture and database-creation authority")
	}
	return fmt.Sprintf("%s:%d/%s", address, port, database), nil
}

func profileConfiguration(raw, prefix string) (*pgx.ConnConfig, error) {
	config, err := pgx.ParseConfig(raw)
	if raw == "" || err != nil || config.Database == "" {
		return nil, fmt.Errorf("explicit valid database URL is required")
	}
	if prefix != "" {
		if !strings.HasPrefix(config.Database, prefix) || len(config.Database) == len(prefix) || !loopback(config.Host) {
			return nil, fmt.Errorf("owned database prefix and literal loopback host are required")
		}
		for _, fallback := range config.Fallbacks {
			if !loopback(fallback.Host) {
				return nil, fmt.Errorf("remote connection fallbacks are forbidden")
			}
		}
	}
	return config, nil
}

func loopback(host string) bool { return host == "127.0.0.1" || host == "localhost" || host == "::1" }

// Match EmbeddedMigrationsIdentity's sorted filename-NUL-content-NUL encoding.
func migrationTreeDigest(root string) (string, error) {
	var names []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("migration source must be a regular file")
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		names = append(names, filepath.ToSlash(name))
		return nil
	})
	if err != nil || len(names) == 0 {
		return "", fmt.Errorf("cannot read migration source")
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return "", err
		}
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(content)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
