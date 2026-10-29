// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileConfigurationRejectsRemoteFallbacksAndUnownedNames(t *testing.T) {
	for _, test := range []struct {
		name, dsn, prefix string
		allowed           bool
	}{
		{"ipv4 backlog", "postgres://fixture@127.0.0.1/hash_backlog_unique?sslmode=disable", "hash_backlog_", true},
		{"ipv6 recipient", "postgres://fixture@[::1]/hash_recipient_lock_unique?sslmode=disable", "hash_recipient_lock_", true},
		{"localhost recipient", "postgres://fixture@localhost/hash_recipient_lock_unique?sslmode=disable", "hash_recipient_lock_", true},
		{"ordinary private service", "postgres://fixture@owned-postgres/ordinary?sslmode=disable", "", true},
		{"empty", "", "hash_backlog_", false},
		{"invalid", "postgres://%/credential-value", "hash_backlog_", false},
		{"remote primary", "postgres://fixture@remote.invalid/hash_backlog_unique?sslmode=disable", "hash_backlog_", false},
		{"remote fallback", "postgres://fixture@127.0.0.1,remote.invalid/hash_backlog_unique?sslmode=disable", "hash_backlog_", false},
		{"wrong database", "postgres://fixture@127.0.0.1/ordinary?sslmode=disable", "hash_backlog_", false},
		{"no unique suffix", "postgres://fixture@127.0.0.1/hash_recipient_lock_?sslmode=disable", "hash_recipient_lock_", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := profileConfiguration(test.dsn, test.prefix)
			if (err == nil) != test.allowed {
				t.Fatalf("profile admission allowed=%t, want %t", err == nil, test.allowed)
			}
			if err != nil && (test.dsn != "" && strings.Contains(err.Error(), test.dsn) || strings.Contains(err.Error(), "credential-value")) {
				t.Fatal("configuration error exposed its connection input")
			}
		})
	}
}

func TestMigrationTreeIdentityDetectsChangedAndMissingSource(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "00001_one.sql")
	second := filepath.Join(root, "00002_two.sql")
	// Create out of order: filesystem enumeration must not choose the release
	// identity. This independent literal is the documented release encoding.
	for path, content := range map[string]string{second: "SELECT 2;\n", first: "SELECT 1;\n"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want := sha256.Sum256([]byte("00001_one.sql\x00SELECT 1;\n\x00" + "00002_two.sql\x00SELECT 2;\n\x00"))
	original, err := migrationTreeDigest(root)
	if err != nil || original != hex.EncodeToString(want[:]) {
		t.Fatal("disk migration identity differs from the release encoding")
	}
	if err := os.WriteFile(first, []byte("SELECT 999;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := migrationTreeDigest(root)
	if err != nil || changed == original {
		t.Fatal("changed migration bytes retained the reviewed identity")
	}
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	missing, err := migrationTreeDigest(root)
	if err != nil || missing == changed || missing == original {
		t.Fatal("missing migration retained the reviewed identity")
	}
	if _, err := migrationTreeDigest(filepath.Join(root, "absent")); err == nil {
		t.Fatal("missing migration directory was accepted")
	}
}

func TestMigrationTreeRejectsIrregularSQLSource(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "external.sql")
	if err := os.WriteFile(target, []byte("SELECT 1;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "00001_external.sql")); err != nil {
		t.Fatal(err)
	}
	if _, err := migrationTreeDigest(root); err == nil {
		t.Fatal("a symlink could substitute SQL outside the reviewed migration tree")
	}
}
