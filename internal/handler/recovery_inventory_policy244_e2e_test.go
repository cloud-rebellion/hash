//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/recoveryinventory"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type recoveryInventoryPolicy244Row struct {
	KeyBase64, KeyJSON, Classes, Owners, OrgIDs, SHA256 string
	HashConflict, LegalEvidence                         bool
	ReferenceCount                                      int64
	VersionID                                           string
	VersionConflict, LegacyVersionLookup                bool
	RetainUntil                                         string
}

func TestRecoveryInventoryPolicy244E2E(t *testing.T) {
	q := newOwnedDocumentPackageMeasurementFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if err := malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := malwarescan.Configure(ctx, "", "development"); err != nil {
			t.Error("restore local scanner fixture", err)
		}
	})
	root, _, metadata, err := packageAttemptBirth235(t, q, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := packageAttemptTransition235(t, q, metadata, "aborted", false); err != nil {
		t.Fatal(err)
	}
	packageAttemptInspect235(t, q, metadata, false, "aborted")
	ownedCreationAssertDrainedV1(t, q, 2)

	raw, err := os.ReadFile("../../ops/recovery-object-inventory.sql")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if len(raw) != 18652 || hex.EncodeToString(sum[:]) != "df4247d6ea6766e8b0d428c4d90e5976273f012b3db1c7b201f6ddf6c589a939" {
		t.Fatal("canonical inventory changed; review full inventory policy equivalence")
	}
	config := q.f.pool.Config().ConnConfig.Copy()
	if config.RuntimeParams == nil {
		config.RuntimeParams = map[string]string{}
	}
	config.RuntimeParams["application_name"] = "hash-inventory-policy244"
	conn, err := pgx.ConnectConfig(q.f.ctx, config)
	if err != nil {
		t.Fatal("connect inventory policy fixture")
	}
	pid := conn.PgConn().PID()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := conn.Close(ctx); err != nil {
			t.Error("close inventory policy backend")
		}
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			var present bool
			if err := q.f.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1)", pid).Scan(&present); err != nil {
				t.Error("observe inventory policy backend retirement")
				return
			}
			if !present {
				return
			}
			select {
			case <-ctx.Done():
				t.Error("inventory policy backend did not retire within original cleanup bound")
				return
			case <-ticker.C:
			}
		}
	})
	if pid == 0 {
		t.Fatal("inventory policy fixture has no actual backend")
	}
	// Only this disposable direct test connection is changed. Starting with JIT
	// on makes a leaked local off value observable even on an off-by-default host.
	if _, err := conn.Exec(q.f.ctx, "SET jit=on"); err != nil {
		t.Fatal("prepare owned inventory policy backend")
	}

	assertSession := func(t *testing.T, query interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}, inTransaction bool) {
		t.Helper()
		var actualPID uint32
		var jit, statement, lock, idle, isolation, readOnly string
		err := query.QueryRow(q.f.ctx, "SELECT pg_backend_pid(),current_setting('jit'),current_setting('statement_timeout'),current_setting('lock_timeout'),current_setting('idle_in_transaction_session_timeout'),current_setting('transaction_isolation'),current_setting('transaction_read_only')").
			Scan(&actualPID, &jit, &statement, &lock, &idle, &isolation, &readOnly)
		if err != nil || actualPID != pid || statement != "5s" || lock != "3s" || idle != "15s" {
			t.Fatal("inventory policy changed backend or original timeout settings")
		}
		if inTransaction {
			if jit != "off" || isolation != "repeatable read" || readOnly != "on" {
				t.Fatal("inventory policy is not local to the read-only repeatable-read snapshot")
			}
		} else if jit != "on" {
			t.Fatal("inventory policy leaked beyond its transaction")
		}
	}
	assertIdle := func(t *testing.T) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			var idle bool
			err := q.f.pool.QueryRow(ctx, "SELECT state='idle' AND xact_start IS NULL FROM pg_stat_activity WHERE pid=$1", pid).Scan(&idle)
			if err != nil {
				t.Fatal("observe original inventory backend transaction retirement")
			}
			if idle {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("original inventory backend retained a transaction")
			case <-ticker.C:
			}
		}
	}
	assertSession(t, conn, false)

	var committed []recoveryInventoryPolicy244Row
	for _, finish := range []string{"commit", "rollback"} {
		t.Run(finish+"_restores_same_backend_and_full_inventory", func(t *testing.T) {
			tx, err := recoveryinventory.Begin(q.f.ctx, conn)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := recoveryinventory.Rollback(tx); err != nil {
					t.Error("close inventory policy snapshot")
				}
			}()
			assertSession(t, tx, true)
			rows, err := tx.Query(q.f.ctx, string(raw))
			if err != nil {
				t.Fatal("execute unchanged canonical inventory")
			}
			defer rows.Close()
			wantColumns := []string{"object_key_b64", "object_key_json", "reference_classes", "owners", "org_ids", "expected_sha256", "hash_conflict", "legal_evidence", "reference_count", "expected_version_id", "version_conflict", "legacy_version_lookup_allowed", "expected_retain_until"}
			fields := rows.FieldDescriptions()
			if len(fields) != len(wantColumns) {
				t.Fatal("canonical inventory lost its full13column projection")
			}
			for i, field := range fields {
				if field.Name != wantColumns[i] {
					t.Fatal("canonical inventory reordered or renamed a column")
				}
			}
			var got []recoveryInventoryPolicy244Row
			for rows.Next() {
				var row recoveryInventoryPolicy244Row
				if err := rows.Scan(&row.KeyBase64, &row.KeyJSON, &row.Classes, &row.Owners, &row.OrgIDs, &row.SHA256, &row.HashConflict, &row.LegalEvidence, &row.ReferenceCount, &row.VersionID, &row.VersionConflict, &row.LegacyVersionLookup, &row.RetainUntil); err != nil {
					t.Fatal("decode complete canonical inventory row")
				}
				got = append(got, row)
			}
			if err := rows.Err(); err != nil {
				t.Fatal("drain complete canonical inventory")
			}
			rows.Close()
			if len(got) != 1 {
				t.Fatal("genuine main-only fixture inventory cardinality changed")
			}
			row := got[0]
			var decodedKey string
			if err := json.Unmarshal([]byte(row.KeyJSON), &decodedKey); err != nil ||
				decodedKey != root.PdfStorageKey.String ||
				row.KeyBase64 != base64.StdEncoding.EncodeToString([]byte(decodedKey)) ||
				row.LegalEvidence || row.RetainUntil != "-" ||
				row.VersionID != root.PdfStorageVersionID.String ||
				row.SHA256 != hex.EncodeToString(root.PdfSha256) ||
				row.HashConflict || row.VersionConflict || row.LegacyVersionLookup ||
				row.ReferenceCount < 1 || row.OrgIDs != metadata.Capture.OrgID.String() ||
				!strings.Contains(row.Classes, "package_send_capture_pdf") ||
				!strings.Contains(row.Owners, metadata.AttemptID.String()) {
				t.Fatal("complete inventory lost exact key, pins, legal state or provenance")
			}
			if finish == "commit" {
				committed = got
			} else if !reflect.DeepEqual(committed, got) {
				t.Fatal("transaction finish choice changed ordered inventory rows")
			}
			query := "SELECT legal_evidence,expected_retain_until,expected_version_id,reference_classes::text,owners::text,version_conflict FROM (" + strings.TrimSuffix(strings.TrimSpace(string(raw)), ";") + ") inventory WHERE object_key_b64=$1"
			var legal, conflict bool
			var until, version, classes, owners string
			err = tx.QueryRow(q.f.ctx, query, row.KeyBase64).Scan(&legal, &until, &version, &classes, &owners, &conflict)
			if err != nil || legal || until != "-" || version != root.PdfStorageVersionID.String || conflict ||
				!strings.Contains(classes, "package_send_capture_pdf") || !strings.Contains(owners, metadata.AttemptID.String()) {
				t.Fatal("original embedded target oracle changed under inventory policy")
			}
			if finish == "commit" {
				err = tx.Commit(q.f.ctx)
			} else {
				err = recoveryinventory.Rollback(tx)
			}
			if err != nil {
				t.Fatal("finish inventory snapshot")
			}
			assertSession(t, conn, false)
			assertIdle(t)
		})
	}

	t.Run("canceled_caller_cleanup_restores_same_backend", func(t *testing.T) {
		ctx, cancel := context.WithCancel(q.f.ctx)
		defer cancel()
		tx, err := recoveryinventory.Begin(ctx, conn)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := recoveryinventory.Rollback(tx); err != nil {
				t.Error("close canceled inventory snapshot")
			}
		}()
		assertSession(t, tx, true)
		cancel()
		if ctx.Err() == nil {
			t.Fatal("inventory cleanup caller was not canceled")
		}
		if err := recoveryinventory.Rollback(tx); err != nil {
			t.Fatal("independent inventory rollback adopted canceled caller")
		}
		assertSession(t, conn, false)
		assertIdle(t)
	})

	t.Run("statement_timeout_rolls_back_and_restores_same_backend", func(t *testing.T) {
		tx, err := recoveryinventory.Begin(q.f.ctx, conn)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := recoveryinventory.Rollback(tx); err != nil {
				t.Error("close canceled inventory statement")
			}
		}()
		assertSession(t, tx, true)
		_, err = tx.Exec(q.f.ctx, "SELECT pg_sleep(30)")
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "57014" ||
			pgError.Message != "canceling statement due to statement timeout" || q.f.ctx.Err() != nil {
			t.Fatal("original5s server timeout did not cancel the actual inventory backend statement")
		}
		if err := recoveryinventory.Rollback(tx); err != nil {
			t.Fatal("rollback actual server-canceled inventory transaction")
		}
		assertSession(t, conn, false)
		assertIdle(t)
	})
	ownedCreationAssertDrainedV1(t, q, 2)
}
