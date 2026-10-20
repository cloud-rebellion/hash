//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5"
)

// Retain the original owner-policy data and empty audit baseline. One runtime
// uses that SAME actual pool/config; REST and the subsequently rebuilt MCP
// dependency graph share its genuine factory. No borrowed transaction, second
// factory, renderer/provider, measurement cache insertion or production claim.
func setupOwnerPolicyNative441E2E(t *testing.T, sharedDatabase ...string) ownerOrgMutationFixture {
	t.Helper()
	if len(sharedDatabase) > 1 {
		t.Fatal("owner-policy supports only one explicitly shared owned database")
	}
	database := ""
	if len(sharedDatabase) == 0 {
		database = isolateHTMLTemplateDatabaseE2E(t)
	} else {
		// The cross-tenant test needs both actual foreign rows in the SAME DB.
		// Reuse only its already selected unique fixture DB, never a parent DB.
		database = sharedDatabase[0]
		cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
		if err != nil || !strings.HasPrefix(database, "hash_html_e2e_") || cfg.Database != database {
			t.Fatal("owner-policy sibling requires the exact selected owned database", err)
		}
	}
	dsn := os.Getenv("HASH_E2E_DB_URL")
	application := ""
	// Register before pool birth: native Close, owned-estate disposal, original
	// lifecycle cleanup and pool.Close must all run before this physical witness.
	t.Cleanup(func() {
		if application == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Error("owner-policy independent witness configuration", err)
			return
		}
		cfg.RuntimeParams["application_name"] = "hash_owner_policy441_witness"
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Error("owner-policy independent witness connection", err)
			return
		}
		defer func() {
			closeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := conn.Close(closeCtx); err != nil {
				t.Error("owner-policy independent witness close", err)
			}
		}()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var count int
			if err := conn.QueryRow(ctx, "SELECT count(*)::integer FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1", application).Scan(&count); err != nil { //nolint:rawsql -- exact unique fixture pool/native identity only
				t.Error("owner-policy independent backend observation", err)
				return
			}
			if count == 0 {
				return
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				t.Errorf("owner-policy pool/native backends did not retire: count=%d", count)
				return
			}
		}
	})
	f := setupOwnerOrgMutationE2E(t)
	// Observe the same latest-per-version history rule as the genuine migration
	// getter, after actual embedded Up and before any selected catalog work.
	var version int64
	if err := f.pool.QueryRow(f.ctx, `SELECT version_id FROM (
  SELECT DISTINCT ON (version_id) id,version_id,is_applied
  FROM goose_db_version ORDER BY version_id,id DESC
 ) AS latest_versions WHERE is_applied ORDER BY id DESC LIMIT 1`).Scan(&version); err != nil || version != 114 { //nolint:rawsql -- scalar actual child history oracle only
		t.Fatal("owner-policy fixture is not at exact current migration114", version, err)
	}
	application = f.pool.Config().ConnConfig.RuntimeParams["application_name"]
	if application == "" || f.s.Send == nil {
		t.Fatal("original owner-policy pool identity/send dependency unavailable")
	}
	// This runs after native Close and before the original lifecycle DELETEs.
	// The immutable history is disposed only in this exact synthetic database.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var actual string
		if err := f.pool.QueryRow(ctx, "SELECT current_database()").Scan(&actual); err != nil || actual != database || !strings.HasPrefix(actual, "hash_html_e2e_") { //nolint:rawsql -- exact owned teardown fence
			t.Error("refuse non-owned owner-policy disposal", err)
			return
		}
		if _, err := f.pool.Exec(ctx, "TRUNCATE orgs CASCADE"); err != nil { //nolint:rawsql -- whole uniquely owned synthetic estate only
			t.Error("owner-policy owned-estate disposal", err)
		}
	})
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 1}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 1}, MaxGrants: 128, MaxOrganisationGrants: 64}
	runtime, err := pdfadmission.NewWorkRuntimeV1(f.pool, limits, int64(f.pool.Config().MaxConns)+8)
	if err != nil || !runtime.MatchesPoolV1(f.pool) {
		t.Fatal("owner-policy genuine same-pool runtime unavailable", err)
	}
	f.s.HTMLCreationSessions = runtime.SessionsV1()
	f.s.Send.WorkRuntime = runtime
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := runtime.ReconcileCleanupV1(ctx); err != nil {
			t.Error("owner-policy original work reconciliation", err)
		}
		observers := runtime.SessionsV1().PendingV1().ObserverSessions
		// Explicit rule preparation starts one process observer; catalog HTTP/MCP
		// work can additionally start this one tenant observer. Preserve their debt.
		if observers < 1 || observers > 2 {
			t.Errorf("owner-policy observer recipe outside process+one tenant: %d", observers)
		}
		closeErr := runtime.CloseV1(ctx)
		pending := runtime.SessionsV1().PendingV1()
		if pending != (pdfadmission.ApplicationSessionPendingV1{ObserverSessions: observers, Closing: true}) || !errors.Is(closeErr, pdfadmission.ErrApplicationSessionUnknownV1) {
			t.Errorf("owner-policy native work/debt cleanup differs: pending=%+v err=%v", pending, closeErr)
		}
		snapshot, err := runtime.SnapshotV1(f.org)
		want := workguard.SnapshotV1{Global: workguard.VectorV1{SQLSessions: int64(observers)}, Organisation: workguard.VectorV1{SQLSessions: int64(observers - 1)}, GlobalGrants: int64(observers), OrganisationGrants: int64(observers - 1), ActiveOrganisations: int64(observers - 1)}
		if err != nil || snapshot != want {
			t.Errorf("owner-policy body work leaked or observer debt refunded: got=%+v want=%+v err=%v", snapshot, want, err)
		}
		// The independent witness AFTER pool.Close proves actual backend absence.
		// It never changes the runtime's unresolved final-observer accounting.
	})
	return f
}

func ownerPolicyPrepareRule441E2E(t *testing.T, f ownerOrgMutationFixture, rule *generated.EidasRoutingRule) {
	t.Helper()
	owner, err := f.s.HTMLCreationSessions.ControlledMeasureEIDASRuleSourceV1(f.ctx, f.org, rule.ID)
	if owner != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := owner.CloseV1(ctx); err != nil {
				t.Error("owner-policy explicit M96 source owner cleanup", err)
			}
		})
	}
	if err != nil || owner == nil {
		t.Fatal("owner-policy explicit M96 source preparation failed", err)
	}
	receipt, err := owner.ReceiptV1()
	if err != nil || receipt.Kind != "eidas-rule" || receipt.SourceID != rule.ID || receipt.OrgID != f.org || receipt.CreatedAt != rule.CreatedAt || receipt.UpdatedAt != rule.UpdatedAt || !receipt.CreatedAt.Valid || !receipt.UpdatedAt.Valid || !receipt.MeasuredAt.Valid || receipt.WireBytes != int64(len(rule.PredicateJson)) || receipt.WireBytes <= 0 || receipt.ServerVersionNum != 160015 {
		t.Fatal("owner-policy actual M96 acknowledged source receipt differs", err)
	}
	owner.CloseConsumerV1()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := owner.CloseV1(ctx); err != nil {
		t.Fatal("owner-policy actual M96 source owner did not retire", err)
	}
	if err := owner.CloseV1(ctx); err != nil {
		t.Fatal("owner-policy actual M96 source owner close not idempotent", err)
	}
	runtime := f.s.Send.WorkRuntime
	if err := runtime.ReconcileCleanupV1(ctx); err != nil {
		t.Fatal("owner-policy M96 source reconciliation", err)
	}
	// This fixture has performed only controlled process maintenance so far.
	if pending := runtime.SessionsV1().PendingV1(); pending != (pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 1}) {
		t.Fatalf("owner-policy M96 process-only recipe differs: %+v", pending)
	}
	snapshot, err := runtime.SnapshotV1(f.org)
	if err != nil || snapshot != (workguard.SnapshotV1{Global: workguard.VectorV1{SQLSessions: 1}, GlobalGrants: 1}) {
		t.Fatal("owner-policy M96 work remains beyond genuine process observer", snapshot, err)
	}
}

func awaitOwnerPolicyOrgLock441E2E(t *testing.T, f ownerPolicyFixture, name string) {
	t.Helper()
	query := "-- name: GetOrgForOwnerMutation"
	if name == "rule-create" || name == "rule-update" || name == "rule-delete" {
		query = "-- name: GetCatalogRuleOrgExistenceV1"
	}
	// NewWorkRuntimeV1 copies THIS actual pool's ConnConfig, including this
	// application_name. No invented distinct identity or waiter substitution.
	application := f.pool.Config().ConnConfig.RuntimeParams["application_name"]
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, query, "transactionid", application)
}

func ownerPolicyAssertTwoPatchAudits441E2E(t *testing.T, f ownerPolicyFixture) {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*)::integer FROM events WHERE org_id=$1 AND actor_user_id=$2 AND kind='document.updated' AND payload_json->>'via'='rest' AND payload_json->>'tool'='update_eidas_rule' AND payload_json->>'rule_id'=$3`, f.org, f.user.ID, f.rule.ID.String()).Scan(&count); err != nil || count != 2 { //nolint:rawsql -- exact two genuine concurrent PATCH audit effects
		t.Fatal("owner-policy two genuine PATCH audit effects differ", count, err)
	}
	chain, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(chain)
	if got := verifier.Result(); !got.OK || !got.Complete || got.TotalChecked != 2 {
		t.Fatalf("owner-policy concurrent PATCH audit chain differs: %+v", got)
	}
}
