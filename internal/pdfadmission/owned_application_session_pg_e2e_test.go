//go:build owned_app_session_pg

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Finite real-PG qualification over the PUBLIC fixed factory and actual shared
// coordinator. Root supplies an owned disposable Unix/trust admin fixture,
// migrated through91, with network disabled; missing env fails, never skips.
// The one independent raw connection is a bounded synthetic witness, not a
// production observer, retirement/controller authority or credential workaround.
// No connection/transaction/observer injection, fake READY or application rows.
// This does not qualify full request capture, uncertain attempted Commit,
// provider/controller/authentication/signing/deployment or restart acceptance.

type ownedPGSessionConsumerV1 struct {
	session  *pdfadmission.ApplicationSessionV1
	registry *pdfadmission.ApplicationAdmissionV1
	consumer func()
}
type ownedPGQualifierV1 struct {
	coordinator                       *workguard.CoordinatorV1
	work                              *pdfadmission.WorkAdmissionV1
	factory                           *pdfadmission.ApplicationSessionFactoryV1
	raw                               *pgx.Conn
	rawGrant                          func()
	org                               uuid.UUID
	applicationName, table            string
	tableCreateDispatched, rawStarted bool
	handles                           []*ownedPGSessionConsumerV1
	disposed                          sync.Once
	disposeProblems                   []string
}

func (q *ownedPGQualifierV1) disposeV1(ctx context.Context) []string {
	q.disposed.Do(func() {
		// Attempt every teardown even if an assertion or earlier teardown failed.
		for _, h := range q.handles {
			if h.consumer != nil {
				h.consumer()
			}
			if h.session != nil {
				if !h.session.RetiredV1() {
					if err := h.session.RollbackV1(ctx); err != nil {
						q.disposeProblems = append(q.disposeProblems, "owned rollback failed")
					}
				}
				if err := h.session.CloseV1(ctx); err != nil || !h.session.RetiredV1() {
					q.disposeProblems = append(q.disposeProblems, "owned physical retirement failed")
				}
			}
			if h.registry != nil {
				if err := h.registry.CloseV1(ctx); err != nil {
					q.disposeProblems = append(q.disposeProblems, "owned consumer registry failed")
				}
			}
		}
		if q.factory != nil {
			// Deliberately retains the last observer grant: a closed observer cannot
			// prove itself gone. Expected unknown is an explicit production gate.
			err := q.factory.CloseV1(ctx)
			if q.factory.PendingV1().ObserverSessions > 0 {
				if !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
					q.disposeProblems = append(q.disposeProblems, "factory final observer did not remain unknown")
				}
			} else if err != nil {
				q.disposeProblems = append(q.disposeProblems, "factory without observer did not close")
			}
		}
		witnessJoined := !q.rawStarted
		if q.raw != nil {
			if q.tableCreateDispatched && !q.raw.IsClosed() {
				if _, err := q.raw.Exec(ctx, "DROP TABLE IF EXISTS "+q.table); err != nil {
					q.disposeProblems = append(q.disposeProblems, "owned witness table removal failed")
				}
			}
			cleanup := q.raw.PgConn().CleanupDone()
			if err := q.raw.Close(ctx); err != nil {
				q.disposeProblems = append(q.disposeProblems, "synthetic witness close failed")
			}
			select {
			case <-cleanup:
				witnessJoined = true
			case <-ctx.Done():
				q.disposeProblems = append(q.disposeProblems, "synthetic witness client cleanup did not join")
			}
		}
		// This grant belongs solely to the explicit test witness, and is closed by
		// its fixture owner after pgx client cleanup. It is not factory/resource/debt
		// retirement proof. Root verifies test-process/container disposal separately.
		if q.rawGrant != nil && witnessJoined {
			q.rawGrant()
		}
	})
	return append([]string(nil), q.disposeProblems...)
}
func ownedPGBackendAbsentV1(ctx context.Context, raw *pgx.Conn, pid int32, start time.Time) error {
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var exists bool
		if err := raw.QueryRow(probe, "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND backend_start=$2)", pid, start).Scan(&exists); err != nil {
			return errors.New("synthetic witness backend observation failed")
		}
		if !exists {
			return nil
		}
		select {
		case <-ticker.C:
		case <-probe.Done():
			return errors.New("actual backend remained present")
		}
	}
}
func ownedPGWitnessCountV1(ctx context.Context, raw *pgx.Conn, table, key string) (int64, error) {
	var n int64
	err := raw.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE operation=$1", key).Scan(&n)
	return n, err
}
func ownedPGExpectedSnapshotV1(org uuid.UUID, coordinator *workguard.CoordinatorV1, sqlSessions, parentBytes, dbBytes int64, grants int64) bool {
	s := coordinator.SnapshotV1(org)
	v := workguard.VectorV1{SQLSessions: sqlSessions, ParentBytes: parentBytes, DBStagingBytes: dbBytes}
	return s.Global == v && s.Organisation == v && s.GlobalGrants == grants && s.OrganisationGrants == grants
}

func TestOwnedApplicationSessionRealPGV1(t *testing.T) {
	dsn := os.Getenv("HASH_OWNED_SESSION_PG_DSN")
	if dsn == "" {
		t.Fatal("HASH_OWNED_SESSION_PG_DSN is required for the disposable real-PG qualifier")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid disposable Unix PG fixture config")
	}
	if !filepath.IsAbs(config.Host) || config.TLSConfig != nil || len(config.Fallbacks) != 0 || config.Password != "" {
		t.Fatal("qualifier requires explicit disposable Unix/trust config, without TLS/fallback/password")
	}
	config.ConnectTimeout = 2 * time.Second
	if config.RuntimeParams == nil {
		config.RuntimeParams = make(map[string]string)
	}
	tag := "hash_owned_pg_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	config.RuntimeParams["application_name"] = tag
	config.RuntimeParams["statement_timeout"] = "3000"
	config.RuntimeParams["lock_timeout"] = "1000"
	config.RuntimeParams["idle_in_transaction_session_timeout"] = "10000"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	limits := workguard.VectorV1{ParentBytes: 32 << 20, DBStagingBytes: 32 << 20, SQLSessions: 4}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 32, MaxOrganisationGrants: 32})
	if err != nil {
		t.Fatal("construct fixed disposable coordinator")
	}
	work, err := pdfadmission.NewWorkAdmissionV1(coordinator)
	if err != nil {
		t.Fatal("construct actual work admission")
	}
	q := &ownedPGQualifierV1{coordinator: coordinator, work: work, org: uuid.New(), applicationName: tag}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, problem := range q.disposeV1(cleanup) {
			t.Error(problem)
		}
	})
	q.rawGrant, err = work.SQLSessionV1(ctx, q.org)
	if err != nil {
		t.Fatal("admit bounded independent witness SQL session")
	}
	rawConfig := config.Copy()
	rawConfig.RuntimeParams["application_name"] = tag + "_raw"
	q.rawStarted = true
	q.raw, err = pgx.ConnectConfig(ctx, rawConfig)
	if err != nil {
		t.Fatal("connect independent disposable witness")
	}
	var version int64
	// Read only the latest history record for each version, so an old successful
	// Up cannot hide a later Down. Also require the actual91 cache relations and
	// all four enabled guard triggers; version history alone is not schema proof.
	if err = q.raw.QueryRow(ctx, "SELECT COALESCE(max(version_id),0) FROM (SELECT DISTINCT ON(version_id) version_id,is_applied FROM public.goose_db_version ORDER BY version_id,id DESC) latest WHERE is_applied").Scan(&version); err != nil || version != 91 {
		t.Fatal("disposable fixture must currently be at migration91")
	}
	var schema91 bool
	if err = q.raw.QueryRow(ctx, `SELECT
 to_regclass('public.document_signing_policy_sizes_v1') IS NOT NULL
 AND to_regclass('public.field_signing_policy_sizes_v1') IS NOT NULL
 AND (SELECT count(*) FROM pg_catalog.pg_trigger t WHERE NOT t.tgisinternal AND t.tgenabled='O' AND (
  (t.tgname='derive_document_policy_sizes_v1' AND t.tgrelid=to_regclass('public.document_signing_policy_sizes_v1')) OR
  (t.tgname='derive_field_policy_sizes_v1' AND t.tgrelid=to_regclass('public.field_signing_policy_sizes_v1')) OR
  (t.tgname='invalidate_document_policy_sizes_v1' AND t.tgrelid=to_regclass('public.documents')) OR
  (t.tgname='invalidate_field_policy_sizes_v1' AND t.tgrelid=to_regclass('public.document_fields'))
 ))=4`).Scan(&schema91); err != nil || !schema91 {
		t.Fatal("actual migration91 cache relations and enabled guard triggers are required")
	}
	q.table = pgx.Identifier{"hash_owned_session_witness_" + strings.ReplaceAll(uuid.NewString(), "-", "")}.Sanitize()
	var witnessAlreadyPresent bool
	if err = q.raw.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", q.table).Scan(&witnessAlreadyPresent); err != nil || witnessAlreadyPresent {
		t.Fatal("generated witness name must be absent in the owned disposable fixture")
	}
	// Dispatch can fail with an unknown CREATE result. Teardown still removes
	// this uniquely generated preflight-absent owned fixture name.
	q.tableCreateDispatched = true
	if _, err = q.raw.Exec(ctx, "CREATE TABLE "+q.table+" (operation text PRIMARY KEY, marker text NOT NULL)"); err != nil {
		t.Fatal("create owned ephemeral witness table")
	}
	q.factory, err = pdfadmission.NewApplicationSessionFactoryV1(config, work, pdfadmission.ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal("construct actual fixed owned session factory")
	}
	for _, mode := range []string{"cancelled_commit", "acknowledged_commit"} {
		for _, order := range []string{"consumer_first", "physical_first"} {
			passed := t.Run(mode+"/"+order, func(t *testing.T) {
				documentID, recipientID := uuid.New(), uuid.New()
				h, openErr := q.factory.OpenV1(ctx, q.org, documentID)
				holder := &ownedPGSessionConsumerV1{session: h}
				q.handles = append(q.handles, holder)
				if openErr != nil || h == nil || !h.WorkStartedV1() {
					t.Fatal("actual owned transaction did not start")
				}
				holder.registry, err = h.NewAdmissionV1(ctx)
				if err != nil || holder.registry == nil {
					t.Fatal("actual owned admission registry unavailable")
				}
				holder.consumer, err = h.AcquireRequestHeaderV1(ctx, q.org, documentID, recipientID)
				if err != nil {
					t.Fatal("actual fixed header consumer loan unavailable")
				}
				if !ownedPGExpectedSnapshotV1(q.org, coordinator, 3, 8<<20, 8<<20, 4) {
					t.Fatal("initial shared observer/work/witness/header accounting differs")
				}
				key := uuid.NewString()
				var workPID int32
				var workStart time.Time
				err = h.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
					if err := db.QueryRow(call, "SELECT a.pid,a.backend_start FROM pg_catalog.pg_stat_activity a WHERE a.pid=pg_catalog.pg_backend_pid()").Scan(&workPID, &workStart); err != nil {
						return err
					}
					_, err := db.Exec(call, "INSERT INTO "+q.table+" (operation,marker) VALUES ($1,$2)", key, "synthetic owned transaction witness")
					return err
				})
				if err != nil || workPID <= 0 || workStart.IsZero() {
					t.Fatal("actual owned witness write/identity failed")
				}
				if n, e := ownedPGWitnessCountV1(ctx, q.raw, q.table, key); e != nil || n != 0 {
					t.Fatal("uncommitted owned write became independently visible")
				}
				if mode == "cancelled_commit" {
					stopped, stop := context.WithCancel(ctx)
					stop()
					commitErr := h.CommitV1(stopped)
					if !errors.Is(commitErr, context.Canceled) || !h.CommitDispatchObservationV1().NeverDispatchedV1() || h.CommitUnknownV1() {
						t.Fatal("pre-dispatch cancelled Commit was not known never dispatched")
					}
					if n, e := ownedPGWitnessCountV1(ctx, q.raw, q.table, key); e != nil || n != 0 {
						t.Fatal("never-dispatched Commit made row visible")
					}
					if err = h.RollbackV1(ctx); err != nil || !h.CommitDispatchObservationV1().NeverDispatchedV1() {
						t.Fatal("actual rollback or immutable never-dispatched observation failed")
					}
				} else {
					if err = h.CommitV1(ctx); err != nil || h.CommitDispatchObservationV1().NeverDispatchedV1() || h.CommitUnknownV1() {
						t.Fatal("actual acknowledged Commit did not retain dispatched state")
					}
					if n, e := ownedPGWitnessCountV1(ctx, q.raw, q.table, key); e != nil || n != 1 {
						t.Fatal("actual acknowledged Commit was not independently visible")
					}
				}
				if order == "consumer_first" {
					holder.consumer()
					holder.consumer()
					pending, cleanupErr := holder.registry.ReconcileCleanupV1(ctx)
					if cleanupErr != nil || pending != 1 || !ownedPGExpectedSnapshotV1(q.org, coordinator, 3, 8<<20, 8<<20, 4) {
						t.Fatal("logical consumer close credited live owned session")
					}
				}
				if err = h.CloseV1(ctx); err != nil || !h.RetiredV1() {
					t.Fatal("actual owned backend/client retirement failed")
				}
				if err = ownedPGBackendAbsentV1(ctx, q.raw, workPID, workStart); err != nil {
					t.Fatal("independent witness did not observe old work backend disappearance")
				}
				if !ownedPGExpectedSnapshotV1(q.org, coordinator, 2, 8<<20, 8<<20, 3) {
					t.Fatal("physical SQL retirement prematurely credited header consumer registry")
				}
				if order == "physical_first" {
					pending, cleanupErr := holder.registry.ReconcileCleanupV1(ctx)
					if cleanupErr != nil || pending != 1 || !ownedPGExpectedSnapshotV1(q.org, coordinator, 2, 8<<20, 8<<20, 3) {
						t.Fatal("physical retirement credited unclosed header consumer")
					}
					holder.consumer()
					holder.consumer()
				}
				if err = holder.registry.CloseV1(ctx); err != nil || holder.registry.PendingV1().Loans != 0 {
					t.Fatal("actual consumer/session/registry conjunction did not close")
				}
				if !ownedPGExpectedSnapshotV1(q.org, coordinator, 2, 0, 0, 2) {
					t.Fatal("actual owned work/header resources did not return to observer+witness baseline")
				}
				want := int64(0)
				if mode == "acknowledged_commit" {
					want = 1
				}
				if n, e := ownedPGWitnessCountV1(ctx, q.raw, q.table, key); e != nil || n != want {
					t.Fatal("post-retirement independent rollback/commit witness differs")
				}
				p := q.factory.PendingV1()
				if p.WorkSessions != 0 || p.UnknownStarts != 0 || p.ObserverSessions != 1 || p.Closing {
					t.Fatal("owned work lifecycle left unexpected factory state")
				}
			})
			if !passed {
				return
			}
		}
	}
	if t.Failed() {
		return
	}
	var taggedBackends int64
	if err = q.raw.QueryRow(ctx, "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name=$1 AND datid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())", tag).Scan(&taggedBackends); err != nil || taggedBackends != 1 {
		t.Fatal("actual factory must retain exactly one observer backend")
	}
	var observerPID int32
	var observerStart time.Time
	if err = q.raw.QueryRow(ctx, "SELECT pid,backend_start FROM pg_catalog.pg_stat_activity WHERE application_name=$1", tag).Scan(&observerPID, &observerStart); err != nil || observerPID <= 0 || observerStart.IsZero() {
		t.Fatal("single retained actual factory observer not independently identifiable")
	}
	if err = q.factory.CloseV1(ctx); !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
		t.Fatal("final observer close should retain explicit unknown ownership")
	}
	if err = ownedPGBackendAbsentV1(ctx, q.raw, observerPID, observerStart); err != nil {
		t.Fatal("independent witness did not observe actual final observer backend disappearance")
	}
	if err = q.raw.QueryRow(ctx, "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name=$1 AND datid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())", tag).Scan(&taggedBackends); err != nil || taggedBackends != 0 {
		t.Fatal("actual factory left a backend after final observer close")
	}
	p := q.factory.PendingV1()
	if !p.Closing || p.WorkSessions != 0 || p.UnknownStarts != 0 || p.ObserverSessions != 1 || !ownedPGExpectedSnapshotV1(q.org, coordinator, 2, 0, 0, 2) {
		t.Fatal("final observer was fabricated as retired or credited")
	}
	teardown, finishTeardown := context.WithTimeout(context.Background(), 5*time.Second)
	problems := q.disposeV1(teardown)
	finishTeardown()
	for _, problem := range problems {
		t.Error(problem)
	}
	if !ownedPGExpectedSnapshotV1(q.org, coordinator, 1, 0, 0, 1) {
		t.Fatal("final state must contain exactly one retained factory observer SQL grant")
	}
	p = q.factory.PendingV1()
	if p.WorkSessions != 0 || p.UnknownStarts != 0 || p.ObserverSessions != 1 || !p.Closing {
		t.Fatal("final retained observer gate changed during fixture teardown")
	}
	t.Log("real owned work/header/Commit visibility and retirement qualified; exact final observer SQL grant remains charged despite independently observed backend absence; genuine whole-process/controller retirement and root fixture disposal remain separate")
}
