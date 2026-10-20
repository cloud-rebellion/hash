//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/billing"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
)

type packageWorkerJob239 struct {
	meta    pdfadmission.HTMLSendPackageIntentMetadataV1
	created time.Time
}

func packageWorkerObservation239(v pdfadmission.HTMLSendPackageAttemptObservationV1, job packageWorkerJob239, outcome pdfadmission.HTMLSendPackageAttemptOutcomeV1) error {
	capture := job.meta.Capture
	capture.RootUpdatedAt = capture.RootUpdatedAt.UTC()
	capture.CreatedAt = capture.CreatedAt.UTC()
	if v.AttemptID != job.meta.AttemptID || v.Outcome != outcome || v.Capture != capture || v.Capture.CreatedBy != job.meta.Capture.CreatedBy || !v.CreatedAt.Equal(job.created) || !v.CreatedAt.Equal(job.meta.CreatedAt) || !v.Article13NoticeEpochAt.Equal(job.meta.Article13NoticeEpochAt) || !v.RetainUntil.Equal(job.meta.RetainUntil) {
		return fmt.Errorf("worker observation changed exact persisted attempt: got=%+v wantAttempt=%s wantOutcome=%v", v, job.meta.AttemptID, outcome)
	}
	return nil
}

func packageWorkerCursor239(job packageWorkerJob239) pdfadmission.PackageSendRecoveryCursorV1 {
	return pdfadmission.PackageSendRecoveryCursorV1{CreatedAt: job.created.UTC(), AttemptID: job.meta.AttemptID}
}

func packageWorkerDrained239(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	ownedCreationAssertDrainedV1(t, q, 2)
	if p := q.runtime.SessionsV1().PendingV1(); p.PackageSendRecoveryBatches != 0 {
		t.Fatal("worker recovery batch survived consumer and physical cleanup", p)
	}
}

func packageWorkerScan239(t *testing.T, q *ownedPublicReadFixtureV1, after pdfadmission.PackageSendRecoveryCursorV1) *pdfadmission.ApplicationPackageSendRecoveryBatchV1 {
	t.Helper()
	batch, err := q.runtime.SessionsV1().ScanPendingPackageSendRecoveryV1(q.f.ctx, after)
	if batch != nil {
		t.Cleanup(batch.CloseConsumerV1)
	}
	if err != nil || batch == nil {
		t.Fatal("worker queue scan failed", err)
	}
	p := q.runtime.SessionsV1().PendingV1()
	if p.PackageSendRecoveryBatches != 1 || p.WorkSessions != 0 || p.UnknownStarts != 0 || p.ObserverSessions != 2 {
		t.Fatal("queue rows delivered before physical scan retirement", p)
	}
	return batch
}

func packageWorkerBirth239(t *testing.T, q *ownedPublicReadFixtureV1) packageWorkerJob239 {
	t.Helper()
	_, _, meta, err := packageAttemptBirth235(t, q, false)
	if err != nil {
		t.Fatal("genuine main-only worker job birth", err)
	}
	// The genuine preparation/birth helpers and their exact observer oracle have
	// all returned before the new global batch can open. No original operation,
	// Work, actor callback or diagnostic UUID is reused as process authority.
	packageWorkerDrained239(t, q)
	var created time.Time
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT created_at FROM document_package_send_attempts_v1 WHERE attempt_id=$1", meta.AttemptID).Scan(&created); err != nil {
		t.Fatal(err)
	}
	return packageWorkerJob239{meta: meta, created: created.UTC()}
}

// These are real native births, private batch slots, PostgreSQL locks and
// cancellation. They prove no provider retention, nonempty Send activation,
// OS process restart, complete retirement or production capacity claim.
// The seeded Enterprise subscription is the existing higher-capacity product
// plan. Select it through normal stored subscription policy for this 51-job
// queue fixture; Pro's real 50-document quota remains enforced everywhere.
// Operator mode intentionally rejects unlimited plans, so it is not used here.
func packageWorkerEnterprisePlan239(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	var planID uuid.UUID
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT id FROM billing_plans WHERE slug='enterprise' AND active").Scan(&planID); err != nil || planID == uuid.Nil {
		t.Fatal("actual seeded Enterprise plan identity unavailable", err)
	}
	owner, err := q.runtime.SessionsV1().ControlledMeasurePlanSourceV1(q.f.ctx, planID)
	if owner != nil {
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := owner.CloseV1(cleanup); err != nil {
				t.Error("actual Enterprise M95 preparation cleanup", err)
			}
		})
	}
	if err != nil || owner == nil {
		t.Fatal("actual Enterprise M95 preparation failed", err)
	}
	receipt, err := owner.ReceiptV1()
	if err != nil || receipt.Kind != "plan" || receipt.SourceID != planID || receipt.OrgID != uuid.Nil || receipt.WireBytes <= 0 || receipt.ServerVersionNum != 160015 || !receipt.CreatedAt.Valid || !receipt.MeasuredAt.Valid {
		t.Fatal("Enterprise preparation lacks exact acknowledged receipt", err)
	}
	owner.CloseConsumerV1()
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := owner.CloseV1(cleanup); err != nil {
		t.Fatal("actual Enterprise plan owner did not close", err)
	}
	now := time.Now().UTC()
	subscription, err := q.f.q.UpsertOrgSubscription(q.f.ctx, generated.UpsertOrgSubscriptionParams{
		OrgID: q.f.org, PlanID: planID, Provider: "mock", Status: "active",
		ProviderCustomerID:     pgtype.Text{String: "synthetic-worker-enterprise-customer", Valid: true},
		ProviderSubscriptionID: pgtype.Text{String: "synthetic-worker-enterprise-subscription", Valid: true},
		CurrentPeriodStart:     pgtype.Timestamptz{Time: now.Add(-time.Hour), Valid: true},
		CurrentPeriodEnd:       pgtype.Timestamptz{Time: now.Add(time.Hour), Valid: true},
	})
	if err != nil || subscription == nil || subscription.PlanID != planID || subscription.OrgID != q.f.org {
		t.Fatal("actual Enterprise fixture subscription unavailable", err)
	}
	q.f.s.Billing = billing.New(q.f.q, billing.MockProvider{}, q.f.s.PublicURL, "")
	plan, current, err := q.f.s.Billing.PlanForOrg(q.f.ctx, q.f.org)
	if err != nil || plan == nil || current == nil || plan.ID != planID || plan.Slug != "enterprise" || !plan.Active || current.ID != subscription.ID || current.Status != "active" || q.f.s.Billing.OperatorMode() || (plan.DocumentQuotaMonthly != 0 && plan.DocumentQuotaMonthly < 51) || (plan.RecipientQuotaMonthly != 0 && plan.RecipientQuotaMonthly < 51) {
		t.Fatal("normal stored Enterprise entitlement does not cover real fixture jobs", err)
	}
	packageWorkerDrained239(t, q)
}

func TestDocumentPackageWorkerRecoveryBatchV1E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	packageWorkerEnterprisePlan239(t, q)
	var jobs [51]packageWorkerJob239
	for i := range jobs {
		jobs[i] = packageWorkerBirth239(t, q)
	}
	sort.Slice(jobs[:], func(i, j int) bool {
		if jobs[i].created.Equal(jobs[j].created) {
			return jobs[i].meta.AttemptID.String() < jobs[j].meta.AttemptID.String()
		}
		return jobs[i].created.Before(jobs[j].created)
	})
	// Original transport authorization is now revoked. The process owner must
	// inspect the accepted immutable actor evidence without impersonating that
	// expired request or substituting a fake user/transaction authorization.
	if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE users SET session_generation=session_generation+1,role='viewer' WHERE id=$1", q.f.user.ID); err != nil {
		t.Fatal(err)
	}
	requests := q.storagePeer.requests.Load()
	var afterFirst, afterLast pdfadmission.PackageSendRecoveryCursorV1

	t.Run("bounded page consumes privacy refusal and terminal handoff", func(t *testing.T) {
		dsr, err := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: jobs[0].meta.Capture.DocumentID, Valid: true}, SubjectEmail: "worker-privacy@hash.example.test", Kind: "access", RequestedVia: "sender", PayloadJson: []byte("{}")})
		if err != nil {
			t.Fatal(err)
		}
		batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
		defer batch.CloseConsumerV1()
		if batch.CursorV1() != (pdfadmission.PackageSendRecoveryCursorV1{}) {
			t.Fatal("scan advanced a cursor before slot consumption")
		}
		// A queue coordinate is stale immediately after this valid transition.
		// The batch must read the exact terminal history, not a guessed active job.
		if err := packageAttemptTransition235(t, q, jobs[1].meta, "aborted", false); err != nil {
			t.Fatal(err)
		}
		called := false
		more, err := batch.WithNextObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error { called = true; return nil })
		if !more || called || !errors.Is(err, pdfadmission.ErrDocumentPackagePendingPrivacyV1) || batch.CursorV1() != packageWorkerCursor239(jobs[0]) {
			t.Fatal("privacy job disappeared from discovery or delivered an observation", more, called, batch.CursorV1(), err)
		}
		if _, err := q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: dsr.ID, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); err != nil {
			t.Fatal(err)
		}
		before := packageMeasurementState232(t, q)
		copyBatch := *batch
		for i := 1; i < 50; i++ {
			want := pdfadmission.HTMLSendPackageAttemptActiveV1
			if i == 1 {
				want = pdfadmission.HTMLSendPackageAttemptAbortedV1
			}
			owner := batch
			if i%2 == 0 {
				owner = &copyBatch
			}
			more, err := owner.WithNextObservationV1(func(v pdfadmission.HTMLSendPackageAttemptObservationV1) error {
				return packageWorkerObservation239(v, jobs[i], want)
			})
			if !more || err != nil || batch.CursorV1() != packageWorkerCursor239(jobs[i]) || copyBatch.CursorV1() != batch.CursorV1() {
				t.Fatal("copied batch duplicated or skipped a private slot", i, more, batch.CursorV1(), err)
			}
		}
		for _, owner := range []*pdfadmission.ApplicationPackageSendRecoveryBatchV1{batch, &copyBatch} {
			called = false
			more, err := owner.WithNextObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error { called = true; return nil })
			if more || called || err != nil {
				t.Fatal("bounded page delivered a fifty-first slot", more, called, err)
			}
		}
		afterFirst = batch.CursorV1()
		batch.CloseConsumerV1()
		copyBatch.CloseConsumerV1()
		packageWorkerDrained239(t, q)
		if packageMeasurementState232(t, q) != before {
			t.Fatal("worker page inspection changed durable state")
		}
	})
	if t.Failed() {
		return
	}

	t.Run("next page progresses past first fifty", func(t *testing.T) {
		batch := packageWorkerScan239(t, q, afterFirst)
		defer batch.CloseConsumerV1()
		more, err := batch.WithNextObservationV1(func(v pdfadmission.HTMLSendPackageAttemptObservationV1) error {
			return packageWorkerObservation239(v, jobs[50], pdfadmission.HTMLSendPackageAttemptActiveV1)
		})
		if !more || err != nil || batch.CursorV1() != packageWorkerCursor239(jobs[50]) {
			t.Fatal("second page did not reach the actual fifty-first job", more, batch.CursorV1(), err)
		}
		more, err = batch.WithNextObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error {
			return errors.New("unexpected second slot")
		})
		if more || err != nil {
			t.Fatal("second page did not exhaust", more, err)
		}
		afterLast = batch.CursorV1()
		batch.CloseConsumerV1()
		packageWorkerDrained239(t, q)
	})
	if t.Failed() {
		return
	}

	t.Run("equal timestamp cursor uses uuid boundary", func(t *testing.T) {
		lower := jobs[50].meta.AttemptID
		for i := len(lower) - 1; i >= 0; i-- {
			if lower[i] > 0 {
				lower[i]--
				break
			}
			lower[i] = 255
		}
		if lower == uuid.Nil {
			t.Fatal("fixture has no valid lower UUID cursor")
		}
		batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{CreatedAt: jobs[50].created, AttemptID: lower})
		more, err := batch.WithNextObservationV1(func(v pdfadmission.HTMLSendPackageAttemptObservationV1) error {
			return packageWorkerObservation239(v, jobs[50], pdfadmission.HTMLSendPackageAttemptActiveV1)
		})
		if !more || err != nil {
			batch.CloseConsumerV1()
			t.Fatal("equal timestamp and lower UUID excluded the genuine job", more, err)
		}
		batch.CloseConsumerV1()
		packageWorkerDrained239(t, q)
		empty := packageWorkerScan239(t, q, afterLast)
		defer empty.CloseConsumerV1()
		called := false
		more, err = empty.WithNextObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error { called = true; return nil })
		if more || called || err != nil || empty.CursorV1() != afterLast {
			t.Fatal("exact cursor repeated its own job or changed on an empty page", more, called, empty.CursorV1(), err)
		}
		empty.CloseConsumerV1()
		packageWorkerDrained239(t, q)
	})

	t.Run("closed copied handle cannot replay", func(t *testing.T) {
		batch := packageWorkerScan239(t, q, afterFirst)
		copyBatch := *batch
		copyBatch.CloseConsumerV1()
		called := false
		more, err := batch.WithNextObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error { called = true; return nil })
		if more || called || !errors.Is(err, pdfadmission.ErrHTMLSendPackageInspectionV1) || batch.CursorV1() != afterFirst {
			t.Fatal("copied close failed to close shared consumer state", more, called, err)
		}
		batch.CloseConsumerV1()
		packageWorkerDrained239(t, q)
	})

	t.Run("close during callback retains process and native work funding", func(t *testing.T) {
		batch := packageWorkerScan239(t, q, afterFirst)
		defer batch.CloseConsumerV1()
		copyBatch := *batch
		ready, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		wait, stop := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
		defer stop()
		type result struct {
			more bool
			err  error
		}
		finished := make(chan result, 1)
		defer func() {
			unblock()
			select {
			case <-done:
			case <-wait.Done():
				t.Error("worker callback activity did not join")
			}
		}()
		go func() {
			defer close(done)
			more, err := batch.WithNextObservationV1(func(v pdfadmission.HTMLSendPackageAttemptObservationV1) error {
				if err := packageWorkerObservation239(v, jobs[50], pdfadmission.HTMLSendPackageAttemptActiveV1); err != nil {
					return err
				}
				close(ready)
				select {
				case <-release:
					return nil
				case <-wait.Done():
					return wait.Err()
				}
			})
			finished <- result{more, err}
		}()
		select {
		case <-ready:
		case out := <-finished:
			t.Fatal("worker callback did not start", out.more, out.err)
		case <-wait.Done():
			t.Fatal("worker callback readiness deadline")
		}
		funded := q.snapshotV1(t)
		p := q.runtime.SessionsV1().PendingV1()
		if funded.Global.ParentBytes == 0 || funded.Global.DBStagingBytes == 0 || funded.Organisation.ParentBytes == 0 || p.PackageSendRecoveryBatches != 1 || p.DocumentPackageOperations != 0 || p.HTMLAdmissions != 1 || p.WorkSessions != 0 {
			t.Fatal("delivered worker result lost process/native funding or SQL retirement", funded, p)
		}
		copyBatch.CloseConsumerV1()
		if held := q.snapshotV1(t); held != funded {
			t.Fatal("copied close credited an active callback", funded, held)
		}
		called := false
		if more, err := batch.WithNextObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error { called = true; return nil }); more || called || err == nil {
			t.Fatal("closed active batch delivered another slot", more, called, err)
		}
		unblock()
		select {
		case out := <-finished:
			if !out.more || out.err != nil {
				t.Fatal("worker callback failed to finish", out.more, out.err)
			}
		case <-wait.Done():
			t.Fatal("worker callback result did not join")
		}
		packageWorkerDrained239(t, q)
	})

	t.Run("partial cursor refuses before ownership", func(t *testing.T) {
		before := q.snapshotV1(t)
		for _, cursor := range []pdfadmission.PackageSendRecoveryCursorV1{{CreatedAt: jobs[0].created}, {AttemptID: jobs[0].meta.AttemptID}} {
			batch, err := q.runtime.SessionsV1().ScanPendingPackageSendRecoveryV1(q.f.ctx, cursor)
			if batch != nil {
				batch.CloseConsumerV1()
			}
			if batch != nil || !errors.Is(err, pdfadmission.ErrHTMLSendPackageInspectionV1) {
				t.Fatal("partial cursor acquired queue authority", batch, err)
			}
		}
		packageWorkerDrained239(t, q)
		if q.snapshotV1(t) != before {
			t.Fatal("invalid cursor changed resource accounting")
		}
	})
	if q.storagePeer.requests.Load() != requests {
		t.Fatal("worker recovery inspection performed provider IO")
	}
	packageWorkerDrained239(t, q)
}

func TestDocumentPackageWorkerRecoveryCancellationV1E2E(t *testing.T) {
	for _, kind := range []string{"blocked queue scan", "blocked exact slot read"} {
		t.Run(kind, func(t *testing.T) {
			q := inspectionFixturePG236(t)
			_ = packageWorkerBirth239(t, q)
			before := packageMeasurementState232(t, q)
			requests := q.storagePeer.requests.Load()
			ctx, cancel := context.WithTimeout(q.f.ctx, 15*time.Second)
			defer cancel()
			var batch *pdfadmission.ApplicationPackageSendRecoveryBatchV1
			if kind == "blocked exact slot read" {
				batch = packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
				defer batch.CloseConsumerV1()
			}
			holder := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
			var holderPID int32
			if err := holder.QueryRow(q.f.ctx, "SELECT pg_backend_pid()").Scan(&holderPID); err != nil {
				rollbackHTMLQueryFixtureV1(t, holder)
				t.Fatal(err)
			}
			table, query := "document_package_send_attempts_v1", "ListPendingDocumentPackageSendRecoveryV1"
			if batch != nil {
				table, query = "document_package_captures_v1", "InspectDocumentPackageSendAttemptStateV1"
			}
			if _, err := holder.Exec(q.f.ctx, "LOCK TABLE "+table+" IN ACCESS EXCLUSIVE MODE"); err != nil {
				rollbackHTMLQueryFixtureV1(t, holder)
				t.Fatal(err)
			}
			type result struct {
				batch        *pdfadmission.ApplicationPackageSendRecoveryBatchV1
				more, called bool
				err          error
			}
			finished, done := make(chan result, 1), make(chan struct{})
			defer func() {
				cancel()
				if batch != nil {
					batch.CloseConsumerV1()
				}
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_ = holder.Rollback(cleanup)
				select {
				case <-done:
					select {
					case out := <-finished:
						if out.batch != nil {
							out.batch.CloseConsumerV1()
						}
					default:
					}
				case <-cleanup.Done():
					t.Error("canceled worker queue activity unjoined")
				}
			}()
			go func() {
				defer close(done)
				if batch == nil {
					h, err := q.runtime.SessionsV1().ScanPendingPackageSendRecoveryV1(ctx, pdfadmission.PackageSendRecoveryCursorV1{})
					finished <- result{batch: h, err: err}
					return
				}
				called := false
				more, err := batch.WithNextObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error { called = true; return nil })
				finished <- result{more: more, called: called, err: err}
			}()
			ownedReadWaitV1(t, q, holderPID, query)
			if batch == nil {
				cancel()
			} else {
				batch.CloseConsumerV1()
			}
			select {
			case out := <-finished:
				if out.batch != nil {
					out.batch.CloseConsumerV1()
				}
				if out.err == nil || out.called || (batch != nil && !out.more) {
					t.Fatal("canceled worker SQL delivered a successful result", out.more, out.called, out.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("worker SQL cancellation did not join")
			}
			if err := holder.Rollback(q.f.ctx); err != nil {
				t.Fatal(err)
			}
			packageWorkerDrained239(t, q)
			if packageMeasurementState232(t, q) != before || q.storagePeer.requests.Load() != requests {
				t.Fatal("canceled worker SQL changed durable state or called a provider")
			}
		})
	}
}

// M104 adds queue readiness and an index only. Both empty and occupied attempt
// histories survive its real Goose rollback; the new reader must refuse until
// the matching schema is reapplied. M103's occupied-history guard is unchanged.
func TestDocumentPackageWorkerRecoverySchemaV1E2E(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		name := "empty queue"
		if occupied {
			name = "occupied queue"
		}
		t.Run(name, func(t *testing.T) {
			q := inspectionFixturePG236(t)
			var job packageWorkerJob239
			if occupied {
				job = packageWorkerBirth239(t, q)
			} else {
				root := packageImported220(t, q, "Empty recovery queue schema witness")
				_ = packageCreate223(t, q, root)
				packageWorkerDrained239(t, q)
			}
			before := packageMeasurementState232(t, q)
			requests := q.storagePeer.requests.Load()
			cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
			if err != nil {
				t.Fatal(err)
			}
			db := stdlib.OpenDB(*cfg)
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			defer db.Close()
			// Exercise the unchanged M104 reader from its actual schema. The new
			// member ledger is empty in this inspection-only fixture.
			if err := mdb.RunMigrationsDownToContext(q.f.ctx, db, 104); err != nil {
				t.Fatal("prepare original M104 queue schema", err)
			}
			if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 104 {
				t.Fatal("queue schema did not start at M104", version, err)
			}
			if err := mdb.RunMigrationsDownToContext(q.f.ctx, db, 103); err != nil {
				t.Fatal("M104 rollback refused unchanged attempt history", err)
			}
			restore := true
			defer func() {
				if restore {
					cleanup, stop := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
					defer stop()
					if err := mdb.RunMigrationsUpToContext(cleanup, db, 106); err != nil {
						t.Error("restore current M106 after test failure", err)
					}
				}
			}()
			if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 103 {
				t.Fatal("M104 rollback did not stop at M103", version, err)
			}
			var missingMarker, missingIndex bool
			if err := q.f.pool.QueryRow(q.f.ctx, "SELECT to_regprocedure('hash_package_send_recovery_queue_version_v1()') IS NULL,to_regclass('document_package_send_recovery_queue_v1') IS NULL").Scan(&missingMarker, &missingIndex); err != nil || !missingMarker || !missingIndex {
				t.Fatal("M104 Down retained queue marker or index", missingMarker, missingIndex, err)
			}
			batch, err := q.runtime.SessionsV1().ScanPendingPackageSendRecoveryV1(q.f.ctx, pdfadmission.PackageSendRecoveryCursorV1{})
			if batch != nil {
				batch.CloseConsumerV1()
			}
			var failure *pgconn.PgError
			if err == nil || !errors.Is(err, pdfadmission.ErrHTMLSendPackageInspectionV1) || !errors.As(err, &failure) || failure.Code != "42883" {
				t.Fatal("new reader did not fail closed on missing M104 marker", err)
			}
			packageWorkerDrained239(t, q)
			if packageMeasurementState232(t, q) != before {
				t.Fatal("M104 Down or refused reader changed attempt history")
			}
			if err := mdb.RunMigrationsUpToContext(q.f.ctx, db, 104); err != nil {
				t.Fatal(err)
			}
			restore = false
			if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 104 {
				t.Fatal("M104 reapply did not restore schema", version, err)
			}
			recovered := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
			defer recovered.CloseConsumerV1()
			called := false
			more, err := recovered.WithNextObservationV1(func(v pdfadmission.HTMLSendPackageAttemptObservationV1) error {
				called = true
				if !occupied {
					return errors.New("empty queue invented a durable attempt")
				}
				return packageWorkerObservation239(v, job, pdfadmission.HTMLSendPackageAttemptActiveV1)
			})
			if err != nil || more != occupied || called != occupied {
				t.Fatal("reapplied queue lost or invented durable work", more, called, err)
			}
			recovered.CloseConsumerV1()
			packageWorkerDrained239(t, q)
			if packageMeasurementState232(t, q) != before || q.storagePeer.requests.Load() != requests {
				t.Fatal("M104 down/up changed history or performed provider IO")
			}
			if err := mdb.RunMigrationsUpToContext(q.f.ctx, db, 106); err != nil {
				t.Fatal("restore current member-retention schema", err)
			}

		})
	}
}
