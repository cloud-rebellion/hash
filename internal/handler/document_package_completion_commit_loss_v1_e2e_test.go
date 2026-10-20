//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// The terminal applied-finalize case retains a stale registered discovery
// result while another worker runs. Keep exact physical SQL retirement and
// the expected registered batch count as separate oracles.
func packageCommitLossScan242(t *testing.T, q *ownedPublicReadFixtureV1) *pdfadmission.ApplicationPackageSendRecoveryBatchV1 {
	t.Helper()
	before := q.runtime.SessionsV1().PendingV1().PackageSendRecoveryBatches
	b, err := q.runtime.SessionsV1().ScanPendingPackageSendRecoveryV1(q.f.ctx, pdfadmission.PackageSendRecoveryCursorV1{})
	if b != nil {
		t.Cleanup(b.CloseConsumerV1)
	}
	if err != nil || b == nil {
		t.Fatal("actual concurrent discovery failed", err)
	}
	packageCommitLossRetired242(t, q, before+1)
	return b
}

func packageCommitLossRetired242(t *testing.T, q *ownedPublicReadFixtureV1, batches int) {
	t.Helper()
	if err := packageRetentionNativeNoWorkSQL240(q); err != nil {
		t.Fatal(err)
	}
	if p := q.runtime.SessionsV1().PendingV1(); p.PackageSendRecoveryBatches != batches {
		t.Fatal("registered discovery ownership differs", p, batches)
	}
}

// This test drops only genuine PostgreSQL COMMIT replies. The original native
// worker, exact-version retention SDK and durable effects are unchanged. A
// database constraint rejects the selected transaction in the rejected cases;
// neither successful rows nor a commit outcome are supplied by the fixture.
func TestDocumentPackageNativeSendCommitResponseLossV1E2E(t *testing.T) {
	for _, phase := range []string{"start", "confirm", "finalize"} {
		for _, mode := range []string{"applied", "rejected"} {
			t.Run(phase+"/"+mode, func(t *testing.T) {
				proxy := commitWireProxy236(t, mode)
				q, peer, client, m, _ := packageCompletionNativeFixture241(t)
				// A genuine pre-existing discovery slot can later inspect a final
				// commit that became terminal before the first worker learned it.
				// Only an applied final COMMIT disappears from fresh pending
				// discovery. The five pending cases qualify fresh recovery;
				// their additional stale replay is covered by the original241
				// suite, without duplicating it inside this finite proxy.
				var stale *pdfadmission.ApplicationPackageSendRecoveryBatchV1
				expectedBatches := 0
				if phase == "finalize" && mode == "applied" {
					stale = packageCommitLossScan242(t, q)
					defer stale.CloseConsumerV1()
					expectedBatches = 1
				}
				name := "StartDocumentPackageSendMemberRetentionV1"
				table, operation, predicate := "document_package_send_member_retention_v1", "INSERT", "true"
				switch phase {
				case "confirm":
					name = "ConfirmDocumentPackageSendMemberRetentionV1"
					operation, predicate = "UPDATE", "NEW.verified_at IS NOT NULL"
				case "finalize":
					name = "RecordDocumentPackageSendCompletionV1"
					table = "document_package_send_completions_v1"
				}
				if mode == "rejected" {
					// All identifiers are fixed test literals and the attempt is the
					// server-created UUID. No user text is interpolated into SQL.
					ddl := fmt.Sprintf(`CREATE FUNCTION hash_test_package_commit_reject242() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'controlled deferred package commit rejection' USING ERRCODE='23514'; END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER hash_test_package_commit_reject242 AFTER %s ON %s
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
WHEN (NEW.attempt_id='%s'::uuid AND (%s)) EXECUTE FUNCTION hash_test_package_commit_reject242();`, operation, table, m.AttemptID, predicate)
					if _, err := q.f.pool.Exec(q.f.ctx, ddl); err != nil {
						t.Fatal("install controlled real deferred rejection", err)
					}
				}
				proxy.armQuery.Store(&name)
				batch := packageCommitLossScan242(t, q)
				defer batch.CloseConsumerV1()
				called := false
				more, err := batch.WithNextSendV1(client, packageCompletionConfig241(t, q), func(pdfadmission.HTMLSendPackageSendObservationV1) error {
					called = true
					return nil
				})
				// The fixed worker intentionally exposes only its public refusal
				// sentinel. Actual lost acknowledgement is established by the
				// real protocol completion+idle barrier below, not a raw SQL error.
				if !more || !errors.Is(err, pdfadmission.ErrHTMLSendPackageRetentionV1) || called || proxy.bad.Load() || proxy.target.Load() <= 0 || proxy.armQuery.Load() != nil {
					t.Fatal("uncertain native phase was accepted or fault was not reached", more, called, err)
				}
				select {
				case <-proxy.fault:
				default:
					t.Fatal("native result preceded real withheld COMMIT idle response")
				}
				if (mode == "applied" && !proxy.observedCommit.Load()) || (mode == "rejected" && !proxy.observedRollback.Load()) {
					t.Fatal("expected actual PostgreSQL commit outcome not observed")
				}
				batch.CloseConsumerV1()
				packageCommitLossRetired242(t, q, expectedBatches)
				if phase == "start" && peer.counts240() != ([5]int{}) {
					t.Fatal("unknown Start COMMIT dispatched provider I/O", peer.counts240())
				}
				var started, verified, completed, invited int
				if err := q.f.pool.QueryRow(q.f.ctx, `SELECT
 (SELECT count(*) FROM document_package_send_member_retention_v1 WHERE attempt_id=$1),
 (SELECT count(*) FROM document_package_send_member_retention_v1 WHERE attempt_id=$1 AND verified_at IS NOT NULL),
 (SELECT count(*) FROM document_package_send_completions_v1 WHERE attempt_id=$1),
 (SELECT count(*) FROM document_package_send_initial_invite_receipts_v1 WHERE attempt_id=$1)`, m.AttemptID).Scan(&started, &verified, &completed, &invited); err != nil {
					t.Fatal(err)
				}
				wantStarted, wantVerified, wantCompleted := 1, 0, 0
				if phase == "start" && mode == "rejected" {
					wantStarted = 0
				}
				if phase == "finalize" || (phase == "confirm" && mode == "applied") {
					wantVerified = 1
				}
				if phase == "finalize" && mode == "applied" {
					wantCompleted = 1
				}
				if started != wantStarted || verified != wantVerified || completed != wantCompleted || invited != wantCompleted {
					t.Fatal("persisted uncertainty differs from actual transaction", started, verified, completed, invited)
				}
				countsAfterLoss := peer.counts240()
				if mode == "rejected" {
					if _, err := q.f.pool.Exec(q.f.ctx, "DROP TRIGGER hash_test_package_commit_reject242 ON "+table+"; DROP FUNCTION hash_test_package_commit_reject242()"); err != nil {
						t.Fatal("remove controlled deferred rejection", err)
					}
				}
				if wantCompleted == 0 {
					// A fresh worker reads durable state, with none of the failed
					// worker's ephemeral observation/retention authority handed in.
					recovery := packageCommitLossScan242(t, q)
					seen := false
					found, e := recovery.WithNextSendV1(client, packageCompletionConfig241(t, q), func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
						seen = true
						if err := packageCompletionObservation241(v, m, "sent"); err != nil {
							return err
						}
						return packageRetentionNativeNoWorkSQL240(q)
					})
					recovery.CloseConsumerV1()
					if !found || !seen || e != nil {
						t.Fatal("fresh native worker could not recover exact durable phase", found, seen, e)
					}
					packageCommitLossRetired242(t, q, expectedBatches)
				} else {
					fresh := packageCommitLossScan242(t, q)
					found, e := fresh.WithNextSendV1(client, packageCompletionConfig241(t, q), func(pdfadmission.HTMLSendPackageSendObservationV1) error {
						t.Fatal("terminal completion was redispatched by fresh pending scan")
						return nil
					})
					fresh.CloseConsumerV1()
					if found || e != nil {
						t.Fatal("completed uncertain transaction remained pending", found, e)
					}
				}
				if wantVerified == 1 && peer.counts240() != countsAfterLoss {
					t.Fatal("fresh recovery redispatched provider despite durable exact verification", countsAfterLoss, peer.counts240())
				}
				if stale != nil {
					// The stale slot is historical inspection after either path. It
					// cannot rotate tokens, write another outbox row or call storage.
					before, counts := packageCompletionNativeState241(t, q, m), peer.counts240()
					seen := false
					more, err = stale.WithNextSendV1(client, packageCompletionConfig241(t, q), func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
						seen = true
						return packageCompletionObservation241(v, m, "sent")
					})
					if !more || !seen || err != nil || peer.counts240() != counts || packageCompletionNativeState241(t, q, m) != before {
						t.Fatal("historical recovery replayed irreversible effects", more, seen, err)
					}
					stale.CloseConsumerV1()
				}
				packageWorkerDrained239(t, q)
				packageCompletionActualEffects241(t, q, m, "sent")
				t.Logf("genuine %s %s COMMIT reply loss; actual state recovered; exact invitation and complete audit chain verified; all native work retired", phase, mode)
			})
		}
	}
}
