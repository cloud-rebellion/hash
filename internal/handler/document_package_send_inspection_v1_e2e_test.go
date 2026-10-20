//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5/pgtype"
)

type packageBirthPlan236 struct {
	seal, rollback, unknown bool
	arm                     func(int32) error
	finish                  func(context.Context, generated.DBTX, pdfadmission.HTMLSendPackageIntentMetadataV1) error
}

// Actual original preparation/auth/measurement, same native Admission and
// acknowledged/uncertain COMMIT, followed by physical backend absence. No SQL,
// outcome, attempt ID or ownership proof is injected into production.
func withPackageAttempt236(t *testing.T, q *ownedPublicReadFixtureV1, root *generated.Document, p *generated.DocumentPackagesV1, plan packageBirthPlan236, after func(*pdfadmission.ApplicationHTMLSendOperationV1, *pdfadmission.ApplicationSessionV1, pdfadmission.HTMLSendPackageIntentMetadataV1, authoring.Actor) error) error {
	t.Helper()
	return withPackageSendDraft234(t, q, root.ID, packageCaptureExpected234(p), false, func(op *pdfadmission.ApplicationHTMLSendOperationV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1, actor authoring.Actor) error {
		if e := prior.MeasurePDFsV1(q.f.s.Storage); e != nil {
			return e
		}
		stage, e := op.OpenSQLV1(pdfadmission.HTMLSendAdmissionV1)
		if e != nil {
			return e
		}
		session := stage.SessionV1()
		if _, e = session.NewAdmissionV1(stage.ContextV1()); e != nil {
			return e
		}
		var work *pdfadmission.ApplicationHTMLSendWorkV1
		var meta pdfadmission.HTMLSendPackageIntentMetadataV1
		var pid int32
		var started time.Time
		e = stage.WithTxV1(func(call context.Context, db generated.DBTX) error {
			var e error
			work, e = session.NewHTMLSendWorkV1(call, stage)
			if e != nil {
				return e
			}
			state, e := work.StateV1(call)
			if e != nil {
				return e
			}
			user, e := work.ReadActorV1(call, actor.UserID)
			if e != nil {
				return e
			}
			if user.Role != "owner" && (user.Role != "sender" || state.SenderID != user.ID) {
				return auth.ErrMutationPermissionRevoked
			}
			if e = actor.Authorize(call, &htmlCreationPolicyTxV1{DBTX: db}, user); e != nil {
				return e
			}
			if _, e = work.ReadModelsV1(call); e != nil {
				return e
			}
			source, e := work.NewSourceV1(call)
			if e != nil {
				return e
			}
			if e = source.ValidateReviewedV1(); e != nil {
				return e
			}
			if e = source.ValidateCurrentV1(); e != nil {
				return e
			}
			if _, e = packageCaptureAppend234(t, call, work, prior); e != nil {
				return e
			}
			if _, e = work.FreezeBrandingV1(call); e != nil {
				return e
			}
			meta, e = work.CreatePackageIntentV1(call, pdfadmission.HTMLSendIntentActorV1{Via: "synthetic-owned-test", Tool: "exact-attempt-inspection"})
			if e != nil {
				return e
			}
			// A wrong-purpose call must not burn the genuine later inspection.
			if got, e := work.InspectPackageSendAttemptV1(call); !errors.Is(e, pdfadmission.ErrHTMLSendPackageInspectionV1) || got != (pdfadmission.HTMLSendPackageAttemptObservationV1{}) {
				t.Fatal("birth Work inspected itself", got, e)
			}
			if e = db.QueryRow(call, "SELECT pid,backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()").Scan(&pid, &started); e != nil {
				return e
			}
			if plan.seal {
				if e = work.BeginSendSealingV1(call); e != nil {
					return e
				}
			}
			if plan.finish != nil {
				if e = plan.finish(call, db, meta); e != nil {
					return e
				}
			}
			return actor.Authorize(call, &htmlCreationPolicyTxV1{DBTX: db}, user)
		})
		if e != nil {
			return e
		}
		if plan.arm != nil {
			if e = plan.arm(pid); e != nil {
				return e
			}
		}
		if plan.rollback {
			e = session.RollbackV1(stage.ContextV1())
		} else {
			e = session.CommitV1(stage.ContextV1())
		}
		if plan.unknown {
			if !errors.Is(e, pdfadmission.ErrApplicationSessionCommitUnknownV1) || !session.CommitUnknownV1() {
				t.Fatal("genuine commit result was not uncertain", e)
			}
		} else if e != nil {
			return e
		}
		if plan.rollback && session.CommitUnknownV1() {
			t.Fatal("explicit rollback relabeled as unknown commit")
		}
		if e = stage.CloseSQLV1(); e != nil {
			return e
		}
		if !session.RetiredV1() {
			t.Fatal("inspection preceded physical birth retirement")
		}
		var live int
		if e = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2", pid, started).Scan(&live); e != nil || live != 0 {
			t.Fatal("actual birth backend survived retirement", live, e)
		}
		// Independent reference must survive complete birth Work consumer close.
		work.CloseConsumerV1()
		if id, present := op.PackageSendAttemptIDV1(); !present || id != meta.AttemptID {
			t.Fatal("birth close lost exact private attempt")
		}
		requests := q.storagePeer.requests.Load()
		e = after(op, session, meta, actor)
		if q.storagePeer.requests.Load() != requests {
			t.Fatal("inspection performed provider I/O")
		}
		return e
	})
}
func inspectPackageAttempt236(t *testing.T, q *ownedPublicReadFixtureV1, op *pdfadmission.ApplicationHTMLSendOperationV1, actor authoring.Actor) (out pdfadmission.HTMLSendPackageAttemptObservationV1, failure error) {
	t.Helper()
	stage, e := op.OpenSQLV1(pdfadmission.HTMLSendIntentReadV1)
	if e != nil {
		return out, e
	}
	session := stage.SessionV1()
	if _, e = session.NewAdmissionV1(stage.ContextV1()); e != nil {
		return out, e
	}
	e = stage.WithTxV1(func(call context.Context, db generated.DBTX) error {
		work, e := session.NewHTMLSendWorkV1(call, stage)
		if e != nil {
			return e
		}
		state, e := work.StateV1(call)
		if e != nil {
			return e
		}
		user, e := work.ReadActorV1(call, actor.UserID)
		if e != nil {
			return e
		}
		if user.Role != "owner" && (user.Role != "sender" || state.SenderID != user.ID) {
			return auth.ErrMutationPermissionRevoked
		}
		if e = actor.Authorize(call, &htmlCreationPolicyTxV1{DBTX: db}, user); e != nil {
			return e
		}
		out, e = work.InspectPackageSendAttemptV1(call)
		if e != nil {
			return e
		}
		if _, e = work.InspectPackageSendAttemptV1(call); !errors.Is(e, pdfadmission.ErrHTMLSendPackageInspectionV1) {
			t.Fatal("same Work replay inspected twice", e)
		}
		return actor.Authorize(call, &htmlCreationPolicyTxV1{DBTX: db}, user)
	})
	closeErr := stage.CloseSQLV1()
	failure = errors.Join(e, closeErr)
	if failure != nil {
		out = pdfadmission.HTMLSendPackageAttemptObservationV1{}
	}
	return out, failure
}
func inspectionFixturePG236(t *testing.T) *ownedPublicReadFixtureV1 {
	t.Helper()
	q := newOwnedDocumentPackageMeasurementFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if e := malwarescan.Configure(q.f.ctx, "", "development"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := malwarescan.Configure(context.Background(), "", "development"); e != nil {
			t.Error(e)
		}
	})
	return q
}
func TestDocumentPackageSendAttemptInspectionV1E2E(t *testing.T) {
	for _, kind := range []string{"active exact attempt", "aborted history after later draft edit", "completed sent history", "completed expired history", "rolled back attempt is missing without replay", "missing capture still fences deleted frozen member", "original credential revoked", "original role revoked", "deleted root is policy error not missing"} {
		t.Run(kind, func(t *testing.T) {
			q := inspectionFixturePG236(t)
			root := packageImported220(t, q, "Actual exact inspection root")
			var annexes []*generated.Document
			if kind == "missing capture still fences deleted frozen member" {
				annexes = append(annexes, packageImported220(t, q, "Original frozen privacy subject"))
			}
			p := packageCreate223(t, q, root, annexes...)
			root = packageLatest223(t, q, root.ID)
			beforeBirth := packageMeasurementState232(t, q)
			rollback := kind == "rolled back attempt is missing without replay" || len(annexes) > 0
			e := withPackageAttempt236(t, q, root, p, packageBirthPlan236{seal: !rollback, rollback: rollback}, func(op *pdfadmission.ApplicationHTMLSendOperationV1, birth *pdfadmission.ApplicationSessionV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, actor authoring.Actor) error {
				want := pdfadmission.HTMLSendPackageAttemptActiveV1
				switch kind {
				case "aborted history after later draft edit", "deleted root is policy error not missing":
					if e := packageAttemptTransition235(t, q, m, "aborted", false); e != nil {
						return e
					}
					want = pdfadmission.HTMLSendPackageAttemptAbortedV1
					sql := "UPDATE documents SET name='Later draft revision' WHERE id=$1"
					if kind == "deleted root is policy error not missing" {
						sql = "UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1"
					}
					if _, e := q.f.pool.Exec(q.f.ctx, sql, root.ID); e != nil {
						return e
					}
				case "completed sent history", "completed expired history":
					if e := packageAttemptTransition235(t, q, m, "completed", kind == "completed expired history"); e != nil {
						return e
					}
					want = pdfadmission.HTMLSendPackageAttemptCompletedV1
				case "rolled back attempt is missing without replay":
					if packageMeasurementState232(t, q) != beforeBirth {
						t.Fatal("explicit rollback retained tentative birth")
					}
					want = pdfadmission.HTMLSendPackageAttemptMissingV1
				case "missing capture still fences deleted frozen member":
					if packageMeasurementState232(t, q) != beforeBirth {
						t.Fatal("rolled back annex birth retained state")
					}
					if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1", annexes[0].ID); e != nil {
						return e
					}
					if _, e := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: annexes[0].ID, Valid: true}, SubjectEmail: "synthetic@hash.example.test", Kind: "access", RequestedVia: "sender", PayloadJson: []byte("{}")}); e != nil {
						return e
					}
				case "original credential revoked":
					if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE users SET session_generation=session_generation+1 WHERE id=$1", q.f.user.ID); e != nil {
						return e
					}
				case "original role revoked":
					if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"}); e != nil {
						return e
					}
				}
				before := packageMeasurementState232(t, q)
				got, e := inspectPackageAttempt236(t, q, op, actor)
				switch kind {
				case "original credential revoked", "original role revoked", "deleted root is policy error not missing", "missing capture still fences deleted frozen member":
					if e == nil || got != (pdfadmission.HTMLSendPackageAttemptObservationV1{}) {
						t.Fatal("policy/privacy failure became an observation", got, e)
					}
					if kind == "missing capture still fences deleted frozen member" && !errors.Is(e, pdfadmission.ErrDocumentPackagePendingPrivacyV1) {
						t.Fatal("missing subject bypassed original privacy fence", e)
					}
				default:
					if e != nil || got.AttemptID != m.AttemptID || got.Outcome != want {
						t.Fatal("exact native inspection", got, e)
					}
					if want == pdfadmission.HTMLSendPackageAttemptMissingV1 {
						if got.Capture.Present {
							t.Fatal("missing claimed a capture")
						}
					} else if got.Capture != m.Capture || !got.Article13NoticeEpochAt.Equal(m.Article13NoticeEpochAt) || !got.RetainUntil.Equal(m.RetainUntil) {
						t.Fatal("native inspection switched immutable capture or epoch")
					}
					again, e := inspectPackageAttempt236(t, q, op, actor)
					if !errors.Is(e, pdfadmission.ErrHTMLSendPackageInspectionV1) || again != (pdfadmission.HTMLSendPackageAttemptObservationV1{}) {
						t.Fatal("second native stage replayed inspection", again, e)
					}
				}
				if packageMeasurementState232(t, q) != before {
					t.Fatal("read-only inspection changed persistent state")
				}
				if birth.CommitUnknownV1() {
					t.Fatal("known fixture unexpectedly relabeled uncertain")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestDocumentPackageSendInspectionCloseV1E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	root := packageImported220(t, q, "Interrupted exact inspection")
	p := packageCreate223(t, q, root)
	root = packageLatest223(t, q, root.ID)
	e := withPackageAttempt236(t, q, root, p, packageBirthPlan236{seal: true}, func(op *pdfadmission.ApplicationHTMLSendOperationV1, _ *pdfadmission.ApplicationSessionV1, _ pdfadmission.HTMLSendPackageIntentMetadataV1, actor authoring.Actor) error {
		before := packageMeasurementState232(t, q)
		stage, e := op.OpenSQLV1(pdfadmission.HTMLSendIntentReadV1)
		if e != nil {
			return e
		}
		session := stage.SessionV1()
		if _, e = session.NewAdmissionV1(stage.ContextV1()); e != nil {
			return e
		}
		ready, start, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
		result := make(chan error, 1)
		holder := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		var holderPID int32
		if e = holder.QueryRow(q.f.ctx, "SELECT pg_backend_pid()").Scan(&holderPID); e != nil {
			rollbackHTMLQueryFixtureV1(t, holder)
			return e
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			op.EndConsumerV1()
			_ = holder.Rollback(cleanup)
			select {
			case <-finished:
			case <-cleanup.Done():
				t.Error("inspection callback activity unjoined")
			}
			if e := op.CloseV1(cleanup); e != nil {
				t.Error(e)
			}
		}()
		go func() {
			defer close(finished)
			result <- stage.WithTxV1(func(call context.Context, db generated.DBTX) error {
				work, e := session.NewHTMLSendWorkV1(call, stage)
				if e != nil {
					return e
				}
				state, e := work.StateV1(call)
				if e != nil {
					return e
				}
				user, e := work.ReadActorV1(call, actor.UserID)
				if e != nil {
					return e
				}
				if user.Role != "owner" && (user.Role != "sender" || state.SenderID != user.ID) {
					return auth.ErrMutationPermissionRevoked
				}
				if e = actor.Authorize(call, &htmlCreationPolicyTxV1{DBTX: db}, user); e != nil {
					return e
				}
				close(ready)
				select {
				case <-start:
				case <-call.Done():
					return call.Err()
				}
				out, e := work.InspectPackageSendAttemptV1(call)
				if out != (pdfadmission.HTMLSendPackageAttemptObservationV1{}) {
					return errors.New("interrupted inspection exposed a result")
				}
				return e
			})
		}()
		select {
		case <-ready:
		case <-stage.ContextV1().Done():
			return stage.ContextV1().Err()
		}
		// Acquired only after scalar root/actor authorization. StateV1 itself does
		// not touch captures, so this is the actual new inspection SQL boundary.
		if _, e = holder.Exec(q.f.ctx, "LOCK TABLE document_package_captures_v1 IN ACCESS EXCLUSIVE MODE"); e != nil {
			return e
		}
		close(start)
		ownedReadWaitV1(t, q, holderPID, "InspectDocumentPackageSendAttemptStateV1")
		op.EndConsumerV1()
		select {
		case e = <-result:
			if e == nil {
				return errors.New("closed operation inspection succeeded")
			}
		case <-time.After(5 * time.Second):
			return errors.New("interrupted inspection did not join")
		}
		if e = stage.CloseSQLV1(); e != nil {
			return e
		}
		if !session.RetiredV1() {
			return errors.New("closed inspection backend did not physically retire")
		}
		if e = holder.Rollback(q.f.ctx); e != nil {
			return e
		}
		if packageMeasurementState232(t, q) != before {
			return errors.New("interrupted inspection changed persistent state")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
