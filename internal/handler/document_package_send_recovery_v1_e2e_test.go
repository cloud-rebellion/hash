//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func packageFreshActor238(t *testing.T, q *ownedPublicReadFixtureV1, user *generated.User) (sendengine.Actor, string) {
	t.Helper()
	cookie := dsrSessionCookieE2E(t, q.f.s, user.ID, user.SessionGeneration, time.Hour)
	raw, e := q.f.s.Cookies.Verify(cookie)
	if e != nil {
		t.Fatal(e)
	}
	var payload auth.SessionPayload
	if e = json.Unmarshal(raw, &payload); e != nil {
		t.Fatal(e)
	}
	return sendengine.Actor{OrgID: user.OrgID, UserID: &user.ID, Via: "rest", Authorize: auth.SessionTransactionAuthorization(q.f.s.Cookies, cookie, payload, user.OrgID)}, cookie
}

// A NEW factory reads persisted history after the old factory closes its work.
// Last-observer debt remains charged in the old ledger; it is never adopted as
// credit in the new one. This is not an OS process-restart or retirement proof.
func packageFreshFactory238(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	cleanup, stop := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
	defer stop()
	old := q.runtime
	err := old.CloseV1(cleanup)
	pending := old.SessionsV1().PendingV1()
	if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.ObserverSessions != 2 || !pending.Closing || !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
		t.Fatal("old work/debt boundary differs", pending, err)
	}
	snap, e := old.SnapshotV1(q.f.org)
	if e != nil || snap.Global != (workguard.VectorV1{SQLSessions: 2}) || snap.GlobalGrants != 2 {
		t.Fatal("old observer debt was released or work retained", snap, e)
	}

	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 1, ChildAddressBytes: 2 << 30, PDFWorkers: 1}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 1, ChildAddressBytes: 2 << 30, PDFWorkers: 1}, MaxGrants: 128, MaxOrganisationGrants: 64}
	runtime, e := pdfadmission.NewWorkRuntimeV1(q.f.pool, limits, int64(q.f.pool.Config().MaxConns)+8)
	if e != nil {
		t.Fatal(e)
	}
	q.runtime, q.f.s.Send.WorkRuntime, q.f.s.HTMLCreationSessions = runtime, runtime, runtime.SessionsV1()
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		err := runtime.CloseV1(cleanup)
		p := runtime.SessionsV1().PendingV1()
		if p.WorkSessions != 0 || p.UnknownStarts != 0 || p.HTMLAdmissions != 0 || p.SignerScopes != 0 || p.SignerReaders != 0 || p.DocumentPackageOperations != 0 || p.ObserverSessions != 1 || !p.Closing || !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			t.Errorf("fresh runtime work/debt boundary differs: %+v %v", p, err)
		}
		snap, e := runtime.SnapshotV1(q.f.org)
		if e != nil || snap.Global != (workguard.VectorV1{SQLSessions: 1}) || snap.GlobalGrants != 1 {
			t.Errorf("fresh observer debt lost or work retained: %+v %v", snap, e)
		}

	})
}

func TestDocumentPackageDurableInspectionV1E2E(t *testing.T) {
	for _, kind := range []string{"closed original request", "fresh factory with retained observer debt", "aborted historical capture after edit", "completed historical capture", "rollback has no durable job", "fresh credential revoked", "role revoked", "unassigned sender", "different current owner", "foreign root locator", "foreign tenant", "deleted root", "unknown exact attempt", "post-read authorization refused", "result context expired", "close during response use", "HTTP status contract", "frozen annex privacy after source deletion"} {
		t.Run(kind, func(t *testing.T) {
			q := inspectionFixturePG236(t)
			root := packageImported220(t, q, "Actual durable history root")
			var annexes []*generated.Document
			if kind == "frozen annex privacy after source deletion" {
				annexes = append(annexes, packageImported220(t, q, "Original frozen annex"))
			}
			p := packageCreate223(t, q, root, annexes...)
			root = packageLatest223(t, q, root.ID)
			plan := packageBirthPlan236{seal: true}
			if kind == "rollback has no durable job" {
				plan.seal = false
				plan.rollback = true
			}
			if len(annexes) > 0 {
				// A genuine bound capture is deliberately aborted in its birth tx.
				// No nonempty Send is activated and no M99 guard is bypassed.
				plan.seal = false
				plan.finish = func(call context.Context, db generated.DBTX, m pdfadmission.HTMLSendPackageIntentMetadataV1) error {
					queries := generated.New(db)
					_, e := queries.TerminalizeDocumentPackageSendAttemptV1(call, generated.TerminalizeDocumentPackageSendAttemptV1Params{AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID, ExpectedManifestSha256: m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.Capture.CommitmentSHA256[:], Outcome: "aborted"})
					if e != nil {
						return e
					}
					n, e := queries.DeleteDocumentPackageSealingIntentV1(call, generated.DeleteDocumentPackageSealingIntentV1Params{AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID, ExpectedManifestSha256: m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.Capture.CommitmentSHA256[:]})
					if e == nil && n != 1 {
						t.Fatal("did not remove exact aborted intent", n)
					}
					return e
				}
			}
			var m pdfadmission.HTMLSendPackageIntentMetadataV1
			var birth *pdfadmission.ApplicationSessionV1
			e := withPackageAttempt236(t, q, root, p, plan, func(op *pdfadmission.ApplicationHTMLSendOperationV1, session *pdfadmission.ApplicationSessionV1, record pdfadmission.HTMLSendPackageIntentMetadataV1, _ authoring.Actor) error {
				op.EndConsumerV1()
				cleanup, stop := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
				e := op.CloseV1(cleanup)
				stop()
				if e != nil {
					return e
				}
				m, birth = record, session
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			// The original helper, context, consumer and exact observer assertions have
			// now all returned before any independent request or fixture setup begins.
			e = func() error {
				want := pdfadmission.HTMLSendPackageAttemptActiveV1
				switch kind {
				case "fresh factory with retained observer debt":
					packageFreshFactory238(t, q)
				case "aborted historical capture after edit", "deleted root":
					if e = packageAttemptTransition235(t, q, m, "aborted", false); e != nil {
						return e
					}
					if _, e = q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Later draft after signed history' WHERE id=$1", root.ID); e != nil {
						return e
					}
					want = pdfadmission.HTMLSendPackageAttemptAbortedV1
					if kind == "deleted root" {
						if _, e = q.f.pool.Exec(q.f.ctx, "UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1", root.ID); e != nil {
							return e
						}
					}
				case "completed historical capture":
					if e = packageAttemptTransition235(t, q, m, "completed", false); e != nil {
						return e
					}
					want = pdfadmission.HTMLSendPackageAttemptCompletedV1
				case "rollback has no durable job":
					want = pdfadmission.HTMLSendPackageAttemptNotRecordedV1
				case "frozen annex privacy after source deletion":
					if _, e = q.f.pool.Exec(q.f.ctx, "UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1", annexes[0].ID); e != nil {
						return e
					}
					if _, e = q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: annexes[0].ID, Valid: true}, SubjectEmail: "synthetic@hash.example.test", Kind: "access", RequestedVia: "sender", PayloadJson: []byte("{}")}); e != nil {
						return e
					}
				}
				user := q.f.user
				if kind == "different current owner" || kind == "unassigned sender" {
					role := "owner"
					if kind == "unassigned sender" {
						role = "sender"
					}
					user, e = q.f.q.CreateUser(q.f.ctx, generated.CreateUserParams{OrgID: q.f.org, Email: "current-recoverer@hash.example.test", Name: "Current operator", Role: role})
					if e != nil {
						return e
					}
				}
				if kind == "foreign tenant" {
					org, e := q.f.q.CreateOrg(q.f.ctx, generated.CreateOrgParams{Name: "Other recovery tenant", Plan: "free"})
					if e != nil {
						return e
					}
					user, e = q.f.q.CreateUser(q.f.ctx, generated.CreateUserParams{OrgID: org.ID, Email: "foreign-owner@hash.example.test", Name: "Foreign owner", Role: "owner"})
					if e != nil {
						return e
					}
				}
				actor, cookie := packageFreshActor238(t, q, user)
				if kind == "fresh credential revoked" {
					if _, e = q.f.pool.Exec(q.f.ctx, "UPDATE users SET session_generation=session_generation+1 WHERE id=$1", user.ID); e != nil {
						return e
					}
				}
				if kind == "role revoked" {
					if _, e = q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: user.ID, OrgID: q.f.org, Role: "viewer"}); e != nil {
						return e
					}
				}
				document, attempt := root.ID, m.AttemptID
				if kind == "foreign root locator" {
					document = packageImported220(t, q, "Other authorized root").ID
					want = pdfadmission.HTMLSendPackageAttemptNotRecordedV1
				}
				if kind == "unknown exact attempt" {
					attempt = uuid.New()
					want = pdfadmission.HTMLSendPackageAttemptNotRecordedV1
				}
				if kind == "post-read authorization refused" {
					original := actor.Authorize
					calls := 0
					actor.Authorize = func(call context.Context, tx pgx.Tx, u *generated.User) error {
						calls++
						if e := original(call, tx, u); e != nil {
							return e
						}
						if calls == 2 {
							return auth.ErrMutationPermissionRevoked
						}
						return nil
					}
				}
				requests := q.storagePeer.requests.Load()
				before := packageMeasurementState232(t, q)
				ctx, cancel := context.WithTimeout(q.f.ctx, 15*time.Second)
				defer cancel()
				result, e := q.f.s.Send.InspectPackageSendAttemptV1(ctx, actor, document, attempt)
				if result != nil {
					defer result.CloseConsumerV1()
				}
				denied := kind == "foreign tenant" || kind == "deleted root" || kind == "fresh credential revoked" || kind == "role revoked" || kind == "unassigned sender" || kind == "post-read authorization refused" || kind == "frozen annex privacy after source deletion"
				if denied {
					if e == nil || result != nil {
						t.Fatal("failed policy became successful observation", result, e)
					}
					if kind == "frozen annex privacy after source deletion" && !errors.Is(e, pdfadmission.ErrDocumentPackagePendingPrivacyV1) {
						t.Fatal("frozen original subject bypassed", e)
					}
				} else {
					if e != nil || result == nil {
						t.Fatal("fresh inspection failed", e)
					}
					if kind == "close during response use" {
						ready, release, joined := make(chan struct{}), make(chan struct{}), make(chan error, 1)
						funded, _ := q.runtime.SnapshotV1(q.f.org)
						go func() {
							joined <- result.WithObservationV1(func(v pdfadmission.HTMLSendPackageAttemptObservationV1) error {
								close(ready)
								select {
								case <-release:
									return nil
								case <-ctx.Done():
									return ctx.Err()
								}
							})
						}()
						select {
						case <-ready:
						case <-ctx.Done():
							t.Fatal("result use never started")
						}
						result.CloseConsumerV1()
						held, _ := q.runtime.SnapshotV1(q.f.org)
						if funded.Global.ParentBytes == 0 || held.Global.ParentBytes != funded.Global.ParentBytes {
							t.Fatal("close credited active response use", funded, held)
						}
						close(release)
						select {
						case e = <-joined:
							if e != nil {
								t.Fatal(e)
							}
						case <-ctx.Done():
							t.Fatal("response callback did not join")
						}
					} else if kind == "result context expired" {
						cancel()
						if e = result.WithObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error { return nil }); e == nil {
							t.Fatal("expired result delivered")
						}
					} else {
						var view pdfadmission.HTMLSendPackageAttemptObservationV1
						e := result.WithObservationV1(func(v pdfadmission.HTMLSendPackageAttemptObservationV1) error { view = v; return nil })
						if e != nil || view.AttemptID != attempt || view.Outcome != want {
							t.Fatal(view, e)
						}
						expected := m.Capture
						expected.RootUpdatedAt = expected.RootUpdatedAt.UTC()
						expected.CreatedAt = expected.CreatedAt.UTC()
						if want != pdfadmission.HTMLSendPackageAttemptNotRecordedV1 && (view.Capture != expected || view.Capture.CreatedBy != q.f.user.ID) {
							t.Fatal("recovery changed original capture/actor", view, m)
						}
						copyResult := *result
						if e = copyResult.WithObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error { return nil }); e == nil {
							t.Fatal("copied result delivered twice")
						}
					}
					result.CloseConsumerV1()
					result.CloseConsumerV1()
					if e = result.WithObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error { return nil }); e == nil {
						t.Fatal("closed result delivered")
					}
				}
				if kind == "HTTP status contract" {
					response := submitSessionOperationE2E(q.f.s, http.MethodGet, "/api/v1/documents/"+root.ID.String()+"/send-attempts/"+m.AttemptID.String(), "", cookie)
					var wire struct {
						AttemptID       string `json:"attempt_id"`
						Outcome         string `json:"outcome"`
						RetryAuthorized bool   `json:"retry_authorized"`
					}
					if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(response.Body.Bytes(), &wire) != nil || wire.AttemptID != m.AttemptID.String() || wire.Outcome != "active" || wire.RetryAuthorized {
						t.Fatal("HTTP inspection contract", response.Code, response.Body.String())
					}
				}
				if packageMeasurementState232(t, q) != before {
					t.Fatal("read-only inspection changed database state")
				}
				if q.storagePeer.requests.Load() != requests {
					t.Fatal("inspection performed provider I/O")
				}
				if birth.CommitUnknownV1() {
					t.Fatal("known birth unexpectedly changed uncertainty")
				}
				return nil
			}()
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestDocumentPackageDurableInspectionCancellationV1E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	root := packageImported220(t, q, "Canceled fresh recovery")
	p := packageCreate223(t, q, root)
	root = packageLatest223(t, q, root.ID)
	e := withPackageAttempt236(t, q, root, p, packageBirthPlan236{seal: true}, func(op *pdfadmission.ApplicationHTMLSendOperationV1, _ *pdfadmission.ApplicationSessionV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, _ authoring.Actor) error {
		op.EndConsumerV1()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
		e := op.CloseV1(cleanup)
		stop()
		if e != nil {
			return e
		}
		before := packageMeasurementState232(t, q)
		actor, _ := packageFreshActor238(t, q, q.f.user)
		original := actor.Authorize
		ready, start, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		calls := 0
		actor.Authorize = func(call context.Context, tx pgx.Tx, u *generated.User) error {
			if e := original(call, tx, u); e != nil {
				return e
			}
			calls++
			if calls == 1 {
				close(ready)
				select {
				case <-start:
				case <-call.Done():
					return call.Err()
				}
			}
			return nil
		}
		ctx, cancel := context.WithTimeout(q.f.ctx, 15*time.Second)
		holder := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		var holderPID int32
		if e = holder.QueryRow(q.f.ctx, "SELECT pg_backend_pid()").Scan(&holderPID); e != nil {
			cancel()
			rollbackHTMLQueryFixtureV1(t, holder)
			return e
		}
		type outcome struct {
			result *sendengine.PackageSendAttemptInspectionV1
			err    error
		}
		finished := make(chan outcome, 1)
		defer func() {
			cancel()
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			_ = holder.Rollback(cleanup)
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("fresh recovery activity unjoined")
			}
		}()
		go func() {
			defer close(done)
			r, e := q.f.s.Send.InspectPackageSendAttemptV1(ctx, actor, root.ID, m.AttemptID)
			finished <- outcome{r, e}
		}()
		select {
		case <-ready:
		case <-ctx.Done():
			return ctx.Err()
		}
		if _, e = holder.Exec(q.f.ctx, "LOCK TABLE document_package_captures_v1 IN ACCESS EXCLUSIVE MODE"); e != nil {
			return e
		}
		close(start)
		ownedReadWaitV1(t, q, holderPID, "InspectDocumentPackageSendAttemptStateV1")
		cancel()
		select {
		case out := <-finished:
			if out.result != nil {
				out.result.CloseConsumerV1()
				return errors.New("canceled fresh inspection exposed a result")
			}
			if out.err == nil {
				return errors.New("canceled fresh inspection succeeded")
			}
		case <-time.After(5 * time.Second):
			return errors.New("fresh inspection did not join cancellation")
		}
		if e = holder.Rollback(q.f.ctx); e != nil {
			return e
		}
		pending := q.runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.UnknownStarts != 0 {
			t.Fatal("canceled read retained unjoined SQL", pending)
		}
		if packageMeasurementState232(t, q) != before {
			return errors.New("canceled fresh inspection changed persisted state")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
