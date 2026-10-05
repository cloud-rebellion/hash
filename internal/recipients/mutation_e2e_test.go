//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package recipients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// Fixtures contain synthetic draft rows and use a real signed session and
// PostgreSQL transactions. No email worker, integration or storage is involved.
func TestRecipientMutationFinalAuthorizationRollsBackExactStateE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupRecipientMutationE2E(t)
			f.seedRecipientAndField(t)
			before := f.snapshot(t)
			actor := f.actor(t)
			originalGuard := actor.Authorize
			checks := 0
			actor.Authorize = func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
				if err := originalGuard(ctx, tx, user); err != nil {
					return err
				}
				checks++
				if user.ID != f.user.ID || user.OrgID != f.orgID || user.Role != "sender" {
					t.Error("authorization did not receive the live member")
				}
				if checks == 2 {
					var recipients, fields, events int
					if err := tx.QueryRow(ctx, `SELECT
						(SELECT count(*) FROM recipients WHERE document_id=$1),
						(SELECT count(*) FROM document_fields WHERE document_id=$1),
						(SELECT count(*) FROM events WHERE document_id=$1)`, f.doc.ID).Scan(&recipients, &fields, &events); err != nil {
						return err
					}
					wantRecipients, wantFields := 1, 1
					if operation == "create" {
						wantRecipients = 2
					}
					if operation == "delete" {
						wantRecipients, wantFields = 0, 0
					}
					if recipients != wantRecipients || fields != wantFields || events != 1 {
						t.Errorf("final callback missed staged mutation: recipients/fields/events=%d/%d/%d", recipients, fields, events)
					}
					if operation == "update" {
						var name, locale string
						if err := tx.QueryRow(ctx, `SELECT name,locale FROM recipients WHERE id=$1`, f.recipient.ID).Scan(&name, &locale); err != nil {
							return err
						}
						if name != "Updated recipient" || locale != "sv" {
							t.Errorf("final callback saw unnormalized update: %q/%q", name, locale)
						}
					}
					return auth.ErrMutationCredentialExpired
				}
				return nil
			}
			result, err := f.mutate(operation, actor)
			if result != nil || !errors.Is(err, auth.ErrMutationCredentialExpired) {
				t.Fatalf("mutation returned result=%t error=%v", result != nil, err)
			}
			if checks != 2 {
				t.Fatalf("authorization checks=%d, want 2", checks)
			}
			f.assertUnchanged(t, before)
			if f.logger.published != 0 {
				t.Fatalf("uncommitted events published=%d", f.logger.published)
			}
		})
	}
}

func TestRecipientMutationAuditFailureRollsBackExactStateE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupRecipientMutationE2E(t)
			f.seedRecipientAndField(t)
			before := f.snapshot(t)
			f.logger.fail = true
			result, err := f.mutate(operation, f.actor(t))
			if result != nil || !errors.Is(err, errRecipientFixtureAudit) {
				t.Fatalf("audit failure result=%t error=%v", result != nil, err)
			}
			f.assertUnchanged(t, before)
			if f.logger.published != 0 {
				t.Fatalf("failed audit published=%d", f.logger.published)
			}
		})
	}
}

func TestRecipientMutationRequiresOriginalGuardForEverySurfaceE2E(t *testing.T) {
	f := setupRecipientMutationE2E(t)
	f.seedRecipientAndField(t)
	before := f.snapshot(t)
	for _, via := range []string{"", "rest", "mcp", "automation", "worker", "test"} {
		actor := f.actor(t)
		actor.Via = via
		actor.Authorize = nil
		for _, operation := range []string{"create", "update", "delete"} {
			if result, err := f.mutate(operation, actor); result != nil || !errors.Is(err, auth.ErrMutationPermissionRevoked) {
				t.Errorf("missing guard via=%q operation=%s result=%t error=%v", via, operation, result != nil, err)
			}
		}
	}
	actor := f.actor(t)
	actor.UserID = uuid.Nil
	if result, err := f.mutate("create", actor); result != nil || !errors.Is(err, auth.ErrMutationPermissionRevoked) {
		t.Errorf("missing user result=%t error=%v", result != nil, err)
	}
	f.assertUnchanged(t, before)
}

func TestRecipientCreateQuotaWaitRejectsSoftDeletedParentE2E(t *testing.T) {
	f := setupRecipientMutationE2E(t)
	f.seedRecipientAndField(t)
	f.engine.Billing = billing.New(f.q, billing.MockProvider{}, "", "")
	blocked, pid := f.holdQuota(t)
	actor := f.actor(t)
	done := make(chan recipientMutationResult, 1)
	go func() {
		r, err := f.engine.Create(f.ctx, actor, f.doc.ID, f.values())
		done <- recipientMutationResult{r, err}
	}()
	f.awaitBlocked(t, pid, "-- name: LockBillingUsageForOrg")
	if err := f.q.DeleteDraftDocument(f.ctx, generated.DeleteDraftDocumentParams{ID: f.doc.ID, OrgID: f.orgID}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	r := receiveRecipientMutation(t, done)
	if r.recipient != nil || !errors.Is(r.err, ErrDocumentNotFound) {
		t.Fatalf("soft-deleted admission result=%t error=%v", r.recipient != nil, r.err)
	}
	f.assertUnchanged(t, before)
	var hidden int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM recipients WHERE document_id=$1`, f.doc.ID).Scan(&hidden); err != nil {
		t.Fatal(err)
	}
	if hidden != 1 {
		t.Fatalf("soft-delete race added hidden recipients: count=%d", hidden)
	}
}

func TestRecipientCreateUsesFreshParentLocaleAndDeadlineAfterQuotaWaitE2E(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit_locale_%t", explicit), func(t *testing.T) {
			f := setupRecipientMutationE2E(t)
			f.engine.Billing = billing.New(f.q, billing.MockProvider{}, "", "")
			if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET expires_at=clock_timestamp()+interval '10 days' WHERE id=$1`, f.doc.ID); err != nil {
				t.Fatal(err)
			}
			blocked, pid := f.holdQuota(t)
			actor := f.actor(t)
			input := f.values()
			input.Locale = ""
			if explicit {
				input.Locale = " EN_us "
			}
			done := make(chan recipientMutationResult, 1)
			go func() {
				r, err := f.engine.Create(f.ctx, actor, f.doc.ID, input)
				done <- recipientMutationResult{r, err}
			}()
			f.awaitBlocked(t, pid, "-- name: LockBillingUsageForOrg")
			var deadline time.Time
			if err := f.pool.QueryRow(f.ctx, `UPDATE documents SET default_locale='sv',expires_at=date_trunc('microseconds',clock_timestamp()+interval '2 hours'),updated_at=clock_timestamp() WHERE id=$1 RETURNING expires_at`, f.doc.ID).Scan(&deadline); err != nil {
				t.Fatal(err)
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			r := receiveRecipientMutation(t, done)
			if r.err != nil || r.recipient == nil {
				t.Fatalf("create error=%v", r.err)
			}
			wantLocale := "sv"
			if explicit {
				wantLocale = "en"
			}
			if r.recipient.Locale != wantLocale || !r.recipient.MagicTokenExpiresAt.Valid || !r.recipient.MagicTokenExpiresAt.Time.Equal(deadline) || len(r.recipient.MagicTokenHash) != 32 {
				t.Fatalf("fresh locale/deadline/hash length=%s/%s/%d", r.recipient.Locale, r.recipient.MagicTokenExpiresAt.Time, len(r.recipient.MagicTokenHash))
			}
			if f.logger.published != 1 {
				t.Fatalf("successful create publications=%d", f.logger.published)
			}
		})
	}
}

func TestRecipientAuthoringQueriesRejectSoftDeletedDraftE2E(t *testing.T) {
	f := setupRecipientMutationE2E(t)
	f.seedRecipientAndField(t)
	if err := f.q.DeleteDraftDocument(f.ctx, generated.DeleteDraftDocumentParams{ID: f.doc.ID, OrgID: f.orgID}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	_, err := f.q.CreateRecipient(f.ctx, generated.CreateRecipientParams{DocumentID: f.doc.ID, Role: "signer", Email: f.values().Email, Name: "Hidden recipient", Locale: "en", MagicTokenHash: make([]byte, 32), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("direct create on deleted draft error=%v", err)
	}
	_, err = f.q.UpdateRecipient(f.ctx, generated.UpdateRecipientParams{ID: f.recipient.ID, DocumentID: f.doc.ID, Email: f.recipient.Email, Name: "Hidden update", Role: "signer", Locale: "en"})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("direct update on deleted draft error=%v", err)
	}
	_, err = f.q.DeleteRecipient(f.ctx, generated.DeleteRecipientParams{ID: f.recipient.ID, DocumentID: f.doc.ID})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("direct delete on deleted draft error=%v", err)
	}
	for _, operation := range []string{"create", "update", "delete"} {
		if result, err := f.mutate(operation, f.actor(t)); result != nil || !errors.Is(err, ErrDocumentNotFound) {
			t.Errorf("engine deleted parent operation=%s result=%t error=%v", operation, result != nil, err)
		}
	}
	f.assertUnchanged(t, before)
}

func TestRecipientCreateQuotaFailureRollsBackNewTokenAndAuditE2E(t *testing.T) {
	f := setupRecipientMutationE2E(t)
	f.seedRecipientAndField(t)
	var planID uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `INSERT INTO billing_plans(slug,name,recipient_quota_monthly,document_quota_monthly) VALUES($1,'Synthetic recipient cap',1,100) RETURNING id`, "recipient-fixture-"+f.orgID.String()).Scan(&planID); err != nil {
		t.Fatal(err)
	}
	f.planIDs = append(f.planIDs, planID)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO org_subscriptions(org_id,plan_id,provider,status,current_period_start,current_period_end) VALUES($1,$2,'mock','active',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour')`, f.orgID, planID); err != nil {
		t.Fatal(err)
	}
	f.engine.Billing = billing.New(f.q, billing.MockProvider{}, "", "")
	before := f.snapshot(t)
	if result, err := f.engine.Create(f.ctx, f.actor(t), f.doc.ID, f.values()); result != nil || !errors.Is(err, billing.ErrQuotaExceeded) {
		t.Fatalf("quota result=%t error=%v", result != nil, err)
	}
	f.assertUnchanged(t, before)
	if f.logger.published != 0 {
		t.Fatalf("quota rejection published=%d", f.logger.published)
	}
}

func TestRecipientSuccessfulCRUDKeepsDeletedSubjectAndValidChainE2E(t *testing.T) {
	f := setupRecipientMutationE2E(t)
	var subjectFKs int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid='events'::regclass AND contype='f' AND confrelid IN ('recipients'::regclass,'documents'::regclass,'users'::regclass)`).Scan(&subjectFKs); err != nil {
		t.Fatal(err)
	}
	if subjectFKs != 0 {
		t.Fatalf("mutable audit subject FKs remain after migration43: %d", subjectFKs)
	}
	input := f.values()
	input.Email = " " + input.Email + " "
	input.Name = " Created recipient "
	input.Role = " Signer "
	input.Locale = " EN_us "
	created, err := f.engine.Create(f.ctx, f.actor(t), f.doc.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if created.Email != strings.TrimSpace(input.Email) || created.Name != "Created recipient" || created.Role != "signer" || created.Locale != "en" || len(created.MagicTokenHash) != 32 || !created.MagicTokenExpiresAt.Valid {
		t.Fatal("successful create did not persist normalized routing and a bounded token")
	}
	f.recipient = created
	f.seedField(t)
	name := " Updated recipient "
	updated, err := f.engine.Update(f.ctx, f.actor(t), f.doc.ID, created.ID, Patch{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated recipient" || updated.Email != created.Email || updated.Role != created.Role || updated.Locale != created.Locale || updated.OrderIndex != created.OrderIndex || !reflect.DeepEqual(updated.MagicTokenHash, created.MagicTokenHash) || updated.MagicTokenExpiresAt != created.MagicTokenExpiresAt {
		t.Fatal("omitted patch fields or the existing credential changed")
	}
	beforeInvalid := f.snapshot(t)
	empty := ""
	if _, err := f.engine.Update(f.ctx, f.actor(t), f.doc.ID, created.ID, Patch{Locale: &empty}); err == nil {
		t.Fatal("explicit empty locale was accepted")
	}
	f.assertUnchanged(t, beforeInvalid)
	deleted, err := f.engine.Delete(f.ctx, f.actor(t), f.doc.ID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if deleted == nil || deleted.ID != updated.ID || deleted.Name != updated.Name || deleted.Email != updated.Email {
		t.Fatal("delete did not return the original removed identity")
	}
	var recs, fields int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM recipients WHERE document_id=$1),(SELECT count(*) FROM document_fields WHERE document_id=$1)`, f.doc.ID).Scan(&recs, &fields); err != nil {
		t.Fatal(err)
	}
	if recs != 0 || fields != 0 {
		t.Fatalf("deleted recipient/assigned fields remain=%d/%d", recs, fields)
	}
	events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.orgID, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("successful CRUD audit count=%d", len(events))
	}
	for i, event := range events {
		if !event.RecipientID.Valid || uuid.UUID(event.RecipientID.Bytes) != created.ID || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != f.user.ID || !event.DocumentID.Valid || uuid.UUID(event.DocumentID.Bytes) != f.doc.ID {
			t.Fatalf("event %d lost immutable subject scope after delete", i)
		}
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	result := verifier.Result()
	if !result.OK || !result.Complete || result.TotalChecked != 3 {
		t.Fatalf("recipient CRUD chain failed verification: %+v", result)
	}
	if f.logger.published != 3 {
		t.Fatalf("committed CRUD publications=%d", f.logger.published)
	}
}

func TestRecipientMutationsPreserveAnomalousDraftEvidenceE2E(t *testing.T) {
	for _, evidence := range []string{"signature", "accepted", "empty_field_value", "completed_field"} {
		for _, operation := range []string{"create", "update", "delete"} {
			t.Run(evidence+"/"+operation, func(t *testing.T) {
				f := setupRecipientMutationE2E(t)
				f.seedRecipientAndField(t)
				switch evidence {
				case "signature":
					if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET type='signature' WHERE id=$1`, f.fieldID); err != nil {
						t.Fatal(err)
					}
					if _, err := f.q.InsertSignature(f.ctx, generated.InsertSignatureParams{
						DocumentID: f.doc.ID, RecipientID: f.recipient.ID, FieldID: f.fieldID,
						Font: "synthetic", TypedName: "Synthetic captured response", ImageStorageKey: f.orgID.String() + "/fixture/signature.png",
						ImageSha256: make([]byte, 32), ImageVersionID: pgtype.Text{String: "synthetic-version-pin", Valid: true},
					}); err != nil {
						t.Fatal(err)
					}
				case "accepted":
					if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET status='accepted' WHERE id=$1`, f.recipient.ID); err != nil {
						t.Fatal(err)
					}
				case "empty_field_value":
					if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET value='' WHERE id=$1`, f.fieldID); err != nil {
						t.Fatal(err)
					}
				case "completed_field":
					if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET completed_at=clock_timestamp() WHERE id=$1`, f.fieldID); err != nil {
						t.Fatal(err)
					}
				}
				before := f.snapshot(t)
				if result, err := f.mutate(operation, f.actor(t)); result != nil || !errors.Is(err, ErrDocumentHasEvidence) {
					t.Fatalf("captured draft operation=%s result=%t error=%v", operation, result != nil, err)
				}
				f.assertUnchanged(t, before)
				if f.logger.published != 0 {
					t.Fatalf("retained-evidence refusal published=%d", f.logger.published)
				}
			})
		}
	}
}

func TestRecipientMutationsPreservePendingPrivacyReviewE2E(t *testing.T) {
	for _, linked := range []bool{true, false} {
		for _, status := range []string{"open", "in_progress"} {
			for _, operation := range []string{"create", "update", "delete"} {
				t.Run(fmt.Sprintf("linked_%t/%s/%s", linked, status, operation), func(t *testing.T) {
					f := setupRecipientMutationE2E(t)
					f.seedRecipientAndField(t)
					f.privacyRequest(t, f.q, linked, status)
					before := f.snapshot(t)
					if result, err := f.mutate(operation, f.actor(t)); result != nil || !errors.Is(err, ErrPendingPrivacyReview) {
						t.Fatalf("pending privacy review operation=%s result=%t error=%v", operation, result != nil, err)
					}
					f.assertUnchanged(t, before)
					if f.logger.published != 0 {
						t.Fatalf("pending review refusal published=%d", f.logger.published)
					}
				})
			}
		}
	}
}

func TestRecipientPrivacyReviewClosedAndUnrelatedScopeAllowAuthoringE2E(t *testing.T) {
	for _, scope := range []string{"linked_fulfilled", "linked_denied", "linked_withdrawn", "global_fulfilled", "global_denied", "global_withdrawn", "other_document", "other_tenant"} {
		for _, operation := range []string{"create", "update", "delete"} {
			t.Run(scope+"/"+operation, func(t *testing.T) {
				f := setupRecipientMutationE2E(t)
				f.seedRecipientAndField(t)
				switch scope {
				case "other_document":
					other, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.orgID, SenderID: f.user.ID, Name: "Unrelated privacy draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.orgID, DocumentID: pgtype.UUID{Bytes: other.ID, Valid: true}, SubjectEmail: "unrelated@example.test", SubjectName: "Unrelated subject", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}); err != nil {
						t.Fatal(err)
					}
				case "other_tenant":
					foreign := setupRecipientMutationE2E(t)
					foreign.privacyRequest(t, foreign.q, false, "in_progress")
				default:
					parts := strings.SplitN(scope, "_", 2)
					f.privacyRequest(t, f.q, parts[0] == "linked", parts[1])
				}
				if result, err := f.mutate(operation, f.actor(t)); result == nil || err != nil {
					t.Fatalf("closed/unrelated privacy scope=%s operation=%s result=%t error=%v", scope, operation, result != nil, err)
				}
				var rows, fields, events int
				if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM recipients WHERE document_id=$1),(SELECT count(*) FROM document_fields WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)`, f.doc.ID).Scan(&rows, &fields, &events); err != nil {
					t.Fatal(err)
				}
				wantRows, wantFields := 1, 1
				if operation == "create" {
					wantRows = 2
				}
				if operation == "delete" {
					wantRows, wantFields = 0, 0
				}
				if rows != wantRows || fields != wantFields || events != 1 || f.logger.published != 1 {
					t.Fatalf("allowed mutation rows/fields/audits/publications=%d/%d/%d/%d", rows, fields, events, f.logger.published)
				}
			})
		}
	}
}

func TestRecipientMutationSeesLinkedPrivacyRequestCommittedDuringParentWaitE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupRecipientMutationE2E(t)
			f.seedRecipientAndField(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = blocked.Rollback(context.Background()) })
			q := f.q.WithTx(blocked)
			if _, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.orgID}); err != nil {
				t.Fatal(err)
			}
			var pid int32
			if err := blocked.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			actor := f.actor(t)
			done := make(chan recipientMutationResult, 1)
			go func() { r, err := f.mutate(operation, actor); done <- recipientMutationResult{r, err} }()
			f.awaitBlocked(t, pid, "-- name: GetDocumentForUpdate")
			f.privacyRequest(t, q, true, "in_progress")
			// Include the uncommitted request in the expected snapshot before
			// releasing the parent; an accidentally committed mutation cannot
			// contaminate this expected state.
			before := f.snapshotWithDB(t, blocked)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			result := receiveRecipientMutation(t, done)
			if result.recipient != nil || !errors.Is(result.err, ErrPendingPrivacyReview) {
				t.Fatalf("linked request after wait result=%t error=%v", result.recipient != nil, result.err)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestRecipientPrivacyExclusiveFenceRefusesImmediatelyAndRetriesFreshE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupRecipientMutationE2E(t)
			f.seedRecipientAndField(t)
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = blocked.Rollback(context.Background()) })
			if _, err := blocked.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hash_collab_archive_dsr_lock_key($1::uuid))`, f.orgID); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(f.ctx, time.Second)
			start := time.Now()
			result, err := f.mutateWithContext(ctx, operation, f.actor(t))
			elapsed := time.Since(start)
			cancel()
			if result != nil || !errors.Is(err, ErrPrivacyReviewChanging) || elapsed >= 900*time.Millisecond {
				t.Fatalf("exclusive fence result=%t error=%v elapsed=%s, want immediate typed refusal", result != nil, err, elapsed)
			}
			f.assertUnchanged(t, before)
			// The same exclusive writer now publishes a global pending request.
			// A new mutation must observe its committed state after release.
			f.privacyRequest(t, f.q.WithTx(blocked), false, "in_progress")
			withPending := f.snapshotWithDB(t, blocked)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if result, err := f.mutate(operation, f.actor(t)); result != nil || !errors.Is(err, ErrPendingPrivacyReview) {
				t.Fatalf("retry after global review committed result=%t error=%v", result != nil, err)
			}
			f.assertUnchanged(t, withPending)
			if f.logger.published != 0 {
				t.Fatalf("privacy contention/refusal published=%d", f.logger.published)
			}
		})
	}
}

var errRecipientFixtureAudit = errors.New("synthetic recipient audit append failure")

type recipientMutationAudit struct {
	logger    *audit.Logger
	fail      bool
	published int
}

func (a *recipientMutationAudit) LogTx(ctx context.Context, tx pgx.Tx, entry audit.Entry) (audit.PendingEvent, error) {
	pending, err := a.logger.LogTx(ctx, tx, entry)
	if err == nil && a.fail {
		return audit.PendingEvent{}, errRecipientFixtureAudit
	}
	return pending, err
}
func (a *recipientMutationAudit) Publish(pending audit.PendingEvent) {
	a.published++
	a.logger.Publish(pending)
}

type recipientMutationFixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	q         *generated.Queries
	engine    *MutationEngine
	logger    *recipientMutationAudit
	orgID     uuid.UUID
	user      *generated.User
	doc       *generated.Document
	recipient *generated.Recipient
	fieldID   uuid.UUID
	cookies   *auth.SignedCookie
	planIDs   []uuid.UUID
}

func setupRecipientMutationE2E(t *testing.T) *recipientMutationFixture {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	if err := mdb.RunMigrations(migrationDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migrationDB.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Recipient mutation " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@recipient-owner.test", Name: "Synthetic sender", Role: "sender", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, SenderID: user.ID, Name: "Synthetic recipient draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := auth.NewSignedCookie(strings.Repeat("4b", 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := &recipientMutationAudit{logger: audit.New(q, pool)}
	f := &recipientMutationFixture{ctx: ctx, pool: pool, q: q, engine: &MutationEngine{Pool: pool, Audit: logger}, logger: logger, orgID: org.ID, user: user, doc: doc, cookies: cookies}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM orgs WHERE id=$1`, f.orgID); err != nil {
			t.Error(err)
		}
		for _, id := range f.planIDs {
			if _, err := pool.Exec(cleanupCtx, `DELETE FROM billing_plans WHERE id=$1`, id); err != nil {
				t.Error(err)
			}
		}
	})
	return f
}

func (f *recipientMutationFixture) actor(t *testing.T) MutationActor {
	t.Helper()
	session := auth.SessionPayload{UserID: f.user.ID, Generation: f.user.SessionGeneration}
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	cookie := f.cookies.Mint(raw, time.Hour)
	return MutationActor{OrgID: f.orgID, UserID: f.user.ID, Via: "test", Authorize: auth.SessionTransactionAuthorization(f.cookies, cookie, session, f.orgID)}
}
func (f *recipientMutationFixture) values() Values {
	return Values{Email: "next@recipient-" + f.orgID.String() + ".test", Name: "Created recipient", Role: "signer", Locale: "en"}
}
func (f *recipientMutationFixture) mutate(operation string, actor MutationActor) (*generated.Recipient, error) {
	return f.mutateWithContext(f.ctx, operation, actor)
}
func (f *recipientMutationFixture) mutateWithContext(ctx context.Context, operation string, actor MutationActor) (*generated.Recipient, error) {
	switch operation {
	case "create":
		return f.engine.Create(ctx, actor, f.doc.ID, f.values())
	case "update":
		name, locale := " Updated recipient ", " SV-se "
		return f.engine.Update(ctx, actor, f.doc.ID, f.recipient.ID, Patch{Name: &name, Locale: &locale})
	case "delete":
		return f.engine.Delete(ctx, actor, f.doc.ID, f.recipient.ID)
	default:
		return nil, errors.New("unknown fixture operation")
	}
}
func (f *recipientMutationFixture) seedRecipientAndField(t *testing.T) {
	t.Helper()
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	f.recipient, err = f.q.CreateRecipient(f.ctx, generated.CreateRecipientParams{DocumentID: f.doc.ID, Role: "signer", Email: "original@recipient-" + f.orgID.String() + ".test", Name: "Original recipient", Locale: "en", MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	f.seedField(t)
}
func (f *recipientMutationFixture) seedField(t *testing.T) {
	t.Helper()
	if err := f.pool.QueryRow(f.ctx, `INSERT INTO document_fields(document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required,label,options_json) VALUES($1,$2,'text',1,0,0,20,5,true,'Synthetic assigned field','[]'::jsonb) RETURNING id`, f.doc.ID, f.recipient.ID).Scan(&f.fieldID); err != nil {
		t.Fatal(err)
	}
}
func (f *recipientMutationFixture) snapshot(t *testing.T) string {
	return f.snapshotWithDB(t, f.pool)
}

type recipientSnapshotDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (f *recipientMutationFixture) snapshotWithDB(t *testing.T, db recipientSnapshotDB) string {
	t.Helper()
	var state string
	if err := db.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1) SELECT jsonb_build_object(
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
		'fields',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM document_fields f WHERE document_id IN (SELECT id FROM owned)),
		'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM signatures s WHERE document_id IN (SELECT id FROM owned)),
		'privacy_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$1),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1)
	)::text`, f.orgID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}
func (f *recipientMutationFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before {
		t.Fatal("rejected recipient mutation changed parent, recipient credentials/routing, captured data, privacy request identity or exact audit state")
	}
}
func (f *recipientMutationFixture) holdQuota(t *testing.T) (pgx.Tx, int32) {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if err := f.q.WithTx(tx).LockBillingUsageForOrg(f.ctx, f.orgID.String()); err != nil {
		t.Fatal(err)
	}
	var pid int32
	if err := tx.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return tx, pid
}
func (f *recipientMutationFixture) awaitBlocked(t *testing.T, pid int32, query string) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE $1=ANY(pg_blocking_pids(a.pid)) AND position($2 in a.query)>0)`, pid, query).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("mutation did not wait on the exact synthetic lock holder")
		}
	}
}

func (f *recipientMutationFixture) privacyRequest(t *testing.T, q *generated.Queries, linked bool, status string) *generated.DataSubjectRequest {
	t.Helper()
	input := generated.CreateDataSubjectRequestParams{OrgID: f.orgID, SubjectEmail: "synthetic-subject@example.test", SubjectName: "Synthetic privacy subject", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}
	if linked {
		input.DocumentID = pgtype.UUID{Bytes: f.doc.ID, Valid: true}
		input.RecipientID = pgtype.UUID{Bytes: f.recipient.ID, Valid: true}
		input.SubjectEmail, input.SubjectName = f.recipient.Email, f.recipient.Name
	}
	request, err := q.CreateDataSubjectRequest(f.ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if status != "open" {
		request, err = q.UpdateDataSubjectRequestStatus(f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: request.ID, OrgID: f.orgID, ExpectedStatus: "open", Status: status, ResolutionNote: "Synthetic reviewed fixture state"})
		if err != nil {
			t.Fatal(err)
		}
	}
	return request
}

type recipientMutationResult struct {
	recipient *generated.Recipient
	err       error
}

func receiveRecipientMutation(t *testing.T, done <-chan recipientMutationResult) recipientMutationResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("recipient mutation did not complete after releasing its lock")
		return recipientMutationResult{}
	}
}
