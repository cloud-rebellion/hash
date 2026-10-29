//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/blocks"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/docintake"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/recipientauthoring"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/sanitize"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
)

// These tests use only synthetic PostgreSQL rows, in-process CRM sources and
// the durable email queue. No SMTP worker or production storage is involved.
func TestSendResolverWaitRechecksAuthorityAndOriginalSnapshotsE2E(t *testing.T) {
	for _, scenario := range []string{"member_demoted", "credential_revoked", "document_edited", "binding_edited"} {
		t.Run(scenario, func(t *testing.T) {
			f := setupSendAdmissionE2E(t)
			doc, _ := f.blocksDocument(t, true)
			before := f.snapshot(t, doc.ID)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			source := sendAdmissionSource{fetch: func(ctx context.Context, _ resolver.Ref) (string, error) {
				once.Do(func() { close(entered) })
				select {
				case <-release:
					return "4200", nil
				case <-ctx.Done():
					return "", ctx.Err()
				}
			}}
			f.engine.Resolver = f.resolver(t, source.fetch)
			actor := f.actor()
			var credentialRevoked atomic.Bool
			actor.Authorize = func(context.Context, pgx.Tx, *generated.User) error {
				if credentialRevoked.Load() {
					return auth.ErrMutationPermissionRevoked
				}
				return nil
			}
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			if scenario != "credential_revoked" {
				f.trace.arm(doc.ID)
				defer f.trace.unblock()
			}
			done := make(chan error, 1)
			go func() {
				result, err := f.engine.Send(ctx, actor, doc.ID)
				result.CloseConsumerV1()
				done <- err
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("send finished before CRM preflight reached the held source: %v", err)
			case <-ctx.Done():
				t.Fatal("CRM preflight did not reach the held source")
			}
			f.assertSnapshot(t, before, doc.ID)
			// Native preparation holds the original source/member locks through
			// the HTTP read. Release that read, then pause the actual admission
			// query after preparation commits; queued writers can now change the
			// source without a test-induced lock/fetch deadlock.
			if scenario != "credential_revoked" {
				close(release)
				select {
				case <-f.trace.reached:
				case err := <-done:
					t.Fatalf("send finished before its native admission boundary: %v", err)
				case <-ctx.Done():
					t.Fatal("send did not reach its native admission boundary")
				}
			}
			want := error(auth.ErrMutationPermissionRevoked)
			switch scenario {
			case "credential_revoked":
				credentialRevoked.Store(true)
			case "member_demoted":
				_, err := f.pool.Exec(f.ctx, `UPDATE users SET role='viewer' WHERE id=$1`, f.user.ID)
				if err != nil {
					t.Fatal(err)
				}
			case "document_edited":
				_, err := f.pool.Exec(f.ctx, `UPDATE documents SET name='Edited after CRM loading, before admission',updated_at=clock_timestamp() WHERE id=$1`, doc.ID)
				if err != nil {
					t.Fatal(err)
				}
				want = sendengine.ErrDraftChangedDuringSend
			case "binding_edited":
				_, err := f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{
					DocumentID: doc.ID, VariableName: "amount", SourceKind: "crm.deal", SourceRef: "changed-deal", SourcePath: "amount",
				})
				if err != nil {
					t.Fatal(err)
				}
				want = sendengine.ErrDraftChangedDuringSend
			}
			expected := f.snapshot(t, doc.ID)
			if scenario == "credential_revoked" {
				close(release)
			} else {
				f.trace.unblock()
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("send error=%v, want %v", err, want)
				}
			case <-ctx.Done():
				t.Fatal("send did not finish after releasing CRM")
			}
			f.assertSnapshot(t, expected, doc.ID)
		})
	}
}

func TestSendEnvelopePreparationFailureLeavesEveryDraftUnchangedE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	root := f.envelopeDocument(t)
	first, _ := f.blocksDocument(t, true)
	second, _ := f.blocksDocument(t, true)
	for i, child := range []*generated.Document{first, second} {
		f.attach(t, root.ID, child.ID, int32(i+1))
	}
	before := f.snapshot(t, root.ID, first.ID, second.ID)
	f.engine.Resolver = f.resolver(t, func(_ context.Context, ref resolver.Ref) (string, error) {
		if ref.DocID == second.ID {
			return "", resolver.ErrNotFound
		}
		return "4200", nil
	})
	_, err := f.send(t, f.ctx, f.actor(), root.ID)
	if !errors.Is(err, sendengine.ErrUnresolvedVariables) {
		t.Fatalf("send error=%v, want unresolved variables", err)
	}
	f.assertSnapshot(t, before, root.ID, first.ID, second.ID)
}

func TestSendAndVoidFinalAuthorizationRollsBackAllArtifactsE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	doc, recipient := f.blocksDocument(t, true)
	f.engine.Resolver = f.resolver(t, func(context.Context, resolver.Ref) (string, error) { return "4200", nil })
	before := f.snapshot(t, doc.ID)
	actor := f.actor()
	checks := 0
	actor.Authorize = func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
		checks++
		if user.ID != f.user.ID || user.Email != f.user.Email {
			t.Error("callback did not receive the live canonical user")
		}
		if checks == 4 {
			var status, amount string
			if err := tx.QueryRow(ctx, `SELECT status,variables_json->>'amount' FROM documents WHERE id=$1`, doc.ID).Scan(&status, &amount); err != nil {
				return err
			}
			if status != "sealing" || amount != "4200" {
				t.Errorf("final send check saw %s/%s", status, amount)
			}
			return auth.ErrMutationCredentialExpired
		}
		return nil
	}
	if _, err := f.send(t, f.ctx, actor, doc.ID); !errors.Is(err, auth.ErrMutationCredentialExpired) {
		t.Fatalf("send error=%v", err)
	}
	if checks != 4 {
		t.Fatalf("send authorization checks=%d, want 4 (preparation entry/exit, admission entry/final)", checks)
	}
	f.assertSnapshot(t, before, doc.ID)

	checks = 0
	actor.Authorize = func(context.Context, pgx.Tx, *generated.User) error { checks++; return nil }
	result, err := f.send(t, f.ctx, actor, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "sent" || len(result.Links) != 1 || checks != 4 {
		t.Fatalf("successful send status/links/checks=%s/%d/%d", result.Status, len(result.Links), checks)
	}
	var replyTo, deliveryStatus string
	if err := f.pool.QueryRow(f.ctx, `SELECT reply_to,status FROM email_deliveries WHERE to_email=$1`, recipient.Email).Scan(&replyTo, &deliveryStatus); err != nil {
		t.Fatal(err)
	}
	if replyTo != f.user.Email || deliveryStatus != "pending" {
		t.Fatalf("queued invitation canonical sender/status=%q/%q", replyTo, deliveryStatus)
	}
	sent := f.snapshot(t, doc.ID)
	checks = 0
	actor.Authorize = func(ctx context.Context, tx pgx.Tx, _ *generated.User) error {
		checks++
		if checks == 2 {
			var status string
			var reminders, events int
			if err := tx.QueryRow(ctx, `SELECT status,(SELECT count(*) FROM reminders WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.voided') FROM documents WHERE id=$1`, doc.ID).Scan(&status, &reminders, &events); err != nil {
				return err
			}
			if status != "voided" || reminders != 0 || events != 1 {
				t.Errorf("final void check saw status/reminders/events=%s/%d/%d", status, reminders, events)
			}
			return auth.ErrMutationCredentialExpired
		}
		return nil
	}
	if err := f.engine.Void(f.ctx, actor, doc.ID, "Synthetic revoked request"); !errors.Is(err, auth.ErrMutationCredentialExpired) {
		t.Fatalf("void error=%v", err)
	}
	if checks != 2 {
		t.Fatalf("void authorization checks=%d, want 2", checks)
	}
	f.assertSnapshot(t, sent, doc.ID)
	checks = 0
	actor.Authorize = func(context.Context, pgx.Tx, *generated.User) error { checks++; return nil }
	if err := f.engine.Void(f.ctx, actor, doc.ID, "Synthetic authorized request"); err != nil {
		t.Fatal(err)
	}
	if checks != 2 {
		t.Fatalf("successful void checks=%d, want 2", checks)
	}
	var status string
	var tokenExpired bool
	var reminderCount, voidCount int
	if err := f.pool.QueryRow(f.ctx, `SELECT d.status,r.magic_token_expires_at <= clock_timestamp(),(SELECT count(*) FROM reminders WHERE document_id=d.id),(SELECT count(*) FROM events WHERE document_id=d.id AND kind='document.voided') FROM documents d JOIN recipients r ON r.document_id=d.id WHERE d.id=$1`, doc.ID).Scan(&status, &tokenExpired, &reminderCount, &voidCount); err != nil {
		t.Fatal(err)
	}
	if status != "voided" || !tokenExpired || reminderCount != 0 || voidCount != 1 {
		t.Fatalf("void did not atomically revoke the ceremony: %s/%t/%d/%d", status, tokenExpired, reminderCount, voidCount)
	}
}

func TestSendPDFWithResolverFreezesVariablesWithoutBlockUpdateE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	pdf := onePageSendPDF(t)
	requiresSignature := false
	created, err := docintake.CreateOwnedPDFSourceDocumentV1(f.ctx, docintake.OwnedPDFDependenciesV1{Sessions: f.engine.WorkRuntime.SessionsV1(), Audit: f.engine.Audit, Store: f.engine.Storage.(*storage.Client)}, docintake.OwnedPDFActorV1{OrgID: f.orgID, UserID: f.user.ID, Authorize: f.authorize, Via: "rest"}, "Synthetic PDF acknowledgement", pdf, &requiresSignature)
	if created != nil {
		defer created.CloseConsumerV1()
	}
	if err != nil || created == nil || created.Document == nil {
		t.Fatal("actual native acknowledgement intake", err)
	}
	docID := created.Document.ID
	created.CloseConsumerV1()
	doc := f.document(t, docID)
	f.recipient(t, doc.ID)
	f.binding(t, doc.ID)
	f.engine.Resolver = f.resolver(t, func(context.Context, resolver.Ref) (string, error) { return "4200", nil })
	result, err := f.send(t, f.ctx, f.actor(), doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "sent" {
		t.Fatalf("PDF status=%s", result.Status)
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.orgID})
	if err != nil {
		t.Fatal(err)
	}
	var variables map[string]string
	if err := json.Unmarshal(current.VariablesJson, &variables); err != nil {
		t.Fatal(err)
	}
	if variables["amount"] != "4200" || current.SourceKind != "pdf" || current.PdfStorageKey != doc.PdfStorageKey || current.PdfStorageVersionID != doc.PdfStorageVersionID {
		t.Fatal("PDF freeze did not preserve source identity and freeze the resolved values")
	}
}

func TestSendEnvelopeFinalAuthorizationRollsBackFrozenFamilyE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	root := f.envelopeDocument(t)
	children := make([]uuid.UUID, 0, 2)
	for i := 0; i < 2; i++ {
		child, _ := f.blocksDocument(t, true)
		f.attach(t, root.ID, child.ID, int32(i+1))
		children = append(children, child.ID)
	}
	ids := append([]uuid.UUID{root.ID}, children...)
	before := f.snapshot(t, ids...)
	f.engine.Resolver = f.resolver(t, func(context.Context, resolver.Ref) (string, error) { return "4200", nil })
	actor := f.actor()
	checks := 0
	actor.Authorize = func(ctx context.Context, tx pgx.Tx, _ *generated.User) error {
		checks++
		if checks == 4 {
			var sealing, frozenChildren int
			if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='sealing'), count(*) FILTER (WHERE parent_envelope_id=$1 AND variables_json->>'amount'='4200') FROM documents WHERE id=$1 OR parent_envelope_id=$1`, root.ID).Scan(&sealing, &frozenChildren); err != nil {
				return err
			}
			if sealing != 3 || frozenChildren != 2 {
				t.Errorf("final check did not reach fully frozen family: %d/%d", sealing, frozenChildren)
			}
			return auth.ErrMutationCredentialExpired
		}
		return nil
	}
	if _, err := f.send(t, f.ctx, actor, root.ID); !errors.Is(err, auth.ErrMutationCredentialExpired) {
		t.Fatalf("envelope send error=%v", err)
	}
	if checks != 4 {
		t.Fatalf("envelope authorization checks=%d, want preparation and admission entry/final checks", checks)
	}
	f.assertSnapshot(t, before, ids...)
}

func TestSendFinalAdmissionDeadlineRollsBackFrozenValuesE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	doc, _ := f.blocksDocument(t, true)
	base := time.Now().UTC()
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET expires_at=$2 WHERE id=$1`, doc.ID, base.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t, doc.ID)
	f.engine.Resolver = f.resolver(t, func(context.Context, resolver.Ref) (string, error) { return "4200", nil })
	reads := 0
	f.engine.Now = func() time.Time {
		reads++
		if reads >= 3 {
			return base.Add(2 * time.Minute)
		}
		return base
	}
	if _, err := f.send(t, f.ctx, f.actor(), doc.ID); !errors.Is(err, sendengine.ErrExpiryTooSoon) {
		t.Fatalf("send error=%v, want final deadline rejection", err)
	}
	if reads != 3 {
		t.Fatalf("admission clock checks=%d, want 3", reads)
	}
	f.assertSnapshot(t, before, doc.ID)
}

func TestLifecycleAdmissionRequiresLiveActorAndExternalCredentialE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	doc, _ := f.blocksDocument(t, false)
	before := f.snapshot(t, doc.ID)
	actors := []sendengine.Actor{
		{OrgID: f.orgID, Via: "worker"},
		{UserID: &f.user.ID, OrgID: f.orgID, Via: "rest"},
		{UserID: &f.user.ID, OrgID: f.orgID, Via: "mcp"},
		{UserID: &f.user.ID, OrgID: f.orgID, Via: "automation"},
	}
	for _, actor := range actors {
		if _, err := f.send(t, f.ctx, actor, doc.ID); !errors.Is(err, auth.ErrMutationPermissionRevoked) {
			t.Errorf("send missing identity/credential via=%s error=%v", actor.Via, err)
		}
		if err := f.engine.Void(f.ctx, actor, doc.ID, "Synthetic denied request"); !errors.Is(err, auth.ErrMutationPermissionRevoked) {
			t.Errorf("void missing identity/credential via=%s error=%v", actor.Via, err)
		}
		if _, err := f.engine.Remind(f.ctx, actor, doc.ID, false); !errors.Is(err, auth.ErrMutationPermissionRevoked) {
			t.Errorf("remind missing identity/credential via=%s error=%v", actor.Via, err)
		}
	}
	f.assertSnapshot(t, before, doc.ID)
}

func TestManualReminderFinalAuthorizationRollsBackCeremonyArtifactsE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	doc, recipient := f.blocksDocument(t, false)
	if _, err := f.send(t, f.ctx, f.actor(), doc.ID); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t, doc.ID)
	actor := f.actor()
	checks := 0
	actor.Authorize = func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
		checks++
		if user.ID != f.user.ID || user.Email != f.user.Email {
			t.Error("reminder callback did not receive live canonical membership")
		}
		if checks == 2 {
			q := f.q.WithTx(tx)
			rotated, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: f.orgID})
			if err != nil {
				return err
			}
			if bytes.Equal(rotated.MagicTokenHash, before.Recipients[0][0].MagicTokenHash) {
				t.Error("final authorization did not run after token rotation")
			}
			var reset bool
			var outbox, audits int
			if err := tx.QueryRow(ctx, `SELECT
				(SELECT last_fired_at IS NOT NULL FROM reminders WHERE document_id=$1),
				(SELECT count(*) FROM email_deliveries WHERE to_email=$2),
				(SELECT count(*) FROM events WHERE document_id=$1 AND kind='reminder.sent')`, doc.ID, recipient.Email).Scan(&reset, &outbox, &audits); err != nil {
				return err
			}
			if !reset || outbox != 2 || audits != 1 {
				t.Errorf("final check did not reach reminder mutations: reset/outbox/audits=%t/%d/%d", reset, outbox, audits)
			}
			return auth.ErrMutationCredentialExpired
		}
		return nil
	}
	if _, err := f.engine.Remind(f.ctx, actor, doc.ID, false); !errors.Is(err, auth.ErrMutationCredentialExpired) {
		t.Fatalf("manual reminder error=%v", err)
	}
	if checks != 2 {
		t.Fatalf("manual reminder authorization checks=%d, want 2", checks)
	}
	f.assertSnapshot(t, before, doc.ID)
	checks = 0
	actor.Authorize = func(context.Context, pgx.Tx, *generated.User) error { checks++; return nil }
	count, err := f.engine.Remind(f.ctx, actor, doc.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || checks != 2 {
		t.Fatalf("manual reminder count/checks=%d/%d", count, checks)
	}
	var deliveries, canonicalReplies, audits int
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM email_deliveries WHERE to_email=$1),
		(SELECT count(*) FROM email_deliveries WHERE to_email=$1 AND reply_to=$2 AND status='pending'),
		(SELECT count(*) FROM events WHERE document_id=$3 AND kind='reminder.sent' AND actor_user_id=$4 AND payload_json->>'manual'='true')`, recipient.Email, f.user.Email, doc.ID, f.user.ID).Scan(&deliveries, &canonicalReplies, &audits); err != nil {
		t.Fatal(err)
	}
	if deliveries != 2 || canonicalReplies != 2 || audits != 1 {
		t.Fatalf("successful manual reminder outbox/canonical reply/audit=%d/%d/%d", deliveries, canonicalReplies, audits)
	}
}

func TestAutomaticReminderKeepsLockedScheduleAuthorityWithoutActorE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	doc, recipient := f.blocksDocument(t, false)
	if _, err := f.send(t, f.ctx, f.actor(), doc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE reminders SET next_fire_at=clock_timestamp()-interval '1 minute' WHERE document_id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	}
	worker := sendengine.Actor{OrgID: f.orgID, Email: f.user.Email, Via: "worker", Authorize: func(context.Context, pgx.Tx, *generated.User) error { return auth.ErrMutationPermissionRevoked }}
	type result struct {
		count int
		err   error
	}
	done := make(chan result, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			count, err := f.engine.Remind(f.ctx, worker, doc.ID, true)
			done <- result{count, err}
		}()
	}
	close(start)
	counts := map[int]int{}
	for i := 0; i < 2; i++ {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		counts[r.count]++
	}
	if counts[1] != 1 || counts[0] != 1 {
		t.Fatalf("concurrent automatic reminders=%v, want one fire and one no-op", counts)
	}
	var remaining, deliveries, audits int
	var future bool
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT fires_remaining FROM reminders WHERE document_id=$1),
		(SELECT next_fire_at>clock_timestamp() FROM reminders WHERE document_id=$1),
		(SELECT count(*) FROM email_deliveries WHERE to_email=$2),
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind='reminder.sent' AND actor_user_id IS NULL AND payload_json->>'automatic'='true')`, doc.ID, recipient.Email).Scan(&remaining, &future, &deliveries, &audits); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 || !future || deliveries != 2 || audits != 1 {
		t.Fatalf("automatic schedule/outbox/audit=%d/%t/%d/%d", remaining, future, deliveries, audits)
	}
	after := f.snapshot(t, doc.ID)
	if count, err := f.engine.Remind(f.ctx, worker, doc.ID, true); err != nil || count != 0 {
		t.Fatalf("not-due automatic reminder=%d, %v", count, err)
	}
	f.assertSnapshot(t, after, doc.ID)
}

func TestManualReminderFinalDocumentDeadlineRollsBackArtifactsE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	doc, _ := f.blocksDocument(t, false)
	if _, err := f.send(t, f.ctx, f.actor(), doc.ID); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET expires_at=$2 WHERE id=$1`, doc.ID, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t, doc.ID)
	clock := base
	f.engine.Now = func() time.Time { return clock }
	actor := f.actor()
	checks := 0
	actor.Authorize = func(context.Context, pgx.Tx, *generated.User) error {
		checks++
		if checks == 2 {
			clock = base.Add(2 * time.Minute)
		}
		return nil
	}
	if _, err := f.engine.Remind(f.ctx, actor, doc.ID, false); !errors.Is(err, sendengine.ErrNotRemindable) {
		t.Fatalf("manual reminder error=%v, want final document expiry rejection", err)
	}
	if checks != 2 {
		t.Fatalf("manual reminder authorization checks=%d, want 2", checks)
	}
	f.assertSnapshot(t, before, doc.ID)
}

func TestAutomaticReminderFinalDocumentDeadlineRollsBackArtifactsE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	doc, _ := f.blocksDocument(t, false)
	if _, err := f.send(t, f.ctx, f.actor(), doc.ID); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET expires_at=$2 WHERE id=$1`, doc.ID, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE reminders SET next_fire_at=$2 WHERE document_id=$1`, doc.ID, base.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t, doc.ID)
	reads := 0
	f.engine.Now = func() time.Time {
		reads++
		// Parent deadline, schedule admission and token expiry observe a live
		// document; the final check observes time elapsed during audit work.
		if reads >= 4 {
			return base.Add(2 * time.Minute)
		}
		return base
	}
	worker := sendengine.Actor{OrgID: f.orgID, Email: f.user.Email, Via: "worker"}
	count, err := f.engine.Remind(f.ctx, worker, doc.ID, true)
	if count != 0 || !errors.Is(err, sendengine.ErrNotRemindable) {
		t.Fatalf("automatic reminder=%d, %v, want no fire and final document expiry rejection", count, err)
	}
	if reads != 4 {
		t.Fatalf("automatic reminder clock checks=%d, want 4", reads)
	}
	f.assertSnapshot(t, before, doc.ID)
}

type sendAdmissionSource struct {
	fetch func(context.Context, resolver.Ref) (string, error)
}

type sendAdmissionFixture struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	q      *generated.Queries
	engine *sendengine.Engine
	orgID  uuid.UUID
	user   *generated.User
	trace  *sendAdmissionTrace
}

func setupSendAdmissionE2E(t *testing.T) *sendAdmissionFixture {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	// Send owns source/model borrowers until the caller closes its result. Use
	// the same finite entry lifetime and process runtime as application callers.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	if err := mdb.RunMigrations(migrationDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migrationDB.Close()
	trace := &sendAdmissionTrace{}
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Send admission " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@send-admission.test", Name: "Synthetic sender", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	// These are bounded logical admission caps for this synthetic integration
	// process, not a physical provider or PostgreSQL capacity claim.
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 1}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 1}, MaxGrants: 128, MaxOrganisationGrants: 64}
	runtime, err := pdfadmission.NewWorkRuntimeV1(pool, limits, int64(pool.Config().MaxConns)+8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		observers := runtime.SessionsV1().PendingV1().ObserverSessions
		err := runtime.CloseV1(cleanup)
		pending := runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.SignerScopes != 0 || pending.SignerReaders != 0 || pending.ObserverSessions != observers {
			t.Errorf("send runtime retained non-observer work: %+v", pending)
		}
		if observers > 0 && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			t.Errorf("observer cleanup debt falsely resolved: %v", err)
		} else if observers == 0 && err != nil {
			t.Error(err)
		}
		snapshot, snapshotErr := runtime.SnapshotV1(org.ID)
		if snapshotErr != nil || snapshot.Global != (workguard.VectorV1{SQLSessions: int64(observers)}) || snapshot.GlobalGrants != int64(observers) {
			t.Errorf("send work leaked or observer debt lost: %+v, err=%v", snapshot, snapshotErr)
		}
	})
	t.Cleanup(trace.unblock)
	if worker := os.Getenv("HASH_E2E_PDF_WORKER_PATH"); worker != "" {
		if err := sanitize.ConfigurePDFWorker(ctx, worker, "production"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := sanitize.ConfigurePDFWorker(context.Background(), "", "development"); err != nil {
				t.Error(err)
			}
		})
	}
	engine := &sendengine.Engine{Pool: pool, Queries: q, WorkRuntime: runtime, Audit: audit.New(q, pool), Mailer: dispatch.QueueingMailer{Q: q}, Envelopes: envelopes.New(q), PublicURL: "https://hash.example.test", OrgName: org.Name}
	f := &sendAdmissionFixture{ctx: ctx, pool: pool, q: q, engine: engine, orgID: org.ID, user: user, trace: trace}
	engine.Storage = f.evidenceClient(t)
	return f
}

func (f *sendAdmissionFixture) send(t *testing.T, ctx context.Context, actor sendengine.Actor, document uuid.UUID) (sendengine.SendResult, error) {
	t.Helper()
	result, err := f.engine.Send(ctx, actor, document)
	// Error results can also retain source owners. Keep every result alive
	// through the test's final assertions, then close it before the runtime.
	t.Cleanup(result.CloseConsumerV1)
	return result, err
}

func (f *sendAdmissionFixture) document(t *testing.T, id uuid.UUID) *generated.Document {
	t.Helper()
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.orgID})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func (f *sendAdmissionFixture) authorize(_ context.Context, _ pgx.Tx, user *generated.User) error {
	if user == nil || user.ID != f.user.ID || user.OrgID != f.orgID || user.Role != "owner" {
		return auth.ErrMutationPermissionRevoked
	}
	return nil
}

func (f *sendAdmissionFixture) createBlocks(t *testing.T, name string, raw []byte) *generated.Document {
	t.Helper()
	created, err := blockauthoring.CreateV1(f.ctx, blockauthoring.DependenciesV1{Sessions: f.engine.WorkRuntime.SessionsV1(), Audit: f.engine.Audit}, blockauthoring.ActorV1{OrgID: f.orgID, UserID: f.user.ID, Authorize: f.authorize, Via: "rest", Tool: "create_document"}, blockauthoring.CreateInputV1{Name: name, BlocksJSON: raw, VariablesJSON: json.RawMessage(`{}`)})
	if created != nil {
		defer created.CloseConsumerV1()
	}
	if err != nil || created == nil || created.Document == nil {
		t.Fatal("actual native block creation", err)
	}
	id := created.Document.ID
	created.CloseConsumerV1()
	return f.document(t, id)
}

func (f *sendAdmissionFixture) envelopeDocument(t *testing.T) *generated.Document {
	t.Helper()
	doc := f.createBlocks(t, "Synthetic admission envelope", []byte(`{"version":1,"blocks":[]}`))
	f.topology(t, blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopePromoteV1, Root: doc.ID})
	f.recipient(t, doc.ID)
	return f.document(t, doc.ID)
}

func (f *sendAdmissionFixture) attach(t *testing.T, root, child uuid.UUID, position int32) {
	t.Helper()
	f.topology(t, blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopeAttachV1, Root: root, Children: []uuid.UUID{child}, Position: position})
}

func (f *sendAdmissionFixture) topology(t *testing.T, input blockauthoring.EnvelopeInputV1) {
	t.Helper()
	result, err := blockauthoring.EnvelopeV1(f.ctx, blockauthoring.DependenciesV1{Sessions: f.engine.WorkRuntime.SessionsV1(), Audit: f.engine.Audit}, blockauthoring.ActorV1{OrgID: f.orgID, UserID: f.user.ID, Authorize: f.authorize, Via: "rest", Tool: "fixture_envelope"}, input)
	if result != nil {
		result.CloseConsumerV1()
	}
	if err != nil {
		t.Fatal("actual native envelope topology", err)
	}
}

func (f *sendAdmissionFixture) resolver(t *testing.T, fetch func(context.Context, resolver.Ref) (string, error)) *resolver.Resolver {
	t.Helper()
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, "/api/v1/deals/"))
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/v1/deals/") || err != nil || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer synthetic-send-crm" {
			t.Error("unexpected synthetic CRM request")
			http.Error(w, "unexpected synthetic CRM request", http.StatusBadRequest)
			return
		}
		value, err := fetch(r.Context(), resolver.Ref{OrgID: f.orgID, DocID: id, Source: id.String(), Path: "amount"})
		if errors.Is(err, resolver.ErrNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"amount": value})
	}))
	t.Cleanup(peer.Close)
	source := resolver.NewCRMDealSource(peer.URL, "synthetic-send-crm", true)
	client, ok := source.Client.(*http.Client)
	if !ok {
		t.Fatal("actual first-party CRM HTTP client unavailable")
	}
	t.Cleanup(client.CloseIdleConnections)
	return resolver.New(f.q, source)
}

func (f *sendAdmissionFixture) actor() sendengine.Actor {
	return sendengine.Actor{UserID: &f.user.ID, OrgID: f.orgID, Email: "stale-transport-email@example.test", Via: "rest", LawfulBasis: "contract", Authorize: func(context.Context, pgx.Tx, *generated.User) error { return nil }}
}

func (f *sendAdmissionFixture) blocksDocument(t *testing.T, bound bool) (*generated.Document, *generated.Recipient) {
	t.Helper()
	text := "Synthetic agreement"
	if bound {
		text += " for {{amount}}"
	}
	raw, err := json.Marshal(blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
		{ID: "terms", Type: blocks.TypeParagraph, Text: text},
		{ID: "signature", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	doc := f.createBlocks(t, "Synthetic admission agreement", raw)
	rec := f.recipient(t, doc.ID)
	if bound {
		f.binding(t, doc.ID)
	}
	return doc, rec
}

func (f *sendAdmissionFixture) recipient(t *testing.T, docID uuid.UUID) *generated.Recipient {
	t.Helper()
	engine := &recipientauthoring.MutationEngine{Pool: f.pool, Audit: f.engine.Audit}
	result, err := engine.CreateOwnedV1(f.ctx, f.engine.WorkRuntime.SessionsV1(), f.q, recipientauthoring.MutationActor{OrgID: f.orgID, UserID: f.user.ID, Authorize: f.authorize, Via: "rest", Tool: "add_recipient"}, docID, recipientauthoring.Values{Role: "signer", Email: uuid.NewString() + "@recipient.test", Name: "Synthetic recipient", Locale: "en"})
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil || result == nil || result.Recipient == nil {
		t.Fatal("actual native recipient creation", err)
	}
	id := result.Recipient.ID
	result.CloseConsumerV1()
	rec, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: id, OrgID: f.orgID})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func (f *sendAdmissionFixture) binding(t *testing.T, docID uuid.UUID) {
	t.Helper()
	if _, err := f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{DocumentID: docID, VariableName: "amount", SourceKind: "crm.deal", SourceRef: docID.String(), SourcePath: "amount"}); err != nil {
		t.Fatal(err)
	}
}

type sendAdmissionSnapshot struct {
	Documents      []*generated.Document
	Bindings       [][]*generated.DocumentVariableBinding
	Recipients     [][]*generated.Recipient
	Reminders      []json.RawMessage
	ArtifactCounts [6]int
}

func (f *sendAdmissionFixture) snapshot(t *testing.T, ids ...uuid.UUID) sendAdmissionSnapshot {
	t.Helper()
	s := sendAdmissionSnapshot{}
	for _, id := range ids {
		doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.orgID})
		if err != nil {
			t.Fatal(err)
		}
		bindings, err := f.q.ListVariableBindings(f.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		recs, err := f.q.ListRecipientsByDocument(f.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		var reminder json.RawMessage
		if err := f.pool.QueryRow(f.ctx, `SELECT COALESCE((SELECT to_jsonb(r) FROM reminders r WHERE document_id=$1),'null'::jsonb)`, id).Scan(&reminder); err != nil {
			t.Fatal(err)
		}
		s.Documents = append(s.Documents, doc)
		s.Bindings = append(s.Bindings, bindings)
		s.Recipients = append(s.Recipients, recs)
		s.Reminders = append(s.Reminders, reminder)
	}
	err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM events WHERE org_id=$1),
		(SELECT count(*) FROM send_sealing_intents WHERE org_id=$1),
		(SELECT count(*) FROM document_lawful_basis_confirmations WHERE org_id=$1),
		(SELECT count(*) FROM document_versions WHERE org_id=$1),
		(SELECT count(*) FROM reminders r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1),
		(SELECT count(*) FROM email_deliveries e WHERE EXISTS (SELECT 1 FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1 AND r.email=e.to_email))`, f.orgID).Scan(&s.ArtifactCounts[0], &s.ArtifactCounts[1], &s.ArtifactCounts[2], &s.ArtifactCounts[3], &s.ArtifactCounts[4], &s.ArtifactCounts[5])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *sendAdmissionFixture) assertSnapshot(t *testing.T, want sendAdmissionSnapshot, ids ...uuid.UUID) {
	t.Helper()
	got := f.snapshot(t, ids...)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("draft/ceremony state changed outside an authorized commit: documents=%t bindings=%t recipients=%t reminders=%t artifact counts want=%v got=%v", reflect.DeepEqual(want.Documents, got.Documents), reflect.DeepEqual(want.Bindings, got.Bindings), reflect.DeepEqual(want.Recipients, got.Recipients), reflect.DeepEqual(want.Reminders, got.Reminders), want.ArtifactCounts, got.ArtifactCounts)
	}
}
