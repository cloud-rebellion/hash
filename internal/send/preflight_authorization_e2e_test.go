//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/resolver"
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
			f.engine.Resolver = resolver.New(f.q, source)
			actor := f.actor()
			actor.Authorize = func(context.Context, pgx.Tx, *generated.User) error {
				if scenario == "credential_revoked" {
					return auth.ErrMutationPermissionRevoked
				}
				return nil
			}
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := f.engine.Send(ctx, actor, doc.ID); done <- err }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("CRM preflight did not reach the held source")
			}
			f.assertSnapshot(t, before, doc.ID)
			want := error(auth.ErrMutationPermissionRevoked)
			switch scenario {
			case "member_demoted":
				_, err := f.pool.Exec(f.ctx, `UPDATE users SET role='viewer' WHERE id=$1`, f.user.ID)
				if err != nil {
					t.Fatal(err)
				}
			case "document_edited":
				_, err := f.pool.Exec(f.ctx, `UPDATE documents SET name='Edited while CRM was loading',updated_at=clock_timestamp() WHERE id=$1`, doc.ID)
				if err != nil {
					t.Fatal(err)
				}
				want = ErrDraftChangedDuringSend
			case "binding_edited":
				_, err := f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{
					DocumentID: doc.ID, VariableName: "amount", SourceKind: "crm.deal", SourceRef: "changed-deal", SourcePath: "amount",
				})
				if err != nil {
					t.Fatal(err)
				}
				want = ErrDraftChangedDuringSend
			}
			expected := f.snapshot(t, doc.ID)
			close(release)
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
	root, _ := f.blocksDocument(t, false)
	var err error
	root, err = f.q.MarkAsEnvelope(f.ctx, generated.MarkAsEnvelopeParams{ID: root.ID, OrgID: f.orgID})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := f.blocksDocument(t, true)
	second, _ := f.blocksDocument(t, true)
	for i, child := range []*generated.Document{first, second} {
		if _, err := f.q.AttachToEnvelope(f.ctx, generated.AttachToEnvelopeParams{
			ID: child.ID, ParentEnvelopeID: pgtype.UUID{Bytes: root.ID, Valid: true}, EnvelopePosition: pgtype.Int4{Int32: int32(i + 1), Valid: true}, OrgID: f.orgID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	before := f.snapshot(t, root.ID, first.ID, second.ID)
	f.engine.Resolver = resolver.New(f.q, sendAdmissionSource{fetch: func(_ context.Context, ref resolver.Ref) (string, error) {
		if ref.DocID == second.ID {
			return "", resolver.ErrNotFound
		}
		return "4200", nil
	}})
	_, err = f.engine.Send(f.ctx, f.actor(), root.ID)
	if !errors.Is(err, ErrUnresolvedVariables) {
		t.Fatalf("send error=%v, want unresolved variables", err)
	}
	f.assertSnapshot(t, before, root.ID, first.ID, second.ID)
}

func TestSendAndVoidFinalAuthorizationRollsBackAllArtifactsE2E(t *testing.T) {
	f := setupSendAdmissionE2E(t)
	doc, recipient := f.blocksDocument(t, true)
	f.engine.Resolver = resolver.New(f.q, sendAdmissionSource{fetch: func(context.Context, resolver.Ref) (string, error) { return "4200", nil }})
	before := f.snapshot(t, doc.ID)
	actor := f.actor()
	checks := 0
	actor.Authorize = func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
		checks++
		if user.ID != f.user.ID || user.Email != f.user.Email {
			t.Error("callback did not receive the live canonical user")
		}
		if checks == 2 {
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
	if _, err := f.engine.Send(f.ctx, actor, doc.ID); !errors.Is(err, auth.ErrMutationCredentialExpired) {
		t.Fatalf("send error=%v", err)
	}
	if checks != 2 {
		t.Fatalf("send authorization checks=%d, want 2", checks)
	}
	f.assertSnapshot(t, before, doc.ID)

	checks = 0
	actor.Authorize = func(context.Context, pgx.Tx, *generated.User) error { checks++; return nil }
	result, err := f.engine.Send(f.ctx, actor, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "sent" || len(result.Links) != 1 || checks != 2 {
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
	digest := sha256.Sum256(pdf)
	doc, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{
		OrgID: f.orgID, Name: "Synthetic PDF acknowledgement", SenderID: f.user.ID,
		PdfStorageKey: pgtype.Text{String: f.orgID.String() + "/fixture/source.pdf", Valid: true}, PdfSha256: digest[:],
		PdfStorageVersionID: pgtype.Text{String: "synthetic-pinned-source-version", Valid: true}, EvidenceVersionPinsRequired: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET requires_signature=false WHERE id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	}
	f.recipient(t, doc.ID)
	f.binding(t, doc.ID)
	f.engine.Resolver = resolver.New(f.q, sendAdmissionSource{fetch: func(context.Context, resolver.Ref) (string, error) { return "4200", nil }})
	f.engine.Storage = &fakePDFEvidenceStorage{body: pdf}
	result, err := f.engine.Send(f.ctx, f.actor(), doc.ID)
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
	root, _ := f.blocksDocument(t, false)
	var err error
	root, err = f.q.MarkAsEnvelope(f.ctx, generated.MarkAsEnvelopeParams{ID: root.ID, OrgID: f.orgID})
	if err != nil {
		t.Fatal(err)
	}
	children := make([]uuid.UUID, 0, 2)
	for i := 0; i < 2; i++ {
		child, _ := f.blocksDocument(t, true)
		if _, err := f.q.AttachToEnvelope(f.ctx, generated.AttachToEnvelopeParams{
			ID: child.ID, ParentEnvelopeID: pgtype.UUID{Bytes: root.ID, Valid: true}, EnvelopePosition: pgtype.Int4{Int32: int32(i + 1), Valid: true}, OrgID: f.orgID,
		}); err != nil {
			t.Fatal(err)
		}
		children = append(children, child.ID)
	}
	ids := append([]uuid.UUID{root.ID}, children...)
	before := f.snapshot(t, ids...)
	f.engine.Resolver = resolver.New(f.q, sendAdmissionSource{fetch: func(context.Context, resolver.Ref) (string, error) { return "4200", nil }})
	actor := f.actor()
	checks := 0
	actor.Authorize = func(ctx context.Context, tx pgx.Tx, _ *generated.User) error {
		checks++
		if checks == 2 {
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
	if _, err := f.engine.Send(f.ctx, actor, root.ID); !errors.Is(err, auth.ErrMutationCredentialExpired) {
		t.Fatalf("envelope send error=%v", err)
	}
	if checks != 2 {
		t.Fatalf("envelope authorization checks=%d", checks)
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
	f.engine.Resolver = resolver.New(f.q, sendAdmissionSource{fetch: func(context.Context, resolver.Ref) (string, error) { return "4200", nil }})
	reads := 0
	f.engine.Now = func() time.Time {
		reads++
		if reads >= 3 {
			return base.Add(2 * time.Minute)
		}
		return base
	}
	if _, err := f.engine.Send(f.ctx, f.actor(), doc.ID); !errors.Is(err, ErrExpiryTooSoon) {
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
	actors := []Actor{
		{OrgID: f.orgID, Via: "worker"},
		{UserID: &f.user.ID, OrgID: f.orgID, Via: "rest"},
		{UserID: &f.user.ID, OrgID: f.orgID, Via: "mcp"},
		{UserID: &f.user.ID, OrgID: f.orgID, Via: "automation"},
	}
	for _, actor := range actors {
		if _, err := f.engine.Send(f.ctx, actor, doc.ID); !errors.Is(err, auth.ErrMutationPermissionRevoked) {
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
	if _, err := f.engine.Send(f.ctx, f.actor(), doc.ID); err != nil {
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
	if _, err := f.engine.Send(f.ctx, f.actor(), doc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE reminders SET next_fire_at=clock_timestamp()-interval '1 minute' WHERE document_id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	}
	worker := Actor{OrgID: f.orgID, Email: f.user.Email, Via: "worker", Authorize: func(context.Context, pgx.Tx, *generated.User) error { return auth.ErrMutationPermissionRevoked }}
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
	if _, err := f.engine.Send(f.ctx, f.actor(), doc.ID); err != nil {
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
	if _, err := f.engine.Remind(f.ctx, actor, doc.ID, false); !errors.Is(err, ErrNotRemindable) {
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
	if _, err := f.engine.Send(f.ctx, f.actor(), doc.ID); err != nil {
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
	worker := Actor{OrgID: f.orgID, Email: f.user.Email, Via: "worker"}
	count, err := f.engine.Remind(f.ctx, worker, doc.ID, true)
	if count != 0 || !errors.Is(err, ErrNotRemindable) {
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

func (sendAdmissionSource) Kind() resolver.SourceKind { return resolver.SourceCRMDeal }
func (s sendAdmissionSource) Fetch(ctx context.Context, ref resolver.Ref) (string, error) {
	return s.fetch(ctx, ref)
}

type sendAdmissionFixture struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	q      *generated.Queries
	engine *Engine
	orgID  uuid.UUID
	user   *generated.User
}

func setupSendAdmissionE2E(t *testing.T) *sendAdmissionFixture {
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
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Send admission " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@send-admission.test", Name: "Synthetic sender", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{Pool: pool, Queries: q, Audit: audit.New(q, pool), Mailer: dispatch.QueueingMailer{Q: q}, Envelopes: envelopes.New(q), PublicURL: "https://hash.example.test", OrgName: org.Name}
	return &sendAdmissionFixture{ctx: ctx, pool: pool, q: q, engine: engine, orgID: org.ID, user: user}
}

func (f *sendAdmissionFixture) actor() Actor {
	return Actor{UserID: &f.user.ID, OrgID: f.orgID, Email: "stale-transport-email@example.test", Via: "rest", LawfulBasis: "contract", Authorize: func(context.Context, pgx.Tx, *generated.User) error { return nil }}
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
	doc, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.orgID, Name: "Synthetic admission agreement", BlocksJson: raw, VariablesJson: json.RawMessage(`{}`), SenderID: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	rec := f.recipient(t, doc.ID)
	if bound {
		f.binding(t, doc.ID)
	}
	return doc, rec
}

func (f *sendAdmissionFixture) recipient(t *testing.T, docID uuid.UUID) *generated.Recipient {
	t.Helper()
	rec, err := f.q.CreateRecipient(f.ctx, generated.CreateRecipientParams{DocumentID: docID, Role: "signer", Email: uuid.NewString() + "@recipient.test", Name: "Synthetic recipient", OrderIndex: 0, MagicTokenHash: make([]byte, 32), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en"})
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
