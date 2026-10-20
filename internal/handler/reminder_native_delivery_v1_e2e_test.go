//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

func TestNativeReminderNilMailerKeepsOriginalNoDeliveryBehaviorV1E2E(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		mode := "manual"
		if automatic {
			mode = "scheduled"
		}
		t.Run(mode, func(t *testing.T) {
			q, f, parties := nativeReminderAuthorizationFixture255(t, false)
			defer q.assertObserversOnlyV1(t)
			if automatic {
				if _, err := f.pool.Exec(f.ctx, "UPDATE reminders SET next_fire_at=clock_timestamp()-interval '1 minute' WHERE document_id=$1", f.doc.ID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- make the genuine Send-created schedule due
			}
			oldMail := completedCompanionOutboxIDsV1(t, q)
			before := make([]*generated.Recipient, len(parties))
			for i, party := range parties {
				var err error
				before[i], err = f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: party.RecipientID, OrgID: f.org})
				if err != nil {
					t.Fatal(err)
				}
			}
			originalMailer := f.s.Send.Mailer
			f.s.Send.Mailer = nil
			defer func() { f.s.Send.Mailer = originalMailer }()
			count, err := f.s.Send.Remind(f.ctx, nativeReminderActor255(f, automatic), f.doc.ID, automatic)
			if err != nil || count != len(parties) {
				t.Fatal("nil-mailer reminder lost original rotation/audit behavior", count, err)
			}
			afterMail := completedCompanionOutboxIDsV1(t, q)
			if len(afterMail) != len(oldMail) {
				t.Fatal("nil mailer unexpectedly created queued delivery")
			}
			for id := range afterMail {
				if _, ok := oldMail[id]; !ok {
					t.Fatal("nil mailer changed outbox identity")
				}
			}
			for i, party := range parties {
				after, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: party.RecipientID, OrgID: f.org})
				if err != nil || after.Status != before[i].Status || bytes.Equal(after.MagicTokenHash, before[i].MagicTokenHash) || !after.MagicTokenExpiresAt.Valid || !after.MagicTokenExpiresAt.Time.After(time.Now()) {
					t.Fatal("nil mailer did not rotate each original current capability", err)
				}
			}
			var events, measured, wrongActors int
			if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='reminder.sent'),
 (SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id WHERE e.document_id=$1 AND e.kind='reminder.sent'),
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='reminder.sent' AND CASE WHEN $3::boolean THEN actor_user_id IS NOT NULL ELSE actor_user_id IS DISTINCT FROM $2 END)`, f.doc.ID, f.user.ID, automatic).Scan(&events, &measured, &wrongActors); err != nil || events != 2 || measured != 2 || wrongActors != 0 {
				t.Fatal("nil-mailer native event/measurement/actor association", err, events, measured, wrongActors)
			} //nolint:rawsql -- actual producer effects, independent of optional delivery
		})
	}
}

type nativeReminderHeldDelivery255 struct {
	ctx     context.Context
	message dispatch.Message
}

// A controlled real Mailer.Send consumer holds its actual borrowed message
// until the fixture releases it. It does not manufacture a native loan or
// claim that context cancellation means a downstream consumer has joined.
type nativeReminderHoldingMailer255 struct {
	entered chan nativeReminderHeldDelivery255
	exited  chan struct{}
	release chan struct{}
}

func (m *nativeReminderHoldingMailer255) Send(ctx context.Context, msg dispatch.Message) error {
	m.entered <- nativeReminderHeldDelivery255{ctx: ctx, message: msg}
	defer func() { m.exited <- struct{}{} }()
	<-m.release
	return nil
}

func TestNativeReminderDirectMailerRetainsActualMessageUntilLastUseV1E2E(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		mode := "manual"
		if automatic {
			mode = "scheduled"
		}
		t.Run(mode, func(t *testing.T) {
			q, f, parties := nativeReminderAuthorizationFixture255(t, false)
			defer q.assertObserversOnlyV1(t)
			if automatic {
				if _, err := f.pool.Exec(f.ctx, "UPDATE reminders SET next_fire_at=clock_timestamp()-interval '1 minute' WHERE document_id=$1", f.doc.ID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- make only the real existing reminder schedule due
			}
			oldMail := completedCompanionOutboxIDsV1(t, q)
			held := &nativeReminderHoldingMailer255{entered: make(chan nativeReminderHeldDelivery255, len(parties)), exited: make(chan struct{}, len(parties)), release: make(chan struct{})}
			originalMailer := f.s.Send.Mailer
			f.s.Send.Mailer = held
			caller, cancelCaller := context.WithCancel(f.ctx)
			defer cancelCaller()
			expected, joined := 0, 0
			var release sync.Once
			releaseAndJoin := func(ctx context.Context) error {
				release.Do(func() { close(held.release) })
				for joined < expected {
					select {
					case <-held.exited:
						joined++
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			}
			// On every fatal path, release and join every originally launched
			// consumer before restoring config or checking fixture ownership.
			defer func() {
				cancelCaller()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := releaseAndJoin(ctx); err != nil {
					t.Error("actual direct consumers did not join within independent cleanup budget", err)
					return // Config remains bound until actual consumers are known joined.
				}
				if err := nativeReminderDeliveryRetirement255(ctx, q); err != nil {
					t.Error("outer direct-mail consumers did not retire their actual native budget", err)
					return
				}
				f.s.Send.Mailer = originalMailer
			}()
			count, err := f.s.Send.Remind(caller, nativeReminderActor255(f, automatic), f.doc.ID, automatic)
			expected = count
			if err != nil || count != len(parties) {
				t.Fatal("direct reminder did not commit its actual deliveries", count, err)
			}
			deliveries := make([]nativeReminderHeldDelivery255, 0, count)
			for range count {
				select {
				case delivery := <-held.entered:
					deliveries = append(deliveries, delivery)
				case <-time.After(5 * time.Second):
					t.Fatal("original direct Mailer.Send did not start")
				}
			}
			cancelCaller()
			seen := map[string]bool{}
			for _, delivery := range deliveries {
				deadline, finite := delivery.ctx.Deadline()
				if !finite || !deadline.After(time.Now()) || deadline.Sub(time.Now()) > 30*time.Second || delivery.ctx.Err() != nil {
					t.Fatal("original direct-mail lifetime is not finite and live after caller cancellation")
				}
				msg := delivery.message
				token := nativeReminderToken255(t, f.s.PublicURL, msg.Text)
				recipient, err := f.q.GetRecipientByTokenHash(f.ctx, auth.HashMagicToken(token))
				if err != nil || recipient.DocumentID != f.doc.ID || recipient.Email != msg.To || msg.ReplyTo != f.user.Email || msg.FromName != f.s.Send.OrgName || seen[msg.To] {
					t.Fatal("direct output is not bound to the actual unique rotated recipient and sender", err)
				}
				seen[msg.To] = true
				wantSubject, wantHTML, wantText, err := dispatch.Render(dispatch.KindReminder, dispatch.TemplateContext{DocumentName: f.doc.Name, SenderName: f.user.Email, SenderEmail: f.user.Email, RecipientName: recipient.Name, OrgName: f.s.Send.OrgName, Locale: recipient.Locale, SignURL: f.s.PublicURL + "/sign/" + token, Acknowledgement: !f.doc.RequiresSignature})
				if err != nil || msg.Subject != wantSubject || msg.HTML != wantHTML || msg.Text != wantText {
					t.Fatal("actual retained direct output differs from its original render", err)
				}
			}
			afterMail := completedCompanionOutboxIDsV1(t, q)
			if len(afterMail) != len(oldMail) {
				t.Fatal("direct mailer also queued a duplicate delivery")
			}
			for id := range afterMail {
				if _, ok := oldMail[id]; !ok {
					t.Fatal("direct mailer changed durable outbox identity")
				}
			}
			// The actual original messages are still in two active Send calls.
			// Cancellation and SQL COMMIT must not return their body budget.
			snapshot := q.snapshotV1(t)
			if snapshot.Global.ParentBytes <= 0 || snapshot.Organisation.ParentBytes <= 0 {
				t.Fatal("message/source body budget retired before the real last use", snapshot)
			}
			joinCtx, cancelJoin := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelJoin()
			if err := releaseAndJoin(joinCtx); err != nil {
				t.Fatal("released actual direct consumers did not join", err)
			}
			nativeReminderAwaitDeliveryRetirement255(t, q)
		})
	}
}

func nativeReminderAwaitDeliveryRetirement255(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := nativeReminderDeliveryRetirement255(ctx, q); err != nil {
		t.Fatal("original direct-message consumer did not retire its actual budget", err)
	}
}

func nativeReminderDeliveryRetirement255(ctx context.Context, q *ownedPublicReadFixtureV1) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := q.runtime.ReconcileCleanupV1(ctx)
		if err != nil && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			return err
		}
		snapshot, err := q.runtime.SnapshotV1(q.f.org)
		if err != nil {
			return err
		}
		if snapshot.Global.ParentBytes == 0 && snapshot.Organisation.ParentBytes == 0 {
			return nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
