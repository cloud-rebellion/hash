//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestNativeReminderOwnerAndSenderCompleteAcknowledgementV1E2E(t *testing.T) {
	for _, role := range []string{"owner", "sender"} {
		t.Run(role, func(t *testing.T) {
			q, doc, parties := participantCapacityAcknowledgement253(t)
			f := q.f
			f.doc = doc
			defer q.assertObserversOnlyV1(t)
			if role == "sender" {
				owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
				response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"sender"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
				if response.Code != http.StatusOK {
					t.Fatal("actual acknowledgement sender configuration", response.Code)
				}
				var err error
				f.user, err = f.q.GetUser(f.ctx, f.user.ID)
				if err != nil || f.user.Role != role {
					t.Fatal("actual sender membership readback", err)
				}
			}
			q.f = f
			first, err := participantCapacityRespond253(t, q, parties[0], "acknowledgement")
			if err != nil || first == nil || first.Completed {
				t.Fatal("first actual acknowledgement", err)
			}
			accepted, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: parties[0].RecipientID, OrgID: f.org})
			if err != nil || accepted.Status != "accepted" {
				t.Fatal("first accepted recipient unavailable", err)
			}
			acceptedBytes, err := json.Marshal(accepted)
			if err != nil {
				t.Fatal(err)
			}
			oldMail := completedCompanionOutboxIDsV1(t, q)
			response := f.submit("remind", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
			var body struct {
				Reminded int `json:"reminded"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Reminded != 1 {
				t.Fatal("actual owner/sender acknowledgement reminder", response.Code)
			}
			afterAccepted, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: parties[0].RecipientID, OrgID: f.org})
			afterAcceptedBytes, marshalErr := json.Marshal(afterAccepted)
			if err != nil || marshalErr != nil || string(afterAcceptedBytes) != string(acceptedBytes) {
				t.Fatal("reminder changed the already accepted participant", err)
			}
			ids := make([]uuid.UUID, 0, len(oldMail))
			for id := range oldMail {
				ids = append(ids, id)
			}
			var subject, html, text, reply string
			if err := f.pool.QueryRow(f.ctx, "SELECT subject,html_body,text_body,reply_to FROM email_deliveries WHERE NOT(id=ANY($1::uuid[])) AND to_email=(SELECT email FROM recipients WHERE id=$2)", ids, parties[1].RecipientID).Scan(&subject, &html, &text, &reply); err != nil || reply != f.user.Email {
				t.Fatal("exact acknowledgement reminder outbox missing", err)
			}
			token := nativeReminderToken255(t, f.s.PublicURL, text)
			recipient, err := f.q.GetRecipientByTokenHash(f.ctx, auth.HashMagicToken(token))
			if err != nil || recipient.ID != parties[1].RecipientID || token == parties[1].Token {
				t.Fatal("actual acknowledgement token rotation association", err)
			}
			wantSubject, wantHTML, wantText, err := dispatch.Render(dispatch.KindReminder, dispatch.TemplateContext{DocumentName: doc.Name, SenderName: f.user.Email, SenderEmail: f.user.Email, RecipientName: recipient.Name, OrgName: f.s.Send.OrgName, Locale: recipient.Locale, SignURL: f.s.PublicURL + "/sign/" + token, Acknowledgement: true})
			if err != nil || subject != wantSubject || html != wantHTML || text != wantText {
				t.Fatal("acknowledgement reminder lost its actual mode, locale or canonical sender", err)
			}
			party := parties[1]
			party.Token = token
			last, err := participantCapacityRespond253(t, q, party, "acknowledgement")
			if err != nil || last == nil || !last.Completed {
				t.Fatal("reminded acknowledgement did not complete its genuine mandatory report", err)
			}
			var reports, reminders, measurements, wrongActors int
			if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*)::integer FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2),
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='reminder.sent'),
 (SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id WHERE e.document_id=$1 AND e.kind='reminder.sent'),
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='reminder.sent' AND actor_user_id IS DISTINCT FROM $3)`, doc.ID, f.org, f.user.ID).Scan(&reports, &reminders, &measurements, &wrongActors); err != nil || reports != 1 || reminders != 1 || measurements != 1 || wrongActors != 0 {
				t.Fatal("actual reminder/report/native measurement association", err, reports, reminders, measurements, wrongActors)
			} //nolint:rawsql -- observe actual native producer and completion outcomes
		})
	}
}

func nativeReminderToken255(t *testing.T, publicURL, text string) string {
	t.Helper()
	match := regexp.MustCompile(regexp.QuoteMeta(strings.TrimRight(publicURL, "/")) + `/sign/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`).FindStringSubmatch(text)
	if len(match) != 2 {
		t.Fatal("actual reminder message omitted its current recipient capability")
	}
	return match[1]
}

func nativeReminderActor255(f lifecycleAuthorizationFixture, automatic bool) send.Actor {
	if automatic {
		return send.Actor{OrgID: f.org, Via: "worker", Authorize: func(context.Context, pgx.Tx, *generated.User) error { return auth.ErrMutationPermissionRevoked }}
	}
	return send.Actor{OrgID: f.org, UserID: &f.user.ID, Email: "ignored-presentation@example.test", Via: "test", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || (user.Role != "owner" && user.Role != "sender") || user.Email != f.user.Email {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
}

func TestNativeReminderFinalDocumentDeadlineRollsBackV1E2E(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		mode := "manual"
		if automatic {
			mode = "scheduled"
		}
		t.Run(mode, func(t *testing.T) {
			q, f, _ := nativeReminderAuthorizationFixture255(t, false)
			defer q.assertObserversOnlyV1(t)
			base := time.Now().UTC()
			if _, err := f.pool.Exec(f.ctx, "UPDATE documents SET expires_at=$2 WHERE id=$1", f.doc.ID, base.Add(time.Minute)); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- original final-deadline fixture policy, never fake a legal response/history
			if automatic {
				if _, err := f.pool.Exec(f.ctx, "UPDATE reminders SET next_fire_at=$2 WHERE document_id=$1", f.doc.ID, base.Add(-time.Minute)); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- make the genuine Send-created schedule due
			}
			before := nativeReminderSnapshot254(t, q, f.doc.ID)
			var elapsed atomic.Bool
			var elapsedReads atomic.Int32
			f.s.Send.Now = func() time.Time {
				if elapsed.Load() {
					elapsedReads.Add(1)
					return base.Add(2 * time.Minute)
				}
				return base
			}
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer nativeReminderRollback255(t, blocked)
			if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			type result struct {
				count int
				err   error
			}
			ctx, cancel := context.WithTimeout(f.ctx, 30*time.Second)
			done := make(chan result, 1)
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				n, err := f.s.Send.Remind(ctx, nativeReminderActor255(f, automatic), f.doc.ID, automatic)
				done <- result{n, err}
			}()
			defer nativeReminderCleanupHTTP255(t, blocked, cancel, joined)
			// This is the real native audit lock AFTER provisional rotation,
			// schedule and outbox work. It replaces a brittle Now call count.
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			elapsed.Store(true)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			var r result
			select {
			case r = <-done:
			case <-ctx.Done():
				t.Fatal("original finite reminder call did not return", ctx.Err())
			}
			if r.count != 0 || !errors.Is(r.err, send.ErrNotRemindable) || elapsedReads.Load() == 0 {
				t.Fatal("actual final document deadline was not rechecked after audit work", r.count, r.err)
			}
			if nativeReminderSnapshot254(t, q, f.doc.ID) != before {
				t.Fatal("final deadline committed token, schedule, outbox, event or measurement")
			}
			elapsed.Store(false)
			count, err := f.s.Send.Remind(f.ctx, nativeReminderActor255(f, automatic), f.doc.ID, automatic)
			if err != nil || count != 2 {
				t.Fatal("fresh live deadline retry could not use the unchanged ceremony", count, err)
			}
		})
	}
}

func TestNativeAutomaticReminderNoopAndInvalidSchedulePreserveCeremonyV1E2E(t *testing.T) {
	for _, scenario := range []string{"not-due", "exhausted", "missing", "unordered-cadence", "invalid-shape", "remaining-exceeds-cadence"} {
		t.Run(scenario, func(t *testing.T) {
			q, f, _ := nativeReminderAuthorizationFixture255(t, false)
			defer q.assertObserversOnlyV1(t)
			wantError := false
			switch scenario {
			case "not-due": // Unmodified normal Send schedule is genuinely future.
			case "exhausted":
				if _, err := f.pool.Exec(f.ctx, "UPDATE reminders SET fires_remaining=0,next_fire_at=clock_timestamp()-interval '1 minute' WHERE document_id=$1", f.doc.ID); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := f.q.CancelReminder(f.ctx, f.doc.ID); err != nil {
					t.Fatal(err)
				}
			default:
				wantError = true
				schedule, remaining := `[{"days_after_send":7},{"days_after_send":3}]`, 2
				if scenario == "invalid-shape" {
					schedule = `{"unexpected":"not a schedule array"}`
				}
				if scenario == "remaining-exceeds-cadence" {
					schedule, remaining = `[{"days_after_send":3},{"days_after_send":7}]`, 3
				}
				if _, err := f.pool.Exec(f.ctx, "UPDATE reminders SET schedule_json=$2::jsonb,fires_remaining=$3,next_fire_at=clock_timestamp()-interval '1 minute' WHERE document_id=$1", f.doc.ID, schedule, remaining); err != nil {
					t.Fatal(err)
				}
			} //nolint:rawsql -- alter only real scheduling policy; all documents/recipients/history come from normal native Send
			before := nativeReminderSnapshot254(t, q, f.doc.ID)
			count, err := f.s.Send.Remind(f.ctx, nativeReminderActor255(f, true), f.doc.ID, true)
			if count != 0 || (err != nil) != wantError {
				t.Fatalf("scheduled policy count=%d error=%v expected-error=%v", count, err, wantError)
			}
			if nativeReminderSnapshot254(t, q, f.doc.ID) != before {
				t.Fatal("no-op/invalid schedule changed actual tokens, cadence, outbox, audit or measurement")
			}
		})
	}
}
