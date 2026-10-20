//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// These tests use the actual approved-HTML/native factory and normal Send;
// no signature, lifecycle status, response or event measurement is seeded.
func TestNativeReminderFinalAuthorizationRollsBackEveryEffectV1E2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	defer q.assertObserversOnlyV1(t)
	first, err := ordinaryPreparationSign249(t, q, parties[0].Token, parties[0].Name)
	if err != nil || first == nil || first.Completed {
		t.Fatal("first genuine response", err)
	}
	before := nativeReminderSnapshot254(t, q, doc.ID)
	checks := 0
	actor := send.Actor{OrgID: f.org, UserID: &f.user.ID, Email: "untrusted-presentation@example.test", Via: "mcp", Tool: "remind_recipient", Authorize: func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
		checks++
		if user.ID != f.user.ID || user.OrgID != f.org || user.Email != f.user.Email {
			t.Error("original live canonical actor missing")
		}
		if checks == 2 {
			var events, measurements, mails int
			if err := tx.QueryRow(ctx, `SELECT
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='reminder.sent'),
 (SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id WHERE e.document_id=$1 AND e.kind='reminder.sent'),
 (SELECT count(*)::integer FROM email_deliveries WHERE to_email=(SELECT email FROM recipients WHERE id=$2) AND reply_to=$3)`, doc.ID, parties[1].RecipientID, f.user.Email).Scan(&events, &measurements, &mails); err != nil {
				return err
			} //nolint:rawsql -- observe the genuine provisional native mutation in its actual tx
			if events != 1 || measurements != 1 || mails != 2 {
				t.Errorf("final policy ran before reminder writes: events=%d measurements=%d mails=%d", events, measurements, mails)
			}
			return auth.ErrMutationCredentialExpired
		}
		return nil
	}}
	if _, err = f.s.Send.Remind(f.ctx, actor, doc.ID, false); !errors.Is(err, auth.ErrMutationCredentialExpired) {
		t.Fatalf("reauthorization refusal: %v", err)
	}
	if checks != 2 || nativeReminderSnapshot254(t, q, doc.ID) != before {
		t.Fatal("reauthorization did not atomically roll back schedule/token/outbox/event/measurement")
	}
	checks = 0
	actor.Authorize = func(context.Context, pgx.Tx, *generated.User) error { checks++; return nil }
	count, err := f.s.Send.Remind(f.ctx, actor, doc.ID, false)
	if err != nil || count != 1 || checks != 2 {
		t.Fatalf("fresh retry count=%d checks=%d err=%v", count, checks, err)
	}
}

func TestNativeAutomaticReminderConcurrentWorkersCompleteActualReportV1E2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	defer q.assertObserversOnlyV1(t)
	oldMail := completedCompanionOutboxIDsV1(t, q)
	if _, err := f.pool.Exec(f.ctx, "UPDATE reminders SET next_fire_at=clock_timestamp()-interval '1 minute' WHERE document_id=$1", doc.ID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- make the real Send-created schedule due; no legal evidence/status is fabricated
	actor := send.Actor{OrgID: f.org, Email: "stale-worker-presentation@example.test", Via: "worker", Authorize: func(context.Context, pgx.Tx, *generated.User) error { return auth.ErrMutationPermissionRevoked }}
	type result struct {
		count int
		err   error
	}
	done := make(chan result, 2)
	start := make(chan struct{})
	workerCtx, cancelWorkers := context.WithTimeout(f.ctx, 30*time.Second)
	var workers sync.WaitGroup
	workers.Add(2)
	// Registered after the observer assertion: every failure first cancels
	// and joins both original calls, before observer/fixture cleanup can run.
	defer func() {
		cancelWorkers()
		workers.Wait()
	}()
	for range 2 {
		go func() {
			defer workers.Done()
			select {
			case <-start:
			case <-workerCtx.Done():
				done <- result{err: workerCtx.Err()}
				return
			}
			n, err := f.s.Send.Remind(workerCtx, actor, doc.ID, true)
			done <- result{n, err}
		}()
	}
	close(start)
	// Always receive both finite original calls before asserting either
	// result. An early worker error cannot strand the competing SQL owner.
	results := [2]result{<-done, <-done}
	workers.Wait()
	counts := map[int]int{}
	for _, r := range results {
		counts[r.count]++
	}
	if err := errors.Join(results[0].err, results[1].err); err != nil {
		t.Fatal(err)
	}
	if counts[2] != 1 || counts[0] != 1 {
		t.Fatal("actual due schedule was consumed more than once", counts)
	}
	var remaining, events, measured, wrongActors int
	if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT fires_remaining FROM reminders WHERE document_id=$1),
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='reminder.sent'),
 (SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id WHERE e.document_id=$1 AND e.kind='reminder.sent' AND m.measurement_server_version_num=current_setting('server_version_num')::integer),
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='reminder.sent' AND actor_user_id IS NOT NULL)`, doc.ID).Scan(&remaining, &events, &measured, &wrongActors); err != nil || remaining != 1 || events != 2 || measured != 2 || wrongActors != 0 {
		t.Fatalf("schedule/events/measurement/actor=%d/%d/%d/%d err=%v", remaining, events, measured, wrongActors, err)
	} //nolint:rawsql -- actual immutable producer outcomes
	ids := make([]uuid.UUID, 0, len(oldMail))
	for id := range oldMail {
		ids = append(ids, id)
	}
	for i, p := range parties {
		var text, reply string
		if err := f.pool.QueryRow(f.ctx, "SELECT text_body,reply_to FROM email_deliveries WHERE NOT(id=ANY($1::uuid[])) AND to_email=(SELECT email FROM recipients WHERE id=$2)", ids, p.RecipientID).Scan(&text, &reply); err != nil || reply != f.user.Email {
			t.Fatal("native canonical reminder outbox missing", err)
		}
		match := regexp.MustCompile(regexp.QuoteMeta(strings.TrimRight(f.s.PublicURL, "/")) + `/sign/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`).FindStringSubmatch(text)
		if len(match) != 2 || match[1] == p.Token {
			t.Fatal("new original reminder capability missing")
		}
		current, err := f.q.GetRecipientByTokenHash(f.ctx, auth.HashMagicToken(match[1]))
		if err != nil || current.ID != p.RecipientID {
			t.Fatal("outbox token does not match original rotation", err)
		}
		response, err := ordinaryPreparationSign249(t, q, match[1], p.Name)
		if err != nil || response == nil || response.Completed != (i == len(parties)-1) {
			t.Fatal("actual reminded completion", err)
		}
	}
	var reports int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*)::integer FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, f.org).Scan(&reports); err != nil || reports != 1 {
		t.Fatal("actual automatic reminder ceremony omitted mandatory report", reports, err)
	}
}

func nativeReminderSnapshot254(t *testing.T, q *ownedPublicReadFixtureV1, doc uuid.UUID) string {
	t.Helper()
	var raw string
	if err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object(
 'document',(SELECT to_jsonb(d) FROM documents d WHERE d.id=$1),
 'recipients',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM recipients r WHERE r.document_id=$1),
 'schedule',(SELECT to_jsonb(r) FROM reminders r WHERE r.document_id=$1),
 'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM events e WHERE e.document_id=$1),
 'measurements',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.event_id) FROM html_snapshot_event_payload_sizes_v1 m WHERE m.document_id=$1),
 'outbox',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM email_deliveries e WHERE e.to_email IN(SELECT r.email FROM recipients r WHERE r.document_id=$1)))::text`, doc).Scan(&raw); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- scalar exact snapshot of this actual synthetic ceremony
	var canonical any
	if json.Unmarshal([]byte(raw), &canonical) != nil {
		t.Fatal("snapshot JSON unavailable")
	}
	return raw
}
