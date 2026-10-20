//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type nativeCommentStateReader164V1 interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func nativeCommentWholeState164V1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, reader nativeCommentStateReader164V1) string {
	t.Helper()
	var state string
	err := reader.QueryRow(q.f.ctx, `SELECT jsonb_build_object(
 'document',(SELECT to_jsonb(d) FROM documents d WHERE d.id=$1 AND d.org_id=$2),
 'recipients',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM recipients r WHERE r.document_id=$1),
 'fields',(SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM document_fields f WHERE f.document_id=$1),
 'signatures',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM signatures s WHERE s.document_id=$1),
 'requests',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM change_requests c WHERE c.document_id=$1),
 'comments',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM document_comments c WHERE c.document_id=$1),
 'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM events e WHERE e.org_id=$2),
 'measurements',(SELECT jsonb_agg(to_jsonb(m) ORDER BY event_id) FROM html_snapshot_event_payload_sizes_v1 m WHERE m.org_id=$2),
 'sealing',(SELECT jsonb_agg(to_jsonb(i) ORDER BY document_id) FROM send_sealing_intents i WHERE i.document_id=$1),
 'finalization',(SELECT jsonb_agg(to_jsonb(i) ORDER BY document_id) FROM document_finalization_intents i WHERE i.document_id=$1),
 'outbox',(SELECT jsonb_agg(to_jsonb(ed) ORDER BY id) FROM email_deliveries ed))::text`, doc.ID, q.f.org).Scan(&state) //nolint:rawsql -- complete scoped synthetic effect witnesses, never grants or measurement repair
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func nativeCommentDrained164V1(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	ownedRevisionConsumedV1(t, q)
	if q.runtime.SessionsV1().PendingV1() != (pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 2}) {
		t.Fatal("native comment retains a real consumer after last use")
	}
}

// Every protected relation and every old append-only row must remain exact.
// The returned rows are only the new transactional notifications, never a
// whole-history count that could hide delivery to an unintended address.
func nativeCommentAppendOnly164V1(t *testing.T, before, after string, added int) []map[string]json.RawMessage {
	t.Helper()
	var old, current map[string]json.RawMessage
	if json.Unmarshal([]byte(before), &old) != nil || json.Unmarshal([]byte(after), &current) != nil {
		t.Fatal("complete native comment state is not JSON")
	}
	for _, key := range []string{"document", "recipients", "fields", "signatures", "requests", "sealing", "finalization"} {
		if !bytes.Equal(old[key], current[key]) {
			t.Fatal("native comment changed protected state", key)
		}
	}
	var newMail []map[string]json.RawMessage
	for _, key := range []string{"comments", "events", "measurements", "outbox"} {
		var previous, next []map[string]json.RawMessage
		if json.Unmarshal(old[key], &previous) != nil || json.Unmarshal(current[key], &next) != nil {
			t.Fatal("append-only comment relation is not an array", key)
		}
		if key != "outbox" && len(next) != len(previous)+added {
			t.Fatal("native comments appended an unexpected number of history rows", key)
		}
		id := "id"
		if key == "measurements" {
			id = "event_id"
		}
		seen := make(map[string]map[string]json.RawMessage, len(next))
		for _, row := range next {
			identity := string(row[id])
			if identity == "" || seen[identity] != nil {
				t.Fatal("missing/duplicate append-only row identity", key)
			}
			seen[identity] = row
		}
		for _, row := range previous {
			identity := string(row[id])
			if !reflect.DeepEqual(row, seen[identity]) {
				t.Fatal("native comment rewrote or removed historical row", key)
			}
			delete(seen, identity)
		}
		if key == "outbox" {
			for _, row := range seen {
				newMail = append(newMail, row)
			}
		}
		if key == "events" {
			for _, row := range seen {
				var kind string
				if json.Unmarshal(row["kind"], &kind) != nil || kind != "document.comment_posted" {
					t.Fatal("native comment appended an unrelated event")
				}
			}
		}
	}
	return newMail
}
func nativePublicCommentInput164V1(t *testing.T, q *ownedPublicReadFixtureV1, ctx context.Context, rc *sign.RecipientContext, token string) (*pdfadmission.ApplicationCommentInputV1, sign.ParticipantResponseEvidence, func()) {
	t.Helper()
	notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	input, err := q.f.s.Sign.NewSignerCommentHTTPInputV1(ctx, rc)
	if err != nil {
		t.Fatal(err)
	}
	var finish func()
	var once sync.Once
	closeInput := func() {
		once.Do(func() {
			if finish != nil {
				finish()
			}
			input.CloseConsumerV1()
		})
	}
	t.Cleanup(closeInput)
	rawJSON, err := json.Marshal(createCommentInput{Body: nativeCommentBody163V1})
	if err != nil {
		t.Fatal(err)
	}
	raw, release, err := input.ReadSignerJSONV1(ctx, io.NopCloser(bytes.NewReader(rawJSON)))
	if err != nil {
		t.Fatal(err)
	}
	finish = release
	var declaration createCommentInput
	if err = decodeSignerJSONBytesV1(raw, &declaration); err != nil {
		t.Fatal(err)
	}
	if err = input.CaptureSignerBodyV1(ctx, declaration.Body); err != nil {
		t.Fatal(err)
	}
	return input, sign.ParticipantResponseEvidence{Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic original native comment credential"}, closeInput
}
func nativeStaffCommentInput164V1(t *testing.T, q *ownedPublicReadFixtureV1, ctx context.Context) (*pdfadmission.ApplicationCommentInputV1, func()) {
	t.Helper()
	input, err := q.runtime.SessionsV1().NewStaffCommentHTTPInputV1(ctx, q.f.org)
	if err != nil {
		t.Fatal(err)
	}
	var finish func()
	var once sync.Once
	closeInput := func() {
		once.Do(func() {
			if finish != nil {
				finish()
			}
			input.CloseConsumerV1()
		})
	}
	t.Cleanup(closeInput)
	raw, err := json.Marshal(pdfadmission.CommentDeclarationV1{Body: nativeCommentBody163V1})
	if err != nil {
		t.Fatal(err)
	}
	_, release, err := input.DecodeStaffJSONV1(ctx, io.NopCloser(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	finish = release
	return input, closeInput
}

type nativeCommentDirectResult164V1 struct {
	hadRow bool
	err    error
}

func nativePublicCommentJob164V1(t *testing.T, q *ownedPublicReadFixtureV1, ctx context.Context, cancel context.CancelFunc, held pgx.Tx, rc *sign.RecipientContext, input *pdfadmission.ApplicationCommentInputV1, evidence sign.ParticipantResponseEvidence) <-chan nativeCommentDirectResult164V1 {
	t.Helper()
	result := make(chan nativeCommentDirectResult164V1, 1)
	done := make(chan struct{})
	joinUntil := time.Now().Add(7 * time.Second)
	t.Cleanup(func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		_ = held.Rollback(cleanup)
		stop()
		select {
		case <-done:
		case <-time.After(max(time.Until(joinUntil), time.Nanosecond)):
			t.Error("actual original-credential comment did not join")
		}
	})
	go func() {
		defer close(done)
		row, err := q.f.s.Sign.SignerCommentOwnedV1(rc, input, evidence)
		hadRow := row != nil
		if row != nil {
			row.CloseConsumerV1()
		}
		result <- nativeCommentDirectResult164V1{hadRow: hadRow, err: err}
	}()
	return result
}

// Original admission precedes the lock. A fresh HTTP lookup after taking the
// blocker would admit the replacement timestamp/token and miss this guarantee.
func TestOwnedCommentOriginalCredentialsAfterWaitsE2E(t *testing.T) {
	for _, scenario := range []string{"rotation", "recipient-deadline-extension", "document-deadline-extension", "document-expiry-at-audit"} {
		t.Run(scenario, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			token := parties[0].Token
			deadline := time.Now().Add(1800 * time.Millisecond)
			switch scenario {
			case "recipient-deadline-extension":
				if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_expires_at=$1 WHERE id=$2 AND document_id=$3", deadline, parties[0].RecipientID, doc.ID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- original finite credential deadline
			case "document-deadline-extension", "document-expiry-at-audit":
				if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET expires_at=$1 WHERE id=$2 AND org_id=$3", deadline, doc.ID, q.f.org); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- original finite document deadline
			}
			rc := q.lookupV1(t, token)
			ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
			t.Cleanup(cancel)
			input, evidence, closeInput := nativePublicCommentInput164V1(t, q, ctx, rc, token)
			var held pgx.Tx
			var pid int32
			if scenario == "document-expiry-at-audit" {
				held, pid = nativeCommentAuditHolder163V1(t, q)
			} else {
				held, pid = ownedReadHolderV1(t, q, doc.ID, false)
			}
			// Capture the whole baseline BEFORE launching for the audit case: its
			// transaction deliberately creates provisional comment/outbox rows first.
			before := nativeCommentWholeState164V1(t, q, doc, held)
			result := nativePublicCommentJob164V1(t, q, ctx, cancel, held, rc, input, evidence)
			wait := "GetHTMLSendDocumentStateHeaderV1"
			if scenario == "document-expiry-at-audit" {
				wait = "AcquireOrgChainLock"
			}
			ownedReadWaitV1(t, q, pid, wait)
			replacement := token
			switch scenario {
			case "rotation":
				next, hash, err := auth.MintMagicToken()
				if err != nil {
					t.Fatal(err)
				}
				replacement = next
				if err = q.f.q.WithTx(held).RotateRecipientMagicToken(q.f.ctx, generated.RotateRecipientMagicTokenParams{ID: parties[0].RecipientID, DocumentID: doc.ID, MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}); err != nil {
					t.Fatal(err)
				}
			case "recipient-deadline-extension":
				if _, err := held.Exec(q.f.ctx, "UPDATE recipients SET magic_token_expires_at=$1 WHERE id=$2 AND document_id=$3", time.Now().Add(time.Hour), parties[0].RecipientID, doc.ID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- legitimate later admission, never patch original receipt
			case "document-deadline-extension":
				if _, err := held.Exec(q.f.ctx, "UPDATE documents SET expires_at=$1 WHERE id=$2 AND org_id=$3", time.Now().Add(time.Hour), doc.ID, q.f.org); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- legitimate later admission, no cache repair
			}
			if scenario != "document-expiry-at-audit" {
				before = nativeCommentWholeState164V1(t, q, doc, held)
			}
			if scenario != "rotation" {
				if delay := time.Until(deadline) + 30*time.Millisecond; delay > 0 {
					time.Sleep(delay)
				}
			}
			if err := held.Commit(q.f.ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-result:
				if got.hadRow || !errors.Is(got.err, sign.ErrMagicLinkExpired) {
					t.Fatal("native comment borrowed replacement authority", scenario, got.hadRow, got.err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("original native comment failed to return after release")
			}
			closeInput()
			if err := rc.CloseReadV1(); err != nil {
				t.Fatal(err)
			}
			nativeCommentDrained164V1(t, q)
			if after := nativeCommentWholeState164V1(t, q, doc, q.f.pool); after != before {
				t.Fatal("stale original credential changed complete contract/evidence/outbox state")
			}
			if scenario != "document-expiry-at-audit" {
				notice := nativeCommentNotice163V1(t, q, replacement)
				w := httptest.NewRecorder()
				q.f.s.Routes().ServeHTTP(w, nativeCommentRequest163V1(t, q, q.f.ctx, doc, "signer", replacement, notice, ""))
				if w.Code != http.StatusCreated {
					t.Fatal("new genuine replacement admission was refused", scenario, w.Code)
				}
				rows, err := q.f.q.ListComments(q.f.ctx, doc.ID)
				if err != nil || len(rows) != 1 || rows[0].Body != nativeCommentBody163V1 {
					t.Fatal("replacement admission lacks exact actual row", err)
				}
				var events, measured, mail int
				if err = q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*)::integer FROM events e WHERE e.document_id=$1 AND e.kind='document.comment_posted'),(SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) WHERE e.document_id=$1 AND e.kind='document.comment_posted'),(SELECT count(*)::integer FROM email_deliveries WHERE to_email=$2 AND subject=$3)", doc.ID, q.f.user.Email, "New comment on "+doc.Name).Scan(&events, &measured, &mail); err != nil || events != 1 || measured != 1 || mail != 1 {
					t.Fatal("fresh admitted positive control lost measured audit/owner notification", err)
				} //nolint:rawsql -- exact positive control effects
				nativeCommentDrained164V1(t, q)
			}
		})
	}
}

func nativeCommentSessionGuard164V1(t *testing.T, q *ownedPublicReadFixtureV1, actor *generated.User) func(context.Context, *generated.User) error {
	t.Helper()
	cookie := dsrSessionCookieE2E(t, q.f.s, actor.ID, actor.SessionGeneration, time.Hour)
	raw, err := q.f.s.Cookies.Verify(cookie)
	var session auth.SessionPayload
	if err != nil || json.Unmarshal(raw, &session) != nil || session.UserID != actor.ID || session.Generation != actor.SessionGeneration {
		t.Fatal("real original actor session missing")
	}
	return func(ctx context.Context, current *generated.User) error {
		if current == nil || current.ID != session.UserID || current.OrgID != actor.OrgID || current.SessionGeneration != session.Generation {
			return errCommentSessionRevoked
		}
		if _, err := q.f.s.Cookies.Verify(cookie); err != nil {
			return errCommentSessionExpired
		}
		return ctx.Err()
	}
}
func TestOwnedStaffCommentDirectMembershipGuardsE2E(t *testing.T) {
	t.Run("nil-guard-before-dependencies", func(t *testing.T) {
		spy := &senderCommentDeliverySpy{}
		e := &sign.Engine{Mailer: spy}
		row, err := e.SenderCommentOwnedV1(nil, uuid.Nil, uuid.Nil, uuid.Nil, nil)
		if row != nil || !errors.Is(err, sign.ErrSenderCommentNotAuthorized) || spy.calls.Load() != 0 {
			t.Fatal("nil guard reached dependencies", err)
		}
	})
	for _, kind := range []string{"viewer", "foreign-owner"} {
		t.Run(kind, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			_ = nativeCommentNotice163V1(t, q, parties[0].Token)
			org, role := q.f.org, "viewer"
			if kind == "foreign-owner" {
				other, err := q.f.q.CreateOrg(q.f.ctx, generated.CreateOrgParams{Name: "Synthetic foreign native comment " + uuid.NewString(), Plan: "pro"})
				if err != nil {
					t.Fatal(err)
				}
				org, role = other.ID, "owner"
			}
			actor, err := q.f.q.CreateUser(q.f.ctx, generated.CreateUserParams{OrgID: org, Email: uuid.NewString() + "@native-comment.invalid", Name: "Synthetic actual member", Role: role})
			if err != nil {
				t.Fatal(err)
			}
			guard := nativeCommentSessionGuard164V1(t, q, actor)
			spy := &senderCommentDeliverySpy{}
			q.f.s.Sign.Mailer = spy
			before := nativeCommentWholeState164V1(t, q, doc, q.f.pool)
			ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
			defer cancel()
			input, closeInput := nativeStaffCommentInput164V1(t, q, ctx)
			row, err := q.f.s.Sign.SenderCommentOwnedV1(input, q.f.org, doc.ID, actor.ID, guard)
			hadRow := row != nil
			if row != nil {
				row.CloseConsumerV1()
			}
			closeInput()
			if hadRow || !errors.Is(err, sign.ErrSenderCommentNotAuthorized) || spy.calls.Load() != 0 {
				t.Fatal("typed native engine failed independent membership/role gate", kind, err)
			}
			nativeCommentDrained164V1(t, q)
			if nativeCommentWholeState164V1(t, q, doc, q.f.pool) != before {
				t.Fatal("rejected actual member changed complete state")
			}
		})
	}
}

func TestOwnedStaffCommentCanonicalAuthorAfterWaitE2E(t *testing.T) {
	for _, mode := range []string{"sender-name", "owner-email-fallback"} {
		t.Run(mode, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			_ = nativeCommentNotice163V1(t, q, parties[0].Token)
			actor := q.f.user
			if mode == "sender-name" {
				var err error
				actor, err = q.f.q.CreateUser(q.f.ctx, generated.CreateUserParams{OrgID: q.f.org, Email: uuid.NewString() + "@native-comment.invalid", Name: "Old synthetic name", Role: "sender"})
				if err != nil {
					t.Fatal(err)
				}
			}
			before := captureNativeCommentState163V1(t, q, doc)
			wholeBefore := nativeCommentWholeState164V1(t, q, doc, q.f.pool)
			cookie := dsrSessionCookieE2E(t, q.f.s, actor.ID, actor.SessionGeneration, time.Hour)
			held, pid := ownedReadHolderV1(t, q, doc.ID, false)
			job := startNativeCommentJob163V1(t, q, doc, "sender", "", "", cookie, held)
			ownedReadWaitV1(t, q, pid, "GetHTMLSendDocumentStateHeaderV1")
			name, email := "Current synthetic author ÅÄÖ", uuid.NewString()+"@native-comment.invalid"
			expected := name
			if mode == "owner-email-fallback" {
				name = ""
				expected = email
			}
			if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE users SET name=$1,email=$2 WHERE id=$3 AND org_id=$4", name, email, actor.ID, q.f.org); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- real current actor identity changes, not authority repair
			if err := held.Commit(q.f.ctx); err != nil {
				t.Fatal(err)
			}
			w := job.joinV1(t)
			var response commentResponse
			if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.AuthorName != expected || response.Body != nativeCommentBody163V1 || response.AuthorSide != "sender" {
				t.Fatal("comment response retained stale or spoofed author", mode, w.Code)
			}
			rows, err := q.f.q.ListComments(q.f.ctx, doc.ID)
			if err != nil || len(rows) != 1 || rows[0].AuthorName != expected || rows[0].Body != nativeCommentBody163V1 || rows[0].AuthorSide != "sender" || !rows[0].UserID.Valid || uuid.UUID(rows[0].UserID.Bytes) != actor.ID || rows[0].RecipientID.Valid {
				t.Fatal("comment did not use canonical locked actor", err)
			}
			after := captureNativeCommentState163V1(t, q, doc)
			newMail := nativeCommentAppendOnly164V1(t, wholeBefore, nativeCommentWholeState164V1(t, q, doc, q.f.pool), 1)
			fanout := map[string]int{}
			for _, row := range newMail {
				var address, subject string
				if json.Unmarshal(row["to_email"], &address) != nil || json.Unmarshal(row["subject"], &subject) != nil || subject != "New comment on "+doc.Name {
					t.Fatal("canonical author appended unrelated notification")
				}
				var text, html, status string
				var attempts int
				if json.Unmarshal(row["text_body"], &text) != nil || json.Unmarshal(row["html_body"], &html) != nil || json.Unmarshal(row["status"], &status) != nil || json.Unmarshal(row["attempts"], &attempts) != nil || status != "pending" || attempts != 0 || string(row["sent_at"]) != "null" || !strings.Contains(text, expected) || !strings.Contains(text, nativeCommentBody163V1) || !strings.Contains(html, expected) || !strings.Contains(html, nativeCommentBody163V1) {
					t.Fatal("canonical notification lost actual author/body or pending delivery state")
				}
				if string(row["last_error"]) != "null" {
					var lastError string
					if json.Unmarshal(row["last_error"], &lastError) != nil || lastError != "" {
						t.Fatal("fresh canonical notification retains a delivery failure")
					}
				}
				fanout[address]++
			}
			wantFanout := map[string]int{}
			for _, party := range before.recipients {
				wantFanout[party.Email]++
			}
			if !reflect.DeepEqual(fanout, wantFanout) {
				t.Fatal("canonical author lost exact notification targets")
			}
			if !reflect.DeepEqual(before.document, after.document) || !reflect.DeepEqual(before.recipients, after.recipients) {
				t.Fatal("canonical identity update changed contract/parties")
			}
			var events, measured, notifications int
			if err = q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*)::integer FROM events WHERE document_id=$1 AND actor_user_id=$2 AND kind='document.comment_posted' AND payload_json='{\"side\":\"sender\"}'::jsonb),(SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.payload_wire_bytes=octet_length(e.payload_json::text) WHERE e.document_id=$1 AND e.kind='document.comment_posted'),(SELECT count(*)::integer FROM email_deliveries WHERE subject=$3 AND strpos(text_body,$4)>0)", doc.ID, actor.ID, "New comment on "+doc.Name, expected).Scan(&events, &measured, &notifications); err != nil || events != 1 || measured != 1 || notifications != 2 {
				t.Fatal("canonical actor missing from audit/measurement/every notification", err, events, measured, notifications)
			} //nolint:rawsql -- actual canonical author/evidence/notification projections
			nativeCommentDrained164V1(t, q)
		})
	}
}

func TestOwnedRepeatedCommentsPreserveActiveAndPausedCeremoniesE2E(t *testing.T) {
	for _, status := range []string{"sent", "in_progress", "changes_requested"} {
		for _, side := range []string{"signer", "sender"} {
			t.Run(status+"-"+side, func(t *testing.T) {
				q := newOwnedPublicReadFixtureV1(t)
				doc, parties := q.createSentV1(t)
				if status == "in_progress" {
					rc := q.lookupV1(t, parties[1].Token)
					n, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(parties[1].Token, ""), rc)
					if err != nil {
						t.Fatal(err)
					}
					e, err := signerArticle13NoticeEvidence(rc, n)
					if err != nil {
						t.Fatal(err)
					}
					result, err := q.f.s.Sign.Sign(q.f.ctx, rc, sign.SignInput{TypedName: parties[1].Name, Font: "Caveat", Notice: e, IP: "127.0.0.1", UserAgent: "Synthetic native comment active control"})
					if closeErr := rc.CloseReadV1(); closeErr != nil {
						t.Fatal(closeErr)
					}
					if err != nil || result == nil || result.Completed {
						t.Fatal("genuine partial signing unavailable", err)
					}
					nativeCommentDrained164V1(t, q)
				}
				notice := nativeCommentNotice163V1(t, q, parties[0].Token)
				if status == "changes_requested" {
					for i := 0; i < 2; i++ {
						raw, _ := json.Marshal(signerRequestChangesInput{Message: "Synthetic requested terms", Proposed: "Human-reviewed synthetic scope"})
						r := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/sign/"+parties[0].Token+"/request-changes", bytes.NewReader(raw)).WithContext(q.f.ctx)
						r.Header.Set("Content-Type", "application/json")
						r.Header.Set("Origin", q.f.s.PublicURL)
						r.Header.Set(signerNoticeDigestHeader, notice)
						w := httptest.NewRecorder()
						q.f.s.Routes().ServeHTTP(w, r)
						if w.Code != http.StatusOK {
							t.Fatal("genuine repeated negotiation pause unavailable", w.Code)
						}
						nativeCommentDrained164V1(t, q)
					}
					requests, err := q.f.q.ListChangeRequests(q.f.ctx, doc.ID)
					if err != nil || len(requests) != 2 {
						t.Fatal("repeated real requests missing", err)
					}
				}
				before := captureNativeCommentState163V1(t, q, doc)
				wholeBefore := nativeCommentWholeState164V1(t, q, doc, q.f.pool)
				if before.document.Status != status {
					t.Fatal("genuine ceremony did not reach intended state", status, before.document.Status)
				}
				bodies := []string{"Första kommentaren: granska avtalet ÅÄÖ", "Andra kommentaren: villkoren är tydliga"}
				for _, body := range bodies {
					r := nativeCommentRequest163V1(t, q, q.f.ctx, doc, side, parties[0].Token, notice, q.cookie)
					raw, _ := json.Marshal(createCommentInput{Body: body})
					r.Body = io.NopCloser(bytes.NewReader(raw))
					r.ContentLength = int64(len(raw))
					r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
					w := httptest.NewRecorder()
					q.f.s.Routes().ServeHTTP(w, r)
					if w.Code != http.StatusCreated {
						t.Fatal("valid repeated native comment rejected", status, side, w.Code)
					}
					nativeCommentDrained164V1(t, q)
				}
				after := captureNativeCommentState163V1(t, q, doc)
				newMail := nativeCommentAppendOnly164V1(t, wholeBefore, nativeCommentWholeState164V1(t, q, doc, q.f.pool), 2)
				fanout := map[string]int{}
				for _, row := range newMail {
					var address, subject string
					if json.Unmarshal(row["to_email"], &address) != nil || json.Unmarshal(row["subject"], &subject) != nil || subject != "New comment on "+doc.Name {
						t.Fatal("repeated comments appended unrelated notifications")
					}
					fanout[address]++
				}
				wantFanout := map[string]int{q.f.user.Email: 2}
				if side == "sender" {
					wantFanout = map[string]int{}
					for _, party := range before.recipients {
						wantFanout[party.Email] += 2
					}
				}
				if !reflect.DeepEqual(fanout, wantFanout) {
					t.Fatal("repeated comments notified an unintended address or lost an intended notice")
				}
				if !reflect.DeepEqual(before.document, after.document) || !reflect.DeepEqual(before.recipients, after.recipients) {
					t.Fatal("valid comments changed ceremony or credential state")
				}
				rows, err := q.f.q.ListComments(q.f.ctx, doc.ID)
				if err != nil || len(rows) != 2 {
					t.Fatal("valid repeated comment rows missing", err)
				}
				for i, row := range rows {
					if row.Body != bodies[i] || row.AuthorSide != side {
						t.Fatal("repeated comments lost exact chronological body/side")
					}
				}
				var events, measured, notifications int
				wantMail := 2
				if side == "sender" {
					wantMail = 4
				}
				if err = q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='document.comment_posted'),(SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) WHERE e.document_id=$1 AND e.kind='document.comment_posted'),(SELECT count(*)::integer FROM email_deliveries WHERE subject=$2)", doc.ID, "New comment on "+doc.Name).Scan(&events, &measured, &notifications); err != nil || events != 2 || measured != 2 || notifications != wantMail {
					t.Fatal("valid repeated comment evidence/notification counts differ", events, measured, notifications, err)
				} //nolint:rawsql -- exact real post counts
			})
		}
	}
}

func TestOwnedStaffCommentMissingDocumentKeeps404E2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	_ = nativeCommentNotice163V1(t, q, parties[0].Token)
	before := nativeCommentWholeState164V1(t, q, doc, q.f.pool)
	w := submitSessionOperationContextE2E(q.f.ctx, q.f.s, http.MethodPost, "/api/v1/documents/"+uuid.NewString()+"/comments", "{\"body\":\"Synthetic missing contract\"}", q.cookie)
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "SQLSTATE") {
		t.Fatal("genuine missing staff document lost private404", w.Code)
	}
	nativeCommentDrained164V1(t, q)
	if nativeCommentWholeState164V1(t, q, doc, q.f.pool) != before {
		t.Fatal("missing document comment changed existing scoped state")
	}
}
