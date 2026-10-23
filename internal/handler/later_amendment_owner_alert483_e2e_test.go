//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/hex"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"testing"
	"time"
)

func ownerAlertOtherActor483(t *testing.T, f laterAmendmentFixture483) (*generated.User, string) {
	t.Helper()
	u, e := f.q.f.q.CreateUser(f.q.f.ctx, generated.CreateUserParams{OrgID: f.q.f.org, Email: uuid.NewString() + "@other-owner.test", Name: "Other authorized owner", Role: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(auth.SessionPayload{UserID: u.ID, Generation: u.SessionGeneration})
	return u, f.q.f.s.Cookies.Mint(raw, time.Hour)
}
func ownerAlertAssert483(t *testing.T, f laterAmendmentFixture483, table string, id uuid.UUID) (uuid.UUID, uuid.UUID) {
	t.Helper()
	if table != "document_amendments_v1" && table != "document_amendment_notices_v1" {
		t.Fatal("fixture table")
	}
	var user, delivery, event uuid.UUID
	var sum []byte
	var to, subject, html, text string
	var payload []byte
	e := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT a.owner_alert_user_id,a.owner_alert_email_delivery_id,a.owner_alert_message_sha256,a.event_id,m.to_email,m.subject,m.html_body,m.text_body,e.payload_json FROM `+table+` a JOIN email_deliveries m ON m.id=a.owner_alert_email_delivery_id JOIN events e ON e.id=a.event_id AND e.org_id=a.org_id WHERE a.id=$1 AND a.org_id=$2`, id, f.q.f.org).Scan(&user, &delivery, &sum, &event, &to, &subject, &html, &text, &payload)
	if e != nil || user != f.original.SenderID || to != f.q.f.user.Email || delivery == uuid.Nil || event == uuid.Nil || len(sum) != 32 {
		t.Fatal("actual original-owner queue/event reference", e)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(payload, &obj) != nil {
		t.Fatal("actual audit payload")
	}
	var owner struct {
		UserID          uuid.UUID `json:"user_id"`
		EmailDeliveryID uuid.UUID `json:"email_delivery_id"`
		SHA256          string    `json:"message_sha256"`
		State           string    `json:"state"`
	}
	if json.Unmarshal(obj["owner_alert"], &owner) != nil || owner.UserID != user || owner.EmailDeliveryID != delivery || owner.SHA256 != hex.EncodeToString(sum) || owner.State != "queued" {
		t.Fatal("actual queued audit binding")
	}
	if !strings.Contains(text, "/documents/"+f.original.ID.String()) || !strings.Contains(html, "/documents/"+f.original.ID.String()) || strings.Contains(text+html, "#access=") || strings.Contains(text+html, "hn1.") || strings.Contains(text+html, f.original.Name) || strings.Contains(text+html, f.create.Basis.ReviewedClause) {
		t.Fatal("operational alert leaked legal document/capability or used wrong route")
	}
	var parity, eligible bool
	e = f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT $2::bytea=hash_package_send_message_sha256_v1($1),hash_amendment_owner_alert_dispatch_eligible_v1($1)`, delivery, sum).Scan(&parity, &eligible)
	if e != nil || !parity || !eligible {
		t.Fatal("real SQL message/dispatch eligibility parity", e)
	}
	return delivery, event
}
func ownerAlertNextRequest483(t *testing.T, f laterAmendmentFixture483) amendments.CreateV1 {
	t.Helper()
	candidate := laterAmendmentCandidate483(t, f.q, amendments.AgreedNoticeV1)
	in := f.create
	in.RequestID = uuid.New()
	in.ExpectedHeadID = &f.record.ID
	in.ExpectedHeadRevision = f.record.Revision
	in.AmendmentDocumentID = candidate.ID
	in.ExpectedDocumentUpdatedAt = candidate.UpdatedAt.Time
	return in
}
func TestOwnerAlert483NativeOriginalSenderRoutingReplayAndSeparateLegalAudienceE2E(t *testing.T) {
	f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
	ownerAlertAssert483(t, f, "document_amendments_v1", f.record.ID)
	other, cookie := ownerAlertOtherActor483(t, f)
	in := ownerAlertNextRequest483(t, f)
	raw, _ := json.Marshal(in)
	path := "/api/v1/documents/" + f.original.ID.String() + "/amendments"
	// Pure numeric observation only, after candidate setup. No manual cleanup
	// sweep may hide the actual prior HTTP result's last-use retirement gap.
	beforeMutation := f.q.snapshotV1(t)
	w := submitSessionOperationE2E(f.q.f.s, http.MethodPost, path, string(raw), cookie)
	if got := f.q.snapshotV1(t); got != beforeMutation {
		t.Fatal("actual Create response retained new native debt after serialization/Close", beforeMutation, got)
	}
	var out amendments.OutcomeV1
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.State != "committed" || out.Amendment == nil || out.Amendment.CreatedBy != other.ID {
		t.Fatal("different legitimate actor actual mutation", w.Code)
	}
	delivery, _ := ownerAlertAssert483(t, f, "document_amendments_v1", out.Amendment.ID)
	for replayIndex := 0; replayIndex < 2; replayIndex++ {
		w = submitSessionOperationE2E(f.q.f.s, http.MethodPost, path, string(raw), cookie)
		var replay amendments.OutcomeV1
		if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &replay) != nil || replay.State != "unchanged" || replay.Amendment == nil || replay.Amendment.ID != out.Amendment.ID {
			t.Fatal("owner alert replay", replayIndex, w.Code)
		}
		if got := f.q.snapshotV1(t); got != beforeMutation {
			t.Fatal("exact Create replay retained new native result debt without a manual sweep", replayIndex, beforeMutation, got)
		}
		again, _ := ownerAlertAssert483(t, f, "document_amendments_v1", out.Amendment.ID)
		if again != delivery {
			t.Fatal("replay changed actual owner message")
		}
	}
	f.record = *out.Amendment
	f.candidate = packageLatest223(t, f.q, in.AmendmentDocumentID)
	notice, reviewed := issueLaterNotice483(t, f)
	if got := f.q.snapshotV1(t); got != beforeMutation {
		t.Fatal("Create/replays followed by notice required an external cleanup sweep", beforeMutation, got)
	}
	ownerAlertAssert483(t, f, "document_amendment_notices_v1", notice.ID)
	if len(notice.Deliveries) != len(reviewed.RecipientEmails) || notice.Deliveries[0].RecipientEmail == f.q.f.user.Email {
		t.Fatal("operational owner silently added to legal audience")
	}
	var count int
	e := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT count(*) FROM email_deliveries WHERE headers_json=$1::jsonb`, dispatch.AmendmentOwnerAlertHeadersJSONV1).Scan(&count)
	if e != nil || count != 3 {
		t.Fatal("operational event replay duplicated/missed mail", count, e)
	}
	if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
		t.Fatal("operational alert rewrote completed original")
	}
	f.q.assertObserversOnlyV1(t)
}
func TestOwnerAlert483RevokedOriginalOwnerRefusesWholeMutationE2E(t *testing.T) {
	f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
	_, cookie := ownerAlertOtherActor483(t, f)
	in := ownerAlertNextRequest483(t, f)
	if _, e := f.q.f.q.UpdateUserRole(f.q.f.ctx, generated.UpdateUserRoleParams{ID: f.original.SenderID, OrgID: f.q.f.org, Role: "viewer"}); e != nil {
		t.Fatal(e)
	}
	var before string
	if e := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT jsonb_build_array((SELECT count(*) FROM document_amendments_v1),(SELECT count(*) FROM events),(SELECT count(*) FROM email_deliveries))::text`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(in)
	w := submitSessionOperationE2E(f.q.f.s, http.MethodPost, "/api/v1/documents/"+f.original.ID.String()+"/amendments", string(raw), cookie)
	if w.Code != 409 {
		t.Fatal("revoked owning member received mutation", w.Code)
	}
	var after string
	if e := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT jsonb_build_array((SELECT count(*) FROM document_amendments_v1),(SELECT count(*) FROM events),(SELECT count(*) FROM email_deliveries))::text`).Scan(&after); e != nil || before != after {
		t.Fatal("refused current owner persisted partial amendment/audit/mail", e)
	}
	if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
		t.Fatal("refused owner changed original")
	}
}
func TestOwnerAlert483FreshDispatchRevocationAndMessageRetentionE2E(t *testing.T) {
	f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
	delivery, _ := ownerAlertAssert483(t, f, "document_amendments_v1", f.record.ID)
	if _, e := f.q.f.pool.Exec(f.q.f.ctx, `UPDATE email_deliveries SET text_body=text_body||' changed' WHERE id=$1`, delivery); e == nil {
		t.Fatal("retained owner message mutable")
	}
	if _, e := f.q.f.pool.Exec(f.q.f.ctx, `DELETE FROM email_deliveries WHERE id=$1`, delivery); e == nil {
		t.Fatal("retained owner queue reference deletable")
	}
	if _, e := f.q.f.q.UpdateUserRole(f.q.f.ctx, generated.UpdateUserRoleParams{ID: f.original.SenderID, OrgID: f.q.f.org, Role: "viewer"}); e != nil {
		t.Fatal(e)
	}
	var eligible bool
	e := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT hash_amendment_owner_alert_dispatch_eligible_v1($1)`, delivery).Scan(&eligible)
	if e != nil || eligible {
		t.Fatal("revoked owner remains dispatch eligible", e)
	}
	e = f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT hash_amendment_owner_alert_dispatch_eligible_v1($1)`, uuid.New()).Scan(&eligible)
	if e != nil || eligible {
		t.Fatal("forged purpose-only mail acquires owner authority", e)
	}
}
func TestOwnerAlert483FreshEmailAndPrivacyBeforeDispatchE2E(t *testing.T) {
	for _, which := range []string{"email", "privacy"} {
		t.Run(which, func(t *testing.T) {
			f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
			delivery, _ := ownerAlertAssert483(t, f, "document_amendments_v1", f.record.ID)
			if which == "email" {
				if _, e := f.q.f.pool.Exec(f.q.f.ctx, `UPDATE users SET email=$2 WHERE id=$1 AND org_id=$3`, f.original.SenderID, uuid.NewString()+"@changed-owner.test", f.q.f.org); e != nil {
					t.Fatal(e)
				}
			} else {
				if _, e := f.q.f.q.CreateDataSubjectRequest(f.q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.q.f.org, DocumentID: uuidToPgUUID(&f.original.ID), SubjectEmail: "synthetic-privacy@example.test", SubjectName: "Synthetic privacy boundary", Kind: "restriction", RequestedVia: "sender", RequestedNote: "Controlled dispatch boundary", PayloadJson: []byte("{}")}); e != nil {
					t.Fatal(e)
				}
			}
			var eligible bool
			e := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT hash_amendment_owner_alert_dispatch_eligible_v1($1)`, delivery).Scan(&eligible)
			if e != nil || eligible {
				t.Fatal("stale email/pending privacy remained dispatch eligible", which, e)
			}
		})
	}
}
