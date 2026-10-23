//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This is a test oracle, not an application authorization path. It verifies
// every actual current event against its persisted row; side alone is not proof.
func ownedChatCurrentAudit487V1(events []*generated.Event, rows []*generated.DocumentComment, org, document, actor, recipient uuid.UUID, wantStaff, wantPublic int) error {
	refused := errors.New("current comment evidence/actor contract differs")
	if org == uuid.Nil || document == uuid.Nil || actor == uuid.Nil || recipient == uuid.Nil || wantStaff < 0 || wantPublic < 0 || len(rows) != wantStaff+wantPublic {
		return refused
	}
	byID := make(map[uuid.UUID]*generated.DocumentComment, len(rows))
	for _, row := range rows {
		if row == nil || row.ID == uuid.Nil || row.DocumentID != document || byID[row.ID] != nil {
			return refused
		}
		byID[row.ID] = row
	}
	seen := make(map[uuid.UUID]bool, len(rows))
	staff, public := 0, 0
	for _, event := range events {
		if event == nil {
			return refused
		}
		if event.Kind != audit.KindCommentPosted {
			continue
		}
		if event.ID == uuid.Nil || event.OrgID != org || !event.DocumentID.Valid || event.DocumentID.Bytes != document {
			return refused
		}
		var payload map[string]json.RawMessage
		if json.Unmarshal(event.PayloadJson, &payload) != nil {
			return refused
		}
		var rawID string
		if json.Unmarshal(payload["comment_id"], &rawID) != nil {
			return refused
		}
		id, err := uuid.Parse(rawID)
		if err != nil || rawID != id.String() || seen[id] || byID[id] == nil {
			return refused
		}
		row := byID[id]
		matched, err := sign.CommentAuditEvidenceMatchesV1(event, row)
		if err != nil || !matched {
			return refused
		}
		switch row.AuthorSide {
		case "sender":
			// Exact current five-key staff payload; no legacy side-only or notice keys.
			if len(payload) != 5 || !event.ActorUserID.Valid || event.ActorUserID.Bytes != actor || event.RecipientID.Valid {
				return refused
			}
			for _, key := range []string{"side", "comment_evidence_schema", "comment_id", "comment_body_sha256", "comment_created_at"} {
				if _, ok := payload[key]; !ok {
					return refused
				}
			}
			staff++
		case "signer":
			if event.ActorUserID.Valid || !event.RecipientID.Valid || event.RecipientID.Bytes != recipient {
				return refused
			}
			public++
		default:
			return refused
		}
		seen[id] = true
	}
	if len(seen) != len(rows) || staff != wantStaff || public != wantPublic {
		return refused
	}
	return nil
}

func TestOwnedChatCurrentAuditContract487E2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	notice := nativeCommentNotice163V1(t, q, parties[0].Token)
	for _, side := range []string{"sender", "signer"} {
		response := httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(response, nativeCommentRequest163V1(t, q, q.f.ctx, doc, side, parties[0].Token, notice, q.cookie))
		if response.Code != http.StatusCreated {
			t.Fatal("real current comment producer refused", side, response.Code)
		}
	}
	rows, err := q.f.q.ListComments(q.f.ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := q.f.q.ListEventsByDocumentChronological(q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	check := func(events []*generated.Event, rows []*generated.DocumentComment, org, actor, recipient uuid.UUID) error {
		return ownedChatCurrentAudit487V1(events, rows, org, doc.ID, actor, recipient, 1, 1)
	}
	if err = check(events, rows, q.f.org, q.f.user.ID, parties[0].RecipientID); err != nil {
		t.Fatal("current real payload must bind exact actual actors/rows", err)
	}
	var legacy, current int
	if err = q.f.pool.QueryRow(q.f.ctx, `SELECT count(*) FILTER(WHERE actor_user_id=$3 AND payload_json='{"side":"sender"}'::jsonb)::integer,count(*) FILTER(WHERE actor_user_id=$3 AND recipient_id IS NULL AND payload_json->>'side'='sender')::integer FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.comment_posted'`, doc.ID, q.f.org, q.f.user.ID).Scan(&legacy, &current); err != nil || legacy != 0 || current != 1 {
		t.Fatal("actual before/after payload predicate boundary differs", legacy, current, err)
	}
	var staffIndex, staffRow int = -1, -1
	for i, event := range events {
		if event.Kind == audit.KindCommentPosted && event.ActorUserID.Valid {
			staffIndex = i
		}
	}
	for i, row := range rows {
		if row.AuthorSide == "sender" {
			staffRow = i
		}
	}
	if staffIndex < 0 || staffRow < 0 {
		t.Fatal("real sender event/row missing")
	}
	for _, mutation := range []string{"actor", "tenant", "document", "recipient", "legacy", "extra", "digest"} {
		altered := append([]*generated.Event(nil), events...)
		copyEvent := *events[staffIndex]
		altered[staffIndex] = &copyEvent
		switch mutation {
		case "actor":
			copyEvent.ActorUserID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
		case "tenant":
			copyEvent.OrgID = uuid.New()
		case "document":
			copyEvent.DocumentID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
		case "recipient":
			copyEvent.RecipientID = pgtype.UUID{Bytes: parties[0].RecipientID, Valid: true}
		case "legacy":
			copyEvent.PayloadJson = json.RawMessage(`{"side":"sender"}`)
		case "extra", "digest":
			var payload map[string]any
			if err := json.Unmarshal(copyEvent.PayloadJson, &payload); err != nil {
				t.Fatal(err)
			}
			if mutation == "extra" {
				payload["unexpected"] = true
			} else {
				payload["comment_body_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
			}
			copyEvent.PayloadJson, err = json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
		}
		if check(altered, rows, q.f.org, q.f.user.ID, parties[0].RecipientID) == nil {
			t.Fatal("divergent actual evidence accepted", mutation)
		}
	}
	alteredRows := append([]*generated.DocumentComment(nil), rows...)
	copyRow := *rows[staffRow]
	copyRow.Body += " altered"
	alteredRows[staffRow] = &copyRow
	if check(events, alteredRows, q.f.org, q.f.user.ID, parties[0].RecipientID) == nil {
		t.Fatal("divergent persisted UTF8 body accepted")
	}
	if check(append(events, events[staffIndex]), rows, q.f.org, q.f.user.ID, parties[0].RecipientID) == nil {
		t.Fatal("duplicate comment event accepted")
	}
	if check(events, append(rows, rows[staffRow]), q.f.org, q.f.user.ID, parties[0].RecipientID) == nil {
		t.Fatal("duplicate persisted row accepted")
	}
	if check(events, rows, q.f.org, uuid.New(), parties[0].RecipientID) == nil || check(events, rows, q.f.org, q.f.user.ID, uuid.New()) == nil {
		t.Fatal("wrong expected actor/recipient accepted")
	}
	ownedRevisionConsumedV1(t, q)
}
