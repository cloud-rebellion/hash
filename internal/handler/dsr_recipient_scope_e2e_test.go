//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

func senderDSRRecipientScopeInputE2E(f recipientAuthorizationFixture, explicitDocument bool) string {
	input := senderDSRInput{
		Kind: "erasure", SubjectEmail: f.recipient.Email, SubjectName: f.recipient.Name,
		RecipientID: f.recipient.ID.String(),
	}
	if explicitDocument {
		input.DocumentID = f.doc.ID.String()
	}
	body, _ := json.Marshal(input)
	return string(body)
}

func assertDSRRecipientScopeCountsE2E(t *testing.T, f recipientAuthorizationFixture, requests, events int) {
	t.Helper()
	var actualRequests, actualEvents int
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM data_subject_requests WHERE org_id=$1),
		(SELECT count(*) FROM events WHERE org_id=$1)`, f.org).Scan(&actualRequests, &actualEvents); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- all organization audit records, including null document_id
	if actualRequests != requests || actualEvents != events {
		t.Fatalf("DSR scope side effects: requests/events=%d/%d want%d/%d", actualRequests, actualEvents, requests, events)
	}
}

func TestDSRSenderRecipientScopeRecheckedAfterDocumentWaitE2E(t *testing.T) {
	for _, parent := range []string{"explicit", "derived"} {
		for _, change := range []string{"deleted", "relocated"} {
			t.Run(parent+"/"+change, func(t *testing.T) {
				f := setupRecipientAuthorizationE2E(t, "owner")
				var siblingID uuid.UUID
				if change == "relocated" {
					sibling, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{
						OrgID: f.org, SenderID: f.user.ID, Name: "DSR recipient relocation fixture",
						BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`),
					})
					if err != nil {
						t.Fatal(err)
					}
					siblingID = sibling.ID
				}
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				q := f.q.WithTx(blocked)
				if _, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				body := senderDSRRecipientScopeInputE2E(f, parent == "explicit")
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/dsr", body, cookie) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
				want := http.StatusNotFound
				if change == "deleted" {
					deleted, err := q.DeleteRecipient(f.ctx, generated.DeleteRecipientParams{ID: f.recipient.ID, DocumentID: f.doc.ID})
					if err != nil || deleted != f.recipient.ID {
						t.Fatalf("delete waiting recipient id=%s err=%v", deleted, err)
					}
				} else {
					rows, err := blocked.Exec(f.ctx, `UPDATE recipients SET document_id=$2 WHERE id=$1 AND document_id=$3`, f.recipient.ID, siblingID, f.doc.ID)
					if err != nil || rows.RowsAffected() != 1 {
						t.Fatalf("relocate waiting recipient rows=%d err=%v", rows.RowsAffected(), err)
					} //nolint:rawsql -- synthetic relocation to prove the original target remains binding
					want = http.StatusConflict
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				response := receiveSessionOperationE2E(t, result)
				if response.Code != want {
					t.Fatalf("stale DSR recipient=%d want%d %s", response.Code, want, response.Body.String())
				}
				assertDSRRecipientScopeCountsE2E(t, f, 0, 0)
				live, err := f.q.GetUser(f.ctx, f.user.ID)
				if err != nil || live.Role != f.user.Role || live.SessionGeneration != f.user.SessionGeneration {
					t.Fatalf("fixture changed caller authority: err=%v", err)
				}
				if _, err := f.s.Cookies.Verify(cookie); err != nil {
					t.Fatalf("fixture changed original credential: %v", err)
				}
			})
		}
	}
}

func TestDSRSenderFreshRecipientScopePersistsE2E(t *testing.T) {
	for _, parent := range []string{"explicit", "derived"} {
		t.Run(parent, func(t *testing.T) {
			f := setupRecipientAuthorizationE2E(t, "sender")
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/dsr", senderDSRRecipientScopeInputE2E(f, parent == "explicit"), cookie)
			if response.Code != http.StatusAccepted {
				t.Fatalf("fresh DSR recipient=%d %s", response.Code, response.Body.String())
			}
			var received generated.DataSubjectRequest
			if err := json.Unmarshal(response.Body.Bytes(), &received); err != nil || received.ID == uuid.Nil {
				t.Fatalf("DSR response lacks persisted identity: %v", err)
			}
			stored, err := f.q.GetDataSubjectRequest(f.ctx, generated.GetDataSubjectRequestParams{ID: received.ID, OrgID: f.org})
			if err != nil || stored.OrgID != f.org || !stored.DocumentID.Valid || uuid.UUID(stored.DocumentID.Bytes) != f.doc.ID || !stored.RecipientID.Valid || uuid.UUID(stored.RecipientID.Bytes) != f.recipient.ID || stored.SubjectEmail != f.recipient.Email || stored.SubjectName != f.recipient.Name || stored.Status != "open" {
				t.Fatalf("persisted DSR scope or identity changed: err=%v", err)
			}
			assertDSRRecipientScopeCountsE2E(t, f, 1, 1)
			var actor uuid.UUID
			var requestID string
			if err := f.pool.QueryRow(f.ctx, `SELECT actor_user_id,payload_json->>'request_id' FROM events WHERE org_id=$1 AND kind=$2`, f.org, audit.KindDataSubjectRequested).Scan(&actor, &requestID); err != nil || actor != f.user.ID || requestID != stored.ID.String() {
				t.Fatalf("DSR audit lost canonical actor/subject: actor=%s subject=%s err=%v", actor, requestID, err)
			} //nolint:rawsql -- persisted sender audit includes nullable document_id
		})
	}
}
