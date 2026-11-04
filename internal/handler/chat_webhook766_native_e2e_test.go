//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/webhooksecret"
	"github.com/google/uuid"
)

// Genuine HTML creation/review/send and native sender/signer HTTP comments.
// No cached measurements, grants, notice, credentials or outbox rows are repaired.
func TestChatWebhook766NativeCommentsFanoutE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	doc, parties := q.createSentV1(t)
	notice := nativeCommentNotice163V1(t, q, parties[0].Token)
	keys, err := webhooksecret.NewKeyringHex("1717171717171717171717171717171717171717171717171717171717171717", "")
	if err != nil {
		t.Fatal("synthetic webhook keyring unavailable")
	}
	q.f.s.WebhookSecrets = keys
	dispatch.RegisterWebhookFanout(q.f.s.Audit, q.f.q)
	published := make(map[uuid.UUID]bool)
	q.f.s.Audit.Subscribe(func(ctx context.Context, id uuid.UUID, entry audit.Entry) {
		if entry.Kind == audit.KindCommentPosted {
			row, err := q.f.q.GetEventByID(ctx, id)
			published[id] = err == nil && row.Kind == entry.Kind && row.DocumentID.Valid && uuid.UUID(row.DocumentID.Bytes) == doc.ID
		}
	})
	createEndpoint := func(events []string, want int) webhookEndpointResponse {
		t.Helper()
		body, err := json.Marshal(createWebhookInput{URL: "https://93.184.216.34/chat-callback", Events: events})
		if err != nil {
			t.Fatal(err)
		}
		w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/webhooks/", string(body), q.cookie)
		if w.Code != want {
			t.Fatal("native subscription registration status differs", w.Code, want)
		}
		var endpoint webhookEndpointResponse
		if want == http.StatusCreated && (json.Unmarshal(w.Body.Bytes(), &endpoint) != nil || endpoint.ID == uuid.Nil || endpoint.Secret == "") {
			t.Fatal("native endpoint creation receipt unavailable")
		}
		return endpoint
	}
	selected := createEndpoint([]string{audit.KindCommentPosted}, http.StatusCreated)
	unselected := createEndpoint([]string{audit.KindDocumentCompleted}, http.StatusCreated)
	_ = createEndpoint([]string{"*"}, http.StatusBadRequest)
	_ = createEndpoint([]string{"internal.comment_posted"}, http.StatusBadRequest)
	_ = createEndpoint([]string{}, http.StatusBadRequest)
	for _, side := range []string{"signer", "sender"} {
		t.Run(side, func(t *testing.T) {
			before := captureNativeCommentState163V1(t, q, doc)
			w := httptest.NewRecorder()
			r := nativeCommentRequest163V1(t, q, q.f.ctx, doc, side, parties[0].Token, notice, q.cookie)
			q.f.s.Routes().ServeHTTP(w, r)
			if w.Code != http.StatusCreated {
				t.Fatal("native shared comment failed", w.Code)
			}
			var comment commentResponse
			if json.Unmarshal(w.Body.Bytes(), &comment) != nil || comment.ID == "" {
				t.Fatal("native comment receipt unavailable")
			}
			rows, err := q.f.q.ListDeliveriesByEndpoint(q.f.ctx, generated.ListDeliveriesByEndpointParams{EndpointID: selected.ID, Limit: 100})
			if err != nil || len(rows) != len(published) || len(rows) == 0 {
				t.Fatal("postcommit comment fanout did not queue one delivery per original event")
			}
			matched := 0
			for _, row := range rows {
				event, err := dispatch.LoadEvent(q.f.ctx, q.f.q, row.EventID)
				if err != nil || !published[row.EventID] || event.Document["id"] != doc.ID.String() || event.Kind != audit.KindCommentPosted {
					t.Fatal("queue lacks durable native source association")
				}
				if event.Payload["comment_id"] != comment.ID {
					continue
				}
				matched++
				if !reflect.DeepEqual(event.Payload, map[string]any{"comment_id": comment.ID, "side": side}) {
					t.Fatal("native chat callback leaked audit evidence")
				}
				if side == "signer" && event.Recipient["id"] != parties[0].RecipientID.String() || side == "sender" && event.Recipient != nil {
					t.Fatal("native chat recipient association differs")
				}
			}
			if matched != 1 {
				t.Fatal("native comment did not retain one exact callback identity")
			}
			other, err := q.f.q.ListDeliveriesByEndpoint(q.f.ctx, generated.ListDeliveriesByEndpointParams{EndpointID: unselected.ID, Limit: 100})
			if err != nil || len(other) != 0 {
				t.Fatal("existing explicit selection received optional chat")
			}
			inserted, err := q.f.q.ReconcileMissingWebhookDeliveries(q.f.ctx, 100)
			if err != nil || inserted != 0 {
				t.Fatal("reconciliation duplicated native chat fanout")
			}
			after := captureNativeCommentState163V1(t, q, doc)
			if !reflect.DeepEqual(before.document, after.document) || !reflect.DeepEqual(before.recipients, after.recipients) || before.outbox == after.outbox {
				t.Fatal("native comment changed document state or lost existing email notification")
			}
			ownedRevisionConsumedV1(t, q)
		})
	}
	// A refused native signer post must add neither a shared comment nor callback.
	before := captureNativeCommentState163V1(t, q, doc)
	publishedBefore := len(published)
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, nativeCommentRequest163V1(t, q, q.f.ctx, doc, "signer", parties[0].Token, "", ""))
	if w.Code < 400 || len(published) != publishedBefore {
		t.Fatal("comment without current notice emitted a callback")
	}
	assertNativeCommentUnchanged163V1(t, q, doc, before)
}
