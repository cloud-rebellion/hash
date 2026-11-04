//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/webhooksecret"
	"github.com/google/uuid"
)

// Separate delivery proof: actual canonical audit, fanout, generated queue/
// claim/mark queries, encrypted endpoint manager and signed loopback HTTP.
// Native sender/signer production is covered in the handler companion root.
func TestChatWebhook766SignedDeliveryRetryE2E(t *testing.T) {
	f := setupWebhookDeliveryE2E(t)
	ep := webhookE2EEndpoint{id: uuid.New()}
	var err error
	ep.secret, err = webhooksecret.Mint()
	webhookE2ECheck(t, err, "mint chat fixture secret")
	ep.ciphertext, err = f.keys.SealNew(f.orgID, ep.id, ep.secret)
	webhookE2ECheck(t, err, "seal chat fixture endpoint")
	_, err = f.w.queries.CreateWebhookEndpoint(f.ctx, generated.CreateWebhookEndpointParams{ID: ep.id, OrgID: f.orgID, Url: f.peer.URL, SecretRef: "synthetic-chat-e2e", SecretCiphertext: ep.ciphertext, EventsSubscribed: []string{audit.KindCommentPosted}})
	webhookE2ECheck(t, err, "persist explicit chat fixture endpoint")
	unselected := f.endpoint(t, f.orgID)
	logger := audit.New(f.w.queries, f.pool)
	dispatch.RegisterWebhookFanout(logger, f.w.queries)
	comment, document, recipient := uuid.NewString(), uuid.New(), uuid.New()
	id, err := logger.Log(f.ctx, audit.Entry{OrgID: f.orgID, DocumentID: &document, RecipientID: &recipient, Kind: audit.KindCommentPosted, IP: "192.0.2.1", Payload: map[string]any{"comment_id": comment, "side": "signer", "body": webhookE2EPrivateMarker, "comment_body_sha256": webhookE2EPrivateMarker, "notice_snapshot": map[string]any{"private": webhookE2EPrivateMarker}, "link": webhookE2EPrivateMarker}})
	webhookE2ECheck(t, err, "append chat delivery fixture audit")
	eventBefore := f.eventSnapshot(t, id)
	rows, err := f.w.queries.ListDeliveriesByEndpoint(f.ctx, generated.ListDeliveriesByEndpointParams{EndpointID: ep.id, Limit: 100})
	webhookE2ECheck(t, err, "read actual chat fanout queue")
	if len(rows) != 1 || rows[0].EventID != id {
		t.Fatal("explicit chat subscription did not enqueue exact event")
	}
	other, err := f.w.queries.ListDeliveriesByEndpoint(f.ctx, generated.ListDeliveriesByEndpointParams{EndpointID: unselected.id, Limit: 100})
	webhookE2ECheck(t, err, "read existing nonchat selection")
	if len(other) != 0 {
		t.Fatal("chat widened an existing explicit subscription")
	}
	canonical := f.eventBytes(t, id)
	if bytes.Contains(canonical, []byte(webhookE2EPrivateMarker)) || bytes.Contains(canonical, []byte("192.0.2.1")) {
		t.Fatal("chat callback contains private audit content")
	}
	var wire dispatch.WebhookEvent
	if json.Unmarshal(canonical, &wire) != nil || !reflect.DeepEqual(wire.Payload, map[string]any{"comment_id": comment, "side": "signer"}) || wire.Document["id"] != document.String() || wire.Recipient["id"] != recipient.String() {
		t.Fatal("chat wire identity or safe projection differs")
	}
	for attempt, status := range []int{http.StatusServiceUnavailable, http.StatusNoContent} {
		f.setResponse(status, webhookE2EPrivateMarker)
		claim := f.claim(t, rows[0].ID)
		applied, err := processClaimedWebhookDelivery(f.ctx, claim, f.w.webhookDeliveryDependencies())
		webhookE2ECheck(t, err, "process actual signed chat claim")
		seen := f.requests()
		if !applied || len(seen) != attempt+1 {
			t.Fatal("chat attempt did not persist exactly one actual request")
		}
		request := seen[attempt]
		if !bytes.Equal(request.body, canonical) || request.kind != audit.KindCommentPosted || !dispatch.Verify(dispatch.SignaturePair{Primary: ep.secret}, request.body, request.signature) {
			t.Fatal("chat retry changed event bytes or endpoint signature")
		}
		current := f.delivery(t, ep.id, rows[0].ID)
		if current.Attempts != int32(attempt+1) || current.LastStatusCode.Int32 != int32(status) {
			t.Fatal("chat attempt count or HTTP status differs")
		}
		if attempt == 0 {
			if current.Status != "retrying" || current.LastError.String != webhookHTTPRefused {
				t.Fatal("chat failure lost native retry semantics")
			}
			f.makeDue(t, current.ID)
		} else if current.Status != "delivered" || current.LastError.String != "" {
			t.Fatal("chat success lost native acknowledgement semantics")
		}
		f.assertRedacted(t, current.ID)
	}
	if !bytes.Equal(eventBefore, f.eventSnapshot(t, id)) {
		t.Fatal("chat projection or delivery changed immutable audit evidence")
	}
}
