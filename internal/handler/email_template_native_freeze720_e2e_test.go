//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
)

// Real owner HTTP edit -> original native creation/recipient/Send -> immutable
// rendered outbox. No queue worker, SMTP, recipient token extraction, fake
// source measurements or template-at-delivery replacement participates.
func TestServiceEmailNativeSendFreezesSelectedRevisionE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	legacy, err := f.q.EnqueueEmailDelivery(f.ctx, generated.EnqueueEmailDeliveryParams{ToEmail: "old-queue@synthetic.example.test", Subject: "Original legacy pending", HtmlBody: "<p>Original</p>", TextBody: "Original", HeadersJson: json.RawMessage(`{}`)})
	if err != nil || legacy == nil {
		t.Fatal("original queue fixture unavailable", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, "DELETE FROM email_deliveries WHERE id=$1", legacy.ID); err != nil {
			t.Error(err)
		}
	}) //nolint:rawsql -- only this synthetic preexisting queue fixture
	queueSnapshot := func(id uuid.UUID) string {
		t.Helper()
		var value string
		if err := f.pool.QueryRow(f.ctx, `SELECT row_to_json(d)::text FROM email_deliveries d WHERE id=$1`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value //nolint:rawsql -- immutable synthetic outbox oracle, never source/admission authority
	}
	legacyBefore := queueSnapshot(legacy.ID)
	save := func(expected int64, intro string) {
		t.Helper()
		response := ownedBlocksTemplateCallV1(t, f, q.cookie, http.MethodPut, "/api/v1/email-templates/"+dispatch.KindInvite, map[string]any{"expected_revision": expected, "subject_template": "{{document_name}} · edition " + intro, "html_template": "<p>Edition " + intro + " for {{recipient_name}}</p>", "text_template": "Edition " + intro + " for {{recipient_name}}"})
		if response.Code != http.StatusOK {
			t.Fatalf("genuine owner edition save=%d", response.Code)
		}
		var row struct {
			Revision int64 `json:"revision"`
		}
		if json.Unmarshal(response.Body.Bytes(), &row) != nil || row.Revision != expected+1 {
			t.Fatal("owner save returned no exact successor edition")
		}
	}
	sendDocument := func(label string) (uuid.UUID, string) {
		t.Helper()
		doc := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, "rest", q.cookie, map[string]any{"name": "Native email edition " + label, "source_kind": "blocks", "blocks_json": json.RawMessage(`{"version":1,"blocks":[{"id":"terms","type":"paragraph","text":"Synthetic agreement"},{"id":"signature","type":"signature_field","attrs":{"recipient_role":"signer"}}]}`), "variables_json": map[string]string{}}), "rest")
		email := uuid.NewString() + "@native-email.example.test"
		party := ownedBlocksTemplateCallV1(t, f, q.cookie, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/recipients", map[string]any{"email": email, "name": "Synthetic signer", "role": "signer", "order_index": 0, "locale": "en"})
		if party.Code != http.StatusCreated {
			t.Fatalf("genuine native recipient=%d", party.Code)
		}
		response := ownedBlocksTemplateCallV1(t, f, q.cookie, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/send", map[string]any{"lawful_basis": "contract"})
		if response.Code != http.StatusOK {
			t.Fatalf("genuine native edition Send=%d", response.Code)
		}
		var id uuid.UUID
		var subject, body, text, replyTo, fromName, headers, status string
		var attempts int32
		if err := f.pool.QueryRow(f.ctx, `SELECT id,subject,html_body,text_body,reply_to,from_name,headers_json::text,status,attempts FROM email_deliveries WHERE to_email=$1`, email).Scan(&id, &subject, &body, &text, &replyTo, &fromName, &headers, &status, &attempts); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- actual native queue output witness
		if id == uuid.Nil || !strings.Contains(subject, "edition "+label) || !strings.Contains(body, "Edition "+label) || !strings.Contains(text, "Edition "+label) || !strings.Contains(body, "/sign/") || replyTo != f.user.Email || fromName != f.s.Send.OrgName || headers != "{}" || status != "pending" || attempts != 0 {
			t.Fatal("native producer did not retain exact edition/action/address/queue contract")
		}
		return id, queueSnapshot(id)
	}
	save(0, "one")
	first, firstBefore := sendDocument("one")
	save(1, "two")
	if queueSnapshot(first) != firstBefore {
		t.Fatal("editing current head rewrote an already frozen outbox")
	}
	if queueSnapshot(legacy.ID) != legacyBefore {
		t.Fatal("service edition edit rewrote an old queued row")
	}
	second, _ := sendDocument("two")
	if second == first || queueSnapshot(first) != firstBefore || queueSnapshot(legacy.ID) != legacyBefore {
		t.Fatal("new native enqueue changed prior deliveries")
	}
	ownedPlainAssertDrainedV1(t, q)
}
