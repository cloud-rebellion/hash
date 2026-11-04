// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"reflect"
	"testing"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/google/uuid"
)

func TestChatWebhookPayloadV1(t *testing.T) {
	id := uuid.NewString()
	for _, side := range []string{"sender", "signer"} {
		t.Run(side, func(t *testing.T) {
			input := map[string]any{"comment_id": id, "side": side, "body": "private conversation", "comment_body_sha256": "private digest", "notice_snapshot": map[string]any{"address": "private@example.invalid"}, "magic_link": "private token", "ip": "192.0.2.1"}
			got, err := chatWebhookPayloadV1(input)
			if err != nil || !reflect.DeepEqual(got, map[string]any{"comment_id": id, "side": side}) {
				t.Fatal("chat callback did not project only canonical identity and author side")
			}
			if input["body"] != "private conversation" || len(input) != 7 {
				t.Fatal("projection modified the original audit payload")
			}
		})
	}
	for _, input := range []map[string]any{nil, {"side": "sender"}, {"comment_id": uuid.Nil.String(), "side": "sender"}, {"comment_id": "private-value", "side": "sender"}, {"comment_id": id, "side": "internal"}, {"comment_id": id, "side": "ai"}, {"comment_id": id, "side": id}, {"comment_id": 1, "side": "signer"}, {"comment_id": id, "side": true}} {
		if got, err := chatWebhookPayloadV1(input); err == nil || got != nil {
			t.Fatal("malformed or nonparticipant chat identity reached outbound projection")
		}
	}
}

func TestChatWebhookKindRequiresExplicitSelection(t *testing.T) {
	if !IsPublicEventKind(audit.KindCommentPosted) {
		t.Fatal("shared document comment is not selectable")
	}
	for _, kind := range []string{"*", "comment.*", "collab.peer_joined", "clarifier.answered", "risk.analyzed", "negotiation.proposed", "internal.comment_posted"} {
		if IsPublicEventKind(kind) {
			t.Fatal("wildcard or internal activity became a public subscription")
		}
	}
}
