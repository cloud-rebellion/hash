// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"errors"

	"github.com/google/uuid"
)

// Only the shared document comment producer emits document.comment_posted.
// The immutable audit retains its evidence; outbound chat notifications expose
// only identifiers and the closed author-side enum, never conversation text,
// body digests, notice snapshots or future audit payload additions.
func chatWebhookPayloadV1(payload map[string]any) (map[string]any, error) {
	id, ok := payload["comment_id"].(string)
	commentID, err := uuid.Parse(id)
	if !ok || err != nil || commentID == uuid.Nil || commentID.String() != id {
		return nil, errors.New("invalid shared comment webhook identity")
	}
	side, ok := payload["side"].(string)
	if !ok || (side != "sender" && side != "signer") {
		return nil, errors.New("invalid shared comment webhook side")
	}
	return map[string]any{"comment_id": id, "side": side}, nil
}
