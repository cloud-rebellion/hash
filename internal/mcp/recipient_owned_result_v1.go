// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/recipientauthoring"
)

// Preserve original delete tool wire while retaining the genuine mutation
// owner through both actual error and success transport serialization.
type ownedRecipientDeletedToolResultV1 struct {
	owner *recipientauthoring.OwnedRecipientResultV1
}

func (r *ownedRecipientDeletedToolResultV1) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"deleted": r.owner.Recipient.ID.String()})
}
func (r *ownedRecipientDeletedToolResultV1) CloseConsumerV1() {
	if r != nil && r.owner != nil {
		r.owner.CloseConsumerV1()
	}
}
