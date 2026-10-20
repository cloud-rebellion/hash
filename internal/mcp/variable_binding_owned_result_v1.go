// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/bindingauthoring"
)

type ownedVariableBindingResultV1 struct {
	value any
	owner *bindingauthoring.ResultV1
}

func (r *ownedVariableBindingResultV1) MarshalJSON() ([]byte, error) { return json.Marshal(r.value) }
func (r *ownedVariableBindingResultV1) CloseConsumerV1() {
	if r != nil && r.owner != nil {
		r.owner.CloseConsumerV1()
	}
}
