// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"sync"
)

type ownedBlockToolResultV1 struct{ state *ownedBlockToolResultStateV1 }
type ownedBlockToolResultStateV1 struct {
	mu     sync.Mutex
	value  any
	input  *pdfadmission.ApplicationBlocksInputV1
	closed bool
}

func newOwnedBlockToolResultV1(value any, input *pdfadmission.ApplicationBlocksInputV1) *ownedBlockToolResultV1 {
	return &ownedBlockToolResultV1{state: &ownedBlockToolResultStateV1{value: value, input: input}}
}
func (r *ownedBlockToolResultV1) MarshalJSON() ([]byte, error) {
	if r == nil || r.state == nil {
		return []byte("null"), nil
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, pdfadmission.ErrBlocksInputV1
	}
	return json.Marshal(s.value)
}
func (r *ownedBlockToolResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	value, input := s.value, s.input
	s.value = nil
	s.input = nil
	s.mu.Unlock()
	if owner, ok := value.(interface{ CloseConsumerV1() }); ok {
		owner.CloseConsumerV1()
	}
	if input != nil {
		input.CloseConsumerV1()
	}
}
