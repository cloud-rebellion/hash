// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"net/http"
	"sync"
)

func commitOwnedEnvelopeV1(r *http.Request, d Deps, tool string, input blockauthoring.EnvelopeInputV1) (*blockauthoring.EnvelopeResultV1, error) {
	authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), input.Root, mcpScopeWriteAuthoring)
	if err != nil {
		return nil, err
	}
	user, ok := auth.FromContext(r.Context())
	if !ok {
		return nil, auth.ErrMutationPermissionRevoked
	}
	result, err := blockauthoring.EnvelopeV1(r.Context(), blockauthoring.DependenciesV1{Sessions: d.PDFCreationSessions, Billing: d.Billing, Audit: d.Audit}, blockauthoring.ActorV1{OrgID: user.OrgID, UserID: user.UserID, Authorize: authorize, Via: "mcp", Tool: tool}, input)
	if errors.Is(err, blockauthoring.ErrEnvelopeTargetV1) {
		err = errEnvelopeTargetIneligible
	}
	return result, err
}

type ownedEnvelopeToolResultV1 struct {
	state *ownedEnvelopeToolResultStateV1
}
type ownedEnvelopeToolResultStateV1 struct {
	mu     sync.Mutex
	value  any
	owner  *blockauthoring.EnvelopeResultV1
	closed bool
}

func newOwnedEnvelopeToolResultV1(value any, owner *blockauthoring.EnvelopeResultV1) *ownedEnvelopeToolResultV1 {
	return &ownedEnvelopeToolResultV1{state: &ownedEnvelopeToolResultStateV1{value: value, owner: owner}}
}
func (r *ownedEnvelopeToolResultV1) MarshalJSON() ([]byte, error) {
	if r == nil || r.state == nil {
		return []byte("null"), nil
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, pdfadmission.ErrEnvelopeTopologyV1
	}
	return json.Marshal(s.value)
}
func (r *ownedEnvelopeToolResultV1) CloseConsumerV1() {
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
	owner := s.owner
	s.value = nil
	s.owner = nil
	s.mu.Unlock()
	if owner != nil {
		owner.CloseConsumerV1()
	}
}
