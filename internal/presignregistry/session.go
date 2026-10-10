// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"encoding/json"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/google/uuid"
)

// SessionActor is a private original interactive admission capability. A
// generic API callback or a client DTO cannot construct one. Handler adapters
// pass the captured cookie and admitted identity in the signed-session tree.
type SessionActor struct {
	orgID            uuid.UUID
	userID           uuid.UUID
	authorize        auth.TransactionAuthorization
	credentialSHA256 string
}

func NewSessionActor(cookies *auth.SignedCookie, cookieValue string, expectedOrgID, expectedUserID uuid.UUID) (SessionActor, error) {
	if cookies == nil || cookieValue == "" || expectedOrgID == uuid.Nil || expectedUserID == uuid.Nil {
		return SessionActor{}, auth.ErrMutationPermissionRevoked
	}
	raw, err := cookies.Verify(cookieValue)
	if err != nil {
		return SessionActor{}, auth.ErrMutationCredentialExpired
	}
	var payload auth.SessionPayload
	if json.Unmarshal(raw, &payload) != nil || payload.UserID != expectedUserID || payload.Generation < 0 {
		return SessionActor{}, auth.ErrMutationPermissionRevoked
	}
	return SessionActor{orgID: expectedOrgID, userID: expectedUserID, authorize: auth.SessionTransactionAuthorization(cookies, cookieValue, payload, expectedOrgID), credentialSHA256: domainSHA("hash:presign-original-session:v1", []byte(cookieValue))}, nil
}

func (a SessionActor) OrgID() uuid.UUID  { return a.orgID }
func (a SessionActor) UserID() uuid.UUID { return a.userID }
