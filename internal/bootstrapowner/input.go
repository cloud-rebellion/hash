// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package bootstrapowner provisions one real, credential-less initial owner.
// Deployment owns maintenance, exact-image and first-writer authorization;
// this package neither activates a deployment nor proves mailbox ownership.
package bootstrapowner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
)

var (
	ErrInput       = errors.New("bootstrap-owner: explicit valid organization, company, owner and review reference are required")
	ErrRefused     = errors.New("bootstrap-owner: database or original provisioning evidence does not permit this operation")
	ErrUnavailable = errors.New("bootstrap-owner: operation unavailable; no authentication was issued")
)

type Input struct {
	OrgID      uuid.UUID `json:"org_id"`
	Company    string    `json:"company"`
	OwnerName  string    `json:"owner_name"`
	OwnerEmail string    `json:"owner_email"`
	ReviewRef  string    `json:"review_ref"`
}

// Normalize shares the native account mailbox/name policy. It returns only a
// fixed error, never an input value, if any field is invalid.
func Normalize(in Input) (Input, error) {
	if in.OrgID == uuid.Nil || !utf8.ValidString(in.OwnerEmail) {
		return Input{}, ErrInput
	}
	in.Company = strings.TrimSpace(in.Company)
	in.OwnerName = strings.TrimSpace(in.OwnerName)
	in.ReviewRef = strings.TrimSpace(in.ReviewRef)
	if !plainText(in.Company, 200, 800) || !plainText(in.OwnerName, 200, 800) || !plainText(in.ReviewRef, 256, 256) {
		return Input{}, ErrInput
	}
	identity, err := recipients.Normalize(recipients.Values{Email: in.OwnerEmail, Name: in.OwnerName, Role: "signer", Locale: "en"})
	if err != nil {
		return Input{}, ErrInput
	}
	identity.Email = strings.ToLower(identity.Email)
	identity, err = recipients.Normalize(identity)
	if err != nil {
		return Input{}, ErrInput
	}
	in.OwnerEmail, in.OwnerName = identity.Email, identity.Name
	return in, nil
}

func plainText(value string, maxRunes, maxBytes int) bool {
	return value != "" && utf8.ValidString(value) && len(value) <= maxBytes && utf8.RuneCountInString(value) <= maxRunes &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func inputDigest(in Input) string {
	raw, _ := json.Marshal(in)
	digest := sha256.Sum256(append([]byte("hash.bootstrap-owner.input.v1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}

func bootstrapPayload(in Input, userID uuid.UUID) map[string]any {
	return map[string]any{
		"schema": "hash.bootstrap-owner.v1", "via": "operator-bootstrap",
		"bootstrap": true, "pending_password_setup": true,
		"member_id": userID.String(), "role": "owner",
		"org_id": in.OrgID.String(), "review_ref": in.ReviewRef,
		"input_sha256": inputDigest(in),
	}
}
