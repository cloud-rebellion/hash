// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package crmconnection

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"

	"github.com/bright-interaction/hash/internal/secretbox"
)

type Keyring struct{ box *secretbox.Box }

// The v1 envelope is one version byte, a 12-byte GCM nonce, the canonical
// 64-byte bearer, and a 16-byte authentication tag. Reject corrupt database
// blobs before allocating plaintext for an unbounded ciphertext.
const CredentialCiphertextBytes = 1 + 12 + 64 + 16

func NewKeyring(currentHex, previousHex string) (*Keyring, error) {
	if currentHex == "" {
		return nil, ErrNotConfigured
	}
	current, err := decodeKey(currentHex)
	if err != nil {
		return nil, err
	}
	var previous []byte
	if previousHex != "" {
		previous, err = decodeKey(previousHex)
		if err != nil || subtle.ConstantTimeCompare(current, previous) == 1 {
			return nil, ErrCredential
		}
	}
	box, err := secretbox.New(current, previous)
	if err != nil {
		return nil, ErrCredential
	}
	return &Keyring{box: box}, nil
}

func decodeKey(value string) ([]byte, error) {
	if len(value) != 64 {
		return nil, ErrCredential
	}
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != 32 {
		return nil, ErrCredential
	}
	return b, nil
}

// ValidateToken is the canonical BrightCRM-v1 enrollment contract. It is not
// a claim that every legacy upstream authentication path enforces this syntax.
func ValidateToken(token string) error {
	if len(token) != 64 {
		return ErrCredential
	}
	for i := range len(token) {
		if c := token[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ErrCredential
		}
	}
	return nil
}

func credentialAAD(id Identity) ([]byte, error) {
	if err := ValidateIdentity(id); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Domain   string   `json:"domain"`
		Identity Identity `json:"identity"`
	}{Domain: "hash-crm-credential-v1", Identity: id})
}

func (k *Keyring) Seal(id Identity, token string) ([]byte, error) {
	if k == nil || k.box == nil {
		return nil, ErrNotConfigured
	}
	if err := ValidateToken(token); err != nil {
		return nil, err
	}
	aad, err := credentialAAD(id)
	if err != nil {
		return nil, err
	}
	sealed, err := k.box.Seal([]byte(token), aad)
	if err != nil {
		return nil, ErrCredential
	}
	return sealed, nil
}

func (k *Keyring) Open(id Identity, ciphertext []byte) (string, bool, error) {
	if k == nil || k.box == nil {
		return "", false, ErrNotConfigured
	}
	if len(ciphertext) != CredentialCiphertextBytes {
		return "", false, ErrCredential
	}
	aad, err := credentialAAD(id)
	if err != nil {
		return "", false, err
	}
	plain, previous, err := k.box.Open(ciphertext, aad)
	if err != nil {
		return "", false, ErrCredential
	}
	token := string(plain)
	clear(plain)
	if err := ValidateToken(token); err != nil {
		return "", false, err
	}
	return token, previous, nil
}
