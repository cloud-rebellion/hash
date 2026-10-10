// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

const (
	maxPurposePayload = 4096
	maxPurposeToken   = 8192
	maxPurposeTTL     = 10 * time.Minute
)

var errPurposeProof = errors.New("invalid or expired purpose proof")

// purposeKey derives a separate key for each bounded, server-chosen purpose.
// These proofs have their own format and cannot serve as login cookies.
func (s *SignedCookie) purposeKey(purpose string) ([]byte, error) {
	if s == nil || len(s.key) < 32 || len(purpose) == 0 || len(purpose) > 64 {
		return nil, errPurposeProof
	}
	for _, c := range []byte(purpose) {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("._:/-", rune(c))) {
			return nil, errPurposeProof
		}
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte("hash.signed-purpose.v1\x00" + purpose))
	return mac.Sum(nil), nil
}

// MintPurpose authenticates an opaque payload for one purpose for at most ten
// minutes. The caller remains responsible for validating the payload's meaning
// and rechecking its original session and live permissions when it is consumed.
func (s *SignedCookie) MintPurpose(purpose string, payload []byte, ttl time.Duration) (string, error) {
	if len(payload) == 0 || len(payload) > maxPurposePayload || ttl <= 0 || ttl > maxPurposeTTL {
		return "", errPurposeProof
	}
	key, err := s.purposeKey(purpose)
	if err != nil {
		return "", err
	}
	body := appendInt64(append([]byte(nil), payload...), time.Now().Add(ttl).UnixNano())
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	return "p1." + base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyPurpose refuses other purposes, login cookies, malformed or oversized
// tokens, and expiry at the nanosecond boundary. It returns only signed bytes;
// this method alone does not grant permission to perform a mutation.
func (s *SignedCookie) VerifyPurpose(purpose, token string) ([]byte, error) {
	if len(token) == 0 || len(token) > maxPurposeToken {
		return nil, errPurposeProof
	}
	key, err := s.purposeKey(purpose)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "p1" {
		return nil, errPurposeProof
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(body) <= 8 || len(body) > maxPurposePayload+8 {
		return nil, errPurposeProof
	}
	tag, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(tag) != sha256.Size {
		return nil, errPurposeProof
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, errPurposeProof
	}
	now, expiry := time.Now().UnixNano(), readInt64(body[len(body)-8:])
	if expiry <= now || expiry > now+int64(maxPurposeTTL) {
		return nil, errPurposeProof
	}
	return body[:len(body)-8], nil
}
