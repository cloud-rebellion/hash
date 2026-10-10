// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestPurposeProofSeparatesLoginAndOtherPurposes(t *testing.T) {
	cookies, err := NewSignedCookie(strings.Repeat("42", 32))
	if err != nil {
		t.Fatal(err)
	}
	const purpose = "hash.html-template-preview.v1"
	payload := []byte(`{"revision":1}`)
	token, err := cookies.MintPurpose(purpose, payload, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cookies.VerifyPurpose(purpose, token)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("proof round trip: %v", err)
	}
	if _, err := cookies.Verify(token); err == nil {
		t.Fatal("purpose proof authenticated as a login cookie")
	}
	if _, err := cookies.VerifyPurpose(purpose, cookies.Mint(payload, time.Minute)); err == nil {
		t.Fatal("login cookie authenticated as a purpose proof")
	}
	if _, err := cookies.VerifyPurpose("hash.document-preview.v1", token); err == nil {
		t.Fatal("proof authenticated for another purpose")
	}
	other, _ := NewSignedCookie(strings.Repeat("43", 32))
	if _, err := other.VerifyPurpose(purpose, token); err == nil {
		t.Fatal("proof authenticated using another key")
	}
	parts := strings.Split(token, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString(appendInt64([]byte(`{"revision":2}`), time.Now().Add(time.Minute).UnixNano()))
	if _, err := cookies.VerifyPurpose(purpose, strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered revision was accepted")
	}
}

func TestPurposeProofStrictExpiryAndBounds(t *testing.T) {
	cookies, _ := NewSignedCookie(strings.Repeat("42", 32))
	const purpose = "hash.html-template-preview.v1"
	// Produce correctly signed expiry boundaries without sleeps or clock hooks.
	key, err := cookies.purposeKey(purpose)
	if err != nil {
		t.Fatal(err)
	}
	for _, expiry := range []int64{time.Now().UnixNano(), time.Now().Add(-time.Second).UnixNano(), time.Now().Add(time.Hour).UnixNano()} {
		body := appendInt64([]byte("review"), expiry)
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(body)
		token := "p1." + base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if _, err := cookies.VerifyPurpose(purpose, token); err == nil {
			t.Fatal("invalid expiry was accepted")
		}
	}
	for _, ttl := range []time.Duration{0, -time.Second, maxPurposeTTL + time.Nanosecond} {
		if _, err := cookies.MintPurpose(purpose, []byte("review"), ttl); err == nil {
			t.Fatal("invalid lifetime was accepted")
		}
	}
	for _, p := range []string{"", strings.Repeat("a", 65), "has space", "hash.é", "hash\x00preview"} {
		if _, err := cookies.MintPurpose(p, []byte("review"), time.Minute); err == nil {
			t.Fatal("invalid purpose was accepted")
		}
	}
	for _, payload := range [][]byte{nil, bytes.Repeat([]byte("x"), maxPurposePayload+1)} {
		if _, err := cookies.MintPurpose(purpose, payload, time.Minute); err == nil {
			t.Fatal("invalid payload size was accepted")
		}
	}
	if _, err := cookies.VerifyPurpose(purpose, strings.Repeat("x", maxPurposeToken+1)); err == nil {
		t.Fatal("oversized proof was accepted")
	}
	if _, err := (*SignedCookie)(nil).MintPurpose(purpose, []byte("review"), time.Minute); err == nil {
		t.Fatal("missing signing dependency was accepted")
	}
	if _, err := (&SignedCookie{}).VerifyPurpose(purpose, "p1.invalid.invalid"); err == nil {
		t.Fatal("missing verification key was accepted")
	}
}
