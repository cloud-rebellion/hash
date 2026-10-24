// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNativeAuthStatusAndStrictOriginWithoutOIDC(t *testing.T) {
	s := &Server{PublicURL: "https://hash.example.test"}
	router := s.Routes()
	status := httptest.NewRecorder()
	router.ServeHTTP(status, httptest.NewRequest("GET", "https://hash.example.test/api/v1/auth/status", nil))
	if status.Code != 200 || !strings.Contains(status.Body.String(), "\"password_enabled\":true") ||
		!strings.Contains(status.Body.String(), "\"oidc_enabled\":false") {
		t.Fatalf("native status=%d %s", status.Code, status.Body.String())
	}
	for _, origin := range []string{"", "https://foreign.example.test", "https://other.hash.example.test"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest("POST", "https://hash.example.test/api/v1/auth/login", strings.NewReader(`{"email":"staff@example.test","password":"secret"}`))
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("foreign/missing origin admitted: %q %d", origin, response.Code)
		}
	}
}

func TestStaffPasswordPolicyAndStrictTokenShape(t *testing.T) {
	if !validStaffPassword(" exact long password ") || validStaffPassword(strings.Repeat("x", 11)) ||
		validStaffPassword(strings.Repeat("x", 1025)) || validStaffPassword(strings.Repeat("🙂", 300)) {
		t.Fatal("native password bounds changed")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if digest, err := parseStaffAuthToken(token); err != nil || len(digest) != 32 {
		t.Fatal("native token unavailable", err)
	}
	for _, bad := range []string{token + "=", token[:42], " " + token, strings.Repeat("/", 43)} {
		if _, err := parseStaffAuthToken(bad); err == nil {
			t.Fatal("noncanonical token admitted")
		}
	}
}

func TestNativeAuthAccountRateStateIsBoundedAndCasefolded(t *testing.T) {
	var limits nativeStaffAuthLimits
	now := time.Now()
	if !limits.allow("login", "Staff@Example.Test", now, 1) || limits.allow("login", "staff@example.test", now, 1) {
		t.Fatal("case aliases bypass account limit")
	}
	for i := 0; i < 4096; i++ {
		limits.allow("register", base64.RawURLEncoding.EncodeToString([]byte{byte(i >> 8), byte(i)}), now, 1)
	}
	if len(limits.buckets) > 4096 {
		t.Fatal("account limiter allocated unbounded keys")
	}
	if !limits.allow("login", "staff@example.test", now.Add(16*time.Minute), 1) {
		t.Fatal("expired account bucket never recovers")
	}
}
