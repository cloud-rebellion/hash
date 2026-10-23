// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"encoding/json"
	sentry "github.com/getsentry/sentry-go"
	"strings"
	"testing"
)

func TestNotice483RequestCapabilityNeverLeavesScrubber(t *testing.T) {
	secret := "hn1.PRIVATE_NOTICE_CAPABILITY_483"
	event := &sentry.Event{Request: &sentry.Request{URL: "https://hash.example.test/notice/public-id#access=" + secret, QueryString: "access=" + secret, Data: `{"token":"` + secret + `"}`, Cookies: "__Secure-hash_notice_public=" + secret, Headers: map[string]string{"Cookie": secret}, Env: map[string]string{"PRIVATE": secret}}}
	clean := scrubSensitive(event, nil)
	raw, err := json.Marshal(clean)
	if err != nil || strings.Contains(string(raw), secret) || strings.Contains(string(raw), "#access=") || strings.Contains(string(raw), "__Secure-hash_notice") {
		t.Fatal("notice capability escaped actual error/trace scrubber")
	}
	if clean.Request.URL != "https://hash.example.test/notice/public-id" {
		t.Fatal("safe route identity lost")
	}
}

func TestNotice483FreeTextCapabilityScrubPreservesDiagnostic(t *testing.T) {
	secret := "hn1." + strings.Repeat("A", 43)
	input := "smtp550 https://hash.example.test/notice/id#access=" + secret + " end-of-reply"
	got := scrubLogText(input)
	if strings.Contains(got, secret) || !strings.Contains(got, "smtp550") || !strings.Contains(got, "end-of-reply") || !strings.Contains(got, "[notice-capability]") {
		t.Fatal("notice free-text privacy or diagnostic boundary")
	}
	raw := scrubLogJSON([]byte(`{"error":"` + input + `","nested":{"message":"` + secret + `"}}`))
	if strings.Contains(string(raw), secret) {
		t.Fatal("notice capability survived structured log leaves")
	}
}

func TestNotice483PurposeCookieAndExceptionTextAreRedacted(t *testing.T) {
	secret := "hn1." + strings.Repeat("B", 43)
	cookie := "p1.PRIVATE_NOTICE_COOKIE483.signature"
	input := "Cookie: __Secure-hash_notice_12345678-1234-1234-1234-123456789abc=" + cookie + "; other=safe"
	if got := scrubLogText(input); strings.Contains(got, cookie) || !strings.Contains(got, "other=safe") {
		t.Fatal("purpose cookie escaped free-text egress")
	}
	event := scrubSensitive(&sentry.Event{Message: "notice failure " + secret, Exception: []sentry.Exception{{Type: "provider", Value: input + " " + secret}}}, nil)
	raw, e := json.Marshal(event)
	if e != nil || strings.Contains(string(raw), secret) || strings.Contains(string(raw), cookie) {
		t.Fatal("notice credential escaped exception/message egress")
	}
}
