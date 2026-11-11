// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package documentpackage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestIncorporationClosedEnglishAndSwedishPairsV128(t *testing.T) {
	for _, locale := range []string{"en", "sv"} {
		copy := IncorporationCopyForLocaleV1(locale)
		frozen, err := IncorporationCopyForVersionV1(copy.Version)
		sum := sha256.Sum256([]byte(copy.Text))
		if err != nil || frozen != copy || copy.ValidateV1() != nil || copy.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("canonical UTF-8 statement/version/hash mismatch", locale, err)
		}
		for _, mutation := range []func(*IncorporationV1){
			func(c *IncorporationV1) { c.Text += " " },
			func(c *IncorporationV1) { c.SHA256 = strings.Repeat("f", 64) },
			func(c *IncorporationV1) { c.Version = "hash-package-incorporation-unsupported" },
			func(c *IncorporationV1) {
				c.Text = "Different copy"
				sum := sha256.Sum256([]byte(c.Text))
				c.SHA256 = hex.EncodeToString(sum[:])
			},
			func(c *IncorporationV1) {
				other := IncorporationCopyForLocaleV1("sv")
				if locale == "sv" {
					other = IncorporationCopyV1()
				}
				c.Text, c.SHA256 = other.Text, other.SHA256
			},
		} {
			bad := copy
			mutation(&bad)
			if bad.ValidateV1() == nil {
				t.Fatal("different or cross-language bytes retained canonical version", locale)
			}
		}
	}
	for _, unsupported := range []string{"", "SV", "sv-SE", "de"} {
		if IncorporationCopyForLocaleV1(unsupported) != IncorporationCopyV1() {
			t.Fatal("inferred unsupported root language", unsupported)
		}
	}
	// This fixed value also protects the legacy version from accidental changes.
	if IncorporationCopyV1().SHA256 != "ed7e8d4a4b7e03bb600f94ccd6328e4f457528eb165f18fd0ca6ccfecb972670" {
		t.Fatal("legacy English proof changed")
	}
}

func TestLegacyEnglishResponseAndAuditBytesUnchangedV128(t *testing.T) {
	copy := IncorporationCopyV1()
	r := ResponseV1{ManifestSHA256: strings.Repeat("a", 64), LegalCommitmentSHA256: strings.Repeat("b", 64), IncorporationVersion: copy.Version, IncorporationSHA256: copy.SHA256, Consent: true}
	raw, err := json.Marshal(r)
	want := `{"manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","legal_commitment_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","incorporation_version":"hash-package-incorporation-v1","incorporation_sha256":"ed7e8d4a4b7e03bb600f94ccd6328e4f457528eb165f18fd0ca6ccfecb972670","consent":true}`
	if err != nil || string(raw) != want {
		t.Fatal("legacy response bytes changed", err)
	}
	payload := map[string]any{"notice_digest": "independent-notice"}
	if r.BindAuditPayloadV1(payload, "attempt", "package", "7", "signed") != nil {
		t.Fatal("legacy audit refused")
	}
	raw, err = json.Marshal(payload)
	want = `{"capture_revision":"7","incorporation_sha256":"ed7e8d4a4b7e03bb600f94ccd6328e4f457528eb165f18fd0ca6ccfecb972670","incorporation_version":"hash-package-incorporation-v1","legal_commitment_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","notice_digest":"independent-notice","package_consent":true,"package_id":"package","package_response_schema":"hash-package-response-v1","package_send_attempt_id":"attempt","response_kind":"signed"}`
	if err != nil || string(raw) != want {
		t.Fatal("legacy audit payload bytes changed", err)
	}
}

func TestResponseMustMatchActualFrozenStatementV128(t *testing.T) {
	en, sv := IncorporationCopyV1(), IncorporationCopyForLocaleV1("sv")
	for _, copy := range []IncorporationV1{en, sv} {
		r := ResponseV1{ManifestSHA256: strings.Repeat("a", 64), LegalCommitmentSHA256: strings.Repeat("b", 64), IncorporationVersion: copy.Version, IncorporationSHA256: copy.SHA256, Consent: true}
		if !r.MatchesIncorporationV1(copy) {
			t.Fatal("current explicit response rejected")
		}
		other := en
		if copy.Version == en.Version {
			other = sv
		}
		if r.MatchesIncorporationV1(other) {
			t.Fatal("stale other-language consent accepted for a new frozen Send")
		}
		payload := map[string]any{"notice_digest": "separate-notice-proof"}
		if r.BindAuditPayloadV1(payload, "attempt", "package", "1", "accepted") != nil || payload["incorporation_version"] != copy.Version || payload["incorporation_sha256"] != copy.SHA256 || payload["notice_digest"] != "separate-notice-proof" {
			t.Fatal("actual frozen statement was not bound alongside separate privacy evidence")
		}
		if _, exists := payload["locale"]; exists {
			t.Fatal("interface locale entered consent evidence")
		}
		wrong := r
		wrong.IncorporationSHA256 = other.SHA256
		if wrong.ValidateV1() == nil || wrong.BindAuditPayloadV1(map[string]any{}, "attempt", "package", "1", "accepted") == nil {
			t.Fatal("cross-version response digest accepted")
		}
	}
}
