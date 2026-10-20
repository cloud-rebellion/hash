// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package documentpackage

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestResponseRequiresExplicitWholePackageConsentV1(t *testing.T) {
	copy := IncorporationCopyV1()
	valid := ResponseV1{ManifestSHA256: strings.Repeat("a", 64), LegalCommitmentSHA256: strings.Repeat("b", 64), IncorporationVersion: copy.Version, IncorporationSHA256: copy.SHA256, Consent: true}
	if valid.ValidateV1() != nil {
		t.Fatal("explicit observed consent refused")
	}
	for _, c := range []struct {
		name   string
		change func(*ResponseV1)
	}{
		{"unchecked consent", func(r *ResponseV1) { r.Consent = false }},
		{"different legal copy", func(r *ResponseV1) { r.IncorporationVersion = "other" }},
		{"different legal digest", func(r *ResponseV1) { r.IncorporationSHA256 = strings.Repeat("c", 64) }},
		{"missing manifest", func(r *ResponseV1) { r.ManifestSHA256 = "" }},
		{"zero manifest", func(r *ResponseV1) { r.ManifestSHA256 = strings.Repeat("0", 64) }},
		{"uppercase commitment", func(r *ResponseV1) { r.LegalCommitmentSHA256 = strings.Repeat("B", 64) }},
		{"space digest", func(r *ResponseV1) { r.ManifestSHA256 = " " + strings.Repeat("a", 63) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := valid
			c.change(&r)
			if r.ValidateV1() == nil {
				t.Fatal("invalid consent accepted")
			}
		})
	}
	// A fixed independent UTF-8 hash prevents accidental newline or translated
	// copy changes from retaining the old incorporation version's commitment.
	want := sha256.Sum256([]byte("I have reviewed and agree to the main document and every attachment listed in this contract package. My signature or acknowledgement applies to the complete package identified by the displayed commitments."))
	if copy.Version != "hash-package-incorporation-v1" || copy.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatal("versioned server copy changed")
	}
}

func TestResponseAuditIsSeparateFromPrivacyAcknowledgementV1(t *testing.T) {
	copy := IncorporationCopyV1()
	r := ResponseV1{ManifestSHA256: strings.Repeat("1", 64), LegalCommitmentSHA256: strings.Repeat("2", 64), IncorporationVersion: copy.Version, IncorporationSHA256: copy.SHA256, Consent: true}
	p := map[string]any{"notice_digest": "independent-current-privacy-acknowledgement"}
	if err := r.BindAuditPayloadV1(p, "actual-attempt", "actual-package", "7", "signed"); err != nil {
		t.Fatal(err)
	}
	if p["notice_digest"] != "independent-current-privacy-acknowledgement" || p["package_consent"] != true || p["capture_revision"] != "7" || p["response_kind"] != "signed" {
		t.Fatal("package consent replaced separate evidence")
	}
	if err := r.BindAuditPayloadV1(p, "actual-attempt", "actual-package", "7", "noticed"); err == nil {
		t.Fatal("notice invented contractual response consent")
	}
}
