// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package i18n

import (
	"strings"
	"testing"
)

func TestSwedishEmailSupplementV1(t *testing.T) {
	for key, value := range swedishEmailSupplementV1 {
		if !strings.HasPrefix(key, "email.") || value == "" || T("sv", key, nil) != value {
			t.Fatal("supplement outside email or not selected", key)
		}
	}
	for _, key := range []string{"privacy.purpose", "privacy.legalBasis", "sign.signaturePending"} {
		if T("sv", key, nil) != messages["sv"][key] {
			t.Fatal("non-email catalog changed", key)
		}
	}
	for _, prefix := range []string{"email.inviteAcknowledgement", "email.reminderAcknowledgement", "email.completedAcknowledgement"} {
		for _, suffix := range []string{"subject", "eyebrow", "heading", "body", "cta"} {
			key := prefix + "." + suffix
			got := T("sv", key, nil)
			if got == key || got == T("en", key, nil) {
				t.Fatal("Swedish acknowledgement copy still English", key)
			}
		}
	}
	for _, key := range []string{"email.invite.subject", "email.reminder.body", "email.completedSigner.body"} {
		if T("unknown", key, nil) != T("en", key, nil) {
			t.Fatal("English fallback changed", key)
		}
	}
}
