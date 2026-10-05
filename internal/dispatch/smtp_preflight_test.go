// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"context"
	"strings"
	"testing"
)

func TestSMTPRejectsInvalidMessageBeforeDial(t *testing.T) {
	mailer, err := NewSMTPMailer(SMTPConfig{Host: "invalid host", From: "hash@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		message   Message
		errorPart string
	}{
		{"empty recipient", Message{Subject: "Sign", Text: "Contract"}, "message to"},
		{"recipient list", Message{To: "a@example.test,b@example.test", Subject: "Sign", Text: "Contract"}, "message to"},
		{"recipient injection", Message{To: "a@example.test\r\nBcc: attacker@example.test", Subject: "Sign", Text: "Contract"}, "message to"},
		{"reply injection", Message{To: "a@example.test", ReplyTo: "b@example.test\nBcc: x", Subject: "Sign", Text: "Contract"}, "reply-to"},
		{"empty subject", Message{To: "a@example.test", Text: "Contract"}, "subject required"},
		{"managed header", Message{To: "a@example.test", Subject: "Sign", Text: "Contract", Headers: map[string]string{"Bcc": "x"}}, "managed message headers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := mailer.Send(context.Background(), tc.message)
			if err == nil || !strings.Contains(err.Error(), tc.errorPart) {
				t.Fatalf("error=%v", err)
			}
			if strings.Contains(err.Error(), "smtp dial") {
				t.Fatal("invalid message reached network")
			}
		})
	}
}

func TestSMTPAddressHandlesAngleBracketsInDisplayName(t *testing.T) {
	address, err := parseSMTPAddress(`"Person <Other>" <a@example.test>`)
	if err != nil {
		t.Fatal(err)
	}
	if extractAddress(`"Person <Other>" <a@example.test>`) != "a@example.test" {
		t.Fatal("envelope extraction used display name")
	}
	if address.Address != `a@example.test` {
		t.Fatalf("address=%q", address.Address)
	}
}
