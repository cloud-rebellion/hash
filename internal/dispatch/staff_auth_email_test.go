// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"bytes"
	"html"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestStaffAuthEmailRenderingLocaleAndSealedCopyV1(t *testing.T) {
	box, err := NewStaffAuthMailBox(strings.Repeat("1a", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	const link = `https://hash.example.test/reset-password?example="<&>#token=private-bearer`
	for _, item := range []struct {
		locale, purpose, subject, action string
	}{
		{"en", "register", "Verify your Hash email", "Verify your email"},
		{"en", "setup", "Set your Hash password", "Choose your own password"},
		{"en", "reset", "Reset your Hash password", "Reset your password"},
		{"sv", "register", "Verifiera din e-postadress för Hash", "Verifiera din e-postadress"},
		{"sv", "setup", "Välj ditt lösenord för Hash", "Välj ditt eget lösenord"},
		{"sv", "reset", "Återställ ditt lösenord för Hash", "Återställ ditt lösenord"},
	} {
		t.Run(item.locale+"/"+item.purpose, func(t *testing.T) {
			msg, err := StaffAuthEmailMessageV1("staff@example.test", item.purpose, item.locale, link)
			if err != nil {
				t.Fatal(err)
			}
			instruction := item.action + " using the link below."
			disclaimer := "If you did not request this, ignore this email. The link expires and can be used once."
			foreignCopy := "Om du inte begärde detta"
			if item.locale == "sv" {
				instruction = item.action + " med länken nedan."
				disclaimer = "Om du inte begärde detta kan du ignorera meddelandet. Länken upphör att gälla och kan bara användas en gång."
				foreignCopy = "If you did not request this"
			}
			if msg.To != "staff@example.test" || msg.Subject != item.subject ||
				msg.Text != item.action+":\n"+link+"\n\n"+disclaimer ||
				!strings.Contains(msg.HTML, "<p>"+html.EscapeString(instruction)+"</p>") ||
				!strings.Contains(msg.HTML, `<a href="`+html.EscapeString(link)+`">`+html.EscapeString(item.action)+`</a>`) ||
				!strings.Contains(msg.HTML, html.EscapeString(disclaimer)) || strings.Contains(msg.HTML+msg.Text, foreignCopy) ||
				strings.Contains(msg.HTML, link) || strings.Count(msg.HTML, "href=") != 1 {
				t.Fatal("account mail lost its selected copy, escaped native link or plain-text alternative")
			}
			id := uuid.New()
			sealed, err := SealStaffAuthEmail(box, id, msg)
			if err != nil || bytes.Contains(sealed, []byte("private-bearer")) {
				t.Fatal("localized account mail did not seal its bearer", err)
			}
			opened, err := OpenStaffAuthEmail(box, id, msg.To, msg.Subject, sealed)
			if err != nil || opened.To != msg.To || opened.Subject != msg.Subject || opened.HTML != msg.HTML || opened.Text != msg.Text {
				t.Fatal("queued account mail did not retain its exact selected copy", err)
			}
		})
	}
	for _, item := range []struct{ locale, purpose string }{{"", "setup"}, {"de", "setup"}, {"sv-SE", "setup"}, {"sv", "other"}} {
		if _, err := StaffAuthEmailMessageV1("staff@example.test", item.purpose, item.locale, link); err == nil {
			t.Fatal("account renderer accepted an unvalidated locale or purpose")
		}
	}
}

func TestStaffAuthMailIsSealedAndBoundToDelivery(t *testing.T) {
	box, err := NewStaffAuthMailBox(strings.Repeat("1a", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	msg := Message{To: "staff@example.test", Subject: "Set password", HTML: "<a>#token=private-bearer</a>", Text: "/reset-password#token=private-bearer"}
	sealed, err := SealStaffAuthEmail(box, id, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("private-bearer")) {
		t.Fatal("raw auth token persisted in outbox")
	}
	opened, err := OpenStaffAuthEmail(box, id, msg.To, msg.Subject, sealed)
	if err != nil || opened.HTML != msg.HTML || opened.Text != msg.Text {
		t.Fatal("sealed mail unavailable", err)
	}
	for _, other := range []struct {
		id             uuid.UUID
		email, subject string
	}{
		{uuid.New(), msg.To, msg.Subject}, {id, "other@example.test", msg.Subject}, {id, msg.To, "other subject"},
	} {
		if _, err := OpenStaffAuthEmail(box, other.id, other.email, other.subject, sealed); err == nil {
			t.Fatal("auth mail envelope moved between identities")
		}
	}
	rotated, err := NewStaffAuthMailBox(strings.Repeat("2b", 32), strings.Repeat("1a", 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStaffAuthEmail(rotated, id, msg.To, msg.Subject, sealed); err != nil {
		t.Fatal("previous encryption key cannot deliver queued mail", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := OpenStaffAuthEmail(box, id, msg.To, msg.Subject, sealed); err == nil {
		t.Fatal("tampered mail was opened")
	}
}
