// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/dispatch"
)

func TestPackageSendOutboxActualRendererFitsReservedBoundsV1(t *testing.T) {
	for _, locale := range []string{"en", "sv"} {
		for _, acknowledgement := range []bool{false, true} {
			mode := "invite"
			if acknowledgement {
				mode = "acknowledgement"
			}
			t.Run(locale+"-"+mode, func(t *testing.T) {
				input := dispatch.TemplateContext{DocumentName: `DPA <Core> & "Annex" ä`, SenderName: "sender@example.test", SenderEmail: "sender@example.test", RecipientName: `Åsa <Buyer> & "Team"`, OrgName: "Company & Co <North>", Locale: locale, Acknowledgement: acknowledgement, SignURL: "https://hash.example.test/sign/" + strings.Repeat("A", 43), BeaconURL: "https://hash.example.test/e/o/" + strings.Repeat("A", 43)}
				subject, html, text, err := dispatch.InviteNotificationComponentsV1(input)
				if err != nil {
					t.Fatal(err)
				}
				bound, err := htmlAuthoringSumV1(int64(len("recipient@example.test")), subject, html, text, int64(len(input.SenderEmail)), int64(len(input.OrgName)), int64(len("pending")))
				if err != nil {
					t.Fatal(err)
				}
				shape := applicationPackageSendOutboxShapeV1{raw: bound, subject: subject, html: html, text: text}
				input.SignURL = "https://hash.example.test/sign/" + strings.Repeat("z", 43)
				input.BeaconURL = "https://hash.example.test/e/o/" + strings.Repeat("z", 43)
				actualSubject, actualHTML, actualText, err := dispatch.Render(dispatch.KindInvite, input)
				if err != nil {
					t.Fatal(err)
				}
				msg := dispatch.Message{To: "recipient@example.test", Subject: actualSubject, HTML: actualHTML, Text: actualText, ReplyTo: input.SenderEmail, FromName: input.OrgName}
				raw, err := htmlAuthoringSumV1(int64(len(msg.To)), int64(len(msg.Subject)), int64(len(msg.HTML)), int64(len(msg.Text)), int64(len(msg.ReplyTo)), int64(len(msg.FromName)), int64(len("pending")))
				if err != nil || !shape.coversV1(raw, msg) {
					t.Fatal("actual fixed renderer output does not fit its native reservation", err)
				}
				if shape.coversV1(bound+1, msg) || shape.coversV1(-1, msg) {
					t.Fatal("invalid aggregate return cost fit its reservation")
				}
				for _, component := range []string{"subject", "html", "text"} {
					oversized := msg
					switch component {
					case "subject":
						oversized.Subject = strings.Repeat("x", int(subject)+1)
					case "html":
						oversized.HTML = strings.Repeat("x", int(html)+1)
					case "text":
						oversized.Text = strings.Repeat("x", int(text)+1)
					}
					if shape.coversV1(raw, oversized) {
						t.Fatal("oversized renderer component fit its reservation", component)
					}
				}
			})
		}
	}
}
