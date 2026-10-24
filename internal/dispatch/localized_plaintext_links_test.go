// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/url"
	"strings"
	"testing"
)

func TestLocalizedPlaintextLinksSurviveMIMEAndWhitespaceParsing(t *testing.T) {
	for _, locale := range []string{"en", "sv", "de", "fr"} {
		for _, kind := range []string{KindInvite, KindReminder, KindCompletedSigner} {
			modes := []bool{false}
			if kind != KindCompletedSigner {
				modes = append(modes, true)
			}
			for _, acknowledgement := range modes {
				name := locale + "/" + kind + "/signature"
				if acknowledgement {
					name = locale + "/" + kind + "/acknowledgement"
				}
				t.Run(name, func(t *testing.T) {
					ctx := TemplateContext{
						DocumentName: "Synthetic agreement", SenderName: "Sender", SenderEmail: "sender@example.test",
						RecipientName: "Recipient", OrgName: "Company", Locale: locale, Acknowledgement: acknowledgement,
						SignURL:           "https://example.test/sign/ab" + strings.Repeat("x", 41),
						DownloadURL:       "https://example.test/completed/readonly",
						AuditCertURL:      "https://example.test/sign/artifact/audit-cert",
						PackagePortalURL:  "https://example.test/completed/readonly/package",
						DownloadExpiresAt: "2030-01-01T00:00:00Z",
					}
					subject, html, text, err := Render(kind, ctx)
					if err != nil {
						t.Fatal(err)
					}
					wire, err := buildMIME("sender@example.test", Message{To: "recipient@example.test", Subject: subject, HTML: html, Text: text})
					if err != nil {
						t.Fatal(err)
					}
					message, err := mail.ReadMessage(strings.NewReader(wire))
					if err != nil {
						t.Fatal(err)
					}
					_, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
					if err != nil || params["boundary"] == "" {
						t.Fatal("actual SMTP message has no multipart boundary", err)
					}
					parts := multipart.NewReader(message.Body, params["boundary"])
					var plain string
					for {
						part, err := parts.NextPart()
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Fatal(err)
						}
						media, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
						if err != nil {
							t.Fatal(err)
						}
						if media == "text/plain" {
							body, err := io.ReadAll(io.LimitReader(part, 64<<10))
							if err != nil || len(body) == 64<<10 || plain != "" {
								t.Fatal("expected one bounded actual plaintext part", err)
							}
							plain = string(body)
						}
						if err := part.Close(); err != nil {
							t.Fatal(err)
						}
					}
					want := []string{ctx.SignURL}
					if kind == KindCompletedSigner {
						want = []string{ctx.DownloadURL, ctx.AuditCertURL, ctx.PackagePortalURL}
					}
					words := strings.Fields(plain)
					for _, link := range want {
						found := false
						for _, word := range words {
							if word == link {
								parsed, err := url.Parse(word)
								found = err == nil && parsed.Scheme == "https" && parsed.Host == "example.test"
							}
						}
						if !found {
							t.Fatal("plaintext action link is not a complete standalone URL after SMTP MIME parsing")
						}
					}
					if strings.Contains(plain, `\n`) || strings.Count(plain, "\n\n") < 3 {
						t.Fatal("plaintext paragraphs contain escaped delimiters instead of readable line breaks")
					}
				})
			}
		}
	}
}
