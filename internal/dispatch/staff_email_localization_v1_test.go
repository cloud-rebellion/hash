// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package dispatch

import (
	"github.com/google/uuid"
	"html"
	"reflect"
	"strings"
	"testing"
)

func TestStaffEmailSVLifecycleCopyAndEnglishFallbackV1(t *testing.T) {
	c := designContext760()
	c.Locale = "sv"
	c.ChangeContext = "Hela sammanhanget"
	c.ChangeQuote = "Hela markerade texten"
	c.DeclineReason = "Hela kommentaren"
	c.ChangeProposed = "Hela förslaget"
	c.QuotaKind = "documents"
	c.PlanName = "Test"
	c.QuotaPct = 80
	c.QuotaUsed = 8
	c.QuotaLimit = 10
	c.PeriodResetAt = "2030-01-01"
	for _, kind := range ServiceEmailKindsV1() {
		for _, ack := range []bool{false, true} {
			c.Acknowledgement = ack
			subject, body, text, err := Render(kind, c)
			if err != nil {
				t.Fatal(kind, err)
			}
			for _, bad := range []string{"acknowledgement", "signing ceremony", "All required", "Use the links", "Download audit certificate", "Download original contract files", "No signature", "New comment", "Reason given", "Changes requested", "Signing is paused", "The document has been moved", "You'll receive at most"} {
				if strings.Contains(body, bad) || strings.Contains(text, bad) {
					t.Fatal("mixed English copy", kind, bad)
				}
			}
			if subject == "" || kind != KindQuotaWarning80 && !strings.Contains(body, "Synthetic") {
				t.Fatal("dynamic document data lost", kind)
			}
			svSubject, svBody, svText := subject, body, text
			c.Locale = "en"
			enSubject, enBody, enText, err := Render(kind, c)
			if err != nil {
				t.Fatal(err)
			}
			if svSubject == enSubject && svBody == enBody && svText == enText {
				t.Fatal("Swedish email not localized", kind)
			}
			c.Locale = "unknown"
			s, h, p, err := Render(kind, c)
			if err != nil || s != enSubject || h != enBody || p != enText {
				t.Fatal("English fallback changed", kind, err)
			}
			c.Locale = "sv"
		}
	}
}
func TestStaffEmailSVCommentAndCompletionOwnedBoundsV1(t *testing.T) {
	c := designContext760()
	c.Locale = "sv"
	c.DeclineReason = strings.Repeat("&<>Å ", 100)
	c.DocumentName = strings.Repeat("Dokument & <ord> ", 100)
	for _, ack := range []bool{false, true} {
		c.Acknowledgement = ack
		for _, kind := range []string{KindNewComment, KindCompletedSigner, KindCompletedSender} {
			var s, h, p int64
			var err error
			if kind == KindNewComment {
				s, h, p, err = CommentNotificationComponentsV1(c)
			} else {
				s, h, p, err = CompletedNotificationComponentsV1(kind, c)
			}
			if err != nil {
				t.Fatal(err)
			}
			sub, body, plain, err := Render(kind, c)
			if err != nil || s < int64(len(sub)) || h < int64(len(body)) || p < int64(len(plain)) {
				t.Fatal("actual Swedish output exceeds owned components", kind, err)
			}
			for _, link := range []string{c.DownloadURL, c.AuditCertURL} {
				if kind != KindNewComment && !strings.Contains(body, html.EscapeString(link)) {
					t.Fatal("artifact URL lost", kind)
				}
			}
		}
	}
}
func TestStaffEmailSVOperationalNoticesKeepDestinationAndBoundV1(t *testing.T) {
	id := uuid.New()
	name := strings.Repeat("Avtal & <ord> ", 100)
	person := strings.Repeat("Åsa & 李 ", 100)
	for _, kind := range []string{"document.viewed", "document.signed"} {
		original, err := SenderEventNoticeMessageV1(kind, "https://example.invalid", "owner@example.invalid", id, name, person)
		if err != nil {
			t.Fatal(err)
		}
		english, err := SenderEventNoticeMessageLocaleV1(kind, "https://example.invalid", "owner@example.invalid", id, name, person, "en")
		if err != nil || !reflect.DeepEqual(english, original) {
			t.Fatal("English compatibility changed", err)
		}
		swedish, err := SenderEventNoticeMessageLocaleV1(kind, "https://example.invalid", "owner@example.invalid", id, name, person, "sv")
		if err != nil || swedish.To != original.To || swedish.FromName != original.FromName || !strings.Contains(swedish.HTML, "Öppna Hash") || strings.Contains(swedish.HTML, "Open Hash") {
			t.Fatal("owner notice not localized", err)
		}
		raw, wire, err := SenderEventNoticeOutputBoundV1(int64(len(name)), int64(len(person)), int64(len("https://example.invalid")))
		n := int64(len(swedish.HTML) + len(swedish.Text) + len(swedish.Subject) + len(swedish.To) + len(swedish.FromName))
		if err != nil || n > raw || n > wire {
			t.Fatal("Swedish notice exceeds owned bound", err)
		}
	}
}
