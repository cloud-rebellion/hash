// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"math"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSenderEventNoticeActualEscapedOutputFitsFundedBoundV1(t *testing.T) {
	doc, recipient := strings.Repeat("<&\"é", 4096), strings.Repeat("&<署", 2048)
	for _, kind := range []string{"document.viewed", "document.signed"} {
		t.Run(kind, func(t *testing.T) {
			id := uuid.New()
			raw, wire, err := SenderEventNoticeOutputBoundV1(int64(len(doc)), int64(len(recipient)), int64(len("https://hash.example.test")))
			if err != nil {
				t.Fatal(err)
			}
			m, err := SenderEventNoticeMessageV1(kind, "https://hash.example.test", "sender@example.test", id, doc, recipient)
			if err != nil {
				t.Fatal(err)
			}
			actual := int64(len(m.To) + len(m.Subject) + len(m.HTML) + len(m.Text) + len(m.FromName) + len("pending") + len("workspace") + 2 + 16)
			if raw < 4*actual || wire < actual || strings.Contains(m.HTML, "<署") || !strings.Contains(m.HTML, "&amp;&lt;") || !strings.Contains(m.Text, doc) || !strings.Contains(m.Text, recipient) {
				t.Fatal("actual escaped producer exceeds bound or changes source text")
			}
			if m.To != "sender@example.test" || m.FromName != "Hash" || m.ReplyTo != "" || len(m.Headers) != 0 || strings.Contains(m.HTML, "<img") || strings.Contains(m.HTML, "/sign/") || !strings.Contains(m.HTML, "/documents/"+id.String()) {
				t.Fatal("notice is not bounded staff-only document navigation")
			}
		})
	}
}

func TestSenderEventNoticeClosedKindAddressAndPublicURLV1(t *testing.T) {
	for _, tc := range []struct{ kind, url, to string }{
		{"document.acknowledged", "https://hash.example.test", "sender@example.test"},
		{"document.signed", "http://remote.example.test", "sender@example.test"},
		{"document.viewed", "https://user:secret@hash.example.test", "sender@example.test"},
		{"document.viewed", "https://hash.example.test?token=synthetic", "sender@example.test"},
		{"document.viewed", "https://hash.example.test/#fragment", "sender@example.test"},
		{"document.viewed", "https://hash.example.test/path", "sender@example.test"},
		{"document.viewed", "https://hash.example.test", "Display <sender@example.test>"},
		{"document.viewed", "https://hash.example.test", "sender@example.test\r\nInjected: false"},
	} {
		if _, err := SenderEventNoticeMessageV1(tc.kind, tc.url, tc.to, uuid.New(), "Document", "Recipient"); err == nil {
			t.Fatal("unsafe notice input accepted", tc.kind, tc.url)
		}
	}
	for _, n := range []int64{-1, math.MaxInt64} {
		if _, _, err := SenderEventNoticeOutputBoundV1(n, 1, 1); err == nil {
			t.Fatal("invalid producer arithmetic accepted")
		}
	}
	if _, err := SenderEventNoticeMessageV1("document.viewed", "https://hash.example.test", "sender@example.test", uuid.Nil, "Document", "Recipient"); err == nil {
		t.Fatal("missing actual document accepted")
	}
}
