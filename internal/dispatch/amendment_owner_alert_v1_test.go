// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestOwnerAlert483UsesAuthenticatedOriginalLinkAndClosedWording(t *testing.T) {
	original := uuid.New()
	for _, kind := range []string{"document.amendment_linked", "document.amendment_notice_queued"} {
		m, e := AmendmentOwnerAlertMessageV1(kind, "https://hash.example.test", "owner@example.test", original)
		if e != nil {
			t.Fatal(e)
		}
		link := "https://hash.example.test/documents/" + original.String()
		if !strings.Contains(m.Text, link) || !strings.Contains(m.HTML, link) || m.To != "owner@example.test" || m.FromName != "Hash" || m.Headers[AmendmentOwnerAlertHeaderV1] != AmendmentOwnerAlertPurposeV1 {
			t.Fatal("owner alert route/purpose")
		}
		for _, forbidden := range []string{"#access=", "hn1.", "/sign/", "/completed/", "/a/", "signature completed", "legally effective"} {
			if strings.Contains(m.HTML+m.Text+m.Subject, forbidden) {
				t.Fatal("owner alert claims or grants unrelated authority")
			}
		}
		if _, e = AmendmentOwnerAlertMessageSHA256V1(m); e != nil {
			t.Fatal(e)
		}
	}
}
func TestOwnerAlert483RefusesUntrustedRoutesAndHeaderInjection(t *testing.T) {
	id := uuid.New()
	for _, url := range []string{"https://user:password@hash.example.test", "https://hash.example.test/foreign", "https://hash.example.test?token=x", "https://hash.example.test#access=x", "https://hash.example.test?", "http://foreign.example.test"} {
		if _, e := AmendmentOwnerAlertMessageV1("document.amendment_linked", url, "owner@example.test", id); e == nil {
			t.Fatal("untrusted staff URL accepted")
		}
	}
	for _, to := range []string{"Name <owner@example.test>", "owner@example.test\r\nBcc: foreign@example.test", ""} {
		if _, e := AmendmentOwnerAlertMessageV1("document.amendment_linked", "https://hash.example.test", to, id); e == nil {
			t.Fatal("noncanonical owner mailbox accepted")
		}
	}
	if _, e := AmendmentOwnerAlertMessageV1("document.completed", "https://hash.example.test", "owner@example.test", id); e == nil {
		t.Fatal("unrelated event reclassified")
	}
}
func TestOwnerAlert483DigestBindsExactMessageAndReservedHeader(t *testing.T) {
	m, e := AmendmentOwnerAlertMessageV1("document.amendment_linked", "https://hash.example.test", "owner@example.test", uuid.New())
	if e != nil {
		t.Fatal(e)
	}
	before, e := AmendmentOwnerAlertMessageSHA256V1(m)
	if e != nil {
		t.Fatal(e)
	}
	m.Text += " changed"
	after, e := AmendmentOwnerAlertMessageSHA256V1(m)
	if e != nil || before == after {
		t.Fatal("queue body omitted from exact digest")
	}
	m.Headers["X-Other"] = "unreviewed"
	if _, e = AmendmentOwnerAlertMessageSHA256V1(m); e == nil {
		t.Fatal("unbound extra transport header accepted")
	}
}
