// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package workspacesmtp

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestSavedTemplateSampleUsesActualEditionAndInertSyntheticLinks760(t *testing.T) {
	tpl := dispatch.ServiceEmailTemplateV1{Revision: 4, SubjectTemplate: "Edition four: {{document_name}}", HTMLTemplate: "<p>Reviewed edition four for {{recipient_name}}</p>", TextTemplate: "Reviewed edition four for {{recipient_name}}"}
	subject, html, text, err := renderedTemplateSampleV1(dispatch.KindInvite, tpl)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(subject, "[Test] Edition four:") || !strings.Contains(html, "Reviewed edition four for Example recipient") || !strings.Contains(text, "Reviewed edition four for Example recipient") || !strings.Contains(html, "https://example.invalid/sign/preview") || !strings.Contains(html, templateSampleHTMLNoticeV1) || !strings.HasPrefix(text, templateSampleTextNoticeV1) || strings.Contains(html, "{{recipient_name}}") {
		t.Fatal("test did not render the selected edition with clearly synthetic native actions")
	}
	if _, _, _, err := renderedTemplateSampleV1("email.unrecognized", tpl); err == nil {
		t.Fatal("unknown service-email kind became a test sender")
	}
}

func TestSavedTemplateSampleReceiptBindsFrozenMessageAndFixedRecipient760(t *testing.T) {
	subject, html, text, err := renderedTemplateSampleV1(dispatch.KindInvite, dispatch.ServiceEmailTemplateV1{Revision: 1, HTMLTemplate: "<p>Selected edition one</p>"})
	if err != nil {
		t.Fatal(err)
	}
	d := generated.EmailDelivery{ToEmail: "owner@example.invalid", Subject: subject, HtmlBody: html, TextBody: text, HeadersJson: []byte("{}")}
	msg := dispatch.Message{To: d.ToEmail, Subject: d.Subject, HTML: d.HtmlBody, Text: d.TextBody}
	kind, revision := pgtype.Text{String: dispatch.KindInvite, Valid: true}, pgtype.Int8{Int64: 1, Valid: true}
	sh, hh, th := sha256.Sum256([]byte(subject)), sha256.Sum256([]byte(html)), sha256.Sum256([]byte(text))
	if !workspaceTestContentMatchesV1(&d, msg, kind, revision, sh[:], hh[:], th[:]) {
		t.Fatal("genuine frozen sample refused")
	}
	for _, field := range []string{"recipient", "subject", "html", "text", "reply-to", "headers"} {
		t.Run(field, func(t *testing.T) {
			changed := msg
			switch field {
			case "recipient":
				changed.To = "other@example.invalid"
			case "subject":
				changed.Subject += " changed"
			case "html":
				changed.HTML += "<p>changed</p>"
			case "text":
				changed.Text += " changed"
			case "reply-to":
				changed.ReplyTo = "other@example.invalid"
			case "headers":
				changed.Headers = map[string]string{"X-Unreviewed": "changed"}
			}
			if workspaceTestContentMatchesV1(&d, changed, kind, revision, sh[:], hh[:], th[:]) {
				t.Fatal("unreviewed transport input passed a saved sample receipt")
			}
		})
	}
	changed := d
	changed.HtmlBody += "<p>queue changed</p>"
	changedMessage := msg
	changedMessage.HTML = changed.HtmlBody
	if workspaceTestContentMatchesV1(&changed, changedMessage, kind, revision, sh[:], hh[:], th[:]) || workspaceTestContentMatchesV1(&d, msg, kind, revision, nil, hh[:], th[:]) || workspaceTestContentMatchesV1(&d, msg, kind, pgtype.Int8{}, sh[:], hh[:], th[:]) {
		t.Fatal("incomplete or changed retained sample was authorized")
	}
	canned := generated.EmailDelivery{Subject: testSubject, HtmlBody: testHTML, TextBody: testText, HeadersJson: []byte("{}")}
	if !workspaceTestContentMatchesV1(&canned, dispatch.Message{}, pgtype.Text{}, pgtype.Int8{}, nil, nil, nil) || workspaceTestContentMatchesV1(&d, msg, pgtype.Text{}, pgtype.Int8{}, nil, nil, nil) {
		t.Fatal("canned and actual-template receipts became interchangeable")
	}
}
