// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package dispatch

import (
	"fmt"
	"html"
	"math"
	"strings"
	"testing"
)

func TestCustomerEmail769NativeFooterUsesFrozenCompanyWithoutAnEdition(t *testing.T) {
	for _, kind := range []string{KindInvite, KindReminder, KindCompletedSigner} {
		for _, locale := range []string{"en", "sv", "fi", "unknown"} {
			for _, ack := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/ack=%t", kind, locale, ack), func(t *testing.T) {
					c := serviceEmailFixture720()
					c.Locale, c.Acknowledgement = locale, ack
					c.OrgName = `Frozen <company> & "partners"`
					// Product words in document content are not footer instructions.
					c.DocumentName = "Hash is part of this contract name"
					baseSubject, baseHTML, baseText, err := Render(kind, c)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Count(baseHTML, ">Document service</p>") != 1 || !strings.HasSuffix(baseText, "Document service\n") {
						t.Fatal("raw legacy render did not use its single neutral native footer")
					}
					wantHTML := strings.Replace(baseHTML, ">Document service</p>", ">"+html.EscapeString(c.OrgName)+"</p>", 1)
					wantText := strings.TrimSuffix(baseText, "Document service\n") + c.OrgName + "\n"
					for _, tpl := range []*ServiceEmailTemplateV1{nil, {Revision: 2}} {
						subject, body, text, err := RenderServiceEmailV1(kind, c, tpl)
						if err != nil || subject != baseSubject || body != wantHTML || text != wantText {
							t.Fatal("native action, notice, evidence or company footer changed", err)
						}
						if !strings.Contains(subject, c.DocumentName) || !strings.Contains(body, c.DocumentName) || strings.Contains(body, "<img") {
							t.Fatal("content was globally replaced or a design/tracking image was introduced")
						}
					}
				})
			}
		}
	}
}

func TestCustomerEmail769IntroductionCannotSelectFooterReplacement(t *testing.T) {
	c := serviceEmailFixture720()
	c.OrgName = "Frozen company"
	for _, kind := range []string{KindInvite, KindReminder, KindCompletedSigner} {
		t.Run(kind, func(t *testing.T) {
			intro := "Sent via Hash for Frozen company."
			tpl, err := ValidateServiceEmailTemplateV1(kind, ServiceEmailTemplateV1{HTMLTemplate: "<p>" + intro + "</p><p>Document service</p>", TextTemplate: intro + "\nDocument service"})
			if err != nil {
				t.Fatal(err)
			}
			_, baseHTML, baseText, err := RenderServiceEmailV1(kind, c, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, body, text, err := RenderServiceEmailV1(kind, c, &tpl)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Replace(body, tpl.HTMLTemplate+serviceEmailHTMLJoinV1, "", 1) != baseHTML || strings.TrimPrefix(text, tpl.TextTemplate+"\n\n") != baseText {
				t.Fatal("owner introduction or mandatory native content was rewritten")
			}
			if !strings.Contains(body, "<p>"+intro+"</p><p>Document service</p>") || !strings.HasSuffix(text, "Frozen company\n") {
				t.Fatal("exact native footer was confused with authored content")
			}
		})
	}
}

func TestCustomerEmail769MissingCompanyStaysNeutralAndOtherKindsStayUnchanged(t *testing.T) {
	c := serviceEmailFixture720()
	c.OrgName = " \t "
	c.SenderName, c.SenderEmail = "Personal sender", "person@example.invalid"
	for _, kind := range []string{KindInvite, KindReminder, KindCompletedSigner} {
		_, body, text, err := RenderServiceEmailV1(kind, c, nil)
		if err != nil || !strings.Contains(body, ">Document service</p>") || !strings.HasSuffix(text, "Document service\n") {
			t.Fatal("missing controller name selected a person/address/installation identity", kind, err)
		}
	}
	for _, kind := range []string{KindCompletedSender, KindDeclined, KindChangesRequested, KindNewComment, KindVoided, KindQuotaWarning80} {
		subject, body, text, err := Render(kind, c)
		if err != nil {
			t.Fatal(err)
		}
		s, h, p, err := RenderServiceEmailV1(kind, c, nil)
		if err != nil || subject != s || body != h || text != p {
			t.Fatal("nonrecipient native notice changed", kind, err)
		}
		if kind != KindQuotaWarning80 && (strings.Contains(h, ">Document service</p>") || strings.HasSuffix(p, "Document service\n")) {
			t.Fatal("a footer was added to a previously neutral notice", kind)
		}
	}
	if _, _, _, err := RenderServiceEmailV1("staff.password-reset", c, nil); err == nil {
		t.Fatal("customer presentation renderer gained staff-account authority")
	}
}

func TestCustomerEmail769FooterGrowthIsQuotedBeforeDefaultAndCustomRender(t *testing.T) {
	for _, row := range []struct {
		kind  string
		quote func(TemplateContext) (int64, int64, int64, error)
	}{
		{KindInvite, InviteNotificationComponentsV1},
		{KindReminder, ReminderNotificationComponentsV1},
		{KindCompletedSigner, func(c TemplateContext) (int64, int64, int64, error) {
			return CompletedNotificationComponentsV1(KindCompletedSigner, c)
		}},
	} {
		for _, company := range []string{"", "A", "Frozen company", strings.Repeat(`<>&"' Å界`, 256)} {
			c := serviceEmailFixture720()
			c.OrgName = company
			bs, bh, bt, err := row.quote(c)
			if err != nil {
				t.Fatal(err)
			}
			intro, err := ValidateServiceEmailTemplateV1(row.kind, ServiceEmailTemplateV1{HTMLTemplate: "<p>Reviewed introduction</p>", TextTemplate: "Reviewed introduction"})
			if err != nil {
				t.Fatal(err)
			}
			for _, tpl := range []*ServiceEmailTemplateV1{nil, {}, &intro} {
				s, h, p, err := ServiceEmailTemplateComponentsV1(row.kind, c, tpl, bs, bh, bt)
				if err != nil {
					t.Fatal(err)
				}
				subject, body, text, err := RenderServiceEmailV1(row.kind, c, tpl)
				if err != nil || s < int64(len(subject)) || h < int64(len(body)) || p < int64(len(text)) {
					t.Fatalf("kind=%s quoted=%d/%d/%d actual=%d/%d/%d error=%v", row.kind, s, h, p, len(subject), len(body), len(text), err)
				}
			}
		}
	}
	c := serviceEmailFixture720()
	c.OrgName = strings.Repeat("&", 512)
	if _, _, _, err := ServiceEmailTemplateComponentsV1(KindInvite, c, nil, 0, math.MaxInt64, 0); err == nil {
		t.Fatal("default footer growth overflow was accepted")
	}
	if _, _, _, err := ServiceEmailTemplateComponentsV1(KindInvite, c, nil, 0, 0, math.MaxInt64); err == nil {
		t.Fatal("default plain footer growth overflow was accepted")
	}
}

func TestCustomerEmail769AlreadyRenderedMIMEKeepsLegacyFooter(t *testing.T) {
	// Workers drain stored rendered bodies; they do not select or rerender an
	// edition or company name. Exercise the real MIME builder on those bytes.
	legacy := Message{To: "recipient@example.invalid", Subject: "Frozen legacy notification", HTML: "<p>Sent via Hash for Legacy workspace.</p>", Text: "Sent via Hash for Legacy workspace.\n"}
	wire, err := buildMIME("Configured sender <sender@example.invalid>", legacy)
	if err != nil || !strings.Contains(wire, legacy.HTML) || !strings.Contains(wire, strings.TrimSpace(legacy.Text)) {
		t.Fatal("already-rendered legacy content was presented differently at delivery", err)
	}
}
