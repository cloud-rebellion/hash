// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package dispatch

import (
	"errors"
	nethtml "golang.org/x/net/html"
	"strings"
	"testing"
)

func serviceEmailFixture720() TemplateContext {
	return TemplateContext{DocumentName: "Synthetic <agreement>", SenderName: "Example sender", SenderEmail: "sender@example.invalid", RecipientName: "Example recipient", OrgName: "Example workspace", SignURL: "https://example.invalid/sign/fixture", DownloadURL: "https://example.invalid/completed/fixture", AuditCertURL: "https://example.invalid/audit/fixture", PackagePortalURL: "https://example.invalid/package/fixture", DownloadExpiresAt: "2030-01-01T00:00:00Z", OpenURL: "https://example.invalid/documents/fixture", ApproveURL: "https://example.invalid/approve/fixture", DenyURL: "https://example.invalid/deny/fixture", DeclineReason: "Example response", ChangeQuote: "A clause", ChangeContext: "Context", ChangeProposed: "Wording", QuotaKind: "documents", QuotaUsed: 8, QuotaLimit: 10, QuotaPct: 80, PeriodResetAt: "2030-01-02", UpgradeURL: "https://example.invalid/plan", PlanName: "Example"}
}
func TestServiceEmail720MalformedLayoutCannotOwnNativeActionNodes(t *testing.T) {
	for _, fragment := range []string{"<table><tr><td>Custom720", "<blockquote><p>Custom720", "<ul><li>Custom720", "<h2>Custom720"} {
		t.Run(fragment, func(t *testing.T) {
			v, e := ValidateServiceEmailTemplateV1(KindInvite, ServiceEmailTemplateV1{HTMLTemplate: fragment})
			if e != nil {
				t.Fatal(e)
			}
			if v.HTMLTemplate == fragment {
				t.Fatal("unclosed fragment was retained")
			}
			again, e := ValidateServiceEmailTemplateV1(KindInvite, v)
			if e != nil || again != v {
				t.Fatal("fragment canonicalization not stable", e)
			}
			ctx := serviceEmailFixture720()
			_, h, _, e := RenderServiceEmailV1(KindInvite, ctx, &v)
			if e != nil {
				t.Fatal(e)
			}
			doc, e := nethtml.Parse(strings.NewReader(h))
			if e != nil {
				t.Fatal(e)
			}
			found := 0
			var walk func(*nethtml.Node)
			walk = func(n *nethtml.Node) {
				if n.Type == nethtml.ElementNode && n.Data == "a" {
					for _, a := range n.Attr {
						if a.Key == "href" && a.Val == ctx.SignURL {
							found++
							for p := n.Parent; p != nil; p = p.Parent {
								switch p.Data {
								case "table", "tr", "td", "blockquote", "ul", "li", "h2":
									t.Fatal("native CTA became part of custom layout", p.Data)
								}
							}
						}
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c)
				}
			}
			walk(doc)
			// The native invitation has the button plus its fallback URL anchor.
			if found != 2 {
				t.Fatal("native CTA count", found)
			}
		})
	}
	if _, e := ValidateServiceEmailTemplateV1(KindInvite, ServiceEmailTemplateV1{HTMLTemplate: strings.Repeat("<span>", 40) + "deep" + strings.Repeat("</span>", 40)}); e == nil {
		t.Fatal("custom layout depth bound ignored")
	}
}
func TestServiceEmail720BuiltinAndMandatoryContent(t *testing.T) {
	for _, kind := range ServiceEmailKindsV1() {
		for _, locale := range []string{"en", "sv"} {
			t.Run(kind+"/"+locale, func(t *testing.T) {
				ctx := serviceEmailFixture720()
				ctx.Locale = locale
				bs, bh, bt, e := Render(kind, ctx)
				if e != nil {
					t.Fatal(e)
				}
				s, h, p, e := RenderServiceEmailV1(kind, ctx, nil)
				if e != nil || s != bs || h != bh || p != bt {
					t.Fatal("nil override changed builtin", e)
				}
				empty := ServiceEmailTemplateV1{Revision: 3}
				s, h, p, e = RenderServiceEmailV1(kind, ctx, &empty)
				if e != nil || s != bs || h != bh || p != bt {
					t.Fatal("reset changed builtin", e)
				}
				v, e := ValidateServiceEmailTemplateV1(kind, ServiceEmailTemplateV1{Revision: 4, SubjectTemplate: "For {{recipient_name}}", HTMLTemplate: "<h2>{{document_name}}</h2><p>Hello {{recipient_name}}</p>", TextTemplate: "Hello {{recipient_name}}"})
				if e != nil {
					t.Fatal(e)
				}
				s, h, p, e = RenderServiceEmailV1(kind, ctx, &v)
				if e != nil {
					t.Fatal(e)
				}
				intro := "<h2>Synthetic &lt;agreement&gt;</h2><p>Hello Example recipient</p>" + serviceEmailHTMLJoinV1
				if strings.Replace(h, intro, "", 1) != bh || strings.TrimPrefix(p, "Hello Example recipient\n\n") != bt || s != "For Example recipient" {
					t.Fatal("mandatory native content/action/notice changed")
				}
				ms, mh, mt, e := ServiceEmailTemplateComponentsV1(ctx, &v, int64(len(bs)), int64(len(bh)), int64(len(bt)))
				if e != nil || ms != int64(len(s)) || mh != int64(len(h)) || mt != int64(len(p)) {
					t.Fatal("actual expanded output measurement differs", e)
				}
				if strings.Contains(h, "/e/o/") || strings.Contains(h, "<img") {
					t.Fatal("tracking/image introduced")
				}
			})
		}
	}
}
func TestServiceEmail720RefusesUnsafeAndUnboundedSource(t *testing.T) {
	for _, fragment := range []string{"<script>alert(1)</script>", "<img src=\"https://example.invalid/pixel\">", "<a href=\"https://example.invalid\">link</a>", "<p onclick=\"run()\">x</p>", "<p style=\"color:red\">x</p>", "<iframe src=\"/internal\"></iframe>", "<svg>x</svg>", "<!-- conditional -->", "<!DOCTYPE html>", "<p class=\"anything\">x</p>"} {
		t.Run(fragment, func(t *testing.T) {
			if _, e := ValidateServiceEmailTemplateV1(KindInvite, ServiceEmailTemplateV1{HTMLTemplate: fragment}); !errors.Is(e, ErrServiceEmailTemplateV1) {
				t.Fatal("unsafe source accepted", e)
			}
		})
	}
	for _, v := range []ServiceEmailTemplateV1{{SubjectTemplate: "Subject\r\nBcc: x"}, {SubjectTemplate: strings.Repeat("s", 257)}, {HTMLTemplate: strings.Repeat("h", 16385)}, {TextTemplate: strings.Repeat("t", 8193)}, {TextTemplate: "{{sign_url}}"}, {TextTemplate: "{{document_name"}, {TextTemplate: "text}}"}, {TextTemplate: strings.Repeat("{{org_name}}", 129)}, {TextTemplate: string([]byte{255})}, {TextTemplate: "x\x00y"}} {
		if _, e := ValidateServiceEmailTemplateV1(KindInvite, v); !errors.Is(e, ErrServiceEmailTemplateV1) {
			t.Fatal("invalid source accepted", e)
		}
	}
	if _, e := ValidateServiceEmailTemplateV1("staff.password-reset", ServiceEmailTemplateV1{}); e == nil {
		t.Fatal("staff auth template became editable")
	}
}
func TestServiceEmail720VariablesAreEscapedMissingAndNonrecursive(t *testing.T) {
	v, e := ValidateServiceEmailTemplateV1(KindInvite, ServiceEmailTemplateV1{SubjectTemplate: "{{document_name}}", HTMLTemplate: "<p>{{document_name}}</p>", TextTemplate: "{{document_name}}"})
	if e != nil {
		t.Fatal(e)
	}
	ctx := serviceEmailFixture720()
	ctx.DocumentName = "<b>&\"'{{org_name}}"
	s, h, p, e := RenderServiceEmailV1(KindInvite, ctx, &v)
	if e != nil {
		t.Fatal(e)
	}
	if s != ctx.DocumentName || !strings.Contains(h, "&lt;b&gt;&amp;&#34;&#39;{{org_name}}") || !strings.HasPrefix(p, ctx.DocumentName+"\n\n") {
		t.Fatal("variable was interpreted, recursively expanded or not escaped")
	}
	ctx.DocumentName = ""
	if _, _, _, e = RenderServiceEmailV1(KindInvite, ctx, &v); e != nil {
		t.Fatal("legitimate empty variable changed lifecycle semantics", e)
	}
	optional, e := ValidateServiceEmailTemplateV1(KindNewComment, ServiceEmailTemplateV1{TextTemplate: "From {{sender_email}} to {{recipient_name}}"})
	if e != nil {
		t.Fatal(e)
	}
	ctx.SenderEmail = ""
	ctx.RecipientName = ""
	_, _, empty, e := RenderServiceEmailV1(KindNewComment, ctx, &optional)
	if e != nil || !strings.HasPrefix(empty, "From  to \n\n") {
		t.Fatal("empty optional identity was invented or refused", e)
	}
	ctx.DocumentName = "injected\nheader"
	if _, _, _, e = RenderServiceEmailV1(KindInvite, ctx, &v); e == nil {
		t.Fatal("subject variable newline accepted")
	}
	ctx.DocumentName = strings.Repeat("z", 4097)
	if _, _, _, e = ServiceEmailTemplateComponentsV1(ctx, &v, 10, 10, 10); e == nil {
		t.Fatal("expanded subject cap ignored")
	}
}
func TestServiceEmail720RenderedRevisionDoesNotFollowLaterEdit(t *testing.T) {
	ctx := serviceEmailFixture720()
	v, e := ValidateServiceEmailTemplateV1(KindInvite, ServiceEmailTemplateV1{Revision: 1, HTMLTemplate: "<p>Reviewed edition one</p>", TextTemplate: "Reviewed edition one"})
	if e != nil {
		t.Fatal(e)
	}
	s, h, p, e := RenderServiceEmailV1(KindInvite, ctx, &v)
	if e != nil {
		t.Fatal(e)
	}
	queued := Message{Subject: s, HTML: h, Text: p}
	v.Revision = 2
	v.HTMLTemplate = "<p>Later edition two</p>"
	v.TextTemplate = "Later edition two"
	_, next, _, e := RenderServiceEmailV1(KindInvite, ctx, &v)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(queued.HTML, "edition two") || !strings.Contains(queued.HTML, "edition one") || !strings.Contains(next, "edition two") {
		t.Fatal("rendered content followed later template edit")
	}
}
func TestServiceEmail720CustomContentCannotRemoveNativeRequiredExpiry(t *testing.T) {
	v, e := ValidateServiceEmailTemplateV1(KindCompletedSigner, ServiceEmailTemplateV1{SubjectTemplate: "Complete", HTMLTemplate: "<p>Custom content</p>", TextTemplate: "Custom content"})
	if e != nil {
		t.Fatal(e)
	}
	c := serviceEmailFixture720()
	c.DownloadExpiresAt = ""
	if _, _, _, e = RenderServiceEmailV1(KindCompletedSigner, c, &v); e == nil {
		t.Fatal("custom content bypassed native completion expiry requirement")
	}
}
