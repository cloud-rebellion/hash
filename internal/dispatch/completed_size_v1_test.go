// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestCompletedNotificationComponentsCoverOriginalRenderV1(t *testing.T) {
	for _, kind := range []string{KindCompletedSigner, KindCompletedSender} {
		for _, locale := range []string{"", "unknown", "en", "sv", "da", "nb", "fi", "de", "fr", "es", "it", "nl", "pt", "pl", "cs", "sk", "sl", "hr", "hu", "ro", "bg", "el", "et", "lv", "lt", "ga", "mt"} {
			for _, ack := range []bool{false, true} {
				for _, value := range []string{"", "ordinary", "<&>\"'\x00\xff Å界 {sender}{document}", strings.Repeat("&<Å", 500)} {
					ctx := TemplateContext{Locale: locale, Acknowledgement: ack, DocumentName: value, SenderName: value, SenderEmail: value, RecipientName: value, OrgName: value, DownloadExpiresAt: "2030-01-02T03:04:05Z", DownloadURL: "https://example.test/sign/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/final-pdf?x=1&y=%22", AuditCertURL: "https://example.test/sign/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/audit-cert?x=1&y=%22", PackagePortalURL: "https://example.test/completed/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?x=1&y=%22"}
					s, h, p, err := CompletedNotificationComponentsV1(kind, ctx)
					if err != nil {
						t.Fatal(err)
					}
					subject, html, text, err := Render(kind, ctx)
					if err != nil {
						t.Fatal(err)
					}
					if s < int64(len(subject)) || h < int64(len(html)) || p < int64(len(text)) {
						t.Fatalf("kind=%s locale=%q ack=%v bound=%d/%d/%d actual=%d/%d/%d", kind, locale, ack, s, h, p, len(subject), len(html), len(text))
					}
				}
			}
		}
	}
}
func TestCompletedNotificationBoundsBindOriginalTopologyV1(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "templates.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	literals := 0
	found := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "localizedHTML" {
			continue
		}
		found = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if branch, ok := n.(*ast.IfStmt); ok {
				if condition, ok := branch.Cond.(*ast.BinaryExpr); ok {
					left, lok := condition.X.(*ast.Ident)
					right, rok := condition.Y.(*ast.Ident)
					if lok && rok && left.Name == "kind" && right.Name == "KindInvite" {
						return false
					}
				}
			}
			literal, ok := n.(*ast.BasicLit)
			if ok && literal.Kind == token.STRING {
				value, e := strconv.Unquote(literal.Value)
				if e != nil {
					t.Fatal(e)
				}
				if strings.Contains(value, "<") {
					literals += len(value)
				}
			}
			return true
		})
	}
	if !found || literals > len(completedSignerHTML) {
		t.Fatalf("actual completed localized skeleton=%d allowance=%d", literals, len(completedSignerHTML))
	}
	for _, src := range []string{completedSenderHTML, completedSenderText} {
		if strings.Count(src, "{{.DocumentName}}") != 2 || strings.Count(src, "{{.DownloadURL}}") != 1 || strings.Count(src, "{{.AuditCertURL}}") != 1 {
			t.Fatal("sender insertion topology changed; update concrete bounds")
		}
	}
	if !strings.Contains(completedSenderHTML, "href=\"{{.DownloadURL}}\"") {
		t.Fatal("sender URL output context changed")
	}
	for _, ctx := range []TemplateContext{{DownloadURL: "javascript:bad", DownloadExpiresAt: "2030-01-02T03:04:05Z"}, {DownloadURL: "https://example.test/a\n", DownloadExpiresAt: "2030-01-02T03:04:05Z"}, {DownloadURL: "https://example.test/a"}} {
		if _, _, _, err := CompletedNotificationComponentsV1(KindCompletedSigner, ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := Render(KindCompletedSigner, ctx); err == nil {
			t.Fatal("sizing bypassed original URL or missing-expiry refusal")
		}
	}
	if _, _, _, err := CompletedNotificationComponentsV1(KindInvite, TemplateContext{}); err == nil {
		t.Fatal("completion bound became a universal kind parser")
	}
}
