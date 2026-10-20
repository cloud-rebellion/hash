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

func TestReminderNotificationFixedMarkupCoversActualLocalizedSkeletonV1(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "templates.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	markup, found := 0, false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "localizedHTML" {
			continue
		}
		found = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if ok && lit.Kind == token.STRING {
				text, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(text, "<") {
					markup += len(text)
				}
			}
			return true
		})
	}
	if !found || markup > max(len(reminderHTML), len(inviteHTML)) {
		t.Fatalf("actual localized markup %d exceeds fixed reminder quote", markup)
	}
}

func TestReminderNotificationComponentsCoverOriginalRenderV1(t *testing.T) {
	for _, locale := range []string{"", "unknown", "en", "sv", "da", "nb", "fi", "de", "fr", "es", "it", "nl", "pt", "pl", "cs", "sk", "sl", "hr", "hu", "ro", "bg", "el", "et", "lv", "lt", "ga", "mt"} {
		for _, ack := range []bool{false, true} {
			for _, value := range []string{"", "ordinary value", "<&>\"'\x00\xff Å界 {sender}{document}", strings.Repeat("&<Å", 500)} {
				ctx := TemplateContext{Locale: locale, Acknowledgement: ack, DocumentName: value, SenderName: value, SenderEmail: value, RecipientName: value, OrgName: value, SignURL: "https://example.test/sign/a?x=1&y=%22", BeaconURL: strings.Repeat("ignored", 1000)}
				a, b, c, err := ReminderNotificationComponentsV1(ctx)
				if err != nil {
					t.Fatal(err)
				}
				x, y, z, err := Render(KindReminder, ctx)
				if err != nil {
					t.Fatal(err)
				}
				if a < int64(len(x)) || b < int64(len(y)) || c < int64(len(z)) {
					t.Fatalf("locale=%q ack=%v bounds=%d/%d/%d actual=%d/%d/%d", locale, ack, a, b, c, len(x), len(y), len(z))
				}
			}
		}
	}
}
