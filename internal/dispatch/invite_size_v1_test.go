// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/i18n"
)

func TestInviteNotificationComponentsCoverOriginalRenderV1(t *testing.T) {
	locales := []string{"", "unknown", "en", "sv", "da", "nb", "fi", "de", "fr", "es", "it", "nl", "pt", "pl", "cs", "sk", "sl", "hr", "hu", "ro", "bg", "el", "et", "lv", "lt", "ga", "mt"}
	for _, locale := range locales {
		for _, ack := range []bool{false, true} {
			for _, value := range []string{"", "normal value", "<&>\"'\x00\xff Å界 {sender}{document}", strings.Repeat("&<Å", 500)} {
				ctx := TemplateContext{Locale: locale, Acknowledgement: ack, DocumentName: value, SenderName: value, SenderEmail: value, RecipientName: value, OrgName: value, SignURL: "https://example.test/sign/a?x=1&y=%22", BeaconURL: strings.Repeat("ignored", 1000)}
				s, h, p, err := InviteNotificationComponentsV1(ctx)
				if err != nil {
					t.Fatal(err)
				}
				subject, html, text, err := Render(KindInvite, ctx)
				if err != nil {
					t.Fatal(err)
				}
				if s < int64(len(subject)) || h < int64(len(html)) || p < int64(len(text)) {
					t.Fatalf("locale=%q ack=%v bounds=%d/%d/%d actual=%d/%d/%d", locale, ack, s, h, p, len(subject), len(html), len(text))
				}
			}
		}
	}
}
func TestInviteNotificationComponentsBindLocalizedSkeletonV1(t *testing.T) {
	// Independent original-source topology: sum every fixed string literal in
	// localizedHTML containing emitted markup. This includes all three Sprintf
	// skeletons and overcounts their %s placeholders. It must fit the fixed
	// fallback markup allowance used by the production component.
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
	if !found || literals > len(inviteHTML) {
		t.Fatalf("localized markup %d exceeds fixed allowance %d", literals, len(inviteHTML))
	}
	for _, ack := range []bool{false, true} {
		ctx := TemplateContext{Locale: "en", Acknowledgement: ack, SignURL: "https://example.test/s"}
		_, html, _, err := Render(KindInvite, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if html == "" {
			t.Fatal("original localized render was empty")
		}
		// BeaconURL has no output role. It must not add a large artificial allowance.
		a, b, c, err := InviteNotificationComponentsV1(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ctx.BeaconURL = strings.Repeat("x", 1<<20)
		x, y, z, err := InviteNotificationComponentsV1(ctx)
		if err != nil || a != x || b != y || c != z {
			t.Fatal("ignored pre-notice tracking field changed invite output allowance")
		}
		if !i18n.Has("en") {
			t.Fatal("original English fallback missing")
		}
	}
	for _, ctx := range []TemplateContext{{SignURL: "javascript:bad"}, {SignURL: "https://example.test/a\n"}} {
		if _, _, _, err := InviteNotificationComponentsV1(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := Render(KindInvite, ctx); err == nil {
			t.Fatal("sizing bypassed original URL acceptance")
		}
	}
}
func TestInviteNotificationCheckedArithmeticV1(t *testing.T) {
	for _, v := range [][3]int64{{-1, 0, 1}, {0, -1, 1}, {0, 1, -1}, {math.MaxInt64, 1, 1}, {0, math.MaxInt64, 2}} {
		if _, err := inviteAddBytesV1(v[0], v[1], v[2]); err == nil {
			t.Fatal("invalid/overflow logical component accepted")
		}
	}
	if got, err := inviteAddBytesV1(math.MaxInt64-1, 1, 1); err != nil || got != math.MaxInt64 {
		t.Fatal("exact boundary refused")
	}
}
