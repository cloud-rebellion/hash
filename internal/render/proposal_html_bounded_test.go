// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"errors"
	"html"
	"strings"
	"testing"
)

func TestBoundedDesignedHTMLPublicBoundaryV1(t *testing.T) {
	exact := strings.Repeat("x", MaxDesignedHTMLBytes)
	got, err := SanitizeForRenderBoundedV1(exact)
	if err != nil || got != exact {
		t.Fatalf("exact public input refused: bytes=%d err=%v", len(got), err)
	}
	if got, err := SanitizeForRenderBoundedV1(exact + "x"); !errors.Is(err, ErrDesignedHTMLTooLarge) || got != "" {
		t.Fatalf("raw cap+1: %d %v", len(got), err)
	}
}
func TestBoundedDesignedHTMLGrowingOutputsV1(t *testing.T) {
	tests := []struct {
		name, input string
		limit       int
	}{
		{"attribute escaping", `<img src="/secret" alt="` + strings.Repeat("&", 24) + `">`, 90},
		{"inline CSS", `<p style="a:url(/);b:url(/);c:url(/)">x</p>`, 60},
		{"style element", `<style>a{b:url(/);c:url(/);d:url(/)}</style>`, 65},
		{"style aggregate", `<style>a{b:url(/)}</style><style>c{d:url(/)}</style>`, 60},
		{"malformed CSS", `<style>` + strings.Repeat("x", 28) + `;url(</style>`, 50},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.input) > tc.limit {
				t.Fatal("fixture must overflow during production")
			}
			if len(SanitizeForRender(tc.input)) <= tc.limit {
				t.Fatal("legacy fixture does not expand across boundary")
			}
			if got, err := sanitizeForRenderLimitV1(tc.input, tc.limit); !errors.Is(err, ErrDesignedHTMLTooLarge) || got != "" {
				t.Fatalf("growing output escaped bound: %d %v", len(got), err)
			}
		})
	}
}
func TestBoundedDesignedHTMLEscapingAndUnicodeV1(t *testing.T) {
	for _, input := range []string{"&'<>\"é🖊", strings.Repeat("&", 100), "text", string([]byte{0xff, '&'})} {
		budget := &renderTextBudgetV1{limit: 2048}
		b := newRenderTextBuilderV1(budget)
		b.WriteEscapedString(input)
		if got, want := b.String(), html.EscapeString(input); got != want || budget.err != nil {
			t.Fatalf("escaped bytes differ: %q / %q, %v", got, want, budget.err)
		}
	}
	for _, input := range []string{
		`<STYLE>p{color:red}</STYLE>tail<style>x{background:url(/)}</style>`,
		`<img src="/secret" alt="A&é&#39; &quot;🖊">`,
		`<p style="content:'\e9';background:u\72l(/)">x</p>`,
		`<style>.x{background:url('data:image/svg+xml;a(b)')}</style>`,
	} {
		got, err := SanitizeForRenderBoundedV1(input)
		if err != nil || got != SanitizeForRender(input) {
			t.Fatalf("accepted legacy output changed: %v %q", err, got)
		}
	}
}
func TestBoundedDesignedHTMLWriterNeverAppendsOverflowV1(t *testing.T) {
	budget := &renderTextBudgetV1{limit: 4}
	b := newRenderTextBuilderV1(budget)
	b.WriteString("abcd")
	b.WriteRune('é')
	b.WriteString("later")
	if !errors.Is(budget.err, ErrDesignedHTMLTooLarge) || b.b.Len() != 4 || b.String() != "" {
		t.Fatal("overflow emitted partial/grown output")
	}
}

func TestDesignedHTMLStyleUnicodeByteOffsetV1(t *testing.T) {
	for _, tag := range []string{"style", "STYLE", "StYlE"} {
		input := "<" + tag + ">" + strings.Repeat("Ⱥ", 9) + "</" + tag + ">"
		if got := SanitizeForRender(input); got != input {
			t.Fatalf("legacy Unicode style changed: %q", got)
		}
		if got, err := SanitizeForRenderBoundedV1(input); err != nil || got != input {
			t.Fatalf("bounded Unicode style: %q %v", got, err)
		}
	}
}
