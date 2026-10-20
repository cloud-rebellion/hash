// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"html/template"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
	"text/template/parse"
)

func TestCommentNotificationComponentsCoverActualRenderV1(t *testing.T) {
	values := []string{"", "Åsa 李", "&<>\"'\x00", string([]byte{0xff, 0xfe, '&', '<'}), strings.Repeat("&<>\"'Å", 8192)}
	links := []string{"", "/documents/00000000-0000-0000-0000-000000000001?approve=a&deny=b", "https://example.invalid/å/契約?x=a&y=\"'<>&"}
	for vi, value := range values {
		for li, link := range links {
			ctx := TemplateContext{RecipientName: value, DocumentName: value, ChangeContext: value, ChangeQuote: value,
				DeclineReason: value, ChangeProposed: value, ApproveURL: link, DenyURL: link, OpenURL: link}
			s, h, p, err := CommentNotificationComponentsV1(ctx)
			if err != nil {
				t.Fatal(err)
			}
			subject, html, text, err := Render(KindNewComment, ctx)
			if err != nil {
				t.Fatalf("case %d/%d actual render: %v", vi, li, err)
			}
			if s < int64(len(subject)) || h < int64(len(html)) || p < int64(len(text)) || s <= 0 || h <= 0 || p <= 0 {
				t.Fatalf("case %d/%d actual output %d/%d/%d exceeds %d/%d/%d", vi, li, len(subject), len(html), len(text), s, h, p)
			}
			if s != int64(len(subject)) {
				t.Fatalf("case %d/%d subject multiplicity changed", vi, li)
			}
		}
	}
}

func TestCommentNotificationKeepsOriginalURLPolicyV1(t *testing.T) {
	for _, link := range []string{"javascript:alert(1)", "//example.invalid/x", "https://u:p@example.invalid/", "https://example.invalid/\n"} {
		ctx := TemplateContext{OpenURL: link}
		if _, _, _, err := CommentNotificationComponentsV1(ctx); err != nil {
			t.Fatalf("arithmetic must leave original URL decision to Render: %v", err)
		}
		if _, _, _, err := Render(KindNewComment, ctx); err == nil {
			t.Fatal("original render accepted invalid URL")
		}
	}
}

func TestCommentNotificationUnusedContextStaysUnusedV1(t *testing.T) {
	a := TemplateContext{RecipientName: "Signer", DocumentName: "Contract", OpenURL: "/documents/id"}
	b := a
	b.Locale, b.OrgName, b.SenderName, b.SenderEmail, b.BrandColor = "sv", "ignored org", "ignored sender", "ignored email", "ignored color"
	b.Acknowledgement, b.InternalOperator = true, true
	as, ah, ap, ae := CommentNotificationComponentsV1(a)
	bs, bh, bp, be := CommentNotificationComponentsV1(b)
	if ae != nil || be != nil || as != bs || ah != bh || ap != bp {
		t.Fatal("unrendered metadata changed logical output sizes")
	}
	s1, h1, p1, e1 := Render(KindNewComment, a)
	s2, h2, p2, e2 := Render(KindNewComment, b)
	if e1 != nil || e2 != nil || s1 != s2 || h1 != h2 || p1 != p2 {
		t.Fatal("notification now renders additional context; revise its bound")
	}
}

func TestCommentNotificationCheckedBoundaryV1(t *testing.T) {
	if n, err := addCommentNotificationBytesV1(17, (math.MaxInt64-17)/18, 18); err != nil || n <= 0 {
		t.Fatal("last representable URL charge refused")
	}
	for _, input := range [][3]int64{{17, (math.MaxInt64-17)/18 + 1, 18}, {math.MaxInt64, 1, 1}, {-1, 0, 1}, {0, -1, 1}, {0, 1, 0}} {
		if n, err := addCommentNotificationBytesV1(input[0], input[1], input[2]); err == nil || n != 0 {
			t.Fatal("invalid or overflowing charge accepted")
		}
	}
}

// This is a semantic template guard: any repetition, additional interpolation,
// helper pipeline or different rendering context requires the bound to change.
// No snapshot hash makes unrelated prose edits invalidate it.
func TestCommentNotificationActualTemplateShapeV1(t *testing.T) {
	want := map[string]int{"RecipientName": 1, "DocumentName": 1, "DeclineReason": 1, "OpenURL": 1}
	wantIf := map[string]int{"OpenURL": 1}
	for _, input := range []struct{ name, source string }{{"html", htmlFor(KindNewComment)}, {"text", textFor(KindNewComment)}} {
		t.Run(input.name, func(t *testing.T) {
			tpl, err := template.New(input.name).Parse(input.source)
			if err != nil {
				t.Fatal(err)
			}
			fields, conditions := map[string]int{}, map[string]int{}
			afterEscape := false
			field := func(pipe *parse.PipeNode, condition bool) string {
				if pipe == nil || len(pipe.Decl) != 0 || len(pipe.Cmds) < 1 || len(pipe.Cmds[0].Args) != 1 {
					t.Fatal("template gained a variable or helper pipeline")
				}
				f, ok := pipe.Cmds[0].Args[0].(*parse.FieldNode)
				if !ok || len(f.Ident) != 1 {
					t.Fatal("template gained a non-context interpolation")
				}
				var escapers []string
				if afterEscape && !condition {
					escapers = []string{"_html_template_htmlescaper"}
					if input.name == "html" && strings.HasSuffix(f.Ident[0], "URL") {
						escapers = []string{"_html_template_urlfilter", "_html_template_urlnormalizer", "_html_template_attrescaper"}
					}
				}
				if len(pipe.Cmds) != 1+len(escapers) {
					t.Fatal("template gained a helper or changed escaping context")
				}
				for i, name := range escapers {
					command := pipe.Cmds[i+1]
					if len(command.Args) != 1 {
						t.Fatal("unexpected escaping arguments")
					}
					id, ok := command.Args[0].(*parse.IdentifierNode)
					if !ok || id.Ident != name {
						t.Fatalf("%s changed its actual escaping context", f.Ident[0])
					}
				}
				return f.Ident[0]
			}
			var walk func(parse.Node)
			walk = func(node parse.Node) {
				switch n := node.(type) {
				case *parse.ListNode:
					if n != nil {
						for _, child := range n.Nodes {
							walk(child)
						}
					}
				case *parse.TextNode:
				case *parse.ActionNode:
					fields[field(n.Pipe, false)]++
				case *parse.IfNode:
					conditions[field(n.Pipe, true)]++
					walk(n.List)
					walk(n.ElseList)
				default:
					t.Fatalf("unsupported template node %T", n)
				}
			}
			walk(tpl.Tree.Root)
			if !reflect.DeepEqual(fields, want) || !reflect.DeepEqual(conditions, wantIf) {
				t.Fatalf("actual interpolation/condition multiplicities changed: %v / %v", fields, conditions)
			}
			if err := tpl.Execute(io.Discard, TemplateContext{}); err != nil {
				t.Fatal(err)
			}
			afterEscape = true
			fields, conditions = map[string]int{}, map[string]int{}
			walk(tpl.Tree.Root)
			if !reflect.DeepEqual(fields, want) || !reflect.DeepEqual(conditions, wantIf) {
				t.Fatal("escaped template multiplicities changed")
			}
			if input.name == "html" {
				for name := range want {
					if strings.HasSuffix(name, "URL") {
						if strings.Count(input.source, `href="{{.`+name+`}}"`) != 1 {
							t.Fatalf("%s moved from its single quoted URL attribute", name)
						}
					}
				}
			}
		})
	}
}

func TestCommentNotificationTemplateSourcesMatchV1(t *testing.T) {
	if CommentNotificationTemplateSourceBytesV1() != int64(len(htmlFor(KindNewComment))+len(textFor(KindNewComment))) {
		t.Fatal("template parsing source credit changed")
	}
}
