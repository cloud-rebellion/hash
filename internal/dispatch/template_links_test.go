// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import "testing"

func TestEmailLinksRejectUnsafeSchemesOnBothRenderPaths(t *testing.T) {
	for _, kind := range []string{KindInvite, KindNewComment} {
		for _, value := range []string{"javascript:alert(1)", "data:text/html,test", "vbscript:msgbox(1)", "//attacker.example/path", "https://user:password@example.test/path", " https://example.test/path", "https://example.test/\npath", `https:\\example.test/path`} {
			for _, set := range []func(*TemplateContext, string){
				func(c *TemplateContext, v string) { c.SignURL = v }, func(c *TemplateContext, v string) { c.DownloadURL = v },
				func(c *TemplateContext, v string) { c.OpenURL = v }, func(c *TemplateContext, v string) { c.ApproveURL = v },
				func(c *TemplateContext, v string) { c.DenyURL = v }, func(c *TemplateContext, v string) { c.UpgradeURL = v },
			} {
				ctx := TemplateContext{DocumentName: "Agreement", SenderName: "Sender"}
				set(&ctx, value)
				subject, html, text, err := Render(kind, ctx)
				if err == nil || subject != "" || html != "" || text != "" {
					t.Fatalf("kind=%s unsafe link accepted", kind)
				}
			}
		}
	}
}

func TestEmailLinksPreserveApplicationURLs(t *testing.T) {
	for _, value := range []string{"https://hash.example/sign/token?x=1&y=2", "http://localhost:8090/sign/token", "/documents/123", "legacy-relative-link"} {
		if err := validateEmailLink(value); err != nil {
			t.Fatalf("valid link %q rejected: %v", value, err)
		}
	}
}
