// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package dispatch

import (
	"fmt"
	"html"
	"strings"
	"testing"
)

func changeRequestDesignContextV1() TemplateContext {
	return TemplateContext{DocumentName: "Förslag & leverans", RecipientName: "Åsa", Locale: "sv",
		ChangeContext: "Sammanhanget behålls i sin helhet.\nAndra raden.",
		ChangeQuote:   "Den markerade texten <med villkor> & detaljer.",
		DeclineReason: "Min kommentar: behåll all text.", ChangeProposed: "Föreslagen lydelse med samma omfattning.",
		OpenURL: "https://example.invalid/documents/example?x=1&y=2", ApproveURL: "https://example.invalid/a/cr?t=approve", DenyURL: "https://example.invalid/a/cr?t=deny"}
}

func TestChangeRequestDesignUsesExplicitNotificationLocaleV1(t *testing.T) {
	c := changeRequestDesignContextV1()
	subject, body, text, err := Render(KindChangesRequested, c)
	if err != nil {
		t.Fatal(err)
	}
	if subject != "Åsa har begärt ändringar i Förslag & leverans" {
		t.Fatal("Swedish subject missing", subject)
	}
	for _, want := range []string{"Ändringar begärda", "Sammanhang", "Markerad text", "Kommentar", "Föreslagen text", "Öppna dokumentet", "Godkänn", "Avvisa", "Signeringen är pausad"} {
		if !strings.Contains(body, want) {
			t.Fatalf("Swedish label %q missing", want)
		}
	}
	for _, old := range []string{"Changes requested", "In context", "Marked text", "Their comment", ">Approve<", ">Deny<", "Open document", "Signing is paused"} {
		if strings.Contains(body, old) {
			t.Fatalf("mixed-language label %q", old)
		}
	}
	for _, value := range []string{c.ChangeContext, c.ChangeQuote, c.DeclineReason, c.ChangeProposed} {
		escaped := html.EscapeString(value)
		if strings.Count(body, escaped) != 1 || strings.Count(text, escaped) != 1 {
			t.Fatal("request text removed, shortened, duplicated or reinterpreted", value)
		}
	}
	c.Locale = "en"
	enSubject, enBody, enText, err := Render(KindChangesRequested, c)
	if err != nil || enSubject != "Åsa requested changes to Förslag & leverans" || !strings.Contains(enBody, "Marked text") || !strings.Contains(enText, "Open document:") {
		t.Fatal("English fallback broken", err)
	}
	c.Locale = "unknown"
	fallbackSubject, fallbackBody, fallbackText, err := Render(KindChangesRequested, c)
	if err != nil || fallbackSubject != enSubject || fallbackBody != enBody || fallbackText != enText {
		t.Fatal("unknown notification locale did not keep English fallback", err)
	}
}

func TestChangeRequestDesignKeepsCapabilitiesAndEscapingV1(t *testing.T) {
	c := changeRequestDesignContextV1()
	c.RecipientName = `<script>alert("recipient")</script>`
	c.ChangeQuote = `<img src="https://evil.invalid/pixel" onerror="alert(1)">`
	_, body, _, err := Render(KindChangesRequested, c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "<script>") || strings.Contains(body, "<img ") || !strings.Contains(body, html.EscapeString(c.ChangeQuote)) {
		t.Fatal("request content became active HTML")
	}
	for _, link := range []string{c.OpenURL, c.ApproveURL, c.DenyURL} {
		if strings.Count(body, `href="`+html.EscapeString(link)+`"`) != 1 {
			t.Fatal("native action URL changed or duplicated")
		}
	}
	c.ApproveURL, c.DenyURL = "", ""
	_, body, _, err = Render(KindChangesRequested, c)
	if err != nil || strings.Contains(body, ">Godkänn</a>") || strings.Contains(body, ">Avvisa</a>") {
		t.Fatal("unavailable actions gained controls", err)
	}
	if strings.Count(body, `href="`+html.EscapeString(c.OpenURL)+`"`) != 1 {
		t.Fatal("open action lost")
	}
}

func TestChangeRequestDesignBoundsAndWorkspaceThemeV1(t *testing.T) {
	for _, locale := range []string{"en", "sv", "unknown"} {
		t.Run(locale, func(t *testing.T) {
			c := changeRequestDesignContextV1()
			c.Locale = locale
			s, h, p, err := ChangeRequestNotificationComponentsV1(c)
			if err != nil {
				t.Fatal(err)
			}
			subject, body, text, err := Render(KindChangesRequested, c)
			if err != nil || s != int64(len(subject)) || h < int64(len(body)) || p < int64(len(text)) {
				t.Fatal("localized native output exceeds original owned bound", err)
			}
			for _, dark := range []bool{false, true} {
				d := DefaultServiceEmailDesignV1()
				d.Primary = "#ff4b00"
				if dark {
					d.Background = "#111111"
					d.Surface = "#151515"
					d.Text = "#fffcf4"
				}
				raw := designJSON760(t, d)
				tpl := &ServiceEmailTemplateV1{Revision: 1, DesignJSON: raw}
				bs, bh, bt, err := ServiceEmailTemplateComponentsV1(KindChangesRequested, c, tpl, s, h, p)
				if err != nil {
					t.Fatal(err)
				}
				got, themed, plain, err := RenderServiceEmailV1(KindChangesRequested, c, tpl)
				if err != nil || got != subject || plain != text || bs < int64(len(got)) || bh < int64(len(themed)) || bt < int64(len(plain)) {
					t.Fatal("workspace design changed native copy or exceeded bound", err)
				}
				if strings.Contains(strings.ToLower(themed), "#0891b2") || !strings.Contains(themed, "background-color:"+d.Primary) {
					t.Fatal("legacy accent or workspace primary ignored")
				}
				for _, link := range []string{c.OpenURL, c.ApproveURL, c.DenyURL} {
					if strings.Count(themed, `href="`+html.EscapeString(link)+`"`) != 1 {
						t.Fatal("workspace design altered native actions")
					}
				}
			}
		})
	}
}

func TestChangeRequestDesignFullRequestSurvivesLongWordsV1(t *testing.T) {
	c := changeRequestDesignContextV1()
	for _, locale := range []string{"en", "sv"} {
		c.Locale = locale
		c.ChangeContext = strings.Repeat("kundvillkor", 80)
		c.ChangeQuote = strings.Repeat("Detta är hela texten och får inte kortas. ", 30)
		_, body, text, err := Render(KindChangesRequested, c)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{c.ChangeContext, c.ChangeQuote} {
			if !strings.Contains(body, html.EscapeString(value)) || !strings.Contains(text, html.EscapeString(value)) {
				t.Fatal("full request text lost", fmt.Sprint(len(value)))
			}
		}
	}
}
