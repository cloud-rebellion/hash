// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package dispatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"html"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

func designJSON760(t *testing.T, d ServiceEmailDesignV1) string {
	t.Helper()
	raw, e := json.Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	s, e := CanonicalServiceEmailDesignV1(string(raw))
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func designLogo760(t *testing.T) *htmlmaster.Asset {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.NRGBA{R: 34, G: 80, B: 180, A: 255})
		}
	}
	var b bytes.Buffer
	if e := png.Encode(&b, img); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(b.Bytes())
	return &htmlmaster.Asset{Name: "logo", MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString(b.Bytes()), SHA256: hex.EncodeToString(sum[:])}
}
func designContext760() TemplateContext {
	return TemplateContext{DocumentName: "Synthetic & <contract>", SenderName: "Sender", SenderEmail: "sender@example.invalid", RecipientName: "Recipient", OrgName: "Workspace", Locale: "en", SignURL: "https://example.invalid/sign/test", DownloadURL: "https://example.invalid/completed/test", AuditCertURL: "https://example.invalid/audit/test", PackagePortalURL: "https://example.invalid/package/test", DownloadExpiresAt: "2030-01-01T12:00:00Z", OpenURL: "https://example.invalid/documents/test", ApproveURL: "https://example.invalid/approve/test", DenyURL: "https://example.invalid/deny/test"}
}
func TestEmailDesign760CanonicalFullLayoutAndNativeContent(t *testing.T) {
	d := DefaultServiceEmailDesignV1()
	d.Logo = designLogo760(t)
	d.LogoAlt = `Example "logo"`
	d.LayoutHTML = `<table role="presentation" style="width:100%;background-color:#ffffff;"><tbody><tr><td style="padding:24px;">{{logo}}<h1>{{org_name}}</h1><div>{{native_content}}</div><p>Our footer</p></td></tr></tbody></table>`
	raw := designJSON760(t, d)
	again, e := CanonicalServiceEmailDesignV1(raw)
	if e != nil || again != raw {
		t.Fatal("canonical design drift", e)
	}
	for _, kind := range []string{KindInvite, KindReminder, KindCompletedSigner, KindCompletedSender, KindChangesRequested, KindNewComment} {
		t.Run(kind, func(t *testing.T) {
			c := designContext760()
			subject, base, text, e := Render(kind, c)
			if e != nil {
				t.Fatal(e)
			}

			tpl := &ServiceEmailTemplateV1{Revision: 1, DesignJSON: raw}
			got, body, plain, e := RenderServiceEmailV1(kind, c, tpl)
			if e != nil {
				t.Fatal(e)
			}
			if got != subject || plain != themeServiceEmailPlainFooterV1(c, text) || !strings.Contains(body, "Our footer") || !strings.Contains(body, "data-hash-logo=\"") {
				t.Fatal("native subject/body/actions/plaintext or full authored layout lost")
			}
			if strings.Contains(body, serviceEmailNativeSlotV1) || strings.Contains(body, serviceEmailLogoSlotV1) || !strings.Contains(body, "data:image/png;base64,"+d.Logo.DataBase64) {
				t.Fatal("logo/native slot not materialized")
			}
			s, h, pt, e := ServiceEmailTemplateComponentsV1(c, tpl, int64(len(subject)), int64(len(base)), int64(len(text)))
			if e != nil || s < int64(len(got)) || h < int64(len(body)) || pt < int64(len(plain)) {
				t.Fatal("design output was not priced before expansion", s, h, pt, e)
			}
		})
	}
}
func TestEmailDesign760EmptyEditionRetainsExactLegacyBytes(t *testing.T) {
	for _, kind := range ServiceEmailKindsV1() {
		t.Run(kind, func(t *testing.T) {
			c := designContext760()
			s, h, txt, e := Render(kind, c)
			if e != nil {
				t.Fatal(e)
			}
			actual, b, plain, e := RenderServiceEmailV1(kind, c, &ServiceEmailTemplateV1{})
			if e != nil || actual != s || b != h || plain != txt {
				t.Fatal("empty design changed original content", e)
			}
			if ServiceEmailDesignDigestV1("") != nil {
				t.Fatal("legacy design gained a commitment")
			}
		})
	}
}
func TestEmailDesign760RefusesHiddenOrRemovableNativeSlot(t *testing.T) {
	for _, layout := range []string{`<p>No native actions</p>`, `<div>{{native_content}}{{native_content}}</div>`, `<p>{{native_content}}</p>`, `<div style="display:none;">{{native_content}}</div>`, `<div style="opacity:0;">{{native_content}}</div>`, `<div style="height:0;">{{native_content}}</div>`, `<div style="overflow:hidden;">{{native_content}}</div>`, `<div style="position:absolute;">{{native_content}}</div>`, `<div style="width:0;">{{native_content}}</div>`, `<div style="font-size:0;">{{native_content}}</div>`, `<div onclick="alert(1)">{{native_content}}</div>`, `<script>{{native_content}}</script>`, `<img src="https://tracker.invalid/open"><div>{{native_content}}</div>`, `<div style="background-image:url(https://tracker.invalid)">{{native_content}}</div>`, `<div>{{unknown}}</div><div>{{native_content}}</div>`, `<!--{{native_content}}--><div>Hidden</div>`} {
		t.Run(layout, func(t *testing.T) {
			d := DefaultServiceEmailDesignV1()
			d.LayoutHTML = layout
			raw, _ := json.Marshal(d)
			if _, e := CanonicalServiceEmailDesignV1(string(raw)); e == nil {
				t.Fatal("unsafe authored layout accepted")
			}
		})
	}
}
func TestEmailDesign760AssetDigestBoundsAndClosedJSON(t *testing.T) {
	d := DefaultServiceEmailDesignV1()
	d.Logo = designLogo760(t)
	d.LogoAlt = "Logo"
	good := designJSON760(t, d)
	for _, mutate := range []func(*ServiceEmailDesignV1){func(d *ServiceEmailDesignV1) { d.Logo.SHA256 = strings.Repeat("0", 64) }, func(d *ServiceEmailDesignV1) { d.Logo.MediaType = "image/svg+xml" }, func(d *ServiceEmailDesignV1) { d.Logo.DataBase64 = "https://tracker.invalid/logo.png" }, func(d *ServiceEmailDesignV1) { d.LayoutHTML = `<div>{{native_content}}</div>` }, func(d *ServiceEmailDesignV1) { d.Surface = "#ffffff"; d.Text = "#ffffff" }} {
		var next ServiceEmailDesignV1
		_ = json.Unmarshal([]byte(good), &next)
		mutate(&next)
		raw, _ := json.Marshal(next)
		if _, e := CanonicalServiceEmailDesignV1(string(raw)); e == nil {
			t.Fatal("bad logo/contrast accepted")
		}
	}
	for _, raw := range []string{`null`, `{"schema_version":1,"schema_version":1}`, strings.TrimSuffix(good, "}") + `,"unexpected":true}`, strings.TrimSuffix(good, "}") + `,"\u0073chema_version":1}`} {
		if _, e := CanonicalServiceEmailDesignV1(raw); e == nil {
			t.Fatal("ambiguous or unknown design field accepted")
		}
	}
	d = DefaultServiceEmailDesignV1()
	d.LayoutHTML = `<div>{{native_content}}</div>`
	raw := designJSON760(t, d)
	if len(ServiceEmailDesignDigestV1(raw)) != 32 {
		t.Fatal("exact canonical design digest missing")
	}
}

func TestEmailDesign760LightDarkNativeReadabilityCTAAndWhiteLabel(t *testing.T) {
	for _, dark := range []bool{false, true} {
		for _, locale := range []string{"en", "sv"} {
			t.Run(fmt.Sprintf("dark=%v/%s", dark, locale), func(t *testing.T) {
				d := DefaultServiceEmailDesignV1()
				d.Primary = "#7c3aed"
				if dark {
					d.Background = "#020617"
					d.Surface = "#0f172a"
					d.Text = "#e2e8f0"
				}
				raw := designJSON760(t, d)
				c := designContext760()
				c.Locale = locale
				c.SignURL = "https://example.invalid/sign/t?one=1&two=2"
				_, legacy, _, e := Render(KindInvite, c)
				if e != nil {
					t.Fatal(e)
				}
				_, body, plain, e := RenderServiceEmailV1(KindInvite, c, &ServiceEmailTemplateV1{DesignJSON: raw})
				if e != nil {
					t.Fatal(e)
				}
				if !strings.Contains(body, `href="`+html.EscapeString(c.SignURL)+`"`) || !strings.Contains(plain, c.SignURL) {
					t.Fatal("the actual native action URL changed")
				}
				if !strings.Contains(body, "background:"+d.Primary+";color:"+emailDesignCTAColorV1(d.Primary)) {
					t.Fatal("primary does not theme the actual native CTA")
				}
				if emailDesignContrastV1(d.Primary, emailDesignCTAColorV1(d.Primary)) < 4.5 || emailDesignContrastV1(d.Surface, d.Text) < 4.5 {
					t.Fatal("unreadable native contrast")
				}
				if strings.Contains(body, "color: #777") || strings.Contains(body, "color: #999") || strings.Contains(body, "color:#555") {
					t.Fatal("old muted native styles leaked into explicit theme")
				}
				for _, old := range emailDesignOldFootersV1(c) {
					if strings.Contains(body, html.EscapeString(old)) || strings.Contains(plain, old) {
						t.Fatal("custom design still displays vendor presentation footer")
					}
				}
				if !strings.Contains(body, c.OrgName) || !strings.Contains(plain, c.OrgName) || !strings.Contains(legacy, "Hash") {
					t.Fatal("branding/legacy boundary lost")
				}
			})
		}
	}
}
