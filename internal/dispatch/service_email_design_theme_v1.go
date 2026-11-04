// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package dispatch

import (
	"github.com/bright-interaction/hash/internal/i18n"
	nethtml "golang.org/x/net/html"
	"html"
	"io"
	"regexp"
	"strings"
)

var trustedEmailStyleAttributeV1 = regexp.MustCompile(`\bstyle="([^"]*)"`)

func emailDesignBrandV1(c TemplateContext) string {
	if c.OrgName != "" {
		return c.OrgName
	}
	if c.SenderName != "" {
		return c.SenderName
	}
	if c.SenderEmail != "" {
		return c.SenderEmail
	}
	return "Document service"
}
func emailDesignOldFootersV1(c TemplateContext) []string {
	p := emailParams(c)
	loc := i18n.Normalize(c.Locale)
	return []string{"Sent via Hash for " + c.OrgName + ".", i18n.T(loc, "email.common.footer", p), i18n.T(loc, "email.invite.footer", p), i18n.T(loc, "email.completedSigner.footer", p)}
}
func emailDesignCTAColorV1(primary string) string {
	if emailDesignContrastV1(primary, "#000000") >= emailDesignContrastV1(primary, "#ffffff") {
		return "#000000"
	}
	return "#ffffff"
}
func emailDesignNativeStyleV1(style, tag string, d ServiceEmailDesignV1) string {
	parts := strings.Split(style, ";")
	button := tag == "a" && (strings.Contains(style, "background:") || strings.Contains(style, "background-color:"))
	link := d.Primary
	if emailDesignContrastV1(link, d.Surface) < 4.5 {
		link = d.Text
	}
	seenColor := false
	out := make([]string, 0, len(parts)+2)
	for _, part := range parts {
		pair := strings.SplitN(part, ":", 2)
		if len(pair) != 2 {
			continue
		}
		key, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		switch key {
		case "color":
			seenColor = true
			if button {
				value = emailDesignCTAColorV1(d.Primary)
			} else if tag == "a" {
				value = link
			} else {
				value = d.Text
			}
		case "background", "background-color":
			if button {
				value = d.Primary
			} else {
				value = d.Surface
			}
		}
		out = append(out, key+":"+value)
	}
	if tag == "a" && !seenColor {
		out = append(out, "color:"+link)
	}
	return strings.Join(out, ";") + ";"
}

// Only trusted native element style attributes and the exact known presentation
// footer are themed. Raw text, hrefs, deadlines, signing mode and issuer/evidence
// content are never rewritten. Owner introduction fragments have no attributes.
func themeNativeServiceEmailBodyV1(d ServiceEmailDesignV1, c TemplateContext, native string) (string, error) {
	if len(native) > ServiceEmailDesignRenderedBytesV1 {
		return "", ErrServiceEmailTemplateV1
	}
	limit := int64(len(native)) + 4*serviceEmailEscapedBytesV1(emailDesignBrandV1(c)) + 8192
	if limit > ServiceEmailDesignRenderedBytesV1 {
		return "", ErrServiceEmailTemplateV1
	}
	var out strings.Builder
	out.Grow(int(limit))
	z := nethtml.NewTokenizer(strings.NewReader(native))
	footerText := false
	for count := 0; ; count++ {
		if count > 8192 {
			return "", ErrServiceEmailTemplateV1
		}
		kind := z.Next()
		if kind == nethtml.ErrorToken {
			if z.Err() != io.EOF {
				return "", ErrServiceEmailTemplateV1
			}
			break
		}
		raw := string(z.Raw())
		switch kind {
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken:
			tag := z.Token()
			style := ""
			for _, a := range tag.Attr {
				if a.Key == "style" {
					style = a.Val
				}
			}
			footerText = tag.Data == "p" && strings.Contains(style, "font-size: 11px") && strings.Contains(style, "margin-top: 32px")
			if style != "" {
				match := trustedEmailStyleAttributeV1.FindStringSubmatchIndex(raw)
				if len(match) != 4 {
					return "", ErrServiceEmailTemplateV1
				}
				replacement := emailDesignNativeStyleV1(style, tag.Data, d)
				raw = raw[:match[2]] + replacement + raw[match[3]:]
			} else if tag.Data == "a" {
				insert := strings.LastIndex(raw, ">")
				if insert < 0 {
					return "", ErrServiceEmailTemplateV1
				}
				raw = raw[:insert] + ` style="` + emailDesignNativeStyleV1("", "a", d) + `"` + raw[insert:]
			}
		case nethtml.TextToken:
			if footerText {
				decoded := z.Token().Data
				for _, old := range emailDesignOldFootersV1(c) {
					if decoded == old {
						raw = html.EscapeString(emailDesignBrandV1(c))
						break
					}
				}
			}
			footerText = false
		default:
			footerText = false
		}
		out.WriteString(raw)
		if int64(out.Len()) > limit {
			return "", ErrServiceEmailTemplateV1
		}
	}
	return out.String(), nil
}
func themeServiceEmailPlainFooterV1(c TemplateContext, text string) string {
	trimmed := strings.TrimRight(text, "\r\n")
	for _, old := range emailDesignOldFootersV1(c) {
		if strings.HasSuffix(trimmed, "\n"+old) {
			start := len(trimmed) - len(old)
			return trimmed[:start] + emailDesignBrandV1(c) + text[len(trimmed):]
		}
	}
	return text
}
