// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package dispatch

import (
	"crypto/sha256"
	"encoding/json"
	"html"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/sourcejson"
	nethtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const ServiceEmailDesignSourceBytesV1 = 131072
const ServiceEmailDesignLayoutBytesV1 = 16384
const ServiceEmailDesignLogoBytesV1 = 32768
const ServiceEmailDesignLogoDimensionV1 = 512
const ServiceEmailDesignRenderedBytesV1 = 262144

// Existing native owners reserve these fixed worst-case raster/parser costs
// BEFORE decoding a selected design; no input DTO is an admission receipt.
const ServiceEmailDesignFixedWorkBytesV1 = 16 << 20
const serviceEmailNativeSlotV1 = "{{native_content}}"
const serviceEmailLogoSlotV1 = "{{logo}}"

type ServiceEmailDesignV1 struct {
	SchemaVersion int               `json:"schema_version"`
	LayoutHTML    string            `json:"layout_html"`
	Background    string            `json:"background"`
	Surface       string            `json:"surface"`
	Primary       string            `json:"primary"`
	Text          string            `json:"text"`
	Logo          *htmlmaster.Asset `json:"logo"`
	LogoAlt       string            `json:"logo_alt"`
}

var emailDesignHexV1 = regexp.MustCompile(`^#[0-9a-f]{6}$`)
var emailDesignPixelV1 = regexp.MustCompile(`^(0|[1-9][0-9]*px)$`)

func emailDesignRangeV1(value string, min, max int) bool {
	if !emailDesignPixelV1.MatchString(value) {
		return false
	}
	n, e := strconv.Atoi(strings.TrimSuffix(value, "px"))
	return e == nil && n >= min && n <= max
}
func emailDesignColorChannelV1(value string, start int) float64 {
	n, _ := strconv.ParseUint(value[start:start+2], 16, 8)
	v := float64(n) / 255
	if v <= 0.04045 {
		return v / 12.92
	}
	return math.Pow((v+0.055)/1.055, 2.4)
}
func emailDesignLuminanceV1(value string) float64 {
	return .2126*emailDesignColorChannelV1(value, 1) + .7152*emailDesignColorChannelV1(value, 3) + .0722*emailDesignColorChannelV1(value, 5)
}
func emailDesignContrastV1(a, b string) float64 {
	x, y := emailDesignLuminanceV1(a), emailDesignLuminanceV1(b)
	if x < y {
		x, y = y, x
	}
	return (x + .05) / (y + .05)
}
func emailDesignStyleV1(raw string) (string, error) {
	if len(raw) > 1024 {
		return "", ErrServiceEmailTemplateV1
	}
	values := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		pair := strings.SplitN(part, ":", 2)
		if len(pair) != 2 {
			return "", ErrServiceEmailTemplateV1
		}
		key, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if key != strings.ToLower(key) || values[key] != "" {
			return "", ErrServiceEmailTemplateV1
		}
		valid := false
		switch key {
		case "background-color", "color", "border-color":
			valid = emailDesignHexV1.MatchString(value)
		case "text-align":
			valid = value == "left" || value == "center" || value == "right"
		case "padding", "padding-top", "padding-bottom", "padding-left", "padding-right", "margin", "margin-top", "margin-bottom", "margin-left", "margin-right":
			valid = emailDesignRangeV1(value, 0, 48)
		case "font-size":
			valid = emailDesignRangeV1(value, 12, 48)
		case "font-weight":
			valid = value == "normal" || value == "bold" || value == "400" || value == "500" || value == "600" || value == "700"
		case "line-height":
			n, e := strconv.ParseFloat(value, 64)
			valid = e == nil && n >= 1 && n <= 2.5 && !strings.ContainsAny(value, "eE+-")
		case "border-radius":
			valid = emailDesignRangeV1(value, 0, 24)
		case "border":
			p := strings.Fields(value)
			valid = value == "0" || (len(p) == 3 && emailDesignRangeV1(p[0], 1, 4) && p[1] == "solid" && emailDesignHexV1.MatchString(p[2]))
		case "width":
			valid = value == "100%"
		case "max-width":
			valid = emailDesignRangeV1(value, 320, 800)
		}
		if !valid {
			return "", ErrServiceEmailTemplateV1
		}
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, k := range keys {
		out.WriteString(k)
		out.WriteByte(':')
		out.WriteString(values[k])
		out.WriteByte(';')
	}
	return out.String(), nil
}

var emailDesignElementsV1 = map[string]bool{"div": true, "table": true, "thead": true, "tbody": true, "tr": true, "td": true, "th": true, "p": true, "br": true, "h1": true, "h2": true, "h3": true, "span": true, "strong": true, "em": true, "b": true, "i": true, "u": true, "ul": true, "ol": true, "li": true, "blockquote": true, "hr": true}
var emailDesignSlotAncestorsV1 = map[string]bool{"div": true, "table": true, "thead": true, "tbody": true, "tr": true, "td": true, "th": true}

func canonicalEmailDesignLayoutV1(raw string, hasLogo bool) (string, error) {
	if len(raw) == 0 || len(raw) > ServiceEmailDesignLayoutBytesV1 || strings.Count(raw, serviceEmailNativeSlotV1) != 1 || strings.Count(raw, serviceEmailLogoSlotV1) > 1 || (hasLogo && strings.Count(raw, serviceEmailLogoSlotV1) != 1) {
		return "", ErrServiceEmailTemplateV1
	}
	// Validate lexical tags before the HTML parser can discard or relocate one.
	z := nethtml.NewTokenizer(strings.NewReader(raw))
	for count := 0; ; count++ {
		if count > 2048 {
			return "", ErrServiceEmailTemplateV1
		}
		t := z.Next()
		if t == nethtml.ErrorToken {
			if z.Err() != io.EOF {
				return "", ErrServiceEmailTemplateV1
			}
			break
		}
		if t == nethtml.CommentToken || t == nethtml.DoctypeToken {
			return "", ErrServiceEmailTemplateV1
		}
		if t == nethtml.StartTagToken || t == nethtml.SelfClosingTagToken || t == nethtml.EndTagToken {
			n := z.Token()
			if !emailDesignElementsV1[n.Data] {
				return "", ErrServiceEmailTemplateV1
			}
		}
	}
	context := &nethtml.Node{Type: nethtml.ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, err := nethtml.ParseFragment(strings.NewReader(raw), context)
	if err != nil {
		return "", ErrServiceEmailTemplateV1
	}
	count, slots, logos := 0, 0, 0
	var visit func(*nethtml.Node, int, bool) error
	visit = func(n *nethtml.Node, depth int, safeAncestors bool) error {
		count++
		if count > 2048 || depth > 24 || n.Namespace != "" {
			return ErrServiceEmailTemplateV1
		}
		if n.Type == nethtml.TextNode {
			if strings.Contains(n.Data, serviceEmailNativeSlotV1) {
				if !safeAncestors || strings.TrimSpace(n.Data) != serviceEmailNativeSlotV1 {
					return ErrServiceEmailTemplateV1
				}
				slots++
			}
			if strings.Contains(n.Data, serviceEmailLogoSlotV1) {
				if strings.TrimSpace(n.Data) != serviceEmailLogoSlotV1 {
					return ErrServiceEmailTemplateV1
				}
				logos++
			}
			return serviceEmailWalkV1(n.Data, func(string) {}, func(key string) error {
				if key == "native_content" || key == "logo" {
					return nil
				}
				if _, ok := serviceEmailValueV1(key, TemplateContext{}); !ok {
					return ErrServiceEmailTemplateV1
				}
				return nil
			})
		}
		if n.Type != nethtml.ElementNode || !emailDesignElementsV1[n.Data] {
			return ErrServiceEmailTemplateV1
		}
		attrs := map[string]bool{}
		for i := range n.Attr {
			a := &n.Attr[i]
			if attrs[a.Key] || a.Namespace != "" {
				return ErrServiceEmailTemplateV1
			}
			attrs[a.Key] = true
			switch a.Key {
			case "style":
				value, e := emailDesignStyleV1(a.Val)
				if e != nil {
					return e
				}
				a.Val = value
			case "role":
				if n.Data != "table" || a.Val != "presentation" {
					return ErrServiceEmailTemplateV1
				}
			case "cellpadding", "cellspacing":
				v, e := strconv.Atoi(a.Val)
				if n.Data != "table" || e != nil || v < 0 || v > 24 {
					return ErrServiceEmailTemplateV1
				}
			default:
				return ErrServiceEmailTemplateV1
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if e := visit(c, depth+1, safeAncestors && emailDesignSlotAncestorsV1[n.Data]); e != nil {
				return e
			}
		}
		return nil
	}
	for _, n := range nodes {
		if err := visit(n, 1, true); err != nil {
			return "", err
		}
	}
	if slots != 1 || (hasLogo && logos != 1) || logos > 1 {
		return "", ErrServiceEmailTemplateV1
	}
	var out serviceEmailFragmentWriterV1
	for _, n := range nodes {
		if err := nethtml.Render(&out, n); err != nil {
			return "", ErrServiceEmailTemplateV1
		}
	}
	return out.String(), nil
}
func DecodeServiceEmailDesignV1(raw string) (ServiceEmailDesignV1, error) {
	var d ServiceEmailDesignV1
	if len(raw) == 0 || len(raw) > ServiceEmailDesignSourceBytesV1 || sourcejson.Validate([]byte(raw)) != nil {
		return d, ErrServiceEmailTemplateV1
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || d.SchemaVersion != 1 {
		return d, ErrServiceEmailTemplateV1
	}
	for _, color := range []string{d.Background, d.Surface, d.Primary, d.Text} {
		if !emailDesignHexV1.MatchString(color) {
			return d, ErrServiceEmailTemplateV1
		}
	}
	if emailDesignContrastV1(d.Surface, d.Text) < 4.5 || len(d.LogoAlt) > 200 || !serviceEmailTextV1(d.LogoAlt, true) {
		return d, ErrServiceEmailTemplateV1
	}
	if d.Logo != nil {
		if d.Logo.Name != "logo" {
			return d, ErrServiceEmailTemplateV1
		}
		asset, err := htmlmaster.CanonicalImageAssetV1(*d.Logo, ServiceEmailDesignLogoBytesV1, ServiceEmailDesignLogoDimensionV1)
		if err != nil {
			return d, ErrServiceEmailTemplateV1
		}
		d.Logo = &asset
	}
	layout, err := canonicalEmailDesignLayoutV1(d.LayoutHTML, d.Logo != nil)
	if err != nil {
		return d, err
	}
	d.LayoutHTML = layout
	return d, nil
}
func CanonicalServiceEmailDesignV1(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	d, err := DecodeServiceEmailDesignV1(raw)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(d)
	if err != nil || len(body) > ServiceEmailDesignSourceBytesV1 {
		return "", ErrServiceEmailTemplateV1
	}
	return string(body), nil
}
func serviceEmailNativeBodyV1(body string) (string, error) {
	start := strings.Index(body, "<body")
	end := strings.LastIndex(body, "</body>")
	if start < 0 || end < 0 || strings.Count(body, "<body") != 1 || strings.Count(body, "</body>") != 1 {
		return "", ErrServiceEmailTemplateV1
	}
	open := strings.IndexByte(body[start:], '>')
	if open < 0 || start+open+1 > end {
		return "", ErrServiceEmailTemplateV1
	}
	return body[start+open+1 : end], nil
}
func serviceEmailDesignExpandV1(d ServiceEmailDesignV1, c TemplateContext, native string) (string, error) {
	var out strings.Builder
	err := serviceEmailWalkV1(d.LayoutHTML, func(s string) { out.WriteString(s) }, func(key string) error {
		switch key {
		case "native_content":
			out.WriteString(`<div style="background-color:` + d.Surface + `;color:` + d.Text + `;font-family:Arial,sans-serif;font-size:16px;line-height:1.5;padding:24px;text-align:left;">`)
			out.WriteString(native)
			out.WriteString(`</div>`)
		case "logo":
			if d.Logo != nil {
				out.WriteString(`<img data-hash-logo="` + d.Logo.SHA256 + `" src="data:` + d.Logo.MediaType + `;base64,` + d.Logo.DataBase64 + `" alt="` + html.EscapeString(d.LogoAlt) + `" width="160" style="display:block;max-width:160px;height:auto;border:0;">`)
			}
		default:
			v, ok := serviceEmailValueV1(key, c)
			if !ok || !serviceEmailTextV1(v, false) {
				return ErrServiceEmailTemplateV1
			}
			out.WriteString(html.EscapeString(v))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return out.String(), nil
}
func ApplyServiceEmailDesignV1(raw string, c TemplateContext, body string) (string, error) {
	if raw == "" {
		return body, nil
	}
	d, err := DecodeServiceEmailDesignV1(raw)
	if err != nil {
		return "", err
	}
	native, err := serviceEmailNativeBodyV1(body)
	if err != nil {
		return "", err
	}
	// Price the trusted native theme expansion before constructing it. The scalar
	// bound includes fixed native styles and escaped workspace footer growth.
	measured, err := ServiceEmailDesignHTMLBytesV1(d, c, int64(len(native)))
	if err != nil {
		return "", err
	}
	native, err = themeNativeServiceEmailBodyV1(d, c, native)
	if err != nil {
		return "", err
	}
	content, err := serviceEmailDesignExpandV1(d, c, native)
	if err != nil {
		return "", err
	}
	result := `<html><body style="margin:0;padding:24px;background-color:` + d.Background + `;color:` + d.Text + `;font-family:Arial,sans-serif;"><div style="max-width:640px;margin:0 auto;border-top:4px solid ` + d.Primary + `;">` + content + `</div></body></html>`
	if int64(len(result)) > measured || len(result) > ServiceEmailDesignRenderedBytesV1 {
		return "", ErrServiceEmailTemplateV1
	}
	return result, nil
}
func ServiceEmailDesignHTMLBytesV1(d ServiceEmailDesignV1, c TemplateContext, nativeBytes int64) (int64, error) {
	if nativeBytes < 0 || nativeBytes > ServiceEmailDesignRenderedBytesV1 {
		return 0, ErrServiceEmailTemplateV1
	}
	n := int64(1024+8192) + 4*serviceEmailEscapedBytesV1(emailDesignBrandV1(c))
	err := serviceEmailWalkV1(d.LayoutHTML, func(s string) { n += int64(len(s)) }, func(key string) error {
		switch key {
		case "native_content":
			n += nativeBytes + 512
		case "logo":
			if d.Logo != nil {
				n += int64(len(d.Logo.DataBase64)) + serviceEmailEscapedBytesV1(d.LogoAlt) + 512
			}
		default:
			v, ok := serviceEmailValueV1(key, c)
			if !ok || !serviceEmailTextV1(v, false) {
				return ErrServiceEmailTemplateV1
			}
			n += serviceEmailEscapedBytesV1(v)
		}
		return nil
	})
	if err != nil || n > ServiceEmailDesignRenderedBytesV1 {
		return 0, ErrServiceEmailTemplateV1
	}
	return n, nil
}

// DefaultServiceEmailDesignV1 is an explicit editor starting point, not a saved
// default or implicit migration of existing M119 editions.
func DefaultServiceEmailDesignV1() ServiceEmailDesignV1 {
	return ServiceEmailDesignV1{SchemaVersion: 1, LayoutHTML: `<div style="padding:24px;">{{logo}}</div><div>{{native_content}}</div>`, Background: "#f3f4f6", Surface: "#ffffff", Primary: "#111111", Text: "#111111"}
}

// The row, preview and enqueue commitment use exactly these canonical source
// bytes; an empty legacy design retains its original NULL digest.
func ServiceEmailDesignDigestV1(raw string) []byte {
	if raw == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
