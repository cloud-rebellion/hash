// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package dispatch

import (
	"errors"
	"html"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/microcosm-cc/bluemonday"
	nethtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const ServiceEmailSubjectSourceBytesV1 = 256
const ServiceEmailHTMLSourceBytesV1 = 16384
const ServiceEmailTextSourceBytesV1 = 8192
const ServiceEmailTemplateMaxSourceBytesV1 = ServiceEmailSubjectSourceBytesV1 + ServiceEmailHTMLSourceBytesV1 + ServiceEmailTextSourceBytesV1

// Retained source, bounded sanitizer/tokenizer intermediates and fixed controls;
// the actual native owner still grants this work before reading/parsing source.
const ServiceEmailTemplateSourceWorkBytesV1 = 64*ServiceEmailTemplateMaxSourceBytesV1 + 65536
const ServiceEmailRenderedBodyBytesV1 = 65536
const ServiceEmailRenderedSubjectBytesV1 = 4096

var ErrServiceEmailTemplateV1 = errors.New("invalid service email template")

// Revision is selected from an organization-scoped immutable database row by
// the actual native producer. A DTO or byte limit is never resource admission.
type ServiceEmailTemplateV1 struct {
	Revision        int64  `json:"revision"`
	SubjectTemplate string `json:"subject_template"`
	HTMLTemplate    string `json:"html_template"`
	TextTemplate    string `json:"text_template"`
}

func ServiceEmailKindsV1() []string {
	return []string{KindInvite, KindReminder, KindCompletedSigner, KindCompletedSender, KindDeclined, KindChangesRequested, KindNewComment, KindVoided, KindQuotaWarning80}
}
func ServiceEmailKindV1(kind string) bool {
	for _, k := range ServiceEmailKindsV1() {
		if kind == k {
			return true
		}
	}
	return false
}

// These kinds have real owned native producer integration. Catalog-only,
// legacy raw-transaction and operator-worker notices keep their builtin copy.
func ServiceEmailTemplateEditableKindV1(kind string) bool {
	switch kind {
	case KindInvite, KindReminder, KindCompletedSigner, KindCompletedSender, KindChangesRequested, KindNewComment:
		return true
	default:
		return false
	}
}
func ServiceEmailVariablesV1() []string {
	return []string{"document_name", "sender_name", "sender_email", "recipient_name", "org_name"}
}
func serviceEmailValueV1(key string, c TemplateContext) (string, bool) {
	switch key {
	case "document_name":
		return c.DocumentName, true
	case "sender_name":
		return c.SenderName, true
	case "sender_email":
		return c.SenderEmail, true
	case "recipient_name":
		return c.RecipientName, true
	case "org_name":
		return c.OrgName, true
	default:
		return "", false
	}
}
func serviceEmailTextV1(s string, header bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && (header || r != '\n' && r != '\t') {
			return false
		}
	}
	return true
}

// Use the existing document/import sanitizer, then narrow email fragments to
// formatting only. No owner-authored link, attribute, image, CSS or resource URL
// reaches either browser preview or SMTP; action links stay native-only.
var serviceEmailHTMLPolicyV1 = func() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements("p", "br", "strong", "em", "b", "i", "u", "ul", "ol", "li", "blockquote", "h1", "h2", "h3", "table", "thead", "tbody", "tr", "td", "th", "span")
	return p
}()

func serviceEmailSafeHTMLV1(s string) (string, error) {
	allowed := map[string]bool{"p": true, "br": true, "strong": true, "em": true, "b": true, "i": true, "u": true, "ul": true, "ol": true, "li": true, "blockquote": true, "h1": true, "h2": true, "h3": true, "table": true, "thead": true, "tbody": true, "tr": true, "td": true, "th": true, "span": true}
	z := nethtml.NewTokenizer(strings.NewReader(s))
	for tokens := 0; ; tokens++ {
		if tokens > 2048 {
			return "", ErrServiceEmailTemplateV1
		}
		switch z.Next() {
		case nethtml.ErrorToken:
			if z.Err() != io.EOF {
				return "", ErrServiceEmailTemplateV1
			}
			return serviceEmailClosedFragmentV1(serviceEmailHTMLPolicyV1.Sanitize(blocks.SanitizeRawHTML(s)), allowed)
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken, nethtml.EndTagToken:
			t := z.Token()
			if !allowed[t.Data] || len(t.Attr) != 0 {
				return "", ErrServiceEmailTemplateV1
			}
		case nethtml.CommentToken, nethtml.DoctypeToken:
			return "", ErrServiceEmailTemplateV1
		}
	}
}

type serviceEmailFragmentWriterV1 struct{ strings.Builder }

func (w *serviceEmailFragmentWriterV1) Write(p []byte) (int, error) {
	if w.Len()+len(p) > ServiceEmailHTMLSourceBytesV1 {
		return 0, ErrServiceEmailTemplateV1
	}
	return w.Builder.Write(p)
}
func (w *serviceEmailFragmentWriterV1) WriteString(p string) (int, error) {
	if w.Len()+len(p) > ServiceEmailHTMLSourceBytesV1 {
		return 0, ErrServiceEmailTemplateV1
	}
	return w.Builder.WriteString(p)
}
func (w *serviceEmailFragmentWriterV1) WriteByte(b byte) error {
	if w.Len() >= ServiceEmailHTMLSourceBytesV1 {
		return ErrServiceEmailTemplateV1
	}
	return w.Builder.WriteByte(b)
}

// A streaming allowlist alone does not close table/list/heading markup. Parse
// in an explicit div fragment, bound the resulting tree, then serialize every
// node including its generated closing tags before it can precede native CTA.
func serviceEmailClosedFragmentV1(s string, allowed map[string]bool) (string, error) {
	context := &nethtml.Node{Type: nethtml.ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, err := nethtml.ParseFragment(strings.NewReader(s), context)
	if err != nil {
		return "", ErrServiceEmailTemplateV1
	}
	count := 0
	var check func(*nethtml.Node, int) error
	check = func(n *nethtml.Node, depth int) error {
		count++
		if count > 2048 || depth > 32 {
			return ErrServiceEmailTemplateV1
		}
		if n.Type != nethtml.TextNode && (n.Type != nethtml.ElementNode || !allowed[n.Data] || len(n.Attr) != 0 || n.Namespace != "") {
			return ErrServiceEmailTemplateV1
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if err := check(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, n := range nodes {
		if err := check(n, 1); err != nil {
			return "", err
		}
	}
	var out serviceEmailFragmentWriterV1
	for _, n := range nodes {
		if err := nethtml.Render(&out, n); err != nil {
			return "", ErrServiceEmailTemplateV1
		}
	}
	return out.String(), nil
}

// Walk substitutes exactly one closed token at a time, never recursively.
func serviceEmailWalkV1(source string, literal func(string), variable func(string) error) error {
	for source != "" {
		i := strings.Index(source, "{{")
		if i < 0 {
			if strings.Contains(source, "}}") {
				return ErrServiceEmailTemplateV1
			}
			literal(source)
			return nil
		}
		if strings.Contains(source[:i], "}}") {
			return ErrServiceEmailTemplateV1
		}
		literal(source[:i])
		source = source[i+2:]
		j := strings.Index(source, "}}")
		if j < 0 {
			return ErrServiceEmailTemplateV1
		}
		if err := variable(source[:j]); err != nil {
			return err
		}
		source = source[j+2:]
	}
	return nil
}
func ValidateServiceEmailTemplateV1(kind string, in ServiceEmailTemplateV1) (ServiceEmailTemplateV1, error) {
	if !ServiceEmailKindV1(kind) || in.Revision < 0 || len(in.SubjectTemplate) > ServiceEmailSubjectSourceBytesV1 || len(in.HTMLTemplate) > ServiceEmailHTMLSourceBytesV1 || len(in.TextTemplate) > ServiceEmailTextSourceBytesV1 || !serviceEmailTextV1(in.SubjectTemplate, true) || !serviceEmailTextV1(in.HTMLTemplate, false) || !serviceEmailTextV1(in.TextTemplate, false) {
		return ServiceEmailTemplateV1{}, ErrServiceEmailTemplateV1
	}
	var err error
	in.HTMLTemplate, err = serviceEmailSafeHTMLV1(in.HTMLTemplate)
	if err != nil || len(in.HTMLTemplate) > ServiceEmailHTMLSourceBytesV1 {
		return ServiceEmailTemplateV1{}, ErrServiceEmailTemplateV1
	}
	count := 0
	for _, s := range []string{in.SubjectTemplate, in.HTMLTemplate, in.TextTemplate} {
		err = serviceEmailWalkV1(s, func(string) {}, func(key string) error {
			count++
			if _, ok := serviceEmailValueV1(key, TemplateContext{}); !ok || count > 128 {
				return ErrServiceEmailTemplateV1
			}
			return nil
		})
		if err != nil {
			return ServiceEmailTemplateV1{}, err
		}
	}
	return in, nil
}
func serviceEmailEscapedBytesV1(s string) int64 {
	n := int64(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			n += 4
		case '\'', '"':
			n += 4
		case '<', '>':
			n += 3
		}
	}
	return n
}
func serviceEmailMeasureV1(s string, c TemplateContext, escaped, header bool) (int64, error) {
	n := int64(0)
	err := serviceEmailWalkV1(s, func(v string) { n += int64(len(v)) }, func(key string) error {
		v, ok := serviceEmailValueV1(key, c)
		if !ok || !serviceEmailTextV1(v, header) {
			return ErrServiceEmailTemplateV1
		}
		if escaped {
			n += serviceEmailEscapedBytesV1(v)
		} else {
			n += int64(len(v))
		}
		if n > ServiceEmailRenderedBodyBytesV1 {
			return ErrServiceEmailTemplateV1
		}
		return nil
	})
	if err != nil || n > ServiceEmailRenderedBodyBytesV1 {
		return 0, ErrServiceEmailTemplateV1
	}
	return n, nil
}

// Prices only bounded, already-admitted actual source/context before any
// expanded output is allocated. Existing native builtin calculators still own
// mandatory message bounds. The producer must pay source, parsing and outputs.
func ServiceEmailTemplateComponentsV1(c TemplateContext, tpl *ServiceEmailTemplateV1, bs, bh, bt int64) (s, h, t int64, err error) {
	if bs < 0 || bh < 0 || bt < 0 {
		return 0, 0, 0, ErrServiceEmailTemplateV1
	}
	if tpl == nil {
		return bs, bh, bt, nil
	}
	s, h, t = bs, bh, bt
	if tpl.SubjectTemplate != "" {
		s, err = serviceEmailMeasureV1(tpl.SubjectTemplate, c, false, true)
		if err != nil || s > ServiceEmailRenderedSubjectBytesV1 {
			return 0, 0, 0, ErrServiceEmailTemplateV1
		}
	}
	if tpl.HTMLTemplate != "" {
		var n int64
		n, err = serviceEmailMeasureV1(tpl.HTMLTemplate, c, true, false)
		if err != nil {
			return 0, 0, 0, err
		}
		h += n + lenServiceEmailHTMLJoinV1
	}
	if tpl.TextTemplate != "" {
		var n int64
		n, err = serviceEmailMeasureV1(tpl.TextTemplate, c, false, false)
		if err != nil {
			return 0, 0, 0, err
		}
		t += n + 2
	}
	if h < bh || t < bt {
		return 0, 0, 0, ErrServiceEmailTemplateV1
	}
	return s, h, t, nil
}

const serviceEmailHTMLJoinV1 = "\n<hr>\n"
const lenServiceEmailHTMLJoinV1 = int64(len(serviceEmailHTMLJoinV1))

func serviceEmailExpandV1(s string, c TemplateContext, escaped bool) (string, error) {
	var b strings.Builder
	err := serviceEmailWalkV1(s, func(v string) { b.WriteString(v) }, func(key string) error {
		v, ok := serviceEmailValueV1(key, c)
		if !ok {
			return ErrServiceEmailTemplateV1
		}
		if escaped {
			v = html.EscapeString(v)
		}
		b.WriteString(v)
		return nil
	})
	return b.String(), err
}
func RenderServiceEmailV1(kind string, c TemplateContext, tpl *ServiceEmailTemplateV1) (subject, body, text string, err error) {
	if tpl == nil {
		return Render(kind, c)
	}
	canonical, e := ValidateServiceEmailTemplateV1(kind, *tpl)
	if e != nil || canonical != *tpl {
		return "", "", "", ErrServiceEmailTemplateV1
	}
	// Refuse expansion errors before allocating either custom or builtin output.
	if _, _, _, e = ServiceEmailTemplateComponentsV1(c, tpl, 0, 0, 0); e != nil {
		return "", "", "", e
	}
	subject, body, text, err = Render(kind, c)
	if err != nil {
		return
	}
	if tpl.SubjectTemplate != "" {
		subject, err = serviceEmailExpandV1(tpl.SubjectTemplate, c, false)
		if err != nil {
			return
		}
	}
	if tpl.HTMLTemplate != "" {
		var intro string
		intro, err = serviceEmailExpandV1(tpl.HTMLTemplate, c, true)
		if err != nil {
			return
		}
		start := strings.Index(body, "<body")
		if start < 0 || strings.Count(body, "<body") != 1 {
			return "", "", "", ErrServiceEmailTemplateV1
		}
		end := strings.IndexByte(body[start:], '>')
		if end < 0 {
			return "", "", "", ErrServiceEmailTemplateV1
		}
		end += start + 1
		body = body[:end] + intro + serviceEmailHTMLJoinV1 + body[end:]
	}
	if tpl.TextTemplate != "" {
		var intro string
		intro, err = serviceEmailExpandV1(tpl.TextTemplate, c, false)
		if err != nil {
			return
		}
		text = intro + "\n\n" + text
	}
	return
}
