// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// MaxDesignedHTMLBytes applies before scanning and throughout import
// sanitization. The complete encoded multipart request has its own24MiB limit.
const MaxDesignedHTMLBytes = 20 << 20

var ErrDesignedHTMLTooLarge = errors.New("designed HTML exceeds the 20 MiB render limit")

func ValidateDesignedHTMLSize(raw string) error {
	if len(raw) > MaxDesignedHTMLBytes {
		return ErrDesignedHTMLTooLarge
	}
	return nil
}

// SanitizeForRenderBoundedV1 retains the legacy sanitizer's accepted bytes,
// including unchanged raw tokens. Every growing output is checked before
// append, and failure never returns a partial document. Builder capacities and
// parser controls are not claimed to be exactly the output-byte ceiling.
func SanitizeForRenderBoundedV1(raw string) (string, error) {
	return sanitizeForRenderLimitV1(raw, MaxDesignedHTMLBytes)
}

func sanitizeForRenderLimitV1(raw string, limit int) (string, error) {
	if limit <= 0 || len(raw) > limit {
		return "", ErrDesignedHTMLTooLarge
	}
	budget := &renderTextBudgetV1{limit: limit}
	raw = reScriptBlock.ReplaceAllString(raw, "")
	raw = reScriptStray.ReplaceAllString(raw, "")
	raw = reDangerTags.ReplaceAllString(raw, "")
	raw = reMetaRefresh.ReplaceAllString(raw, "")
	raw = reOnHandler.ReplaceAllString(raw, "$1")
	raw = stripRemoteResourceAttrsBudgetV1(raw, budget)
	if budget.err != nil {
		return "", budget.err
	}
	raw = sanitizeStyleElementsBudgetV1(raw, budget)
	if budget.err != nil {
		return "", budget.err
	}
	return raw, nil
}

type renderTextBudgetV1 struct {
	limit int
	err   error
}

type renderTextBuilderV1 struct {
	b      strings.Builder
	budget *renderTextBudgetV1
}

func newRenderTextBuilderV1(b *renderTextBudgetV1) *renderTextBuilderV1 {
	return &renderTextBuilderV1{budget: b}
}

func (b *renderTextBuilderV1) room(n int) bool {
	if b.budget.err != nil {
		return false
	}
	if n < 0 || n > b.budget.limit-b.b.Len() {
		b.budget.err = ErrDesignedHTMLTooLarge
		return false
	}
	return true
}
func (b *renderTextBuilderV1) Grow(n int) {
	if b.room(n) {
		b.b.Grow(n)
	}
}
func (b *renderTextBuilderV1) Write(p []byte) (int, error) {
	if !b.room(len(p)) {
		return 0, b.budget.err
	}
	return b.b.Write(p)
}
func (b *renderTextBuilderV1) WriteString(s string) (int, error) {
	if !b.room(len(s)) {
		return 0, b.budget.err
	}
	return b.b.WriteString(s)
}
func (b *renderTextBuilderV1) WriteByte(c byte) error {
	if !b.room(1) {
		return b.budget.err
	}
	return b.b.WriteByte(c)
}
func (b *renderTextBuilderV1) WriteRune(r rune) (int, error) {
	n := utf8.RuneLen(r)
	if n < 0 {
		n = 3
	}
	if !b.room(n) {
		return 0, b.budget.err
	}
	return b.b.WriteRune(r)
}
func (b *renderTextBuilderV1) String() string {
	if b.budget.err != nil {
		return ""
	}
	return b.b.String()
}

// Stream the exact html.EscapeString spellings rather than allocating a
// potentially fivefold attribute string before discovering the overflow.
func (b *renderTextBuilderV1) WriteEscapedString(s string) {
	start := 0
	for i := 0; i < len(s) && b.budget.err == nil; i++ {
		var escaped string
		switch s[i] {
		case '&':
			escaped = "&amp;"
		case '\'':
			escaped = "&#39;"
		case '<':
			escaped = "&lt;"
		case '>':
			escaped = "&gt;"
		case '"':
			escaped = "&#34;"
		default:
			continue
		}
		b.WriteString(s[start:i])
		b.WriteString(escaped)
		start = i + 1
	}
	b.WriteString(s[start:])
}

func sanitizeCSSBudgetV1(css string, budget *renderTextBudgetV1) string {
	css = decodeCSSEscapesBudgetV1(css, budget)
	css = stripCSSComments(css)
	css = stripCSSImports(css)
	css = sanitizeCSSURLFunctionsBudgetV1(css, budget)
	// These replacements only shrink their complete matched functions.
	css = reCSSImageSet.ReplaceAllString(css, "none")
	css = reCSSImageFunc.ReplaceAllString(css, "none")
	return css
}

func sanitizeStyleElementsBudgetV1(input string, budget *renderTextBudgetV1) string {
	out := newRenderTextBuilderV1(budget)
	for len(input) > 0 && budget.err == nil {
		loc := reStyleElement.FindStringIndex(input)
		if loc == nil {
			out.WriteString(input)
			break
		}
		out.WriteString(input[:loc[0]])
		element := input[loc[0]:loc[1]]
		openEnd := strings.IndexByte(element, '>')
		closeStart := lastStyleCloseIndex(element)
		if openEnd >= 0 && closeStart > openEnd {
			out.WriteString(element[:openEnd+1])
			out.WriteString(sanitizeCSSBudgetV1(element[openEnd+1:closeStart], budget))
			out.WriteString(element[closeStart:])
		}
		input = input[loc[1]:]
	}
	return out.String()
}

func decodeCSSEscapesBudgetV1(css string, budget *renderTextBudgetV1) string {
	out := newRenderTextBuilderV1(budget)
	out.Grow(len(css))
	for i := 0; i < len(css) && budget.err == nil; {
		if css[i] != '\\' || i+1 >= len(css) {
			out.WriteByte(css[i])
			i++
			continue
		}
		i++
		if css[i] == '\n' || css[i] == '\r' || css[i] == '\f' {
			i++ // escaped newline is a CSS line continuation
			continue
		}
		start := i
		for i < len(css) && i-start < 6 && isHexByte(css[i]) {
			i++
		}
		if i > start {
			code, err := strconv.ParseInt(css[start:i], 16, 32)
			if err == nil && code > 0 && code <= 0x10ffff {
				out.WriteRune(rune(code))
			}
			if i < len(css) && isCSSWhitespace(css[i]) {
				i++
			}
			continue
		}
		out.WriteByte(css[i])
		i++
	}
	return out.String()
}

func sanitizeCSSURLFunctionsBudgetV1(css string, budget *renderTextBudgetV1) string {
	out := newRenderTextBuilderV1(budget)
	out.Grow(len(css))
	for i := 0; i < len(css) && budget.err == nil; {
		if !hasCSSKeywordAt(css, i, "url") {
			out.WriteByte(css[i])
			i++
			continue
		}

		open := i + len("url")
		for open < len(css) && isCSSWhitespace(css[open]) {
			open++
		}
		if open >= len(css) || css[open] != '(' {
			out.WriteByte(css[i])
			i++
			continue
		}

		end, ok := cssFunctionEnd(css, open)
		if !ok {
			// Malformed URL functions have no legitimate static-render value;
			// consume the remainder rather than let Chromium repair it differently.
			out.WriteString("url(about:blank)")
			break
		}
		value := strings.TrimSpace(css[open+1 : end-1])
		if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if isUnsafeResourceURLValue(value) {
			out.WriteString("url(about:blank)")
		} else {
			out.WriteString(css[i:end])
		}
		i = end
	}
	return out.String()
}

func stripRemoteResourceAttrsBudgetV1(input string, budget *renderTextBudgetV1) string {
	z := html.NewTokenizer(strings.NewReader(input))
	b := newRenderTextBuilderV1(budget)
	b.Grow(len(input))
	for budget.err == nil {
		tt := z.Next()
		if tt == html.ErrorToken {
			// io.EOF (the normal terminator) or a read error: emit whatever raw
			// bytes remain for this token and stop.
			b.Write(z.Raw())
			return b.String()
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			b.Write(z.Raw())
			continue
		}
		raw := append([]byte(nil), z.Raw()...) // Raw is only valid until the next Next()
		name, hasAttr := z.TagName()
		if !hasAttr {
			b.Write(raw)
			continue
		}
		type attr struct{ k, v string }
		var kept []attr
		changed := false
		dropTag := false
		metaRefresh := false
		for {
			k, v, more := z.TagAttr()
			key := strings.ToLower(string(k))
			value := string(v)
			if key == "http-equiv" && strings.EqualFold(strings.TrimSpace(value), "refresh") {
				metaRefresh = true
			}
			if key == "srcset" || key == "imagesrcset" {
				// Responsive candidates add another comma-separated URL grammar.
				// The PDF has one fixed viewport and no author-supplied attachments,
				// so removing the attribute is both safer and deterministic.
				changed = true
			} else if resourceAttrs[key] && isUnsafeResourceURLValue(value) {
				changed = true
			} else {
				if cssResourceAttrs[key] {
					safe := sanitizeCSSBudgetV1(value, budget)
					if budget.err != nil {
						return ""
					}
					changed = changed || safe != value
					value = safe
				}
				kept = append(kept, attr{string(k), value})
			}
			if !more {
				break
			}
		}
		if strings.EqualFold(string(name), "meta") && metaRefresh {
			dropTag = true
		}
		if dropTag {
			continue
		}
		if !changed {
			b.Write(raw)
			continue
		}
		b.WriteByte('<')
		b.Write(name)
		for _, a := range kept {
			b.WriteByte(' ')
			b.WriteString(a.k)
			b.WriteString(`="`)
			b.WriteEscapedString(a.v)
			b.WriteByte('"')
		}
		if tt == html.SelfClosingTagToken {
			b.WriteString(" /")
		}
		b.WriteByte('>')
	}
	return b.String()
}
