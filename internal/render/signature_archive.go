// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// ArchivedSignatureSpan contains only the bounded, inert signature grammar.
// Its private representation prevents authored raw HTML from using the
// byte-preserving signature rendering path. Storage commitment verification
// remains the caller's responsibility.
type ArchivedSignatureSpan struct {
	html string
}

// HTML returns the original validated bytes, without serialization or escaping.
// The zero value is empty and cannot inject markup.
func (s ArchivedSignatureSpan) HTML() string { return s.html }

var ErrArchivedSignatureSpan = errors.New("invalid archived signature span")

// MaxArchivedSignatureSpanBytes bounds the v1 wrapper plus worst-case HTML
// entity expansion of the independently bounded signature name.
const MaxArchivedSignatureSpanBytes = 6*MaxSignatureNameBytes + 256

// Check the raw tag too: the HTML tokenizer drops duplicate attributes before
// returning Token().Attr. Exactly two quoted attributes are admitted here.
var archivedSignatureOpeningV1 = regexp.MustCompile(`^<(?i:span)[ \t\r\n]+(?i:class|data-font)[ \t\r\n]*=[ \t\r\n]*(?:"[^"<>\x00]*"|'[^'<>\x00]*')[ \t\r\n]+(?i:class|data-font)[ \t\r\n]*=[ \t\r\n]*(?:"[^"<>\x00]*"|'[^'<>\x00]*')[ \t\r\n]*>$`)

// ValidateArchivedSignatureSpan accepts the historical inert span grammar and
// binds its decoded name and effective font to the captured signature row.
// Equivalent safe attribute/entity serialization is retained byte-for-byte;
// current RenderSignatureSpan output is never used to reconstruct evidence.
func ValidateArchivedSignatureSpan(raw []byte, typedName, font string) (ArchivedSignatureSpan, error) {
	if len(raw) == 0 || len(raw) > MaxArchivedSignatureSpanBytes || !utf8.Valid(raw) || ValidateSignatureName(typedName) != nil {
		return ArchivedSignatureSpan{}, ErrArchivedSignatureSpan
	}
	// The historical manual renderer used Caveat for an unknown font. Preserve
	// that existing effective choice rather than changing old adoption bytes.
	switch font {
	case "Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple":
	default:
		font = "Caveat"
	}
	z := html.NewTokenizer(bytes.NewReader(raw))
	if z.Next() != html.StartTagToken || !archivedSignatureOpeningV1.Match(z.Raw()) {
		return ArchivedSignatureSpan{}, ErrArchivedSignatureSpan
	}
	opening := z.Token()
	if opening.Data != "span" || len(opening.Attr) != 2 {
		return ArchivedSignatureSpan{}, ErrArchivedSignatureSpan
	}
	attributes := make(map[string]string, 2)
	for _, attribute := range opening.Attr {
		if attribute.Namespace != "" || (attribute.Key != "class" && attribute.Key != "data-font") {
			return ArchivedSignatureSpan{}, ErrArchivedSignatureSpan
		}
		if _, duplicate := attributes[attribute.Key]; duplicate {
			return ArchivedSignatureSpan{}, ErrArchivedSignatureSpan
		}
		attributes[attribute.Key] = attribute.Val
	}
	if attributes["class"] != "hash-signature" || attributes["data-font"] != font {
		return ArchivedSignatureSpan{}, ErrArchivedSignatureSpan
	}
	// Decode entities from the original text bytes. Token().Data also normalizes
	// CR/CRLF; comparing it to the unchanged captured row would reject names the
	// historical encoder accepted. This preserves name bytes and archive bytes.
	if z.Next() != html.TextToken || html.UnescapeString(string(z.Raw())) != typedName {
		return ArchivedSignatureSpan{}, ErrArchivedSignatureSpan
	}
	if z.Next() != html.EndTagToken || !strings.EqualFold(string(z.Raw()), "</span>") || z.Token().Data != "span" {
		return ArchivedSignatureSpan{}, ErrArchivedSignatureSpan
	}
	if z.Next() != html.ErrorToken || z.Err() != io.EOF {
		return ArchivedSignatureSpan{}, ErrArchivedSignatureSpan
	}
	return ArchivedSignatureSpan{html: string(raw)}, nil
}
