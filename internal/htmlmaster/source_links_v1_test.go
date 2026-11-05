// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package htmlmaster

import (
	"strings"
	"testing"
)

func TestDesignedSourcesRetainHTTPSLinksWithoutResourceFetchingV1(t *testing.T) {
	m := Master{SchemaVersion: 1, HTML: `<main><p>Source: <a href="https://docs.example.invalid/reference?q=one&amp;page=2#section"><strong>Primary reference</strong></a></p></main>`}
	c, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Materialize(Input{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.HTML, `href="https://docs.example.invalid/reference?q=one&amp;page=2#section"`) || !strings.Contains(r.HTML, `<strong>Primary reference</strong>`) {
		t.Fatal("exact source navigation and visible label were not retained")
	}
	if len(c.assets) != 0 {
		t.Fatal("a source link acquired a render asset")
	}
}

func TestDesignedSourceLinksRejectActiveAndAmbiguousNavigationV1(t *testing.T) {
	for name, source := range map[string]string{
		"script":          `<a href="javascript:alert(1)">x</a>`,
		"encoded-script":  `<a href="jav&#x61;script:alert(1)">x</a>`,
		"data":            `<a href="data:text/html,hello">x</a>`,
		"file":            `<a href="file:///etc/passwd">x</a>`,
		"relative":        `<a href="/private">x</a>`,
		"scheme-relative": `<a href="//example.invalid">x</a>`,
		"http":            `<a href="http://example.invalid">x</a>`,
		"userinfo":        `<a href="https://user:password@example.invalid">x</a>`,
		"empty-host":      `<a href="https:///reference">x</a>`,
		"opaque":          `<a href="https:example.invalid/reference">x</a>`,
		"backslash":       `<a href="https://example.invalid\@other.invalid">x</a>`,
		"space":           `<a href="https://example.invalid/a b">x</a>`,
		"control":         "<a href=\"https://example.invalid/\nnext\">x</a>",
		"event":           `<a href="https://example.invalid" onclick="x">x</a>`,
		"download":        `<a href="https://example.invalid" download="private">x</a>`,
		"image-href":      `<img src="hash-asset:logo" href="https://example.invalid">`,
		"remote-image":    `<img src="https://example.invalid/logo.png">`,
		"iframe":          `<iframe src="https://example.invalid"></iframe>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile(Master{SchemaVersion: 1, HTML: source}); err == nil {
				t.Fatal("active or ambiguous source accepted")
			}
		})
	}
}
