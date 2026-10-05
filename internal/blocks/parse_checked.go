// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html"
)

// MaxImportSourceBytes bounds source accepted by canonical authoring imports.
const MaxImportSourceBytes = 1 << 20

// MaxHTMLImportTokens bounds token processing before construction of the DOM.
const MaxHTMLImportTokens = 20_000

// ParseHTMLChecked rejects oversized or excessively fragmented source before
// constructing a DOM. It returns an error rather than a partial document.
func ParseHTMLChecked(src string) (*Tree, error) {
	if len(src) > MaxImportSourceBytes {
		return nil, fmt.Errorf("%w: HTML source exceeds %d bytes", ErrInvalidBlock, MaxImportSourceBytes)
	}
	tokenizer := html.NewTokenizer(strings.NewReader(src))
	for count := 0; ; count++ {
		token := tokenizer.Next()
		if token == html.ErrorToken {
			if err := tokenizer.Err(); err != io.EOF {
				return nil, fmt.Errorf("%w: invalid HTML source", ErrInvalidBlock)
			}
			break
		}
		if count >= MaxHTMLImportTokens {
			return nil, fmt.Errorf("%w: HTML source exceeds %d tokens", ErrInvalidBlock, MaxHTMLImportTokens)
		}
	}
	tree := ParseHTML(src)
	if err := Validate(tree); err != nil {
		return nil, err
	}
	return tree, nil
}

func ParseMarkdownChecked(src string) (*Tree, error) {
	if len(src) > MaxImportSourceBytes {
		return nil, fmt.Errorf("%w: Markdown source exceeds %d bytes", ErrInvalidBlock, MaxImportSourceBytes)
	}
	tree := ParseMarkdown(src)
	if err := Validate(tree); err != nil {
		return nil, err
	}
	return tree, nil
}
