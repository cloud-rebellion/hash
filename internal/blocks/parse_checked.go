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
func ParseHTMLChecked(src string) (*Tree, error) { return parseHTMLCheckedWithConstructionV1(src, nil) }
func ParseHTMLCheckedForAuthoringV1(src string, admission HTMLImportConstructionV1) (*Tree, error) {
	if admission == nil {
		return nil, fmt.Errorf("%w: HTML import construction unavailable", ErrInvalidBlock)
	}
	return parseHTMLCheckedWithConstructionV1(src, admission)
}
func parseHTMLCheckedWithConstructionV1(src string, admission HTMLImportConstructionV1) (*Tree, error) {
	if len(src) > MaxImportSourceBytes {
		return nil, fmt.Errorf("%w: HTML source exceeds %d bytes", ErrInvalidBlock, MaxImportSourceBytes)
	}
	if admission != nil {
		if err := admission.BeforeHTMLTokensV1(src); err != nil {
			return nil, err
		}
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
	if admission != nil {
		if err := admission.BeforeHTMLDOMV1(src); err != nil {
			return nil, err
		}
	}
	tree, err := parseHTMLWithConstructionV1(src, admission)
	if err != nil {
		return nil, err
	}
	if err := Validate(tree); err != nil {
		return nil, err
	}
	return tree, nil
}

func ParseMarkdownChecked(src string) (*Tree, error) {
	return parseMarkdownCheckedWithConstructionV1(src, nil)
}
func ParseMarkdownCheckedForAuthoringV1(src string, admission MarkdownImportConstructionV1) (*Tree, error) {
	if admission == nil {
		return nil, fmt.Errorf("%w: Markdown import construction unavailable", ErrInvalidBlock)
	}
	return parseMarkdownCheckedWithConstructionV1(src, admission)
}
func parseMarkdownCheckedWithConstructionV1(src string, admission MarkdownImportConstructionV1) (*Tree, error) {
	if len(src) > MaxImportSourceBytes {
		return nil, fmt.Errorf("%w: Markdown source exceeds %d bytes", ErrInvalidBlock, MaxImportSourceBytes)
	}
	if admission != nil {
		if err := admission.BeforeMarkdownBlocksV1(src); err != nil {
			return nil, err
		}
	}
	tree := ParseMarkdown(src)
	if err := Validate(tree); err != nil {
		return nil, err
	}
	return tree, nil
}
