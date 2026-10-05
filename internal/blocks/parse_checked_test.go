// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckedImportSourceByteBounds(t *testing.T) {
	for _, parser := range []struct {
		name  string
		parse func(string) (*Tree, error)
	}{{"html", ParseHTMLChecked}, {"markdown", ParseMarkdownChecked}} {
		t.Run(parser.name, func(t *testing.T) {
			tree, err := parser.parse(strings.Repeat(" ", MaxImportSourceBytes))
			if err != nil || tree == nil {
				t.Fatalf("boundary: %v", err)
			}
			tree, err = parser.parse(strings.Repeat(" ", MaxImportSourceBytes+1))
			if !errors.Is(err, ErrInvalidBlock) || tree != nil {
				t.Fatalf("overflow returned tree=%v err=%v", tree, err)
			}
		})
	}
}

func TestCheckedHTMLTokenBoundary(t *testing.T) {
	source := strings.Repeat("<!--x-->", MaxHTMLImportTokens)
	if _, err := ParseHTMLChecked(source); err != nil {
		t.Fatalf("boundary: %v", err)
	}
	tree, err := ParseHTMLChecked(source + "<!--x-->")
	if tree != nil || !errors.Is(err, ErrInvalidBlock) {
		t.Fatalf("overflow tree=%v err=%v", tree, err)
	}
}

func TestCheckedImportsRejectOversizedCanonicalTree(t *testing.T) {
	for _, source := range []struct {
		parse func(string) (*Tree, error)
		text  string
	}{
		{ParseHTMLChecked, strings.Repeat("<hr>", MaxTreeBlocks+1)},
		{ParseMarkdownChecked, strings.Repeat("---\n", MaxTreeBlocks+1)},
	} {
		tree, err := source.parse(source.text)
		if tree != nil || !errors.Is(err, ErrInvalidBlock) {
			t.Fatalf("overflow tree=%v err=%v", tree, err)
		}
	}
}
