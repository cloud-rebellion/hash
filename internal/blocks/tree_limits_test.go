// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"errors"
	"fmt"
	"testing"
)

func nestedTree(depth int) *Tree {
	block := Block{ID: "leaf", Type: TypeParagraph, Text: "content"}
	for i := 1; i < depth; i++ {
		block = Block{ID: fmt.Sprintf("quote%d", i), Type: TypeQuote, Content: []Block{block}}
	}
	return &Tree{Version: 1, Blocks: []Block{block}}
}
func TestCanonicalTreeDepthBoundary(t *testing.T) {
	if err := Validate(nestedTree(MaxTreeDepth)); err != nil {
		t.Fatal(err)
	}
	if err := Validate(nestedTree(MaxTreeDepth + 1)); !errors.Is(err, ErrInvalidBlock) {
		t.Fatalf("excess depth accepted: %v", err)
	}
}
func TestCanonicalTreeTotalBlockBoundary(t *testing.T) {
	tree := &Tree{Version: 1}
	for i := 0; i < MaxTreeBlocks; i++ {
		tree.Blocks = append(tree.Blocks, Block{ID: fmt.Sprintf("p%d", i), Type: TypeParagraph})
	}
	if err := Validate(tree); err != nil {
		t.Fatal(err)
	}
	// The count includes nested blocks, rather than just top-level entries.
	tree.Blocks[0] = Block{ID: "container", Type: TypeQuote, Content: []Block{{ID: "extra", Type: TypeParagraph}}}
	if err := Validate(tree); !errors.Is(err, ErrInvalidBlock) {
		t.Fatalf("excess total count accepted: %v", err)
	}
}
