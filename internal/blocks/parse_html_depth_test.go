// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"golang.org/x/net/html"
	"testing"
)

func TestHTMLTraversalDeepSubtreePreservesOrderAndBoundary(t *testing.T) {
	root := &html.Node{Type: html.ElementNode, Data: "div"}
	outside := &html.Node{Type: html.ElementNode, Data: "aside"}
	parent := &html.Node{Type: html.ElementNode, Data: "body"}
	parent.AppendChild(root)
	parent.AppendChild(outside)
	outside.AppendChild(&html.Node{Type: html.TextNode, Data: "outside"})
	node := root
	for i := 0; i < 100000; i++ {
		child := &html.Node{Type: html.ElementNode, Data: "div"}
		node.AppendChild(child)
		node = child
	}
	table := &html.Node{Type: html.ElementNode, Data: "table"}
	node.AppendChild(table)
	for _, value := range []string{"first", "second"} {
		row := &html.Node{Type: html.ElementNode, Data: "tr"}
		table.AppendChild(row)
		row.AppendChild(&html.Node{Type: html.TextNode, Data: value + " "})
	}
	if got := textContent(root); got != "first second" {
		t.Fatalf("text = %q", got)
	}
	if got := findFirst(root, "table"); got != table {
		t.Fatal("deep table not found")
	}
	if findFirst(root, "aside") != nil {
		t.Fatal("traversal escaped subtree")
	}
	count := 0
	for range trIter(root) {
		count++
	}
	if count != 2 {
		t.Fatalf("rows = %d", count)
	}
	count = 0
	for range walkHTML(root) {
		count++
		break
	}
	if count != 1 {
		t.Fatal("iterator did not stop")
	}
}
