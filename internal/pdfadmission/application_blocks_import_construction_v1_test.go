// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/google/uuid"
	"golang.org/x/net/html"
	"strings"
	"testing"
	"time"
)

func TestMCPImportConstructionOwnsActualSourceAndOriginalLimitsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	org := uuid.New()
	f, c := htmlInputFactoryTestV1(t, 512<<20)
	for _, test := range []struct {
		html   bool
		source string
		want   string
	}{{true, "<h2>Exact heading</h2><p>Exact clause <b>bold</b></p><table><tr><th>Name</th></tr><tr><td>Value</td></tr></table>", "Exact clause bold"}, {true, "<svg><script><b>foreign markup</b></script></svg><p>After</p>", "After"}, {false, "# Exact heading\r\n\r\nExact clause\n\n|A|B|\n|-|-|\n|C|D|", "Exact clause"}} {
		raw, err := json.Marshal(map[string]string{"source": test.source})
		if err != nil {
			t.Fatal(err)
		}
		h, err := f.NewBlocksArgumentsV1(ctx, org, raw)
		if err != nil {
			t.Fatal(err)
		}
		var source struct{ Source string }
		if err = h.WithArgumentsV1(ctx, func(raw []byte) error { return json.Unmarshal(raw, &source) }); err != nil {
			t.Fatal(err)
		}
		before := c.SnapshotV1(org)
		var tree *blocks.Tree
		if test.html {
			tree, err = h.ParseMCPHTMLImportV1(ctx, source.Source)
		} else {
			tree, err = h.ParseMCPMarkdownImportV1(ctx, source.Source)
		}
		if err != nil || tree == nil {
			t.Fatal("original checked import failed", err)
		}
		encoded, err := json.Marshal(tree)
		if err != nil || !strings.Contains(string(encoded), test.want) {
			t.Fatal("original canonical parser content changed", err, string(encoded))
		}
		after := c.SnapshotV1(org)
		if after.Global.ParentBytes <= before.Global.ParentBytes || after.GlobalGrants <= before.GlobalGrants || f.PendingV1().HTMLInputProducers != 1 {
			t.Fatal("actual DOM/AST result was not retained through its input consumer", before, after, f.PendingV1())
		}
		tree = nil
		source.Source = ""
		h.CloseConsumerV1()
		h.CloseConsumerV1()
		if c.SnapshotV1(org).GlobalGrants != 0 || f.PendingV1().HTMLInputProducers != 0 {
			t.Fatal("actual construction last use was not joined")
		}
		if _, err = h.ParseMCPHTMLImportV1(ctx, test.source); !errors.Is(err, ErrBlocksInputV1) {
			t.Fatal("retired input authorized another DOM", err)
		}
	}
	for _, markdown := range []bool{false, true} {
		h, err := f.NewBlocksArgumentsV1(ctx, org, []byte("{}"))
		if err != nil {
			t.Fatal(err)
		}
		if err = h.WithArgumentsV1(ctx, func([]byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
		base := c.SnapshotV1(org)
		large := strings.Repeat("x", blocks.MaxImportSourceBytes+1)
		if markdown {
			_, err = h.ParseMCPMarkdownImportV1(ctx, large)
		} else {
			_, err = h.ParseMCPHTMLImportV1(ctx, large)
		}
		if !errors.Is(err, blocks.ErrInvalidBlock) || c.SnapshotV1(org) != base {
			t.Fatal("original source ceiling did not precede tokenizer/AST work", err)
		}
		h.CloseConsumerV1()
	}
	h, err := f.NewBlocksArgumentsV1(ctx, org, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if err = h.WithArgumentsV1(ctx, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = h.ParseMCPHTMLImportV1(ctx, strings.Repeat("<hr>", blocks.MaxHTMLImportTokens+1)); !errors.Is(err, blocks.ErrInvalidBlock) || !strings.Contains(err.Error(), "20000 tokens") {
		t.Fatal("original HTML token ceiling/grammar changed", err)
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("original limit refusal retained construction debt")
	}
}
func TestMCPImportRefusesConstructionBeforeWorkAndPricesRealNestedCellsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	raw := []byte("{}")
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	h, err := f.NewBlocksArgumentsV1(ctx, org, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.WithArgumentsV1(ctx, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	base := c.SnapshotV1(org).Global.ParentBytes
	h.CloseConsumerV1()
	f, c = htmlInputFactoryTestV1(t, base+1)
	h, err = f.NewBlocksArgumentsV1(ctx, org, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.WithArgumentsV1(ctx, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if tree, err := h.ParseMCPHTMLImportV1(ctx, "<p>Must not construct</p>"); tree != nil || !errors.Is(err, ErrBlocksInputV1) {
		t.Fatal("HTML tokenizer/DOM entered without construction grant", err)
	}
	if tree, err := h.ParseMCPMarkdownImportV1(ctx, "# Must not construct"); tree != nil || !errors.Is(err, ErrBlocksInputV1) {
		t.Fatal("Markdown AST entered without construction grant", err)
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("construction refusal leaked")
	}
	flat, err := html.Parse(strings.NewReader("<table><tr><td>Exact source</td></tr></table>"))
	if err != nil {
		t.Fatal(err)
	}
	nested, err := html.Parse(strings.NewReader("<table><tr><td><table><tr><td>Exact source</td></tr></table></td></tr></table>"))
	if err != nil {
		t.Fatal(err)
	}
	flatWork, err := blocksHTMLImportTreeWorkV1(ctx, flat)
	if err != nil {
		t.Fatal(err)
	}
	nestedWork, err := blocksHTMLImportTreeWorkV1(ctx, nested)
	if err != nil || nestedWork <= flatWork {
		t.Fatal("actual nested-cell text/canonical storage omitted", flatWork, nestedWork, err)
	}
	// Real source-specific tokenizer/formatting inventory is positive for the
	// unchanged maximum source. This does not claim configured-provider capacity.
	source := strings.Repeat("x", blocks.MaxImportSourceBytes)
	tokenWork, err := blocksHTMLImportTokenWorkV1(source)
	if err != nil || tokenWork <= int64(len(source)) {
		t.Fatal("maximum original tokenizer source not priced", tokenWork, err)
	}
	domWork, err := blocksHTMLImportDOMWorkV1(ctx, source)
	if err != nil || domWork <= int64(len(source)) {
		t.Fatal("maximum original DOM source not priced", domWork, err)
	}
}

func TestMCPImportRequiresActualReadyMCPInputV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	for _, h := range []*ApplicationBlocksInputV1{nil, {}, {state: &applicationHTMLAuthoringInputStateV1{}}} {
		if tree, err := h.ParseMCPHTMLImportV1(ctx, "<p>Unowned</p>"); tree != nil || !errors.Is(err, ErrBlocksInputV1) {
			t.Fatal("unregistered input authorized DOM", err)
		}
	}
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	h, err := f.NewBlocksArgumentsV1(ctx, org, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ParseMCPMarkdownImportV1(ctx, "# Undecoded"); !errors.Is(err, ErrBlocksInputV1) {
		t.Fatal("undecoded input authorized AST", err)
	}
	if err = h.WithArgumentsV1(ctx, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	copy := *h
	h.CloseConsumerV1()
	if _, err = copy.ParseMCPHTMLImportV1(ctx, "<p>Closed copy</p>"); !errors.Is(err, ErrBlocksInputV1) {
		t.Fatal("copied handle revived closed source", err)
	}
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("refused source leaked")
	}
}
