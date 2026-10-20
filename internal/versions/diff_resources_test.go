// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package versions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/blocks"
)

func diffResourceJSON(t *testing.T, list []blocks.Block) []byte {
	t.Helper()
	raw, err := json.Marshal(blocks.Tree{Version: blocks.SchemaVersion, Blocks: list})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestDiffContextPreservesNestedTableAttrsMovesAndStableOrdering(t *testing.T) {
	from := []blocks.Block{
		{ID: "h", Type: blocks.TypeHeading, Text: "Title", Attrs: map[string]any{"level": float64(1)}},
		{ID: "q", Type: blocks.TypeQuote, Content: []blocks.Block{{ID: "p", Type: blocks.TypeParagraph, Text: "before"}}},
		{ID: "t", Type: blocks.TypeTable, Attrs: map[string]any{"columns": []any{"A"}}, Rows: [][]string{{"before"}}},
		{ID: "gone", Type: blocks.TypeParagraph, Text: "removed"},
	}
	to := []blocks.Block{
		{ID: "t", Type: blocks.TypeTable, Attrs: map[string]any{"columns": []any{"A"}}, Rows: [][]string{{"after"}}},
		{ID: "h", Type: blocks.TypeHeading, Text: "Title", Attrs: map[string]any{"level": float64(2)}},
		{ID: "q", Type: blocks.TypeQuote, Content: []blocks.Block{{ID: "p", Type: blocks.TypeParagraph, Text: "after"}}},
		{ID: "added", Type: blocks.TypeParagraph, Text: "added"},
	}
	want := []BlockChange{
		{Kind: ChangeModified, BlockID: "t", Type: "table", Position: 0, FromAttr: "{\"columns\":[\"A\"]}", ToAttr: "{\"columns\":[\"A\"]}"},
		{Kind: ChangeModified, BlockID: "h", Type: "heading", Position: 1, FromText: "Title", ToText: "Title", FromAttr: "{\"level\":1}", ToAttr: "{\"level\":2}"},
		{Kind: ChangeMoved, BlockID: "q", Type: "quote", Position: 2},
		{Kind: ChangeModified, BlockID: "p", Type: "paragraph", Position: 3, FromText: "before", ToText: "after"},
		{Kind: ChangeAdded, BlockID: "added", Type: "paragraph", Position: 4, ToText: "added"},
		{Kind: ChangeRemoved, BlockID: "gone", Type: "paragraph", Position: 4, FromText: "removed"},
	}
	got, err := DiffContext(context.Background(), diffResourceJSON(t, from), diffResourceJSON(t, to))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("block diff semantics/order changed: %v\n%+v", err, got)
	}
}
func TestDiffFlattenDeepWideUsesOneLinearOutputBuffer(t *testing.T) {
	leaves := make([]blocks.Block, blocks.MaxTreeBlocks-(blocks.MaxTreeDepth-1))
	for i := range leaves {
		leaves[i] = blocks.Block{ID: fmt.Sprintf("leaf-%d", i), Type: blocks.TypeParagraph, Text: "original"}
	}
	in := leaves
	for level := blocks.MaxTreeDepth - 2; level >= 0; level-- {
		in = []blocks.Block{{ID: fmt.Sprintf("parent-%d", level), Type: blocks.TypeQuote, Content: in}}
	}
	var sink []flatEntry
	allocations := testing.AllocsPerRun(3, func() {
		var err error
		sink, err = flattenWithPositionContext(context.Background(), in, 11)
		if err != nil || len(sink) != blocks.MaxTreeBlocks {
			t.Fatal("valid deep/wide tree refused")
		}
	})
	if allocations > 8 {
		t.Fatalf("flatten allocates per-subtree rather than one admitted output: %.0f", allocations)
	}
	for i, entry := range sink {
		if entry.Position != 11+i {
			t.Fatal("depth-first positions changed")
		}
	}
	if sink[len(sink)-1].Block.ID != leaves[len(leaves)-1].ID {
		t.Fatal("flatten lost the final original block")
	}
}
func TestDiffAttributeAdmissionMatchesCanonicalJSONBoundary(t *testing.T) {
	cases := []map[string]any{
		{"label": "plain"},
		{"label": "quote\" slash\\ controls\x00\b\f\n\r\t <>& \u2028\u2029 invalid\xff"},
		{"columns": []any{"a", "<>&", "\n\"", "\u2028"}},
		{"required": false, "label": "role", "recipient_role": "signer"},
		{"level": float64(3)},
	}
	for _, attrs := range cases {
		want, err := json.Marshal(attrs)
		if err != nil {
			t.Fatal(err)
		}
		remaining := int64(len(want))
		got, err := boundedAttrSummaryContext(context.Background(), blocks.Block{Attrs: attrs}, &remaining)
		if err != nil || got != string(want) || remaining != 0 {
			t.Fatalf("canonical exact-byte attr admission changed: %v", err)
		}
		remaining = int64(len(want)) - 1
		if got, err := boundedAttrSummaryContext(context.Background(), blocks.Block{Attrs: attrs}, &remaining); got != "" || !errors.Is(err, ErrDiffTooLarge) {
			t.Fatal("limit-minus-one summary was allocated/accepted")
		}
	}
}
func TestDiffAttributeExpansionRefusedBeforeLargeMarshalAllocation(t *testing.T) {
	b := blocks.Block{Type: blocks.TypeImage, Attrs: map[string]any{"storage_key": "asset", "alt": strings.Repeat("<", 1<<20)}}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 3; i++ {
		remaining := int64(4 << 20)
		got, err := boundedAttrSummaryContext(context.Background(), b, &remaining)
		if got != "" || !errors.Is(err, ErrDiffTooLarge) {
			t.Fatal("HTML escaping expansion passed existing evidence work cap")
		}
	}
	runtime.ReadMemStats(&after)
	// A late guard after Marshal/string conversion would allocate multi-MiB
	// buffers. The raw input/map was built before this measurement.
	if after.TotalAlloc-before.TotalAlloc > 256<<10 {
		t.Fatalf("refusal materialized large escaped summary: %d bytes", after.TotalAlloc-before.TotalAlloc)
	}
}
func TestDiffExplicitEvidenceAttributeBudgetPreservesLegacyDefault(t *testing.T) {
	oldText := strings.Repeat("<", 4096)
	// Keep literal HTML bytes in the original JSON wire, as historical inputs
	// can do; canonical attr summaries independently HTML-escape them.
	from := []byte("{\"version\":1,\"blocks\":[{\"id\":\"image\",\"type\":\"image\",\"attrs\":{\"storage_key\":\"asset\",\"alt\":\"" + oldText + "\"}}]}")
	to := []byte("{\"version\":1,\"blocks\":[{\"id\":\"image\",\"type\":\"image\",\"attrs\":{\"storage_key\":\"asset\",\"alt\":\"changed\"}}]}")
	got, err := DiffContext(context.Background(), from, to)
	if err != nil || len(got) != 1 || !strings.Contains(got[0].FromAttr, "\\u003c") {
		t.Fatalf("valid legacy default diff changed: %v", err)
	}
	budget := int64(len(got[0].FromAttr) + len(got[0].ToAttr))
	exact, err := DiffContextWithAttributeLimit(context.Background(), from, to, budget)
	if err != nil || !reflect.DeepEqual(exact, got) {
		t.Fatal("exact combined attr budget changed the diff")
	}
	if limited, err := DiffContextWithAttributeLimit(context.Background(), from, to, budget-1); limited != nil || !errors.Is(err, ErrDiffTooLarge) {
		t.Fatal("combined fitted attr budget returned partial/oversized changes")
	}
}

type diffCancelAfterChecks struct {
	context.Context
	checks, at int
	cancel     context.CancelCauseFunc
	cause      error
}

func (c *diffCancelAfterChecks) Err() error {
	c.checks++
	if c.checks == c.at {
		c.cancel(c.cause)
	}
	return c.Context.Err()
}
func TestDiffContextCancellationStopsFlattenAndHidesPrivateCause(t *testing.T) {
	cause := errors.New("private diff cancellation cause")
	early, stop := context.WithCancelCause(context.Background())
	stop(cause)
	if got, err := DiffContext(early, []byte("not JSON"), nil); got != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("early diff cancellation lost/disclosed cause")
	}
	parent, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	ctx := &diffCancelAfterChecks{Context: parent, at: 50, cancel: cancel, cause: cause}
	in := make([]blocks.Block, 1000)
	for i := range in {
		in[i] = blocks.Block{ID: fmt.Sprintf("a-%d", i), Type: blocks.TypeParagraph}
	}
	got, err := flattenWithPositionContext(ctx, in, 0)
	if got != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("flatten cancellation returned partial blocks or disclosed cause")
	}
}
