// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

// This is the original current-C parser's standard decoder/validation oracle,
// independent of the proposed context reader and withdrawn lexical preflight.
func legacyTreeDecoderOracle(raw []byte) (*Tree, error) {
	if len(raw) == 0 {
		return &Tree{Version: SchemaVersion}, nil
	}
	var tree Tree
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&tree); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	if tree.Version == 0 {
		tree.Version = SchemaVersion
	}
	if err := Validate(&tree); err != nil {
		return nil, err
	}
	return &tree, nil
}
func TestTreeContextDuplicateAttrsMergeAndNullResetMatchDecoder(t *testing.T) {
	fixtures := []string{
		"{\"version\":1,\"blocks\":[{\"id\":\"a\",\"type\":\"signature_field\",\"attrs\":{\"recipient_role\":\"signer\"},\"ATTRS\":{\"label\":\"original\"},\"attrs\":{\"required\":true}}]}",
		"{\"version\":1,\"blocks\":[{\"id\":\"a\",\"type\":\"heading\",\"attrs\":{\"level\":1,\"discarded-a\":\"a\",\"discarded-b\":\"b\"},\"attrs\":{\"discarded-c\":\"c\"},\"attrs\":null,\"attrs\":{\"level\":2}}]}",
		"{\"version\":1,\"blocks\":[{\"id\":\"a\",\"type\":\"heading\",\"attrs\":{\"discarded\":" + strings.Repeat("[", 200) + "null" + strings.Repeat("]", 200) + "},\"attrs\":null,\"attrs\":{\"level\":2}}]}",
	}
	for i, input := range fixtures {
		want, err := legacyTreeDecoderOracle([]byte(input))
		if err != nil {
			t.Fatalf("legacy valid duplicate/null fixture %d: %v", i, err)
		}
		got, err := ParseTreeContext(context.Background(), []byte(input))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("decoder duplicate/null semantics changed for fixture%d: %v", i, err)
		}
	}
	// Non-null attrs merge; without a later reset this remains invalid under
	// the same final canonical validator, rather than a new duplicate policy.
	invalid := []byte("{\"version\":1,\"blocks\":[{\"id\":\"a\",\"type\":\"signature_field\",\"attrs\":{\"recipient_role\":\"signer\",\"label\":\"old\",\"required\":true},\"attrs\":{\"unknown\":\"refuse\"}}]}")
	_, oldErr := legacyTreeDecoderOracle(invalid)
	_, newErr := ParseTreeContext(context.Background(), invalid)
	if !errors.Is(oldErr, ErrInvalidBlock) || !errors.Is(newErr, ErrInvalidBlock) {
		t.Fatal("final canonical rejection changed")
	}
}
func TestTreeContextRepeatedSlicesRetainOmittedFieldsAndResetWithNull(t *testing.T) {
	fixtures := []string{
		"{\"version\":1,\"blocks\":[{\"id\":\"outer\",\"type\":\"quote\",\"content\":[{\"id\":\"child\",\"type\":\"paragraph\",\"text\":\"retained\"}]}],\"blocks\":[{\"id\":\"renamed\"}]}",
		"{\"version\":1,\"blocks\":[{\"id\":\"a\",\"type\":\"paragraph\",\"text\":\"retained\"}],\"blocks\":[{\"id\":null,\"text\":null}]}",
		"{\"version\":1,\"blocks\":[{\"id\":\"a\",\"type\":\"heading\",\"attrs\":{\"level\":1}}],\"blocks\":null,\"blocks\":[{\"id\":\"b\",\"type\":\"heading\",\"text\":\"fresh\",\"attrs\":{\"level\":2}}]}",
		"{\"version\":1,\"blocks\":[{\"id\":\"outer\",\"type\":\"quote\",\"content\":[{\"id\":\"old\",\"type\":\"paragraph\",\"text\":\"old\"}],\"content\":[],\"content\":[{\"id\":\"fresh\",\"type\":\"paragraph\",\"text\":\"new\"}]}]}",
	}
	for i, input := range fixtures {
		want, err := legacyTreeDecoderOracle([]byte(input))
		if err != nil {
			t.Fatalf("legacy valid reuse fixture%d: %v", i, err)
		}
		got, err := ParseTreeContext(context.Background(), []byte(input))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("slice element/null semantics changed for fixture%d: %v", i, err)
		}
	}
}
func TestTreeContextRepeatedWireNodesUseFinalDecoderShape(t *testing.T) {
	nodes := make([]Block, MaxTreeBlocks/2+1)
	for i := range nodes {
		nodes[i] = Block{ID: fmt.Sprintf("n%d", i), Type: TypeParagraph, Text: "original"}
	}
	array, err := json.Marshal(nodes)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("{\"version\":1,\"blocks\":" + string(array) + ",\"BLOCKS\":" + string(array) + "}")
	want, err := legacyTreeDecoderOracle(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTreeContext(context.Background(), raw)
	if err != nil || len(got.Blocks) != len(nodes) || !reflect.DeepEqual(got, want) {
		t.Fatalf("cumulative wire occurrences falsely changed final node policy: %v", err)
	}
}
func TestTreeContextMetadataDuplicatesPreserveExistingCounts(t *testing.T) {
	fixtures := []string{"null", "{\"blocks\":[1,null,\"x\",[]]}", "{\"blocks\":[{},{}],\"blocks\":null}", "{\"blocks\":[{},{},{}],\"BLOCKS\":[{}]}"}
	for _, input := range fixtures {
		var old struct {
			Blocks []json.RawMessage `json:"blocks"`
		}
		oldErr := json.Unmarshal([]byte(input), &old)
		count, err := CountTopLevelTreeBlocksContext(context.Background(), []byte(input))
		if (err != nil) != (oldErr != nil) || count != len(old.Blocks) {
			t.Fatalf("legacy metadata count changed for %s", input)
		}
	}
}

type contextCancelAfterChecksV2 struct {
	context.Context
	checks, at int
	cancel     context.CancelCauseFunc
	cause      error
}

func (c *contextCancelAfterChecksV2) Err() error {
	c.checks++
	if c.checks == c.at {
		c.cancel(c.cause)
	}
	return c.Context.Err()
}
func TestTreeContextEscapedStringCancellationDoesNotDependOnParity(t *testing.T) {
	cause := errors.New("private escaped decoder cancellation cause")
	parent, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	ctx := &contextCancelAfterChecksV2{Context: parent, at: 4, cancel: cancel, cause: cause}
	prefix := "{\"version\":1,\"blocks\":[{\"id\":\"a\",\"type\":\"paragraph\",\"text\":\""
	if len(prefix)%2 == 0 {
		prefix = " " + prefix
	}
	raw := []byte(prefix + strings.Repeat("\\\"", 1<<20) + "\"}]}")
	reader := &treeContextReader{ctx, bytes.NewReader(raw)}
	var tree Tree
	err := json.NewDecoder(reader).Decode(&tree)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) || reader.reader.Len() < len(raw)/2 {
		t.Fatal("escaped-string cancellation waited for a lexical byte-index checkpoint or disclosed cause")
	}
}
func TestTreeContextMetadataCancellationCannotBecomeSuccessfulCount(t *testing.T) {
	cause := errors.New("private metadata cancellation cause")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	count, err := CountTopLevelTreeBlocksContext(ctx, []byte("{\"blocks\":[{}]}"))
	if count != 0 || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("canceled metadata returned successful/partial count or disclosed cause")
	}
	got, err := ParseTreeContext(ctx, []byte("not JSON"))
	if got != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("early canceled parse lost/disclosed private cause")
	}
}

func resourceAllTypesTree(t *testing.T) *Tree {
	t.Helper()
	out := &Tree{Version: SchemaVersion}
	for i, kind := range AllTypes() {
		b := Block{ID: fmt.Sprintf("kind-%d", i), Type: kind}
		switch kind {
		case TypeHeading:
			b.Text = "heading"
			b.Attrs = map[string]any{"level": float64(2)}
		case TypeParagraph, TypeCode, TypeQuote, TypeCallout:
			b.Text = "retained text"
		case TypeRawHTML:
			b.Text = "<p>retained HTML</p>"
		case TypeBulletList, TypeOrderedList:
			b.Content = []Block{{ID: b.ID + "-item", Type: TypeListItem, Text: "item"}}
		case TypeListItem:
			b.Text = "item"
		case TypeTable:
			b.Attrs = map[string]any{"columns": []any{"one", "two"}}
			b.Rows = [][]string{{"first", "second"}}
		case TypeImage:
			b.Attrs = map[string]any{"storage_key": "org/image", "alt": "retained image", "width_pct": "50"}
		case TypeSignatureField, TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox:
			b.Attrs = map[string]any{"recipient_role": "signer", "label": "retained field", "required": true}
		case TypeDynamicVar:
			b.Attrs = map[string]any{"name": "company", "default": "retained company"}
		case TypeConditional:
			b.Attrs = map[string]any{"expression": "var(enabled)"}
			b.Content = []Block{{ID: b.ID + "-child", Type: TypeParagraph, Text: "conditional original"}}
		}
		out.Blocks = append(out.Blocks, b)
	}
	return out
}

func TestTreeContextPreservesAllCurrentContractBlockTypes(t *testing.T) {
	want := resourceAllTypesTree(t)
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	original, err := legacyTreeDecoderOracle(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTreeContext(context.Background(), raw)
	if err != nil || !reflect.DeepEqual(got, original) || !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical contract block types changed: %v", err)
	}
}
