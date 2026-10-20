// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package versions

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/blocks"
)

// Attribute summaries are new retained strings, unlike text/IDs which point
// into parsed trees. Admit their combined canonical JSON bytes before Marshal.
// Default Diff uses a wire-relative bound preserving valid legacy documents;
// fitted evidence explicitly selects its existing4MiB output policy instead.
func diffAttributeWireBudget(from, to []byte) (int64, error) {
	a, b := int64(len(from)), int64(len(to))
	if a > math.MaxInt64/6-b {
		return 0, ErrDiffTooLarge
	}
	// JSON canonical string escaping expands a wire byte by at most six bytes.
	// Each unique block's attrs can be summarized at most once on either side.
	return 6 * (a + b), nil
}

var ErrDiffTooLarge = errors.New("document diff resource limit")

func flattenWithPositionContext(ctx context.Context, in []blocks.Block, startPos int) (out []flatEntry, retErr error) {
	defer func() {
		if err := blocks.TreeContextError(ctx); err != nil {
			out = nil
			retErr = err
		}
	}()
	count := 0
	var countNodes func([]blocks.Block, int) error
	countNodes = func(nodes []blocks.Block, depth int) error {
		if depth > blocks.MaxTreeDepth {
			return ErrDiffTooLarge
		}
		for i := range nodes {
			if err := blocks.TreeContextError(ctx); err != nil {
				return err
			}
			if count >= blocks.MaxTreeBlocks {
				return ErrDiffTooLarge
			}
			count++
			if len(nodes[i].Content) > 0 {
				if err := countNodes(nodes[i].Content, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := countNodes(in, 1); err != nil {
		return nil, err
	}
	out = make([]flatEntry, 0, count)
	var appendNodes func([]blocks.Block) error
	appendNodes = func(nodes []blocks.Block) error {
		for i := range nodes {
			if err := blocks.TreeContextError(ctx); err != nil {
				return err
			}
			out = append(out, flatEntry{Block: nodes[i], Position: startPos + len(out)})
			if err := appendNodes(nodes[i].Content); err != nil {
				return err
			}
		}
		return nil
	}
	if err := appendNodes(in); err != nil {
		return nil, err
	}
	return out, nil
}
func indexByIDContext(ctx context.Context, entries []flatEntry) (map[string]flatEntry, error) {
	out := make(map[string]flatEntry, len(entries))
	for _, entry := range entries {
		if err := blocks.TreeContextError(ctx); err != nil {
			return nil, err
		}
		if entry.Block.ID != "" {
			out[entry.Block.ID] = entry
		}
	}
	return out, nil
}
func attrsEqualContext(ctx context.Context, a, b map[string]any) (bool, error) {
	if len(a) != len(b) {
		return false, nil
	}
	for key, va := range a {
		if err := blocks.TreeContextError(ctx); err != nil {
			return false, err
		}
		vb, ok := b[key]
		if !ok {
			return false, nil
		}
		switch value := va.(type) {
		case string:
			other, ok := vb.(string)
			if !ok || value != other {
				return false, nil
			}
		case bool:
			other, ok := vb.(bool)
			if !ok || value != other {
				return false, nil
			}
		case float64:
			other, ok := vb.(float64)
			if !ok || value != other {
				return false, nil
			}
		case []any:
			other, ok := vb.([]any)
			if !ok || len(value) != len(other) {
				return false, nil
			}
			for i, item := range value {
				if err := blocks.TreeContextError(ctx); err != nil {
					return false, err
				}
				text, ok := item.(string)
				next, ok2 := other[i].(string)
				if !ok || !ok2 || text != next {
					return false, nil
				}
			}
		default:
			// ParseTree's canonical validator excludes this path. Keep the legacy
			// JSON equivalence for direct internal helpers without widening the schema.
			ja, err := json.Marshal(va)
			if err != nil {
				return false, err
			}
			jb, err := json.Marshal(vb)
			if err != nil {
				return false, err
			}
			if string(ja) != string(jb) {
				return false, nil
			}
		}
	}
	return true, nil
}
func blockEquivalentContext(ctx context.Context, a, b blocks.Block) (bool, error) {
	if err := blocks.TreeContextError(ctx); err != nil {
		return false, err
	}
	if a.Type != b.Type || a.Text != b.Text {
		return false, nil
	}
	same, err := attrsEqualContext(ctx, a.Attrs, b.Attrs)
	if err != nil || !same {
		return same, err
	}
	if len(a.Rows) != len(b.Rows) {
		return false, nil
	}
	for i, row := range a.Rows {
		if err := blocks.TreeContextError(ctx); err != nil {
			return false, err
		}
		if len(row) != len(b.Rows[i]) {
			return false, nil
		}
		for j, cell := range row {
			if err := blocks.TreeContextError(ctx); err != nil {
				return false, err
			}
			if cell != b.Rows[i][j] {
				return false, nil
			}
		}
	}
	return true, nil
}

type diffAttributeCounter struct {
	ctx         context.Context
	used, limit int64
}

func (c *diffAttributeCounter) add(n int64) error {
	if err := blocks.TreeContextError(c.ctx); err != nil {
		return err
	}
	if n < 0 || n > c.limit-c.used {
		return ErrDiffTooLarge
	}
	c.used += n
	return nil
}
func (c *diffAttributeCounter) string(s string) error {
	if err := c.add(2); err != nil {
		return err
	}
	for i := 0; i < len(s); {
		if i&1023 == 0 {
			if err := blocks.TreeContextError(c.ctx); err != nil {
				return err
			}
		}
		b := s[i]
		n := int64(1)
		step := 1
		switch {
		case b == '"' || b == '\\' || b == '\b' || b == '\f' || b == '\n' || b == '\r' || b == '\t':
			n = 2
		case b < 0x20 || b == '<' || b == '>' || b == '&':
			n = 6
		case b >= utf8.RuneSelf:
			r, width := utf8.DecodeRuneInString(s[i:])
			step = width
			n = int64(width)
			if r == utf8.RuneError && width == 1 {
				n = 6
			} else if r == '\u2028' || r == '\u2029' {
				n = 6
			}
		}
		if err := c.add(n); err != nil {
			return err
		}
		i += step
	}
	return nil
}
func (c *diffAttributeCounter) value(v any) error {
	switch value := v.(type) {
	case string:
		return c.string(value)
	case bool:
		if value {
			return c.add(4)
		}
		return c.add(5)
	case float64, int:
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		return c.add(int64(len(raw)))
	case []any:
		if err := c.add(2); err != nil {
			return err
		}
		for i, item := range value {
			if i > 0 {
				if err := c.add(1); err != nil {
					return err
				}
			}
			s, ok := item.(string)
			if !ok {
				return ErrDiffTooLarge
			}
			if err := c.string(s); err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrDiffTooLarge
	}
}
func boundedAttrSummaryContext(ctx context.Context, b blocks.Block, remaining *int64) (string, error) {
	if err := blocks.TreeContextError(ctx); err != nil {
		return "", err
	}
	if remaining == nil || *remaining < 0 {
		return "", ErrDiffTooLarge
	}
	if len(b.Attrs) == 0 {
		return "", nil
	}
	c := diffAttributeCounter{ctx: ctx, limit: *remaining}
	if err := c.add(2); err != nil {
		return "", err
	}
	i := 0
	for key, value := range b.Attrs {
		if i > 0 {
			if err := c.add(1); err != nil {
				return "", err
			}
		}
		i++
		if err := c.string(key); err != nil {
			return "", err
		}
		if err := c.add(1); err != nil {
			return "", err
		}
		if err := c.value(value); err != nil {
			return "", err
		}
	}
	// No canonical summary is allocated before its exact size is admitted.
	*remaining -= c.used
	raw, err := json.Marshal(b.Attrs)
	if err != nil {
		return "", err
	}
	if err := blocks.TreeContextError(ctx); err != nil {
		return "", err
	}
	if int64(len(raw)) != c.used {
		return "", ErrDiffTooLarge
	}
	return string(raw), nil
}
