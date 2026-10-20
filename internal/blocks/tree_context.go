// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// Context remains cooperative around the standard decoder. Do not replace
// its duplicate map/slice/null semantics with a wire-occurrence shape count.
// A final-state-compatible pretyped resource projector is still required to
// bound transient typed allocations; this file does not claim that admission.
type treeContextFailure struct{ kind, cause error }

func (e treeContextFailure) Error() string   { return e.kind.Error() }
func (e treeContextFailure) Unwrap() []error { return []error{e.kind, e.cause} }
func TreeContextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil tree context", ErrInvalidBlock)
	}
	if err := ctx.Err(); err != nil {
		return treeContextFailure{err, context.Cause(ctx)}
	}
	return nil
}

type treeContextReader struct {
	ctx    context.Context
	reader *bytes.Reader
}

func (r *treeContextReader) Read(p []byte) (int, error) {
	if err := TreeContextError(r.ctx); err != nil {
		return 0, err
	}
	// Every Read is checked regardless of escaped-string byte index parity.
	if len(p) > 4096 {
		p = p[:4096]
	}
	return r.reader.Read(p)
}
func decodeTreeContext(ctx context.Context, raw []byte) (tree *Tree, retErr error) {
	defer func() {
		if err := TreeContextError(ctx); err != nil {
			tree = nil
			retErr = err
		}
	}()
	if err := TreeContextError(ctx); err != nil {
		return nil, err
	}
	var t Tree
	dec := json.NewDecoder(&treeContextReader{ctx, bytes.NewReader(raw)})
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("decode tree: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("decode tree: trailing JSON content")
	}
	return &t, nil
}
func ParseTreeContext(ctx context.Context, raw []byte) (tree *Tree, retErr error) {
	defer func() {
		if err := TreeContextError(ctx); err != nil {
			tree = nil
			retErr = err
		}
	}()
	if err := TreeContextError(ctx); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return &Tree{Version: SchemaVersion}, nil
	}
	tree, err := decodeTreeContext(ctx, raw)
	if err != nil {
		return nil, err
	}
	if tree.Version == 0 {
		tree.Version = SchemaVersion
	}
	if err := TreeContextError(ctx); err != nil {
		return nil, err
	}
	if err := Validate(tree); err != nil {
		return nil, err
	}
	if err := TreeContextError(ctx); err != nil {
		return nil, err
	}
	return tree, nil
}

// CountTopLevelTreeBlocksContext preserves the existing best-effort metadata
// decoder (including RawMessage/duplicate-field behavior) while checking
// cancellation during reads and before/after conversion. It imposes no new
// canonical-tree or duplicate-key policy on legacy metadata.
func CountTopLevelTreeBlocksContext(ctx context.Context, raw []byte) (count int, retErr error) {
	defer func() {
		if err := TreeContextError(ctx); err != nil {
			count = 0
			retErr = err
		}
	}()
	if err := TreeContextError(ctx); err != nil {
		return 0, err
	}
	if len(raw) == 0 {
		return 0, nil
	}
	var t struct {
		Blocks []json.RawMessage `json:"blocks"`
	}
	dec := json.NewDecoder(&treeContextReader{ctx, bytes.NewReader(raw)})
	if err := dec.Decode(&t); err != nil {
		return 0, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return 0, fmt.Errorf("tree metadata: trailing JSON content")
	}
	return len(t.Blocks), nil
}
