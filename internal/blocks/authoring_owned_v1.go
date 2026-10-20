// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blocks

import (
	"context"
	"encoding/json"
	"fmt"
)

// NormalizeTreeForAuthoringV1 is the original authoring decoder and validator,
// including its version default, generated omitted IDs and JSON merge/null
// behavior. It only joins the existing conditional decimal admission hook;
// it adds no accepted grammar or wire-occurrence/count/depth restriction.
// The concrete native caller must fund typed decoding before entering here.
func ParseTreeForAuthoringV1(ctx context.Context, raw []byte, admission ConditionalSendAdmissionV1) (*Tree, error) {
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
	if err = TreeContextError(ctx); err != nil {
		return nil, err
	}
	if err = ValidateForSendV1(tree, admission); err != nil {
		return nil, err
	}
	if err = TreeContextError(ctx); err != nil {
		return nil, err
	}
	return tree, nil
}
func NormalizeTreeForAuthoringV1(ctx context.Context, raw []byte, admission ConditionalSendAdmissionV1, beforeMarshal func(*Tree) error) (json.RawMessage, error) {
	tree, err := ParseTreeForAuthoringV1(ctx, raw, admission)
	if err != nil {
		return nil, err
	}
	if beforeMarshal != nil {
		if err = beforeMarshal(tree); err != nil {
			return nil, err
		}
	}
	normalized, err := json.Marshal(tree)
	if err != nil {
		return nil, fmt.Errorf("encode canonical tree: %w", err)
	}
	if err = TreeContextError(ctx); err != nil {
		return nil, err
	}
	return normalized, nil
}
