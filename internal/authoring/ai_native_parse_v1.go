// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package authoring

import (
	"context"
	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Same original top-level lookup and not-found policy, now using the actual
// dispatch owner's original parser/decimal hook before any scalable work.
func AIAppBlockContextV1(ctx context.Context, doc *generated.Document, id string) (*blocks.Block, error) {
	tree, err := ai.ParseTreeV1(ctx, doc.BlocksJson)
	if err != nil {
		return nil, err
	}
	for i := range tree.Blocks {
		if tree.Blocks[i].ID == id {
			return &tree.Blocks[i], nil
		}
	}
	return nil, ErrAIBlockNotFound
}
