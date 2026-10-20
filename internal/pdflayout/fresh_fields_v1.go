// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdflayout

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// FreshFieldBatchV1 exposes only the native creator's exact fresh result
// sequence, never a transaction or an existing caller-selected field identity.
type FreshFieldBatchV1 interface {
	CreateNextV1(context.Context) (*generated.DocumentField, error)
	CloseConsumerV1()
}
type FreshFieldProducerV1 interface {
	NewFieldBatchV1(context.Context, []generated.CreateDraftFieldParams) (FreshFieldBatchV1, error)
}
