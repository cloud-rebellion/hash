// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

func TestBlocksRestoreStoredBoundRejectsUnknownAndOverflowV1(t *testing.T) {
	for _, stored := range []int64{-1, 0, math.MaxInt64, math.MaxInt64 / 2} {
		if _, err := blocksRestoreJSONBWireUpperV1(stored); !errors.Is(err, ErrBlocksRestoreSourceV1) {
			t.Fatal("unknown/overflow storage metadata produced body authority", stored, err)
		}
	}
	// Independent literal from the existing pinned PG16.15 bound: L20,
	// at most5 JEntries, numeric text147457 plus8 syntax bytes per entry.
	if upper, err := blocksRestoreJSONBWireUpperV1(16); err != nil || upper != 737447 {
		t.Fatal("uncompressed storage bound differs from the reviewed source proof", upper, err)
	}
}

func TestBlocksRestoreCannotAdoptACallerConstructedWriterV1(t *testing.T) {
	for _, writer := range []*ApplicationBlocksMutationWriterV1{nil, {}, {state: &applicationBlocksMutationStateV1{}}, {state: &applicationBlocksMutationStateV1{closed: true}}} {
		if doc, _, err := writer.RestoreVersionV1(context.Background(), 1); !errors.Is(err, ErrBlocksRestoreSourceV1) || doc != nil {
			t.Fatal("a caller-constructed writer acquired historical source authority", doc, err)
		}
	}
}

func TestBlocksRestoreAuditPurposeRetainsExactKeysV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, via := range []string{"rest", "mcp"} {
		payload := map[string]any{"via": via, "tool": "restore_document_version", "restored_from_v": int32(1)}
		if via == "rest" {
			payload["restored_blocks"] = 2
		}
		if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditBlocksRestoredV1, payload); err != nil || HTMLAuditBlocksRestoredV1.KindV1() != "document.updated" {
			t.Fatal("original restore event shape refused", err)
		}
		payload["unexpected_authority"] = true
		if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditBlocksRestoredV1, payload); err == nil {
			t.Fatal("restore audit accepted an undeclared field")
		}
	}
}
