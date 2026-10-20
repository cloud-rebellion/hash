// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestCatalogRuleMCPInputCannotBorrowHTTPDecoderCreditV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 16<<20)
	org := uuid.New()
	h, err := f.NewCatalogRuleArgumentsV1(ctx, org, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := c.SnapshotV1(org)
	body := io.NopCloser(strings.NewReader(`{"name":"Must not decode"}`))
	if _, err = h.DecodeCreateV1(ctx, httptest.NewRecorder(), body); !errors.Is(err, ErrCatalogRuleInputV1) {
		t.Fatal("MCP actual-args header forged HTTP32KiB credit", err)
	}
	if _, err = h.DecodePatchV1(ctx, httptest.NewRecorder(), body); !errors.Is(err, ErrCatalogRuleInputV1) {
		t.Fatal("MCP actual-args header forged HTTP PATCH credit", err)
	}
	after := c.SnapshotV1(org)
	if after.Global != before.Global || after.GlobalGrants != before.GlobalGrants {
		t.Fatal("foreign decoder consumed or released original grant")
	}
	h.CloseConsumerV1()
}
func TestCatalogRuleRetainedTypedUnionDominatesActualRuleModelsV1(t *testing.T) {
	fixed, err := htmlAuthoringRetainedBodyFixedV1()
	if err != nil {
		t.Fatal(err)
	}
	// One genuine model/header/cache plus retained public response and original
	// full User coexist under each actual body loan. Dynamic TEXT/JSON backing
	// remains separate8raw+16wire; no heap/allocator or RSS bound is asserted.
	need := 2*int64(unsafe.Sizeof(generated.EidasRoutingRule{})) + int64(unsafe.Sizeof(generated.GetCatalogRuleSourceHeaderV1Row{})) + int64(unsafe.Sizeof(generated.EidasRuleWireSizesV1{})) + int64(unsafe.Sizeof(generated.User{})) + int64(unsafe.Sizeof(generated.CreateFreshEIDASRuleSourceV1Row{})) + int64(unsafe.Sizeof(generated.ReadCatalogRuleSourceV1Params{})) + int64(unsafe.Sizeof([]func(){}))
	if fixed < need || need <= 0 {
		t.Fatal("retained native typed union no longer covers actual routing models", fixed, need)
	}
}
