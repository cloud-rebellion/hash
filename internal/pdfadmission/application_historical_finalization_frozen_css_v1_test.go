// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"math"
	"strings"
	"testing"
	"time"
)

func TestHistoricalFrozenCSSRealGrantWaitsForActualBorrowersV1(t *testing.T) {
	v := workguard.VectorV1{ParentBytes: 64}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	grant, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	h := &ApplicationHistoricalFinalizationCSSV1{css: "actual retained output", grant: grant}
	h.self = h
	first, finishFirst, err := h.BorrowCSSV1()
	if err != nil {
		t.Fatal(err)
	}
	second, finishSecond, err := h.BorrowCSSV1()
	if err != nil {
		t.Fatal(err)
	}
	copied := &ApplicationHistoricalFinalizationCSSV1{self: h.self, css: h.css, grant: h.grant}
	copied.CloseConsumerV1()
	cancel()
	if got := c.SnapshotV1(org); got.Global.ParentBytes != 32 {
		t.Fatalf("copy/cancel credited live CSS: %+v", got)
	}
	h.CloseConsumerV1()
	if first != "actual retained output" || second != first {
		t.Fatal("close altered live view")
	}
	if _, _, err := h.BorrowCSSV1(); err == nil {
		t.Fatal("new borrower accepted after close")
	}
	finishFirst()
	finishFirst()
	if got := c.SnapshotV1(org); got.Global.ParentBytes != 32 {
		t.Fatalf("first consumer credited second: %+v", got)
	}
	finishSecond()
	h.CloseConsumerV1()
	if got := c.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatalf("CSS did not drain: %+v", got)
	}
	if h.css != "" || h.grant != nil {
		t.Fatal("closed owner retains output")
	}
}

func TestHistoricalFrozenCSSPricingAndCanonicalOutputBoundV1(t *testing.T) {
	if _, err := historicalFrozenCSSResourcesV1(-1); err == nil {
		t.Fatal("negative input priced")
	}
	if _, err := historicalFrozenCSSResourcesV1(math.MaxInt64); err == nil {
		t.Fatal("overflow priced")
	}
	for _, n := range []int64{0, 1, 256, 4096, 1 << 20} {
		got, err := historicalFrozenCSSResourcesV1(n)
		if err != nil || got <= n {
			t.Fatalf("resources(%d)=%d,%v", n, got, err)
		}
	}
	b := branding.DefaultBranding()
	// The maximum canonical list alternates the shortest valid one-byte name
	// with the actual separator; this maximizes the generator's quote overhead.
	b.FontHeading = strings.Repeat("a, ", 84) + "aaaa"
	b.FontBody = b.FontHeading
	if len(b.FontHeading) != 256 {
		t.Fatal("bad maximum font fixture")
	}
	if _, err := branding.NormaliseFontFamily(b.FontHeading); err != nil {
		t.Fatal(err)
	}
	if got := int64(len(b.CSSVariables())); got > historicalFrozenCSSOutputBytesV1() {
		t.Fatalf("canonical output %d exceeds derived %d", got, historicalFrozenCSSOutputBytesV1())
	}
}

func TestHistoricalFrozenCSSDoesNotAcceptInventedWorkV1(t *testing.T) {
	var nilWork *ApplicationHTMLSendWorkV1
	if owner, err := nilWork.NewHistoricalFinalizationFrozenCSSV1(context.Background(), nil); owner != nil || err == nil {
		t.Fatal("nil work admitted")
	}
	invented := &ApplicationHTMLSendWorkV1{}
	invented.self = invented
	if owner, err := invented.NewHistoricalFinalizationFrozenCSSV1(context.Background(), &ApplicationHistoricalFinalizationStageReferenceV1{}); owner != nil || err == nil {
		t.Fatal("invented work admitted")
	}
}
