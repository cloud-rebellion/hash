// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/google/uuid"
	"math"
	"testing"
	"time"
)

func TestPDFLayoutCaptureRejectsUnownedSourcesAndOverflowV1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	org, doc := uuid.New(), uuid.New()
	for _, factory := range []*ApplicationSessionFactoryV1{nil, {}} {
		source, err := factory.InspectPDFLayoutSourceV1(ctx, org, doc, time.Now(), nil)
		if source != nil || !errors.Is(err, ErrPDFLayoutInspectionV1) {
			t.Fatal("unowned inspection acquired source authority", source, err)
		}
	}
	for _, source := range []*ApplicationPDFLayoutInspectionV1{nil, {}, {state: &pdfLayoutInspectionStateV1{}}} {
		body, pages, release, err := source.borrowV1(org, doc)
		if body != nil || pages != 0 || release != nil || !errors.Is(err, ErrPDFLayoutInspectionV1) {
			t.Fatal("unowned inspection supplied a source", err)
		}
		source.CloseConsumerV1()
	}
	original := &ApplicationPDFLayoutCaptureV1{state: &pdfLayoutCaptureStateV1{}}
	original.self = original
	copied := *original
	for _, owner := range []*ApplicationPDFLayoutCaptureV1{nil, {}, original, &copied} {
		row, err := owner.CreateTemplateV1(ctx)
		if row != nil || !errors.Is(err, ErrPDFLayoutCaptureV1) {
			t.Fatal("unowned capture inserted a template", err)
		}
		event, err := owner.NewAuditV1(ctx)
		if event != nil || !errors.Is(err, ErrPDFLayoutCaptureV1) {
			t.Fatal("unowned capture supplied an audit owner", err)
		}
		owner.CloseConsumerV1()
		owner.CloseConsumerV1()
	}
	session := &ApplicationSessionV1{}
	owner, err := session.NewPDFLayoutCaptureV1(ctx, nil, nil, uuid.New(), pdflayout.ExportInputV1{})
	if owner != nil || !errors.Is(err, ErrPDFLayoutCaptureV1) {
		t.Fatal("caller input supplied native source authority", err)
	}
	for _, count := range []int64{0, 100, 1000} {
		raw, err := pdfLayoutExportMapRawV1(count, 16, 1)
		if err != nil || raw <= count*17 || raw <= 0 {
			t.Fatal("original finite UUID map storage was not included", count, raw, err)
		}
	}
	for _, count := range []int64{-1, math.MaxInt64} {
		raw, err := pdfLayoutExportMapRawV1(count, 16, 1)
		if err == nil || raw != 0 {
			t.Fatal("overflow or negative original count was accepted", count, raw, err)
		}
	}
}
