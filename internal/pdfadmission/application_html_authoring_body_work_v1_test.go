// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/google/uuid"
	"math"
	"testing"
	"time"
)

func TestHTMLAuthoringRetainedBodyPositiveTypedMassAndCheckedDynamicV1(t *testing.T) {
	fixed, err := htmlAuthoringRetainedBodyFixedV1()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("complete retained body typed/container fixed bytes=%d", fixed)
	zero, err := htmlAuthoringRetainedBodyResourcesV1(0, 0)
	if err != nil || fixed <= 0 || fixed%8192 != 0 || zero.WorkingBytes != fixed || zero.DBStagingBytes != fixed {
		t.Fatalf("zero body lost actual fixed typed/container mass: fixed=%d resource=%+v err=%v", fixed, zero, err)
	}
	if fixed >= 32<<20 {
		t.Fatal("per-body typed union repeated whole reader fixed class")
	}
	dynamic, err := htmlAuthoringRetainedBodyResourcesV1(127, 4097)
	if err != nil || dynamic.WorkingBytes != fixed+8*127+16*4097 || dynamic.DBStagingBytes != fixed+16*4097 {
		t.Fatalf("fresh retained model increments changed: %+v %v", dynamic, err)
	}
	for _, pair := range [][2]int64{{-1, 0}, {0, -1}, {math.MaxInt64, 0}, {0, math.MaxInt64}} {
		if _, err = htmlAuthoringRetainedBodyResourcesV1(pair[0], pair[1]); err == nil {
			t.Fatalf("invalid model count accepted: %+v", pair)
		}
	}
}
func TestHTMLAuthoringRetainedBodyPublicPhaseForgeryRefusedV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	factory, coordinator := htmlInputFactoryTestV1(t, 1<<30)
	org, doc := uuid.New(), uuid.New()
	fixed, err := htmlAuthoringRetainedBodyFixedV1()
	if err != nil {
		t.Fatal(err)
	}
	// Public fields cannot manufacture the private actual header/reader grant.
	for _, budget := range []ApplicationBudgetV1{
		{Phase: "locked-html-authoring-retained-body", OrgID: org, DocumentID: doc, WorkingBytes: fixed, DBStagingBytes: fixed},
		{Phase: "locked-html-authoring-retained-body", OrgID: org, DocumentID: doc, WorkingBytes: 32 << 20, DBStagingBytes: 32 << 20},
		{Phase: "locked-html-authoring-retained-body", OrgID: org, DocumentID: doc, HTMLAuthoringRawBytes: 1, HTMLAuthoringWireBytes: 1, WorkingBytes: fixed + 24, DBStagingBytes: fixed + 16},
	} {
		release, err := factory.state.work.ApplicationV1(ctx, budget)
		if release != nil || err == nil {
			t.Fatal("public phase spoof acquired a headerless body")
		}
	}
	if snapshot := coordinator.SnapshotV1(org); snapshot.GlobalGrants != 0 {
		t.Fatalf("forgery installed native work: %+v", snapshot)
	}
	var zero ApplicationHTMLAuthoringReaderV1
	if _, err := zero.acquireRetainedBodyV1(ctx, 0, 0); err == nil {
		t.Fatal("zero reader acquired body")
	}
	// Explicit copied-shell identity without copying the actual mutex.
	original := &ApplicationHTMLAuthoringReaderV1{}
	original.self = original
	copied := &ApplicationHTMLAuthoringReaderV1{self: original}
	if _, err := copied.acquireRetainedBodyV1(ctx, 0, 0); err == nil {
		t.Fatal("copied reader shell acquired body")
	}
	if err := factory.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}
