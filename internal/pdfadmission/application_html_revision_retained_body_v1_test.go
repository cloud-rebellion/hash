// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"math"
	"testing"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
)

// Concrete revision types are independently positive even when all variable
// backing is empty. This is logical retained storage, not measured RSS.
func TestHTMLRevisionRetainedBodyIncludesCompleteTypedResultsV1(t *testing.T) {
	fixed, err := htmlAuthoringRetainedBodyFixedV1()
	if err != nil {
		t.Fatal(err)
	}
	required := 4*int64(unsafe.Sizeof(generated.Document{})) + 2*int64(unsafe.Sizeof(htmlmaterialization.CurrentReadProjectionV1{})) +
		2*int64(unsafe.Sizeof(generated.HtmlDocumentMaterialization{})) + 2*int64(unsafe.Sizeof(generated.HtmlDocumentMaterializationSnapshot{})) +
		2*int64(unsafe.Sizeof(generated.DocumentVersion{})) + int64(unsafe.Sizeof(ApplicationHTMLRevisionWriterV1{})) + int64(unsafe.Sizeof(ApplicationHTMLRevisionCollectionsV1{}))
	empty, err := htmlAuthoringRetainedBodyResourcesV1(0, 0)
	if err != nil || fixed <= required || empty.WorkingBytes != fixed || empty.DBStagingBytes != fixed || fixed >= 32<<20 {
		t.Fatal("empty concrete native results lost positive storage or repeated header floor", fixed, required, empty, err)
	}
}
func TestHTMLRevisionCompleteEmptyTextRowsKeepScalableTypedMassV1(t *testing.T) {
	for _, count := range []int64{0, 1, 64, 1_000_000} {
		h, doc := htmlRevisionSnapshotFixtureV1()
		h.FieldCount = count
		h.MeasuredFieldCount = count
		h.FieldOptionsWireBytes = 2 * count
		h.RecipientCount = count
		h.EventCount = count
		h.MeasuredEventCount = count
		h.EventPayloadWireBytes = 2 * count
		h.HistoryCount = count
		h.MeasuredHistoryCount = count
		h.HistoryWireBytes = 12 * count
		components, err := htmlRevisionSnapshotCollectionComponentsForV1(h, doc, nil)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := htmlRevisionSnapshotSumV1(components.contextJSONBytes, components.historyRowJSONBytes)
		if err != nil {
			t.Fatal(err)
		}
		if err = htmlRevisionCollectionTypedEnvelopeV1(h, components, wire); err != nil {
			t.Fatal("complete fixed-schema row envelopes failed actual typed inventory", count, err)
		}
		if count > 0 && wire <= count {
			t.Fatal("empty text suppressed actual row mass")
		}
		if err = htmlRevisionCollectionTypedEnvelopeV1(h, components, 0); err == nil {
			t.Fatal("caller omitted complete logical rows")
		}
	}
	h, doc := htmlRevisionSnapshotFixtureV1()
	h.RecipientCount = math.MaxInt64
	if _, err := htmlRevisionSnapshotCollectionComponentsForV1(h, doc, nil); err == nil {
		t.Fatal("unrepresentable complete row set admitted")
	}
}
func TestHTMLRevisionConstructedWriterKeepsOneHeaderAndSeparateBodiesV1(t *testing.T) {
	withHTMLRevisionConstructedWriterFixtureV1(t, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
		held := f.coordinator.SnapshotV1(f.document.OrgID)
		if held.GlobalGrants < 9 || held.Global.DBStagingBytes <= 32<<20 || held.Global.DBStagingBytes >= 384<<20 {
			t.Fatal("actual constructed writer lacks separate positive loans or repeats per-body OtherWork", held)
		}
		// Actual original consumer closures still cannot release any retained body
		// before the explicit backend witness; changed cost never creates a refund.
		f.operation.CloseConsumerV1()
		if f.coordinator.SnapshotV1(f.document.OrgID) != held {
			t.Fatal("body class correction manufactured physical retirement")
		}
	})
}
