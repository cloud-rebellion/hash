// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
)

// This queued-close regression uses actual source/Work/admission/coordinator
// loans from the existing explicitly synthetic-SQL fixture. It tests lifetime
// and cancellation, not constructor policy, PG authority or PDF measurement.
func TestHTMLSendPackageQueuedMeasurementJoinsSourceV1(t *testing.T) {
	for _, physicalFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(physicalFirst), func(t *testing.T) {
			work, source, _, fixture, coordinator, ctx := htmlSendEvidenceFixtureV1(t, HTMLSendPreparationV1, true)
			owner := source.state.owner
			if err := owner.beginV1(); err != nil {
				t.Fatal(err)
			}
			if err := owner.holdV1(htmlRevisionSourceStateV1, 0, 4*int64(unsafe.Sizeof(applicationHTMLSendPackageDraftStateV1{}))+4*int64(unsafe.Sizeof(applicationDocumentPackageDraftSnapshotV1{}))+4096); err != nil {
				owner.finishV1()
				t.Fatal(err)
			}
			original, cancel := context.WithCancel(owner.binding.ctx)
			var once sync.Once
			p := &applicationHTMLSendPackageDraftStateV1{work: work, source: source.state, sourceOwner: owner, root: owner.snapshot.document, ctx: original, cancel: cancel, draft: &applicationDocumentPackageDraftSnapshotV1{}, releaseSource: func() { once.Do(owner.finishV1) }}
			h := &ApplicationHTMLSendPackageDraftV1{state: p}
			t.Cleanup(h.CloseConsumerV1)
			work.mu.Lock()
			work.packageDraft = p
			work.mu.Unlock()
			if !p.lockV1() {
				t.Fatal("genuine package activity refused")
			}
			held, queued, joined := true, false, false
			result := make(chan error, 1)
			defer func() {
				if held {
					p.unlockV1()
				}
				if queued && !joined {
					select {
					case <-result:
					case <-time.After(3 * time.Second):
						t.Error("queued actual package consumer did not join")
					}
				}
			}()
			before := coordinator.SnapshotV1(fixture.scope.OrgID)
			if before.Global.ParentBytes == 0 {
				t.Fatal("actual retained source debt absent")
			}
			queued = true
			go func() { result <- h.MeasurePDFsV1(nil) }()
			deadline := time.Now().Add(time.Second)
			for p.activity.state.Load() != 4 && time.Now().Before(deadline) {
				runtime.Gosched()
			}
			if p.activity.state.Load() != 4 {
				t.Fatal("queued measurement did not register before mutex wait")
			}
			if physicalFirst {
				close(fixture.done)
				if _, err := fixture.adapter.ReconcileCleanupV1(ctx); err != nil {
					t.Fatal(err)
				}
			}
			work.CloseConsumerV1()
			var closers sync.WaitGroup
			for i := 0; i < 8; i++ {
				closers.Add(1)
				go func() { defer closers.Done(); h.CloseConsumerV1() }()
			}
			closers.Wait()
			if p.ctx.Err() == nil || p.activity.state.Load() != 5 || owner.retired || work.resourcesClosed || p.root == nil || p.releaseSource == nil || coordinator.SnapshotV1(fixture.scope.OrgID) != before {
				t.Fatal("close failed cancellation/fencing or refunded a live source borrower")
			}
			p.unlockV1()
			held = false
			select {
			case err := <-result:
				joined = true
				if !errors.Is(err, ErrDocumentPackageMeasurementV1) {
					t.Fatal("closed queued measurement produced results", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("queued measurement did not join")
			}
			if p.root != nil || p.source != nil || p.sourceOwner != nil || p.releaseSource != nil || p.ctx != nil || p.cancel != nil || !owner.retired || !work.resourcesClosed {
				t.Fatal("last admitted consumer did not retire actual source and context")
			}
			if !physicalFirst {
				if coordinator.SnapshotV1(fixture.scope.OrgID) == (workguard.SnapshotV1{}) {
					t.Fatal("unretired physical SQL was credited")
				}
				close(fixture.done)
			}
			if pending, err := fixture.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 0 || coordinator.SnapshotV1(fixture.scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("actual physical plus consumer drain failed", pending, err)
			}
			h.CloseConsumerV1()
			if _, _, err := h.MeasurementsV1(); !errors.Is(err, ErrDocumentPackageMeasurementV1) {
				t.Fatal("closed package diagnostics re-admitted", err)
			}
		})
	}
}
