// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
)

// The real native evidence/source/Work consumers and coordinator come from the
// existing explicitly synthetic-SQL unit fixture. No document/PG authority is
// invented by this queued early-refusal regression.
func TestHTMLSendEvidenceQueuedCompletionRefusalJoinsOriginalSourceV3(t *testing.T) {
	for _, physicalFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(physicalFirst), func(t *testing.T) {
			work, source, evidence, fixture, coordinator, ctx := htmlSendEvidenceFixtureV1(t, HTMLSendPreparationV1)
			owner := source.state.owner
			if !evidence.lockV1() {
				t.Fatal("actual evidence registration refused")
			}
			_, _, done, err := evidence.beginV1()
			if err != nil {
				evidence.unlockV1()
				t.Fatal(err)
			}
			held, finished, queued, joined := true, false, false, false
			result := make(chan error, 1)
			defer func() {
				if !finished {
					done()
				}
				if held {
					evidence.unlockV1()
				}
				if queued && !joined {
					select {
					case <-result:
					case <-time.After(3 * time.Second):
						t.Error("queued original completion consumer did not join")
					}
				}
			}()
			before := coordinator.SnapshotV1(fixture.scope.OrgID)
			if before.Global.ParentBytes == 0 {
				t.Fatal("genuine original source debt absent")
			}
			queued = true
			go func() { _, e := evidence.CaptureCompletionReferenceV1(); result <- e }()
			deadline := time.Now().Add(time.Second)
			for evidence.activity.state.Load() != 4 && time.Now().Before(deadline) {
				runtime.Gosched()
			}
			if evidence.activity.state.Load() != 4 {
				t.Fatal("queued Capture did not register before waiting")
			}
			if physicalFirst {
				close(fixture.done)
				if _, err = fixture.adapter.ReconcileCleanupV1(ctx); err != nil {
					t.Fatal(err)
				}
			}
			work.CloseConsumerV1()
			if evidence.activity.state.Load() != 5 || work.resourcesClosed || owner.retired || coordinator.SnapshotV1(fixture.scope.OrgID) != before {
				t.Fatal("Close refunded an admitted original consumer or failed to fence new entry")
			}
			done()
			finished = true
			if evidence.original == nil || evidence.source == nil || evidence.work == nil || evidence.releaseSource == nil || owner.retired || work.resourcesClosed {
				t.Fatal("mandatory captured completion cleared the still-admitted evidence/source borrower")
			}
			evidence.unlockV1()
			held = false
			select {
			case err = <-result:
				joined = true
			case <-time.After(3 * time.Second):
				t.Fatal("queued Capture did not join")
			}
			if err == nil {
				t.Fatal("closed draft evidence produced a completion reference")
			}
			if evidence.original != nil || evidence.source != nil || evidence.work != nil || evidence.releaseSource != nil || !owner.retired || !work.resourcesClosed {
				t.Fatal("last queued refusal did not perform typed source retirement")
			}
			if !physicalFirst {
				if coordinator.SnapshotV1(fixture.scope.OrgID) == (workguard.SnapshotV1{}) {
					t.Fatal("unretired physical backend credited")
				}
				close(fixture.done)
			}
			if pending, err := fixture.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 0 {
				t.Fatal("actual physical+consumer drain failed", pending, err)
			}
			if coordinator.SnapshotV1(fixture.scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("joined source debt remains")
			}
			evidence.CloseConsumerV1()
			if _, err = evidence.CaptureCompletionReferenceV1(); err == nil {
				t.Fatal("closed evidence re-admitted completion")
			}
			if coordinator.SnapshotV1(fixture.scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("closed refusal acquired fresh native debt")
			}
		})
	}
}
