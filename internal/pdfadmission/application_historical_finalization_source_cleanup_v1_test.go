// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This is a close/loan primitive regression, not invented native SQL/source
// authority: the metadata handle intentionally cannot pass validV1. Its actual
// independently acquired Parent grant must nevertheless join every close exit.
func TestHistoricalSourceMetadataCloseJoinsRefusedTryLockV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	v := workguard.VectorV1{ParentBytes: 64}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	for _, borrowers := range []int{0, 1} {
		grant, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 32})
		if err != nil {
			t.Fatal(err)
		}
		var releases atomic.Int32
		e := &ApplicationHistoricalFinalizationSourceEvidenceV1{releaseBody: func() { releases.Add(1); grant.Close() }}
		e.self = e
		if !e.lockV1() {
			t.Fatal("actual source metadata entry refused")
		}
		if borrowers != 0 && !e.beginBodyBorrowLockedV1() {
			t.Fatal("actual source body registration refused")
		}
		// Close fences new entry while the actual admitted metadata/body consumers remain.
		joined := make(chan struct{})
		go func() { e.CloseConsumerV1(); close(joined) }()
		<-joined
		if got := c.SnapshotV1(org); got.Global.ParentBytes != 32 {
			t.Fatalf("close credited lock-held owner: %+v", got)
		}
		e.unlockV1()
		if borrowers != 0 {
			if got := c.SnapshotV1(org); got.Global.ParentBytes != 32 {
				t.Fatalf("metadata exit credited active body: %+v", got)
			}
			e.finishBodyBorrowV1()
		}
		e.CloseConsumerV1()
		if releases.Load() != 1 {
			t.Fatalf("release count %d", releases.Load())
		}
		if got := c.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
			t.Fatalf("owner did not drain: %+v", got)
		}
	}
}

func TestHistoricalSourceRefusalAndCopiedCloseRacesDrainV1(t *testing.T) {
	for i := 0; i < 256; i++ {
		var released atomic.Int32
		e := &ApplicationHistoricalFinalizationSourceEvidenceV1{releaseBody: func() { released.Add(1) }}
		e.self = e
		w := &ApplicationHTMLSendWorkV1{}
		w.self = w
		copied := &ApplicationHistoricalFinalizationSourceEvidenceV1{self: e}
		start := make(chan struct{})
		var joined sync.WaitGroup
		actions := []func(){func() { e.MatchesDocumentV1(nil) }, func() { e.SignatureRowsV1() }, func() { e.WithSourcePDFV1(func([]byte) error { return nil }) }, func() { e.WithSignatureBodyV1(uuid.Nil, func([]byte) error { return nil }) }, func() { e.NewHistoricalRenderContinuationV1(context.Background(), w) }, func() { e.CloseConsumerV1() }, func() { copied.CloseConsumerV1() }}
		for _, action := range actions {
			joined.Add(1)
			go func(fn func()) { defer joined.Done(); <-start; fn() }(action)
		}
		close(start)
		joined.Wait()
		if released.Load() != 1 {
			t.Fatalf("iteration %d pending close lost, releases=%d", i, released.Load())
		}
	}
}
