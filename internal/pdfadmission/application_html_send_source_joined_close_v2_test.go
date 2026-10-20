// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These invalid-for-source metadata shells test actual retirement primitives;
// none can pass native source authority. The Parent grant itself is real.
func TestHTMLSendCPUSourceJoinedCloseKeepsRealActiveOwnerV2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	v := workguard.VectorV1{ParentBytes: 64}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	var releases atomic.Int32
	owner := &applicationHTMLRevisionSourceOwnerV1{cancel: func() {}, active: 1, closes: []func(){grant.Close}, releaseBorrower: func() { releases.Add(1) }}
	owner.self = owner
	state := &applicationHTMLSendSourceStateV1{owner: owner}
	if !state.lockV1() {
		t.Fatal("policy registration refused before close")
	}
	joined := make(chan struct{})
	go func() { state.closeV1(); close(joined) }()
	<-joined
	state.unlockV1()
	if !state.retired || !owner.closed {
		t.Fatal("pending policy Close did not reach original owner")
	}
	if got := c.SnapshotV1(org); got.Global.ParentBytes != 32 || releases.Load() != 0 {
		t.Fatal("policy close credited actual active CPU borrower", got)
	}
	owner.finishV1()
	if got := c.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 || releases.Load() != 1 {
		t.Fatal("original active owner did not join once", got)
	}
}
func TestHTMLSendCPUSourceRefusalCloseRaceJoinsV2(t *testing.T) {
	for index := 0; index < 512; index++ {
		var releases atomic.Int32
		owner := &applicationHTMLRevisionSourceOwnerV1{cancel: func() {}, releaseBorrower: func() { releases.Add(1) }}
		owner.self = owner
		state := &applicationHTMLSendSourceStateV1{owner: owner}
		handle := &ApplicationHTMLSendSourceV1{state: state}
		start := make(chan struct{})
		var joined sync.WaitGroup
		for _, fn := range []func(){func() { handle.MatchesDocumentV1(&generated.Document{}) }, func() { handle.SignatureFieldForSigningV1("signer") }, func() { handle.BlockRolesForSigningV1() }, func() { state.closeV1() }} {
			joined.Add(1)
			go func(f func()) { defer joined.Done(); <-start; f() }(fn)
		}
		close(start)
		joined.Wait()
		if releases.Load() != 1 {
			state.policyMutex.Lock()
			requested, retired := state.closeRequested.Load(), state.retired
			state.policyMutex.Unlock()
			owner.mu.Lock()
			closed, ownerRetired, active, releasePresent := owner.closed, owner.retired, owner.active, owner.releaseBorrower != nil
			owner.mu.Unlock()
			t.Fatalf("iteration %d lost original source Close: %d requested=%t state_retired=%t owner_closed=%t owner_retired=%t active=%d release_present=%t", index, releases.Load(), requested, retired, closed, ownerRetired, active, releasePresent)
		}
	}
}
