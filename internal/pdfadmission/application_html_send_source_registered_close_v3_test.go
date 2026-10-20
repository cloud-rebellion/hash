// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// These metadata shells exercise only real retirement/accounting primitives;
// they cannot supply native SQL/source/signing authority.
func TestHTMLSendSourceRegisteredCloseBeforeEntryV3(t *testing.T) {
	var released atomic.Int32
	owner := &applicationHTMLRevisionSourceOwnerV1{cancel: func() {}, releaseBorrower: func() { released.Add(1) }}
	owner.self = owner
	s := &applicationHTMLSendSourceStateV1{owner: owner}
	s.closeV1()
	s.closeV1()
	if s.lockV1() || s.policyActivity.Load() != 1 || !s.retired || !owner.closed || !owner.retired || released.Load() != 1 {
		t.Fatal("close-before-entry lost once-only owner retirement")
	}
	// Overflow cannot wrap a live registration into false zero activity.
	overflow := &applicationHTMLSendSourceStateV1{}
	overflow.policyActivity.Store(math.MaxUint64 - 1)
	if overflow.lockV1() || overflow.policyActivity.Load() != math.MaxUint64-1 {
		t.Fatal("policy registration count overflowed")
	}
}

func TestHTMLSendSourceRegisteredWaiterAndCPUJoinV3(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	limit := workguard.VectorV1{ParentBytes: 64}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: limit, Organisation: limit, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	var released atomic.Int32
	owner := &applicationHTMLRevisionSourceOwnerV1{cancel: func() {}, active: 1, closes: []func(){grant.Close}, releaseBorrower: func() { released.Add(1) }}
	owner.self = owner
	s := &applicationHTMLSendSourceStateV1{owner: owner, blockRoles: []string{"retained policy result"}}
	if !s.lockV1() {
		t.Fatal("first policy frame refused")
	}
	firstLocked := true
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer func() {
		if firstLocked {
			s.unlockV1()
		}
		once.Do(func() { close(release) })
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("registered policy waiter did not join")
		}
		s.closeV1()
		owner.finishV1()
		if c.SnapshotV1(org).Global != (workguard.VectorV1{}) || released.Load() != 1 {
			t.Error("actual final CPU join failed to retire its original loan once")
		}
	}()
	go func() {
		defer close(done)
		if !s.lockV1() {
			return
		}
		defer s.unlockV1()
		close(entered)
		<-release
	}()
	// Registration precedes the genuine mutex wait. Observe its actual count,
	// not a guessed sleep or failed TryLock as evidence of a future holder.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for s.policyActivity.Load() != 4 {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("waiter never registered before mutex acquisition")
		}
	}
	closed := make(chan struct{})
	go func() { s.closeV1(); close(closed) }()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("Close waited on a real policy mutex")
	}
	if s.policyActivity.Load() != 5 || s.retired || owner.closed || c.SnapshotV1(org).Global.ParentBytes != 32 {
		t.Fatal("close refunded an existing or queued policy frame")
	}
	s.unlockV1()
	firstLocked = false
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("original registered waiter did not enter")
	}
	if s.policyActivity.Load() != 3 || c.SnapshotV1(org).Global.ParentBytes != 32 || released.Load() != 0 {
		t.Fatal("first release lost genuine last policy/CPU debt")
	}
	cancel()
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("last registered policy did not join")
	}
	if s.policyActivity.Load() != 1 || !s.retired || len(s.blockRoles) != 0 || !owner.closed || owner.retired || c.SnapshotV1(org).Global.ParentBytes != 32 || released.Load() != 0 {
		t.Fatal("policy retirement failed or credited still-active original CPU owner")
	}
	// The deferred final actual owner.finishV1 above must retire this real loan.
}
