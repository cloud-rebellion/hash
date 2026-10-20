// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package audit

import (
	"context"
	"github.com/google/uuid"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublishJoinedV1WaitsForEveryActualHookIncludingPanic(t *testing.T) {
	log := New(nil, nil)
	entered := make(chan struct{})
	panicked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	var calls atomic.Int64
	log.Subscribe(func(context.Context, uuid.UUID, Entry) { close(entered); <-release })
	log.Subscribe(func(context.Context, uuid.UUID, Entry) { defer close(panicked); panic("synthetic joined hook panic") })
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	log.PublishJoinedV1(PendingEvent{ID: uuid.New(), Entry: Entry{OrgID: uuid.New(), Kind: KindDocumentCreated}}, func() {
		if calls.Add(1) == 1 {
			close(done)
		}
	})
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	for _, signal := range []<-chan struct{}{entered, panicked} {
		select {
		case <-signal:
		case <-ctx.Done():
			t.Fatal("actual hook did not start/return")
		}
	}
	select {
	case <-done:
		t.Fatal("panic/other hook return ended original blocked consumer")
	default:
	}
	// Release exactly the remaining original hook; callback must join it once.
	unblock()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("actual final hook return did not end joined consumer")
	}
	if calls.Load() != 1 {
		t.Fatal("last-use callback ran more than once")
	}
	var immediate atomic.Int64
	New(nil, nil).PublishJoinedV1(PendingEvent{ID: uuid.New(), Entry: Entry{OrgID: uuid.New(), Kind: KindDocumentCreated}}, func() { immediate.Add(1) })
	if immediate.Load() != 1 {
		t.Fatal("empty hook set did not end original consumer synchronously")
	}
}
