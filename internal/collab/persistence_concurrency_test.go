// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package collab

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

type blockedPersistenceStore struct {
	failingStateStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockedPersistenceStore) UpsertCollabDocState(ctx context.Context, p generated.UpsertCollabDocStateParams) (*generated.CollabDocState, error) {
	first := false
	s.once.Do(func() { first = true; close(s.entered) })
	if first {
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.failingStateStore.UpsertCollabDocState(ctx, p)
}

func TestPersistenceReleasesRoomLockAndRetainsConcurrentEdits(t *testing.T) {
	for _, compact := range []bool{false, true} {
		t.Run(map[bool]string{false: "append", true: "compact_then_append"}[compact], func(t *testing.T) {
			store := &blockedPersistenceStore{entered: make(chan struct{}), release: make(chan struct{})}
			h := NewHub(nil)
			h.Queries = store
			peer := newFakePeer("writer")
			room := &Room{hub: h, documentID: uuid.New(), peers: map[string]Peer{peer.ID(): peer}, flushCh: make(chan struct{}, 1)}
			room.applyAppend([]byte{1, 1})
			if compact {
				room.applyAppend([]byte{1, 2})
			}
			done := make(chan struct{})
			go func() { room.maybeFlush(context.Background()); close(done) }()
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(store.release) }) }
			defer release()
			select {
			case <-store.entered:
			case <-time.After(time.Second):
				t.Fatal("write never entered")
			}
			mutated := make(chan struct{})
			go func() {
				if compact {
					room.mu.Lock()
					room.compactionPending = true
					room.compactionPeerID = peer.ID()
					room.compactionStartedAt = time.Now()
					room.compactionBoundary = len(room.state)
					room.compactionUpdates = room.replayUpdates
					nonce := room.compactionNonce
					room.mu.Unlock()
					room.applySnapshot(nonce, []byte{1, 9}, peer.ID())
				}
				room.applyAppend([]byte{1, 10})
				close(mutated)
			}()
			select {
			case <-mutated:
			case <-time.After(time.Second):
				t.Fatal("database wait held room mutex")
			}
			release()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("write did not finish")
			}
			room.mu.Lock()
			dirty, pending := room.dirty, room.pending
			expected := append([]byte(nil), room.state...)
			room.mu.Unlock()
			if !dirty || pending != 1 {
				t.Fatalf("late receipt cleared newer edits: dirty=%v pending=%d", dirty, pending)
			}
			room.maybeFlush(context.Background())
			if !bytes.Equal(store.state, expected) || store.writes != 2 {
				t.Fatal("second snapshot lost concurrent edits")
			}
			wantCount := int32(2)
			if compact {
				wantCount = 3
			}
			if store.count != wantCount || room.dirty || room.pending != 0 {
				t.Fatalf("count=%d dirty=%v pending=%d", store.count, room.dirty, room.pending)
			}
		})
	}
}

func TestPersistenceAdmissionWaitHonorsDeadline(t *testing.T) {
	room := &Room{}
	room.persistOnce.Do(func() { room.persistGate = make(chan struct{}, 1) })
	room.persistGate <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := room.persist(ctx, false)
	if err != context.DeadlineExceeded {
		t.Fatalf("wait error=%v", err)
	}
	<-room.persistGate
	if err := room.persist(context.Background(), false); err != nil {
		t.Fatalf("recovery=%v", err)
	}
}
