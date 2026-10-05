// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package collab

import (
	"bytes"
	"context"
	"fmt"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestBootstrapOwnershipAndReassignment(t *testing.T) {
	ctx := context.Background()
	h := NewHub(nil)
	doc, org := uuid.New(), uuid.New()
	a, b := newFakePeer("a"), newFakePeer("b")
	first, err := h.Join(ctx, doc, org, a)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Leave(ctx, doc, b.ID())
	_, err = h.Join(ctx, doc, org, b)
	if err != nil {
		t.Fatal(err)
	}
	if first.Room.BootstrapFrame("a")[1] != 1 || first.Room.BootstrapFrame("b")[1] != 0 {
		t.Fatal("multiple seed owners")
	}
	if _, _, _, err := first.Room.applyAppend([]byte{2, 0, 0}, "b"); err != nil {
		t.Fatal(err)
	}
	if len(first.Room.state) != 0 {
		t.Fatal("empty handshake initialized room")
	}
	if _, _, _, err := first.Room.applyAppend([]byte{2, 1, 2}, "b"); err == nil {
		t.Fatal("non-owner seeded room")
	}
	h.Leave(ctx, doc, "a")
	if first.Room.BootstrapFrame("b")[1] != 1 {
		t.Fatal("owner not reassigned")
	}
	if _, _, _, err := first.Room.applyAppend([]byte{2, 1, 2}, "b"); err != nil {
		t.Fatal(err)
	}
	if first.Room.BootstrapFrame("b")[1] != 0 {
		t.Fatal("initialized room still grants seed")
	}
	if _, _, _, err := first.Room.applyAppend([]byte{2, 3, 4}, "b"); err != nil {
		t.Fatal("seed owner persisted after initialization")
	}
}

func TestLegacyNoopOnlyHistoryAllowsSeedButRealHistoryDoesNot(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state []byte
		grant byte
		count int
	}{
		{"noop-only", []byte{2, 0, 0, 2, 0, 0}, 1, 0},
		{"history-with-noop", []byte{2, 0, 0, 2, 1, 2}, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &failingStateStore{state: tc.state}
			h := NewHub(nil)
			h.Queries = store
			peer := newFakePeer("first")
			id := uuid.New()
			res, err := h.Join(context.Background(), id, uuid.New(), peer)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Leave(context.Background(), id, peer.ID())
			if res.Room.BootstrapFrame(peer.ID())[1] != tc.grant {
				t.Fatal("incorrect legacy seed grant")
			}
			if res.Room.replayUpdates != tc.count {
				t.Fatalf("history count %d", res.Room.replayUpdates)
			}
			if tc.count > 0 && string(res.InitialState) != string([]byte{2, 1, 2}) {
				t.Fatal("real history altered")
			}
			if res.Room.pending != 0 {
				t.Fatal("loaded history counted as new edits")
			}
		})
	}
}

type unavailableBootstrapPeer struct{ *fakePeer }

func (p *unavailableBootstrapPeer) Send(context.Context, []byte) error {
	return fmt.Errorf("transport closed")
}

func TestBootstrapReassignmentSkipsFailedTransport(t *testing.T) {
	ctx := context.Background()
	h := NewHub(nil)
	doc, org := uuid.New(), uuid.New()
	owner := newFakePeer("a")
	failed := &unavailableBootstrapPeer{newFakePeer("b")}
	survivor := newFakePeer("c")
	res, err := h.Join(ctx, doc, org, owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []Peer{failed, survivor} {
		if _, err := h.Join(ctx, doc, org, peer); err != nil {
			t.Fatal(err)
		}
	}
	defer h.Leave(ctx, doc, survivor.ID())
	h.Leave(ctx, doc, owner.ID())
	if res.Room.BootstrapFrame(survivor.ID())[1] != 1 {
		t.Fatal("failed transport retained ownership")
	}
	frames := survivor.Received()
	if len(frames) != 1 || !bytes.Equal(frames[0], []byte{MessageBootstrap, 1}) {
		t.Fatal("survivor did not receive grant")
	}
	res.Room.mu.Lock()
	_, retained := res.Room.peers[failed.ID()]
	res.Room.mu.Unlock()
	if retained {
		t.Fatal("failed transport retained in room")
	}
	if _, _, _, err := res.Room.applyAppend([]byte{2, 1, 2}, failed.ID()); err == nil {
		t.Fatal("removed transport can still publish")
	}
}

func TestDepartedPeerCannotDispatchAnyFrame(t *testing.T) {
	ctx := context.Background()
	h := NewHub(nil)
	doc, org := uuid.New(), uuid.New()
	gone, live := newFakePeer("gone"), newFakePeer("live")
	res, err := h.Join(ctx, doc, org, gone)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Join(ctx, doc, org, live); err != nil {
		t.Fatal(err)
	}
	defer h.Leave(ctx, doc, live.ID())
	h.Leave(ctx, doc, gone.ID())
	before := len(live.Received())
	for _, frame := range [][]byte{{MessageAwareness, 0}, {MessageQueryAware}, {MessageAuth}, {MessageSync, SyncStep1, 1, 0}, {MessageCompact, CompactSnapshot}} {
		if err := res.Room.HandleFrame(ctx, gone, frame); err == nil {
			t.Fatalf("departed peer accepted: %v", frame)
		}
	}
	if len(live.Received()) != before || len(gone.Received()) != 0 {
		t.Fatal("departed peer received or relayed data")
	}
	res.Room.mu.Lock()
	res.Room.compactionPending = true
	res.Room.compactionNonce = [16]byte{1}
	res.Room.mu.Unlock()
	res.Room.applySnapshot([16]byte{1}, []byte{2, 0, 0}, gone.ID())
	if res.Room.StateLen() != 0 || !res.Room.compactionPending {
		t.Fatal("departed peer changed compaction state")
	}
}

func TestCompactionPreservesUpdatesAfterRequest(t *testing.T) {
	peer := newFakePeer("peer")
	room := &Room{hub: &Hub{CompactionThreshold: 1}, peers: map[string]Peer{peer.ID(): peer}, flushCh: make(chan struct{}, 1)}
	_, nonce, requested, err := room.applyAppend([]byte{2, 1, 2}, peer.ID())
	if err != nil || !requested {
		t.Fatalf("request: %v %v", requested, err)
	}
	tail := []byte{2, 3, 4}
	if _, _, _, err := room.applyAppend(tail, peer.ID()); err != nil {
		t.Fatal(err)
	}
	snapshot := []byte{2, 5, 6}
	room.applySnapshot(nonce, snapshot, peer.ID())
	if !bytes.Equal(room.state, append(snapshot, tail...)) {
		t.Fatalf("concurrent edit lost: %v", room.state)
	}
	if room.replayUpdates != 2 {
		t.Fatalf("replay count: %d", room.replayUpdates)
	}
}

func TestSnapshotRequiresRequestedPeerAndLiveDeadline(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("expired=%v", expired), func(t *testing.T) {
			owner, other := newFakePeer("a"), newFakePeer("b")
			room := &Room{hub: &Hub{CompactionThreshold: 1}, peers: map[string]Peer{owner.ID(): owner, other.ID(): other}, flushCh: make(chan struct{}, 1)}
			original := []byte{2, 1, 2}
			_, nonce, requested, err := room.applyAppend(original, owner.ID())
			if err != nil || !requested {
				t.Fatal("no snapshot request")
			}
			if expired {
				room.compactionStartedAt = time.Now().Add(-CompactionTimeout - time.Second)
			}
			sender := other.ID()
			if expired {
				sender = owner.ID()
			}
			room.applySnapshot(nonce, []byte{2, 3, 4}, sender)
			if !bytes.Equal(room.state, original) {
				t.Fatal("unauthorized or expired snapshot replaced state")
			}
			if !expired && !room.compactionPending {
				t.Fatal("other peer consumed legitimate request")
			}
			if expired && room.compactionPending {
				t.Fatal("expired request retained")
			}
			if !expired {
				room.applySnapshot(nonce, []byte{2, 3, 4}, owner.ID())
				if !bytes.Equal(room.state, []byte{2, 3, 4}) {
					t.Fatal("requested peer response rejected")
				}
			}
		})
	}
}
