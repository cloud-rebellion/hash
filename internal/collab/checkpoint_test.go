// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package collab

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"

	"github.com/google/uuid"
)

func checkpointRoom() *Room {
	return &Room{documentID: uuid.New(), orgID: uuid.New(), generation: 3, peers: map[string]Peer{"alice": newFakePeer("alice"), "bob": newFakePeer("bob")}, state: []byte{1, 42}}
}

func TestSaveCheckpointRejectsChangedStateAndOtherPeer(t *testing.T) {
	r := checkpointRoom()
	observed, err := r.CaptureSaveCheckpoint("alice")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	commit := func(SaveCheckpoint) error { called = true; return nil }
	if err := r.WithSaveCheckpoint("bob", observed.Token, commit); !errors.Is(err, ErrSaveCheckpoint) {
		t.Fatalf("other peer: %v", err)
	}
	r.state = append(r.state, 1, 43)
	r.stateRevision++
	if err := r.WithSaveCheckpoint("alice", observed.Token, commit); !errors.Is(err, ErrSaveCheckpoint) {
		t.Fatalf("changed room: %v", err)
	}
	if called {
		t.Fatal("rejected checkpoint dispatched save")
	}
	fresh, _ := r.CaptureSaveCheckpoint("alice")
	if err := r.WithSaveCheckpoint("alice", fresh.Token, func(cp SaveCheckpoint) error {
		if cp.Generation != 3 || cp.Revision != 1 || !bytes.Equal(cp.State, []byte{1, 42, 1, 43}) {
			t.Fatalf("wrong snapshot: %+v", cp)
		}
		cp.State[0] = 99
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r.state[0] != 1 {
		t.Fatal("callback mutated live state")
	}
}

func TestSaveCheckpointBindsRoomLifetimeGenerationAndMembership(t *testing.T) {
	r := checkpointRoom()
	cp, _ := r.CaptureSaveCheckpoint("alice")
	other := checkpointRoom()
	other.documentID = r.documentID
	other.orgID = r.orgID
	if err := other.WithSaveCheckpoint("alice", cp.Token, func(SaveCheckpoint) error { return nil }); !errors.Is(err, ErrSaveCheckpoint) {
		t.Fatalf("new lifetime: %v", err)
	}
	r.generation++
	if err := r.WithSaveCheckpoint("alice", cp.Token, func(SaveCheckpoint) error { return nil }); !errors.Is(err, ErrSaveCheckpoint) {
		t.Fatalf("generation: %v", err)
	}
	delete(r.peers, "alice")
	if _, err := r.CaptureSaveCheckpoint("alice"); !errors.Is(err, ErrSaveCheckpoint) {
		t.Fatalf("departed peer: %v", err)
	}
	r.stale = true
	if _, err := r.CaptureSaveCheckpoint("bob"); !errors.Is(err, ErrGeneration) {
		t.Fatalf("stale: %v", err)
	}
}

func TestCheckpointTransportReplaysBeforeReceipt(t *testing.T) {
	r := checkpointRoom()
	peer := r.peers["alice"].(*fakePeer)
	nonce := bytes.Repeat([]byte{17}, 16)
	if err := r.HandleFrame(context.Background(), peer, append([]byte{MessageCheckpoint, 0}, nonce...)); err != nil {
		t.Fatal(err)
	}
	frames := peer.Received()
	if len(frames) != 2 || !bytes.Equal(frames[0], []byte{MessageSync, SyncStep2, 1, 42}) {
		t.Fatalf("replay before receipt: %v", frames)
	}
	cp, _ := r.CaptureSaveCheckpoint(peer.ID())
	want, _ := cp.ResponseFrame(peer.ID(), nonce)
	if !bytes.Equal(frames[1], want) {
		t.Fatalf("receipt mismatch: %v", frames[1])
	}
	for _, invalid := range [][]byte{{MessageCheckpoint}, {MessageCheckpoint, 0}, {MessageCheckpoint, 1, 1}, {MessageCheckpoint, 0, 1}} {
		if err := r.HandleFrame(context.Background(), peer, invalid); err == nil {
			t.Fatalf("accepted invalid request %v", invalid)
		}
	}
	if len(peer.Received()) != 2 {
		t.Fatal("invalid request dispatched frames")
	}
}

func TestCanonicalSaveCommitAdvancesOnlyAfterSuccess(t *testing.T) {
	r := checkpointRoom()
	r.pending = 2
	r.dirty = true
	r.compactionPending = true
	cp, _ := r.CaptureSaveCheckpoint("alice")
	rejected := errors.New("transaction rolled back")
	if err := r.CommitSaveCheckpoint("alice", cp.Token, func(SaveCheckpoint) error { return rejected }); !errors.Is(err, rejected) {
		t.Fatal(err)
	}
	if r.generation != 3 || r.pending != 2 || !r.dirty || !r.compactionPending {
		t.Fatal("failed commit mutated room")
	}
	if err := r.CommitSaveCheckpoint("alice", cp.Token, func(got SaveCheckpoint) error {
		if got.PendingUpdates != 2 || got.Generation != 3 || !bytes.Equal(got.State, r.state) {
			t.Fatal("wrong transaction checkpoint")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r.generation != 4 || r.pending != 0 || r.dirty || r.compactionPending {
		t.Fatal("successful receipt did not advance room")
	}
	if err := r.CommitSaveCheckpoint("alice", cp.Token, func(SaveCheckpoint) error { t.Fatal("old token dispatched"); return nil }); !errors.Is(err, ErrSaveCheckpoint) {
		t.Fatal(err)
	}
	if err := r.CheckGeneration(4); err != nil {
		t.Fatal(err)
	}
}

type delayedGenerationRefusal struct {
	generationStoreFixture
	entered chan generated.PersistCollabDocStateForGenerationParams
	release chan struct{}
}

func (s *delayedGenerationRefusal) PersistCollabDocStateForGeneration(ctx context.Context, p generated.PersistCollabDocStateForGenerationParams) (bool, error) {
	s.entered <- p
	select {
	case <-s.release:
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func TestOldFlushRefusalCannotStaleCanonicalSaveOrAcknowledgeLaterEdit(t *testing.T) {
	store := &delayedGenerationRefusal{entered: make(chan generated.PersistCollabDocStateForGenerationParams, 1), release: make(chan struct{})}
	h := NewHub(nil)
	h.Queries = store
	r := checkpointRoom()
	r.hub = h
	r.pending = 1
	r.dirty = true
	done := make(chan error, 1)
	go func() { done <- r.persist(context.Background(), false) }()
	select {
	case p := <-store.entered:
		if p.Generation != 3 {
			t.Fatal("writer captured wrong generation")
		}
	case <-time.After(time.Second):
		t.Fatal("writer did not enter")
	}
	defer func() {
		select {
		case <-store.release:
		default:
			close(store.release)
		}
	}()
	cp, _ := r.CaptureSaveCheckpoint("alice")
	if err := r.CommitSaveCheckpoint("alice", cp.Token, func(SaveCheckpoint) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := r.applyAppend([]byte{1, 43}, "alice"); err != nil {
		t.Fatal(err)
	}
	close(store.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("writer did not finish")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stale || r.generation != 4 || !r.dirty || r.pending != 1 {
		t.Fatalf("old receipt corrupted new state: generation=%d stale=%v dirty=%v pending=%d", r.generation, r.stale, r.dirty, r.pending)
	}
}

func TestSaveRoomRequiresPeerUserAndTenant(t *testing.T) {
	r := checkpointRoom()
	h := NewHub(nil)
	h.rooms[r.documentID] = r
	user := r.peers["alice"].UserID()
	if got, err := h.RoomForSave(r.documentID, r.orgID, user, "alice"); err != nil || got != r {
		t.Fatalf("valid owner refused: %v", err)
	}
	for _, attempt := range []struct {
		org, user uuid.UUID
		peer      string
	}{{uuid.New(), user, "alice"}, {r.orgID, uuid.New(), "alice"}, {r.orgID, user, "missing"}} {
		if _, err := h.RoomForSave(r.documentID, attempt.org, attempt.user, attempt.peer); !errors.Is(err, ErrSaveCheckpoint) {
			t.Fatalf("wrong peer ownership accepted: %v", err)
		}
	}
}

func TestCanonicalSaveReceiptReachesEveryPeer(t *testing.T) {
	r := checkpointRoom()
	at := "2026-10-05T12:00:00.123456Z"
	if err := r.PublishSaveReceipt(context.Background(), 4, at); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{MessageSaved, 1, '4', byte(len(at))}, []byte(at)...)
	for id, peer := range r.peers {
		frames := peer.(*fakePeer).Received()
		if len(frames) != 1 || !bytes.Equal(frames[0], want) {
			t.Fatalf("peer %s missing exact receipt: %v", id, frames)
		}
	}
	if err := r.PublishSaveReceipt(context.Background(), 0, at); err == nil {
		t.Fatal("zero generation published")
	}
	if err := r.PublishSaveReceipt(context.Background(), 4, "invalid"); err == nil {
		t.Fatal("invalid timestamp published")
	}
}
