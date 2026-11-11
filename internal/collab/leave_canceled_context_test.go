// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package collab

import (
	"bytes"
	"context"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// recordingStateStore records what a final persist writes and the context it uses.
type recordingStateStore struct {
	writes      int
	state       []byte
	entryErr    error
	hasDeadline bool
}

func (s *recordingStateStore) GetCollabDocState(context.Context, uuid.UUID) (*generated.CollabDocState, error) {
	return nil, pgx.ErrNoRows
}

func (s *recordingStateStore) UpsertCollabDocState(ctx context.Context, p generated.UpsertCollabDocStateParams) (*generated.CollabDocState, error) {
	s.writes++
	s.state = append([]byte(nil), p.YdocState...)
	s.entryErr = ctx.Err()
	_, s.hasDeadline = ctx.Deadline()
	return &generated.CollabDocState{}, nil
}

// contextHonoringPeer fails on a cancelled context, as the WebSocket peer does.
type contextHonoringPeer struct{ *fakePeer }

func (p contextHonoringPeer) Send(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return p.fakePeer.Send(ctx, frame)
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// A socket handler's context is already cancelled when its deferred LeaveRoom
// runs. Edits must still be written, on a live and bounded context.
func TestLeaveWithCancelledContextPersistsDirtyRoom(t *testing.T) {
	store := &recordingStateStore{}
	h := NewHub(nil)
	h.Queries = store
	h.FlushEvery = 0
	peer := newFakePeer("departing")
	joined, err := h.Join(context.Background(), uuid.New(), uuid.New(), peer)
	if err != nil {
		t.Fatal(err)
	}
	update := []byte{2, 2, 3}
	if _, _, _, err := joined.Room.applyAppend(update, peer.ID()); err != nil {
		t.Fatal(err)
	}

	h.LeaveRoom(cancelledContext(), joined.Room, peer.ID())

	if store.writes != 1 || string(store.state) != string(update) {
		t.Fatalf("final persist writes=%d state=%x", store.writes, store.state)
	}
	if store.entryErr != nil || !store.hasDeadline {
		t.Fatalf("final persist context err=%v deadline=%v", store.entryErr, store.hasDeadline)
	}
	if len(h.rooms) != 0 {
		t.Fatalf("persisted room retained: %d rooms", len(h.rooms))
	}
}

// Closed editors must not accumulate into a capacity refusal for the org.
func TestLeaveWithCancelledContextReleasesRoomCapacity(t *testing.T) {
	h := NewHub(nil)
	org := uuid.New()
	for i := 0; i < MaxOrgRooms+1; i++ {
		peer := newFakePeer("editor")
		joined, err := h.Join(context.Background(), uuid.New(), org, peer)
		if err != nil {
			t.Fatalf("document %d refused after earlier editors closed: %v", i+1, err)
		}
		h.LeaveRoom(cancelledContext(), joined.Room, peer.ID())
	}
}

// A departing owner's cancelled context must not evict the healthy peers that
// are offered bootstrap ownership.
func TestLeaveWithCancelledContextHandsBootstrapToLivePeer(t *testing.T) {
	h := NewHub(nil)
	doc, org := uuid.New(), uuid.New()
	peers := map[string]*fakePeer{}
	var room *Room
	for _, name := range []string{"0", "1", "2"} {
		peers[name] = newFakePeer(name)
		joined, err := h.Join(context.Background(), doc, org, contextHonoringPeer{peers[name]})
		if err != nil {
			t.Fatal(err)
		}
		room = joined.Room
	}

	h.LeaveRoom(cancelledContext(), room, "0")

	if got := room.PeerCount(); got != 2 {
		t.Fatalf("live peers evicted: %d remain", got)
	}
	if room.bootstrapOwner != "1" {
		t.Fatalf("bootstrap owner = %q", room.bootstrapOwner)
	}
	grant := []byte{MessageBootstrap, 1}
	if got := peers["1"].Received(); len(got) != 1 || !bytes.Equal(got[0], grant) {
		t.Fatalf("new owner frames = %x", got)
	}
	if got := peers["2"].Received(); len(got) != 0 {
		t.Fatalf("other peer frames = %x", got)
	}
}

// Production uses the generation-fenced store, so the same teardown must write
// through it and retire the room.
func TestLeaveWithCancelledContextPersistsThroughGenerationStore(t *testing.T) {
	store := &generationStoreFixture{generation: 3, loadErr: pgx.ErrNoRows, accepted: true}
	h := NewHub(nil)
	h.Queries = store
	h.FlushEvery = 0
	peer := newFakePeer("departing")
	joined, err := h.Join(context.Background(), uuid.New(), uuid.New(), peer)
	if err != nil {
		t.Fatal(err)
	}
	update := []byte{2, 2, 3}
	if _, _, _, err := joined.Room.applyAppend(update, peer.ID()); err != nil {
		t.Fatal(err)
	}

	h.LeaveRoom(cancelledContext(), joined.Room, peer.ID())

	if store.writes != 1 || store.params.Generation != 3 || !bytes.Equal(store.params.YdocState, update) {
		t.Fatalf("fenced writes=%d generation=%d state=%x", store.writes, store.params.Generation, store.params.YdocState)
	}
	if len(h.rooms) != 0 {
		t.Fatalf("persisted room retained: %d rooms", len(h.rooms))
	}
}
