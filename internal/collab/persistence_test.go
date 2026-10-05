// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

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

type failingStateStore struct {
	loadErr  error
	writeErr error
	state    []byte
	writes   int
	count    int32
}

func (s *failingStateStore) GetCollabDocState(context.Context, uuid.UUID) (*generated.CollabDocState, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return &generated.CollabDocState{YdocState: append([]byte(nil), s.state...), UpdateCount: s.count}, nil
}

func (s *failingStateStore) UpsertCollabDocState(_ context.Context, p generated.UpsertCollabDocStateParams) (*generated.CollabDocState, error) {
	s.writes++
	if s.writeErr != nil {
		return nil, s.writeErr
	}
	s.state = append([]byte(nil), p.YdocState...)
	s.count += p.UpdateCount
	return &generated.CollabDocState{}, nil
}

func TestFailedInitializationDoesNotPublishEmptyRoom(t *testing.T) {
	store := &failingStateStore{loadErr: errors.New("database unavailable"), state: []byte{2, 8, 9}}
	h := NewHub(nil)
	h.Queries = store
	h.FlushEvery = time.Hour
	id, org := uuid.New(), uuid.New()
	peer := newFakePeer("first")
	if _, err := h.Join(context.Background(), id, org, peer); err == nil {
		t.Fatal("load failure admitted peer")
	}
	if len(h.rooms) != 0 {
		t.Fatal("failed room published")
	}
	store.loadErr = nil
	res, err := h.Join(context.Background(), id, org, peer)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.InitialState) != string(store.state) {
		t.Fatal("reconnect lost saved state")
	}
	h.Leave(context.Background(), id, peer.ID())
}

func TestFailedFlushRetainsEditsForRetryWithoutNewUpdate(t *testing.T) {
	store := &failingStateStore{writeErr: errors.New("database unavailable")}
	h := NewHub(nil)
	h.Queries = store
	room := &Room{hub: h, documentID: uuid.New(), peers: map[string]Peer{}, state: []byte{2, 2, 3}, dirty: true, pending: 2}
	room.maybeFlush(context.Background())
	if !room.dirty || room.pending != 2 {
		t.Fatal("failed flush discarded pending state")
	}
	store.writeErr = nil
	room.maybeFlush(context.Background())
	if room.dirty || room.pending != 0 || string(store.state) != "\x02\x02\x03" || store.count != 2 {
		t.Fatal("retry did not durably acknowledge original edits")
	}
	room.maybeFlush(context.Background())
	if store.writes != 2 {
		t.Fatal("clean state written again")
	}
}

func TestFailedDepartureRetainsRoomForReconnect(t *testing.T) {
	store := &failingStateStore{writeErr: errors.New("database unavailable")}
	h := NewHub(nil)
	h.Queries = store
	id, org := uuid.New(), uuid.New()
	peer := newFakePeer("first")
	room := &Room{hub: h, documentID: id, orgID: org, peers: map[string]Peer{peer.ID(): peer}, state: []byte{2, 2, 3}, dirty: true, pending: 1}
	h.rooms[id] = room
	h.Leave(context.Background(), id, peer.ID())
	if h.rooms[id] != room || room.closed || !room.dirty {
		t.Fatal("failed departure discarded room")
	}
	store.writeErr = nil
	res, err := h.Join(context.Background(), id, org, peer)
	if err != nil || string(res.InitialState) != "\x02\x02\x03" {
		t.Fatalf("reconnect lost pending edits: %v", err)
	}
	h.Leave(context.Background(), id, peer.ID())
	if len(h.rooms) != 0 || !room.closed || len(store.state) != 3 {
		t.Fatal("recovered departure failed")
	}
}

func TestReconnectDoesNotCountHistoricalUpdatesAgain(t *testing.T) {
	store := &failingStateStore{state: []byte{1, 1}, count: 100}
	h := NewHub(nil)
	h.Queries = store
	room := &Room{hub: h, documentID: uuid.New(), peers: map[string]Peer{}, flushCh: make(chan struct{}, 1)}
	if err := room.loadInitialState(context.Background()); err != nil {
		t.Fatal(err)
	}
	room.applyAppend([]byte{1, 2})
	room.maybeFlush(context.Background())
	if store.count != 101 {
		t.Fatalf("historical updates counted again: %d", store.count)
	}
}

func TestSuccessfulDepartureStopsWorkerWithoutWaitingForTick(t *testing.T) {
	h := NewHub(nil)
	h.FlushEvery = time.Hour
	peer := newFakePeer("departing")
	id := uuid.New()
	res, err := h.Join(context.Background(), id, uuid.New(), peer)
	if err != nil {
		t.Fatal(err)
	}
	h.Leave(context.Background(), id, peer.ID())
	select {
	case <-res.Room.flushDoneCh:
	case <-time.After(time.Second):
		t.Fatal("closed room worker still waiting for hourly tick")
	}
	// Idempotent departure must not close the stop channel again.
	h.Leave(context.Background(), id, peer.ID())
}

func TestShutdownRetainsFailedRoomRejectsAdmissionAndAllowsRetry(t *testing.T) {
	store := &failingStateStore{writeErr: errors.New("database unavailable")}
	h := NewHub(nil)
	h.Queries = store
	id, org := uuid.New(), uuid.New()
	peer := newFakePeer("existing")
	room := &Room{hub: h, documentID: id, orgID: org, peers: map[string]Peer{peer.ID(): peer}, state: []byte{2, 1, 2}, dirty: true, pending: 1}
	h.rooms[id] = room
	if err := h.Shutdown(context.Background()); err == nil {
		t.Fatal("failed persistence reported clean shutdown")
	}
	if h.rooms[id] != room || room.closed || !room.dirty {
		t.Fatal("failed shutdown discarded recoverable edits")
	}
	if _, err := h.Join(context.Background(), id, org, newFakePeer("late")); err == nil {
		t.Fatal("shutdown admitted reconnect")
	}
	if _, err := h.Join(context.Background(), uuid.New(), org, newFakePeer("new")); err == nil {
		t.Fatal("shutdown admitted new room")
	}
	store.writeErr = nil
	if err := h.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.rooms) != 0 || !room.closed || !bytes.Equal(store.state, []byte{2, 1, 2}) || store.count != 1 {
		t.Fatal("retry failed to persist exact pending state")
	}
	if err := h.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownWaitsForWorkerCompletionAndReportsDeadline(t *testing.T) {
	h := NewHub(nil)
	id := uuid.New()
	done := make(chan struct{})
	room := &Room{hub: h, documentID: id, peers: map[string]Peer{}, flushStopCh: make(chan struct{}), flushDoneCh: done}
	h.rooms[id] = room
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := h.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("worker deadline missing: %v", err)
	}
	if h.rooms[id] != room || !room.closed {
		t.Fatal("unconfirmed worker discarded")
	}
	close(done)
	if err := h.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.rooms) != 0 {
		t.Fatal("completed room retained")
	}
}

func TestShutdownReturnsAfterActualWorkersExit(t *testing.T) {
	h := NewHub(nil)
	h.FlushEvery = time.Hour
	peer := newFakePeer("active")
	id := uuid.New()
	res, err := h.Join(context.Background(), id, uuid.New(), peer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-res.Room.flushDoneCh:
	default:
		t.Fatal("shutdown returned before worker exit")
	}
}
