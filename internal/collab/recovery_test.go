// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package collab

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

type recoveryTestPeer struct {
	*fakePeer
	terminate func()
}

func (p *recoveryTestPeer) Terminate() { p.terminate() }

func TestRecoveryLeaseFencesJoinsUntilTransportTeardown(t *testing.T) {
	r := checkpointRoom()
	h := NewHub(nil)
	r.hub = h
	h.rooms[r.documentID] = r
	var terminated atomic.Int64
	for id := range r.peers {
		r.peers[id] = &recoveryTestPeer{fakePeer: newFakePeer(id), terminate: func() {
			if _, err := h.Join(context.Background(), r.documentID, r.orgID, newFakePeer("late")); !errors.Is(err, ErrGeneration) {
				t.Fatalf("join during teardown: %v", err)
			}
			terminated.Add(1)
		}}
	}
	lease, err := h.BeginRecovery(r.documentID, r.orgID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.BeginRecovery(r.documentID, r.orgID); !errors.Is(err, ErrGeneration) {
		t.Fatal("duplicate recovery allowed")
	}
	if err := lease.Finish(); err == nil {
		t.Fatal("unfinished transaction released room")
	}
	if err := r.CommitRecovery(func(RecoverySnapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := lease.Finish(); err != nil {
		t.Fatal(err)
	}
	if terminated.Load() != 2 {
		t.Fatal("transport left running")
	}
	fresh, err := h.Join(context.Background(), r.documentID, r.orgID, newFakePeer("alice"))
	if err != nil {
		t.Fatal(err)
	}
	h.LeaveRoom(context.Background(), r, "alice")
	if fresh.Room.PeerCount() != 1 {
		t.Fatal("old socket removed new room peer")
	}
	h.LeaveRoom(context.Background(), fresh.Room, "alice")
}

func TestRecoveryLeaseRollbackAndEmptyRoomFence(t *testing.T) {
	h := NewHub(nil)
	r := checkpointRoom()
	lease, err := h.BeginRecovery(r.documentID, r.orgID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Join(context.Background(), r.documentID, r.orgID, newFakePeer("early")); !errors.Is(err, ErrGeneration) {
		t.Fatal("join raced database-only recovery")
	}
	lease.Release()
	joined, err := h.Join(context.Background(), r.documentID, r.orgID, newFakePeer("after-rollback"))
	if err != nil {
		t.Fatal(err)
	}
	h.LeaveRoom(context.Background(), joined.Room, "after-rollback")
}

func TestRecoveryRetiresOnlyAfterArchiveCommit(t *testing.T) {
	r := checkpointRoom()
	r.stale, r.dirty, r.pending = true, true, 2
	r.compactionPending = true
	r.flushStopCh = make(chan struct{})
	failed := errors.New("archive rollback")
	if err := r.CommitRecovery(func(s RecoverySnapshot) error {
		if s.Generation != 3 || !bytes.Equal(s.State, r.state) {
			t.Fatal("wrong archive")
		}
		s.State[0] = 99
		return failed
	}); !errors.Is(err, failed) {
		t.Fatal(err)
	}
	if r.closed || !r.dirty || r.pending != 2 || r.state[0] != 1 || !r.compactionPending {
		t.Fatal("rollback changed room")
	}
	select {
	case <-r.flushStopCh:
		t.Fatal("rollback stopped worker")
	default:
	}
	if err := r.CommitRecovery(func(RecoverySnapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !r.closed || r.dirty || r.pending != 0 || r.compactionPending {
		t.Fatal("committed archive did not retire room")
	}
	if len(r.peers) != 2 {
		t.Fatal("retirement released peer capacity before teardown")
	}
	select {
	case <-r.flushStopCh:
	default:
		t.Fatal("worker not stopped")
	}
	if err := r.CommitRecovery(func(RecoverySnapshot) error { t.Fatal("double commit"); return nil }); !errors.Is(err, ErrGeneration) {
		t.Fatal(err)
	}
}
