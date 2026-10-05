// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package collab

import (
	"errors"
	"github.com/google/uuid"
	"sync"
)

// RecoveryPeer must synchronously close its transport and cancel its workers.
// It must not wait on hub/room locks. Implemented by production WebSocket peers.
type RecoveryPeer interface{ Terminate() }

type RecoveryLease struct {
	hub        *Hub
	documentID uuid.UUID
	Room       *Room
	peers      []RecoveryPeer
}

// BeginRecovery fences joins before the caller acquires a document DB lock.
// Release after rollback, or Finish after a committed recovery. No hub lookup
// is permitted from inside the document/room transaction callback.
func (h *Hub) BeginRecovery(documentID, orgID uuid.UUID) (*RecoveryLease, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.shuttingDown || h.recovering[documentID] != nil {
		return nil, ErrGeneration
	}
	if len(h.recovering) >= MaxActiveRooms {
		return nil, ErrCapacity
	}
	l := &RecoveryLease{hub: h, documentID: documentID, Room: h.rooms[documentID]}
	if l.Room != nil {
		l.Room.mu.Lock()
		defer l.Room.mu.Unlock()
		if l.Room.orgID != orgID || l.Room.closed || l.Room.closing {
			return nil, ErrGeneration
		}
		for _, peer := range l.Room.peers {
			closer, ok := peer.(RecoveryPeer)
			if !ok {
				return nil, errors.New("collab: recovery transport cannot terminate")
			}
			l.peers = append(l.peers, closer)
		}
	}
	if h.recovering == nil {
		h.recovering = make(map[uuid.UUID]*RecoveryLease)
	}
	h.recovering[documentID] = l
	return l, nil
}

func (l *RecoveryLease) Release() {
	l.hub.mu.Lock()
	defer l.hub.mu.Unlock()
	if l.hub.recovering[l.documentID] == l {
		delete(l.hub.recovering, l.documentID)
	}
}

// Finish closes all captured transports before releasing the join fence or
// removing the retired room. Call only after successful CommitRecovery (or a
// committed database-only recovery when Room is nil).
func (l *RecoveryLease) Finish() error {
	if l.Room != nil {
		l.Room.mu.Lock()
		closed := l.Room.closed
		l.Room.mu.Unlock()
		if !closed {
			return errors.New("collab: recovery has not committed")
		}
	}
	var stopped sync.WaitGroup
	for _, peer := range l.peers {
		stopped.Add(1)
		go func(p RecoveryPeer) { defer stopped.Done(); p.Terminate() }(peer)
	}
	stopped.Wait()
	l.hub.mu.Lock()
	defer l.hub.mu.Unlock()
	if l.hub.recovering[l.documentID] != l {
		return errors.New("collab: recovery lease changed")
	}
	if l.Room != nil && l.hub.rooms[l.documentID] == l.Room {
		delete(l.hub.rooms, l.documentID)
	}
	delete(l.hub.recovering, l.documentID)
	return nil
}

// RecoverySnapshot preserves active edits independently of persisted history.
type RecoverySnapshot struct {
	Generation int64
	State      []byte
}

// CommitRecovery requires the caller's document transaction lock first. commit
// must archive this snapshot and commit the replacement generation before
// returning nil. It must not acquire hub/room locks or another DB connection.
// Retirement does not detach peers or release hub capacity; transport teardown
// and identity-safe hub removal must finish before a replacement room can join.
func (r *Room) CommitRecovery(commit func(RecoverySnapshot) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.closing || r.generation <= 0 {
		return ErrGeneration
	}
	if commit == nil {
		return errors.New("collab: missing recovery transaction")
	}
	snapshot := RecoverySnapshot{Generation: r.generation, State: append([]byte(nil), r.state...)}
	if err := commit(snapshot); err != nil {
		return err
	}
	r.compactionPending = false
	r.compactionRevision++
	r.stateRevision++
	r.pending = 0
	r.dirty = false
	r.finishCloseLocked()
	return nil
}
