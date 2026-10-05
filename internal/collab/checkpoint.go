// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package collab

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
)

var ErrSaveCheckpoint = errors.New("collab: save checkpoint changed; synchronize and retry")

// PublishSaveReceipt acknowledges a committed generation to every peer. Receipts
// may race later saves; clients must ignore older generations without replacing
// their current editor content. This method never runs under a room/DB lock.
func (r *Room) PublishSaveReceipt(ctx context.Context, generation int64, updatedAt string) error {
	if generation <= 0 {
		return ErrGeneration
	}
	if _, err := time.Parse(time.RFC3339Nano, updatedAt); err != nil {
		return err
	}
	frame := []byte{MessageSaved}
	for _, value := range []string{strconv.FormatInt(generation, 10), updatedAt} {
		frame = binary.AppendUvarint(frame, uint64(len(value)))
		frame = append(frame, value...)
	}
	r.broadcast(ctx, "", frame)
	return nil
}

// RoomForSave verifies that the checkpoint peer belongs to this authenticated
// user. Return the room before acquiring the document transaction lock; callers
// must never acquire the hub mutex from inside the locked save callback.
func (h *Hub) RoomForSave(documentID, orgID, userID uuid.UUID, peerID string) (*Room, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.rooms[documentID]
	if r == nil {
		return nil, ErrSaveCheckpoint
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peers[peerID]
	if r.orgID != orgID || p == nil || p.UserID() != userID {
		return nil, ErrSaveCheckpoint
	}
	if r.closed || r.closing || r.stale {
		return nil, ErrGeneration
	}
	return r, nil
}

// SaveCheckpoint binds a canonical save to one peer, room lifetime, generation
// and exact replay revision. State is a detached copy of the framed replay log.
// It is not a semantic validation of the client's canonical block tree.
type SaveCheckpoint struct {
	Generation     int64
	Revision       uint64
	Token          [32]byte
	State          []byte
	PendingUpdates int
}

// ResponseFrame follows the captured replay on the authenticated WebSocket.
func (c SaveCheckpoint) ResponseFrame(peerID string, nonce []byte) ([]byte, error) {
	if len(nonce) != 16 || len(peerID) == 0 || len(peerID) > 128 || c.Generation <= 0 {
		return nil, errors.New("collab: invalid checkpoint response")
	}
	frame := append([]byte{MessageCheckpoint, 1}, nonce...)
	for _, value := range []string{peerID, strconv.FormatInt(c.Generation, 10), strconv.FormatUint(c.Revision, 10)} {
		frame = binary.AppendUvarint(frame, uint64(len(value)))
		frame = append(frame, value...)
	}
	return append(frame, c.Token[:]...), nil
}

func (r *Room) checkpointLocked(peerID string) (SaveCheckpoint, error) {
	if r.closed || r.closing || r.stale || r.generation <= 0 {
		return SaveCheckpoint{}, ErrGeneration
	}
	if _, ok := r.peers[peerID]; !ok {
		return SaveCheckpoint{}, ErrSaveCheckpoint
	}
	if r.checkpointEpoch == uuid.Nil {
		r.checkpointEpoch = uuid.New()
	}
	h := sha256.New()
	h.Write(r.checkpointEpoch[:])
	h.Write(r.documentID[:])
	h.Write(r.orgID[:])
	var numbers [24]byte
	binary.BigEndian.PutUint64(numbers[:8], uint64(r.generation))
	binary.BigEndian.PutUint64(numbers[8:16], r.stateRevision)
	binary.BigEndian.PutUint64(numbers[16:24], uint64(len(peerID)))
	h.Write(numbers[:])
	h.Write([]byte(peerID))
	h.Write(r.state)
	var token [32]byte
	copy(token[:], h.Sum(nil))
	return SaveCheckpoint{Generation: r.generation, Revision: r.stateRevision, Token: token, State: append([]byte(nil), r.state...), PendingUpdates: r.pending}, nil
}

// CommitSaveCheckpoint follows the same document-before-room lock contract as
// WithSaveCheckpoint. commit must atomically persist canonical content, the
// captured replay and exactly Generation+1, then COMMIT before returning nil.
// Even an unchanged canonical tree must advance that generation, fencing older
// background flushes. An error leaves the room and its pending edits unchanged.
func (r *Room) CommitSaveCheckpoint(peerID string, token [32]byte, commit func(SaveCheckpoint) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	checkpoint, err := r.checkpointLocked(peerID)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(token[:], checkpoint.Token[:]) != 1 {
		return ErrSaveCheckpoint
	}
	if checkpoint.Generation == math.MaxInt64 || commit == nil {
		return errors.New("collab: invalid canonical save transaction")
	}
	if err := commit(checkpoint); err != nil {
		return err
	}
	r.generation++
	r.stateRevision++
	r.compactionRevision++
	r.compactionPending = false
	r.pending = 0
	r.dirty = false
	return nil
}

func (r *Room) CaptureSaveCheckpoint(peerID string) (SaveCheckpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkpointLocked(peerID)
}

// WithSaveCheckpoint validates and operates on the observed state under one room
// lock. The caller MUST acquire its document database lock first, using the same
// transaction for canonical content and associated history. commit must not
// acquire another room/hub lock or another database connection. This ordering
// matches frame authorization and prevents a document-lock/room-lock inversion.
// Production HTTP/client wiring and generation advancement remain separate work.
func (r *Room) WithSaveCheckpoint(peerID string, token [32]byte, commit func(SaveCheckpoint) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	checkpoint, err := r.checkpointLocked(peerID)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(token[:], checkpoint.Token[:]) != 1 {
		return ErrSaveCheckpoint
	}
	if commit == nil {
		return errors.New("collab: missing canonical save transaction")
	}
	return commit(checkpoint)
}
