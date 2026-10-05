// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package collab implements v1.1 Yjs collaborative editing for the
// block editor. The server is a relay: clients hold the CRDT state,
// the server only:
//
//  1. Broadcasts binary updates between connected peers on a per-
//     document hub.
//  2. Persists a snapshot of the document state so a fresh client
//     gets the current state at connect time.
//  3. Tracks awareness (cursors, user labels) so peers can render
//     "Alice is typing here" indicators.
//
// Wire protocol matches y-websocket so the standard yjs client library
// plugs in without a custom adapter:
//
//   - Binary frames only
//   - Message types (first byte):
//     0x00  sync   (subtypes: 0=sync_step1, 1=sync_step2, 2=update)
//     0x01  awareness
//     0x03  query awareness
//
// We forward frames as-is without re-encoding, so the Go side doesn't
// need a Yjs CRDT implementation. Persistence stores the most recent
// "sync_step2" + concatenated "update" frames as one append-only log
// per doc, which any Yjs client can replay via Y.applyUpdate.
package collab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Message types per y-protocols/sync + y-protocols/awareness wire spec.
// MessageCompact is a Hash extension: the server asks a peer for a
// freshly-encoded full doc state so the append-only log can be replaced
// with one self-contained snapshot.
const (
	MessageSync       = 0x00
	MessageAwareness  = 0x01
	MessageAuth       = 0x02
	MessageQueryAware = 0x03
	MessageCompact    = 0x04
	MessageBootstrap  = 0x05
	MessageGeneration = 0x06
	MessageCheckpoint = 0x07
	MessageSaved      = 0x08
	SyncStep1         = 0x00
	SyncStep2         = 0x01
	SyncUpdate        = 0x02
	CompactRequest    = 0x00
	CompactSnapshot   = 0x01
)

// DefaultCompactionThreshold is the size (bytes) above which the room
// asks a connected peer for a fresh snapshot.
const DefaultCompactionThreshold = 1 << 20 // 1 MiB

// CompactionTimeout is how long a pending compaction request is allowed
// to sit unanswered before we let a new one fire.
const CompactionTimeout = 10 * time.Second

// Process-local bounds complement request quotas: long-lived sockets do not
// consume HTTP requests while retaining room histories and goroutines.
const (
	MaxActiveRooms = 64
	MaxOrgRooms    = 16
	MaxRoomPeers   = 16
	MaxOrgPeers    = 64
	MaxUserPeers   = 8
)

var ErrCapacity = errors.New("collab: active collaboration capacity reached")

// Hub is the process-wide collab server. Holds one Room per active
// document; rooms are created on first connect + torn down when the
// last peer leaves (after flushing state to the DB).
type Hub struct {
	Queries             StateStore
	FlushEvery          time.Duration // how often a busy room writes to DB; default 5s
	IdleTimeout         time.Duration // how long an empty room sticks around for late joiners; default 0 (immediate teardown)
	CompactionThreshold int           // size in bytes above which we ask a peer for a snapshot; default 1 MiB

	mu           sync.Mutex
	rooms        map[uuid.UUID]*Room
	recovering   map[uuid.UUID]*RecoveryLease
	shuttingDown bool
}

type StateStore interface {
	GetCollabDocState(context.Context, uuid.UUID) (*generated.CollabDocState, error)
	UpsertCollabDocState(context.Context, generated.UpsertCollabDocStateParams) (*generated.CollabDocState, error)
}

type GenerationStore interface {
	GetDocumentCollabGeneration(context.Context, generated.GetDocumentCollabGenerationParams) (int64, error)
	GetCollabDocStateWithGeneration(context.Context, uuid.UUID) (*generated.GetCollabDocStateWithGenerationRow, error)
	PersistCollabDocStateForGeneration(context.Context, generated.PersistCollabDocStateForGenerationParams) (bool, error)
}

var _ GenerationStore = (*generated.Queries)(nil)
var ErrGeneration = errors.New("collab: canonical generation changed; preserve draft and reload")
var ErrLegacyHistory = errors.New("collab: legacy history needs canonical association recovery")

// NewHub constructs a Hub with sensible defaults.
func NewHub(q *generated.Queries) *Hub {
	var store StateStore
	if q != nil {
		store = q
	}
	return &Hub{
		Queries:             store,
		FlushEvery:          5 * time.Second,
		IdleTimeout:         0,
		CompactionThreshold: DefaultCompactionThreshold,
		rooms:               map[uuid.UUID]*Room{},
	}
}

// Shutdown flushes every live room to the DB and tears them down. Wire it into
// the server's graceful-shutdown path so a SIGTERM/deploy doesn't drop the
// edits each room accumulated since its last periodic flush (up to FlushEvery).
func (h *Hub) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.shuttingDown = true
	var failures []error
	for id, r := range h.rooms {
		if err := r.close(ctx); err != nil {
			slog.Error("collab: shutdown persistence failed; uncommitted edits remain", "doc_id", r.documentID, "err", err)
			failures = append(failures, fmt.Errorf("document %s: %w", id, err))
			continue
		}
		if r.flushDoneCh != nil {
			select {
			case <-r.flushDoneCh:
			case <-ctx.Done():
				failures = append(failures, fmt.Errorf("document %s worker termination: %w", id, ctx.Err()))
				continue
			}
		}
		delete(h.rooms, id)
	}
	return errors.Join(failures...)
}

// Peer is the connection-side view of a single client. Implementations
// wrap a websocket; tests can use an in-memory adapter that buffers
// frames in a channel.
type Peer interface {
	// ID is unique per connection; clients with multiple tabs each get
	// their own peer ID.
	ID() string
	// Send forwards a binary frame to this peer. Returns an error if
	// the underlying transport is closed.
	Send(ctx context.Context, frame []byte) error
	// UserID is the authenticated user for the connection, for audit
	// + awareness labels.
	UserID() uuid.UUID
	// DisplayName is the human-readable label shown next to remote
	// cursors. Falls back to user email if name is empty.
	DisplayName() string
}

// Room is the per-document state. Holds the peer set + the persisted
// state blob; serializes broadcasts behind a mutex so peers never see
// out-of-order frames.
type Room struct {
	hub        *Hub
	documentID uuid.UUID
	orgID      uuid.UUID
	generation int64
	stale      bool

	mu                 sync.Mutex
	peers              map[string]Peer
	bootstrapOwner     string
	state              []byte // append-only Yjs update log
	replayUpdates      int
	dirty              bool
	pending            int // updates since last flush
	closed             bool
	closing            bool
	stateRevision      uint64
	lastUpdateLength   int
	checkpointEpoch    uuid.UUID
	compactionRevision uint64
	persistOnce        sync.Once
	persistGate        chan struct{}
	flushCh            chan struct{}
	flushDoneCh        chan struct{}
	flushStopCh        chan struct{}

	compactionPending   bool
	compactionNonce     [16]byte
	compactionStartedAt time.Time
	compactionBoundary  int
	compactionUpdates   int
	compactionPeerID    string
}

// JoinResult is what a fresh peer receives on connect: the persisted
// state to bootstrap their local Y.Doc and a Send hook for outgoing
// frames.
type JoinResult struct {
	Room         *Room
	InitialState []byte // raw bytes a y-websocket client unwraps via Y.applyUpdate
}

// Join attaches the peer to the room for documentID, loading persisted
// state from the DB on first join.
func (h *Hub) Join(ctx context.Context, documentID, orgID uuid.UUID, peer Peer) (*JoinResult, error) {
	h.mu.Lock()
	if h.shuttingDown {
		h.mu.Unlock()
		return nil, errors.New("collab: hub is shutting down")
	}
	if h.recovering[documentID] != nil {
		h.mu.Unlock()
		return nil, ErrGeneration
	}
	room, ok := h.rooms[documentID]
	orgRooms, orgPeers, userPeers := 0, 0, 0
	for _, active := range h.rooms {
		active.mu.Lock()
		if active.orgID == orgID {
			orgRooms++
			orgPeers += len(active.peers)
		}
		for _, existing := range active.peers {
			if existing.UserID() == peer.UserID() {
				userPeers++
			}
		}
		active.mu.Unlock()
	}
	if orgPeers >= MaxOrgPeers || userPeers >= MaxUserPeers || (!ok && (len(h.rooms) >= MaxActiveRooms || orgRooms >= MaxOrgRooms)) {
		h.mu.Unlock()
		return nil, ErrCapacity
	}
	if ok {
		room.mu.Lock()
		_, duplicate := room.peers[peer.ID()]
		full := len(room.peers) >= MaxRoomPeers
		room.mu.Unlock()
		if duplicate || full {
			h.mu.Unlock()
			if duplicate {
				return nil, errors.New("collab: peer already joined")
			}
			return nil, ErrCapacity
		}
	}
	if !ok {
		room = &Room{
			hub:         h,
			documentID:  documentID,
			orgID:       orgID,
			peers:       map[string]Peer{},
			flushCh:     make(chan struct{}, 1),
			flushDoneCh: make(chan struct{}),
			flushStopCh: make(chan struct{}),
		}
		// Publish only a successfully initialized room. Holding the hub lock
		// prevents another join from observing an empty state during loading.
		if err := room.loadInitialState(ctx); err != nil {
			h.mu.Unlock()
			return nil, fmt.Errorf("collab: load initial state: %w", err)
		}
		h.rooms[documentID] = room
		go room.flushLoop()
	}
	if room.orgID != orgID {
		h.mu.Unlock()
		return nil, errors.New("collab: room organization mismatch")
	}
	room.mu.Lock()
	if room.stale || room.closed || room.closing {
		room.mu.Unlock()
		h.mu.Unlock()
		return nil, ErrGeneration
	}
	room.peers[peer.ID()] = peer
	if len(room.state) == 0 && room.bootstrapOwner == "" {
		room.bootstrapOwner = peer.ID()
	}
	state := append([]byte(nil), room.state...)
	room.mu.Unlock()
	h.mu.Unlock()
	return &JoinResult{Room: room, InitialState: state}, nil
}

// Leave removes the peer + tears the room down if it's now empty.
// Flushes the persisted state to the DB synchronously before
// teardown so a quick reconnect doesn't see stale bytes.
func (h *Hub) Leave(ctx context.Context, documentID uuid.UUID, peerID string) {
	h.leaveRoom(ctx, documentID, nil, peerID)
}

// LeaveRoom prevents a departing socket from touching a replacement room.
func (h *Hub) LeaveRoom(ctx context.Context, room *Room, peerID string) {
	h.leaveRoom(ctx, room.documentID, room, peerID)
}

func (h *Hub) leaveRoom(ctx context.Context, documentID uuid.UUID, expected *Room, peerID string) {
	for {
		replacement := h.leavePeerFromRoom(ctx, documentID, expected, peerID)
		if replacement == nil {
			return
		}
		if err := replacement.Send(ctx, []byte{MessageBootstrap, 1}); err == nil {
			return
		}
		// A failed transport cannot hold initialization ownership. Remove it
		// and elect the next peer without recursive teardown or locked sends.
		peerID = replacement.ID()
	}
}

func (h *Hub) leavePeer(ctx context.Context, documentID uuid.UUID, peerID string) Peer {
	return h.leavePeerFromRoom(ctx, documentID, nil, peerID)
}

func (h *Hub) leavePeerFromRoom(ctx context.Context, documentID uuid.UUID, expected *Room, peerID string) Peer {
	h.mu.Lock()
	room, ok := h.rooms[documentID]
	if !ok || (expected != nil && room != expected) {
		h.mu.Unlock()
		return nil
	}
	room.mu.Lock()
	if room.closed && h.recovering[documentID] != nil {
		// Retirement still counts captured peers until Finish has awaited every
		// socket handler. A departing handler cannot release capacity early.
		room.mu.Unlock()
		h.mu.Unlock()
		return nil
	}
	delete(room.peers, peerID)
	var replacement Peer
	if room.bootstrapOwner == peerID && len(room.state) == 0 {
		room.bootstrapOwner = ""
		for id, p := range room.peers {
			if replacement == nil || id < replacement.ID() {
				replacement = p
			}
		}
		if replacement != nil {
			room.bootstrapOwner = replacement.ID()
		}
	}
	empty := len(room.peers) == 0
	room.mu.Unlock()
	if empty {
		// On failure retain the room and its dirty bytes for retry/reconnect.
		if err := room.close(ctx); err == nil {
			delete(h.rooms, documentID)
		} else {
			slog.Error("collab: final persist failed; room retained", "doc_id", documentID, "err", err)
		}
		h.mu.Unlock()
		return nil
	}
	h.mu.Unlock()
	return replacement
}

// loadInitialState reads any persisted Yjs state from the DB and
// stores it as the room's append-only log.
func (r *Room) loadInitialState(ctx context.Context) error {
	if r.hub == nil || r.hub.Queries == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var row *generated.CollabDocState
	var err error
	if store, ok := r.hub.Queries.(GenerationStore); ok {
		r.generation, err = store.GetDocumentCollabGeneration(ctx, generated.GetDocumentCollabGenerationParams{ID: r.documentID, OrgID: r.orgID})
		if err != nil {
			return err
		}
		if r.generation <= 0 {
			return ErrGeneration
		}
		associated, loadErr := store.GetCollabDocStateWithGeneration(ctx, r.documentID)
		err = loadErr
		if err == nil {
			if !associated.Generation.Valid {
				return ErrLegacyHistory
			}
			if associated.Generation.Int64 != r.generation {
				return ErrGeneration
			}
			row = &generated.CollabDocState{YdocState: associated.YdocState, UpdateCount: associated.UpdateCount}
		}
	} else {
		row, err = r.hub.Queries.GetCollabDocState(ctx, r.documentID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateReplay(row.YdocState); err != nil {
		return fmt.Errorf("collab: invalid persisted update log: %w", err)
	}
	r.mu.Lock()
	r.state = nil
	for rest := row.YdocState; len(rest) > 0; {
		n, _ := encodedUpdateLength(rest)
		if !bytes.Equal(rest[:n], []byte{2, 0, 0}) {
			r.state = append(r.state, rest[:n]...)
			r.lastUpdateLength = n
			r.replayUpdates++
		}
		rest = rest[n:]
	}
	// Stored UpdateCount is historical; pending tracks only new local updates.
	r.pending = 0
	r.mu.Unlock()
	return nil
}

// HandleFrame routes a wire frame from a peer. Sync updates get
// appended to the room state + broadcast; awareness frames just relay.
// Returns an error if the frame is malformed.
func (r *Room) HandleFrame(ctx context.Context, sender Peer, frame []byte) error {
	r.mu.Lock()
	_, present := r.peers[sender.ID()]
	closed := r.closed || r.closing || r.stale
	r.mu.Unlock()
	if !present || closed {
		return errors.New("collab: peer has left the room")
	}
	if len(frame) == 0 {
		return errors.New("collab: empty frame")
	}
	switch frame[0] {
	case MessageSync:
		if len(frame) < 2 {
			return errors.New("collab: sync frame missing subtype")
		}
		switch frame[1] {
		case SyncStep1:
			// Peer asked for our state vector. Respond with our full
			// state as a sync_step2 frame so they can fast-forward.
			r.mu.Lock()
			state := append([]byte(nil), r.state...)
			r.mu.Unlock()
			frames, err := SyncFrames(state)
			if err != nil {
				return err
			}
			for _, resp := range frames {
				if err := sender.Send(ctx, resp); err != nil {
					return err
				}
			}
		case SyncStep2, SyncUpdate:
			// Append the update bytes (skip the 2-byte header) to our
			// log + broadcast to other peers.
			update := frame[2:]
			if err := validateSingleUpdate(update); err != nil {
				return err
			}
			if err := r.appendUpdate(ctx, sender, update); err != nil {
				return err
			}
		default:
			return fmt.Errorf("collab: unknown sync subtype %d", frame[1])
		}
	case MessageAwareness, MessageQueryAware:
		// Awareness is ephemeral (cursor positions, user labels). We
		// don't persist it; just relay between peers.
		r.broadcast(ctx, sender.ID(), frame)
	case MessageAuth:
		// Auth frames are advisory; the websocket-layer auth gate
		// already accepted this peer. Echo back so y-protocols stays
		// happy.
		_ = sender.Send(ctx, []byte{MessageAuth, 0x01})
	case MessageCheckpoint:
		// Request: type, subtype 0, and a 16-byte client correlation nonce.
		if len(frame) != 18 || frame[1] != 0 {
			return errors.New("collab: invalid checkpoint request")
		}
		checkpoint, err := r.CaptureSaveCheckpoint(sender.ID())
		if err != nil {
			return err
		}
		replay, err := SyncFrames(checkpoint.State)
		if err != nil {
			return err
		}
		// Replay the exact captured state before its receipt. Later room edits
		// invalidate the token at save validation rather than being overwritten.
		for _, response := range replay {
			if err := sender.Send(ctx, response); err != nil {
				return err
			}
		}
		response, err := checkpoint.ResponseFrame(sender.ID(), frame[2:])
		if err != nil {
			return err
		}
		return sender.Send(ctx, response)
	case MessageCompact:
		// Hash extension: peer is responding to a compact-request
		// with a freshly encoded full snapshot. We do not broadcast
		// this; only the server cares about the snapshot.
		if len(frame) < 2 {
			return errors.New("collab: compact frame missing subtype")
		}
		if frame[1] != CompactSnapshot {
			return fmt.Errorf("collab: unexpected compact subtype %d", frame[1])
		}
		if len(frame) < 2+16 {
			return errors.New("collab: compact snapshot frame too short")
		}
		var nonce [16]byte
		copy(nonce[:], frame[2:2+16])
		if err := validateSingleUpdate(frame[2+16:]); err != nil {
			return err
		}
		r.applySnapshot(nonce, frame[2+16:], sender.ID())
	default:
		return fmt.Errorf("collab: unknown message type %d", frame[0])
	}
	return nil
}

func (r *Room) appendUpdate(ctx context.Context, sender Peer, update []byte) error {
	target, nonce, shouldRequest, err := r.applyAppend(update, sender.ID())
	if err != nil {
		return err
	}
	// Deliver the triggering update before asking a different peer to encode
	// its snapshot. Later updates are preserved separately at acceptance.
	r.broadcast(ctx, sender.ID(), append([]byte{MessageSync, SyncUpdate}, update...))
	if shouldRequest && target != nil {
		frame := make([]byte, 0, 2+16)
		frame = append(frame, MessageCompact, CompactRequest)
		frame = append(frame, nonce[:]...)
		if err := target.Send(ctx, frame); err != nil {
			slog.Debug("collab: compact request send", "peer_id", target.ID(), "err", err)
			r.mu.Lock()
			if r.compactionNonce == nonce {
				r.compactionPending = false
			}
			r.mu.Unlock()
		}
	}
	return nil
}

// applyAppend is the locked half of appendUpdate. Returns a peer + nonce
// when the log has crossed the compaction threshold and we want to ask
// for a fresh snapshot.
func (r *Room) applyAppend(update []byte, senderIDs ...string) (Peer, [16]byte, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var zeroNonce [16]byte
	if r.closed || r.closing || r.stale {
		return nil, zeroNonce, false, errors.New("collab: room is closed")
	}
	if len(senderIDs) > 0 {
		if _, present := r.peers[senderIDs[0]]; !present {
			return nil, zeroNonce, false, errors.New("collab: peer has left the room")
		}
	}
	if bytes.Equal(update, []byte{2, 0, 0}) {
		return nil, zeroNonce, false, nil
	}
	if r.bootstrapOwner != "" && len(senderIDs) > 0 && senderIDs[0] != r.bootstrapOwner {
		return nil, zeroNonce, false, errors.New("collab: initial seed belongs to another peer")
	}
	// Yjs CRDT is associative + commutative; appending raw updates is
	// safe because the client unifies them via Y.applyUpdate. We do a
	// trivial de-dup so a chatty client retransmitting the same frame
	// doesn't bloat the log.
	// Compare a complete framed record, not an arbitrary suffix inside a
	// previous update's payload. Different Yjs updates may share byte suffixes.
	if r.lastUpdateLength == len(update) && r.lastUpdateLength > 0 &&
		r.lastUpdateLength <= len(r.state) && bytes.Equal(r.state[len(r.state)-r.lastUpdateLength:], update) {
		return nil, zeroNonce, false, nil
	}
	if len(update) > MaxReplayBytes-len(r.state) || r.replayUpdates >= MaxReplayUpdates {
		return nil, zeroNonce, false, errors.New("collab: active history limit reached; compaction required")
	}
	r.bootstrapOwner = ""
	r.replayUpdates++
	r.state = append(r.state, update...)
	r.lastUpdateLength = len(update)
	r.pending++
	r.stateRevision++
	r.dirty = true
	// Signal the flush loop without blocking; if the channel is full
	// the loop will pick up the work on its next tick.
	select {
	case r.flushCh <- struct{}{}:
	default:
	}

	threshold := DefaultCompactionThreshold
	if r.hub != nil && r.hub.CompactionThreshold > 0 {
		threshold = r.hub.CompactionThreshold
	}
	if r.compactionPending {
		if time.Since(r.compactionStartedAt) <= CompactionTimeout {
			return nil, zeroNonce, false, nil
		}
		// Stale; let a new request fire below.
		r.compactionPending = false
	}
	if len(r.state) <= threshold || len(r.peers) == 0 {
		return nil, zeroNonce, false, nil
	}
	// Pick the deterministically-lowest peer ID so we don't race two
	// snapshots from different peers.
	var target Peer
	var targetID string
	for id, p := range r.peers {
		if target == nil || id < targetID {
			target = p
			targetID = id
		}
	}
	if target == nil {
		return nil, zeroNonce, false, nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, zeroNonce, false, nil
	}
	r.compactionPending = true
	r.compactionNonce = nonce
	r.compactionStartedAt = time.Now()
	r.compactionBoundary = len(r.state)
	r.compactionUpdates = r.replayUpdates
	r.compactionPeerID = targetID
	return target, nonce, true, nil
}

// applySnapshot replaces the append-only log with a single freshly
// encoded full state from one peer. Rejects snapshots with mismatched
// nonces or that are larger than the log we were trying to shrink.
func (r *Room) applySnapshot(nonce [16]byte, snapshot []byte, senderID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.closing || r.stale {
		return
	}
	if _, present := r.peers[senderID]; !present {
		return
	}
	if !r.compactionPending {
		slog.Debug("collab: ignore snapshot, no pending compaction", "doc_id", r.documentID)
		return
	}
	if nonce != r.compactionNonce {
		slog.Debug("collab: ignore snapshot, nonce mismatch", "doc_id", r.documentID)
		return
	}
	if senderID != r.compactionPeerID {
		return
	}
	if time.Since(r.compactionStartedAt) > CompactionTimeout {
		r.compactionPending = false
		return
	}
	r.compactionPending = false
	if len(snapshot) == 0 {
		return
	}
	// A correct snapshot should be smaller than the bloated log; allow
	// a 10% slack for varint framing differences. If it's bigger, the
	// peer is confused; leave the existing state alone.
	limit := len(r.state) + len(r.state)/10
	if limit > 0 && len(snapshot) > limit {
		slog.Warn("collab: reject oversized snapshot", "doc_id", r.documentID, "old", len(r.state), "new", len(snapshot))
		return
	}
	// Lower-bound guard: a real full-state encode of substantial content can't
	// collapse to a near-empty blob. A 1-byte/degenerate snapshot replacing a
	// non-trivial log means the peer sent a corrupt/half-initialised state, so
	// keep what we have rather than wiping the persisted doc.
	if len(r.state) >= 64 && len(snapshot) < 8 {
		slog.Warn("collab: reject degenerate snapshot", "doc_id", r.documentID, "old", len(r.state), "new", len(snapshot))
		return
	}
	oldSize := len(r.state)
	boundary := r.compactionBoundary
	if boundary < 0 || boundary > len(r.state) {
		return
	}
	tail := r.state[boundary:]
	if len(snapshot) > MaxReplayBytes-len(tail) {
		return
	}
	r.state = append(append([]byte(nil), snapshot...), tail...)
	if len(tail) == 0 {
		r.lastUpdateLength = len(snapshot)
	}
	r.replayUpdates = 1 + r.replayUpdates - r.compactionUpdates
	r.pending = 0
	r.stateRevision++
	r.compactionRevision++
	r.dirty = true
	select {
	case r.flushCh <- struct{}{}:
	default:
	}
	slog.Info("collab: compacted state", "doc_id", r.documentID, "from", oldSize, "to", len(snapshot))
}

func (r *Room) broadcast(ctx context.Context, exceptPeerID string, frame []byte) {
	r.mu.Lock()
	peers := make([]Peer, 0, len(r.peers))
	for id, p := range r.peers {
		if id == exceptPeerID {
			continue
		}
		peers = append(peers, p)
	}
	r.mu.Unlock()
	for _, p := range peers {
		if err := p.Send(ctx, frame); err != nil {
			slog.Debug("collab: peer send", "peer_id", p.ID(), "err", err)
		}
	}
}

// flushLoop debounces DB writes so a hot room doesn't hammer Postgres.
// Exits when close() is called.
func (r *Room) flushLoop() {
	defer close(r.flushDoneCh)
	if r.hub == nil || r.hub.FlushEvery <= 0 {
		return
	}
	ticker := time.NewTicker(r.hub.FlushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.maybeFlush(context.Background())
		case <-r.flushCh:
			// Coalesce a few rapid updates into one flush.
			r.maybeFlush(context.Background())
		case <-r.flushStopCh:
			return
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return
		}
		r.mu.Unlock()
	}
}

func (r *Room) maybeFlush(ctx context.Context) {
	if err := r.persist(ctx, false); err != nil {
		slog.Warn("collab: persist state; pending edits retained", "doc_id", r.documentID, "err", err)
	}
}

// persist serializes writes without holding the room mutex during database I/O.
// Frame authorization can hold a document lock before taking the room mutex;
// database persistence must therefore never wait on that lock with it held.
func (r *Room) persist(ctx context.Context, final bool) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r.persistOnce.Do(func() { r.persistGate = make(chan struct{}, 1) })
	select {
	case r.persistGate <- struct{}{}:
		defer func() { <-r.persistGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	if final {
		r.closing = true
	}
	if !r.dirty || r.hub == nil || r.hub.Queries == nil {
		if final {
			r.finishCloseLocked()
		}
		r.mu.Unlock()
		return nil
	}
	state := append([]byte(nil), r.state...)
	count, revision, compaction := r.pending, r.stateRevision, r.compactionRevision
	generation := r.generation
	var lastUser pgtype.UUID
	for _, p := range r.peers {
		if uid := p.UserID(); uid != uuid.Nil {
			lastUser = pgtype.UUID{Bytes: uid, Valid: true}
			break
		}
	}
	r.mu.Unlock()
	var err error
	if store, ok := r.hub.Queries.(GenerationStore); ok {
		var accepted bool
		accepted, err = store.PersistCollabDocStateForGeneration(ctx, generated.PersistCollabDocStateForGenerationParams{
			DocumentID: r.documentID, OrgID: r.orgID, Generation: generation, YdocState: state, StateSize: int32(len(state)), UpdateCount: int32(count), LastUserID: lastUser,
		})
		if err == nil && !accepted {
			err = ErrGeneration
		}
	} else {
		_, err = r.hub.Queries.UpsertCollabDocState(ctx, generated.UpsertCollabDocStateParams{
			DocumentID: r.documentID, YdocState: state, StateSize: int32(len(state)), UpdateCount: int32(count), LastUserID: lastUser,
		})
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.generation != generation {
		// A canonical save committed this snapshot (and any newer accepted
		// edits) in a new generation. An older writer's refusal/receipt must
		// neither stale the new room nor acknowledge its subsequent edits.
		return nil
	}
	if err != nil {
		r.closing = false
		if errors.Is(err, ErrGeneration) {
			r.stale = true
		}
		return err
	}
	if r.stateRevision == revision {
		r.dirty = false
		r.pending = 0
	} else if r.compactionRevision == compaction {
		// New edits remain dirty. Only the acknowledged snapshot's updates count
		// as persisted; compaction starts a new pending-count epoch.
		r.pending -= count
	}
	if final {
		r.finishCloseLocked()
	}
	return nil
}

func (r *Room) finishCloseLocked() {
	r.closed = true
	r.closing = false
	if r.flushStopCh != nil {
		close(r.flushStopCh)
	}
}

func (r *Room) close(ctx context.Context) error { return r.persist(ctx, true) }

func (r *Room) CheckGeneration(generation int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.closing || r.stale || r.generation <= 0 || r.generation != generation {
		r.stale = true
		return ErrGeneration
	}
	return nil
}

// PeerCount returns the number of attached peers. Used by metrics +
// tests; the value can be stale by the time the caller reads it.
func (r *Room) PeerCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.peers)
}

// StateLen returns the byte length of the current state log. Tests use
// this to confirm updates landed.
func (r *Room) StateLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.state)
}

// BootstrapFrame is sent before initial sync; only one fresh-room peer may seed.
func (r *Room) BootstrapFrame(peerID string) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	granted := byte(0)
	if len(r.state) == 0 && r.bootstrapOwner == peerID {
		granted = 1
	}
	return []byte{MessageBootstrap, granted}
}

// GenerationFrame uses a decimal string so JavaScript preserves all int64 values.
// Its short ASCII string has a single-byte lib0 length prefix.
func (r *Room) GenerationFrame() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	generation := strconv.FormatInt(r.generation, 10)
	return append([]byte{MessageGeneration, byte(len(generation))}, generation...)
}
