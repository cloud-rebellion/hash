// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package collab

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func yjsReplayVectors() [][]byte {
	// Real Yjs v1 incremental updates: client 123 inserts "first", then
	// " second" in the text named "test". Includes lib0 array lengths.
	return [][]byte{
		{18, 1, 1, 123, 0, 4, 1, 4, 116, 101, 115, 116, 5, 102, 105, 114, 115, 116, 0},
		{16, 1, 1, 123, 5, 132, 123, 4, 7, 32, 115, 101, 99, 111, 110, 100, 0},
	}
}

func TestSyncFramesYjsReplayVectors(t *testing.T) {
	updates := yjsReplayVectors()
	state := append(append([]byte(nil), updates[0]...), updates[1]...)
	frames, err := SyncFrames(state)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]byte{append([]byte{MessageSync, SyncUpdate}, updates[0]...), append([]byte{MessageSync, SyncStep2}, updates[1]...)}
	if !reflect.DeepEqual(frames, want) {
		t.Fatalf("replay skipped or combined updates: %v", frames)
	}
	// Logged wire vectors allow independent validation with y-protocols.
	ints := make([][]int, len(frames))
	for i, frame := range frames {
		for _, b := range frame {
			ints[i] = append(ints[i], int(b))
		}
	}
	raw, _ := json.Marshal(ints)
	t.Logf("YJS_REPLAY_FRAMES=%s", raw)
}

func TestRoomSyncStep1ReplaysEveryUpdate(t *testing.T) {
	updates := yjsReplayVectors()
	peer := newFakePeer("reconnect")
	room := &Room{documentID: uuid.New(), peers: map[string]Peer{peer.ID(): peer}, state: append(append([]byte(nil), updates[0]...), updates[1]...)}
	if err := room.HandleFrame(context.Background(), peer, []byte{MessageSync, SyncStep1, 1, 0}); err != nil {
		t.Fatal(err)
	}
	frames := peer.Received()
	if len(frames) != 2 || frames[0][1] != SyncUpdate || frames[1][1] != SyncStep2 {
		t.Fatalf("sync completed before all edits replayed: %v", frames)
	}
}

func TestInvalidUpdateFramingRejectedBeforeMutation(t *testing.T) {
	peer := newFakePeer("invalid")
	for _, update := range [][]byte{{}, {0}, {2, 1}, {1, 1, 1}, {128}, {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}} {
		room := &Room{peers: map[string]Peer{peer.ID(): peer}, flushCh: make(chan struct{}, 1)}
		if err := room.HandleFrame(context.Background(), peer, append([]byte{MessageSync, SyncUpdate}, update...)); err == nil {
			t.Fatalf("malformed update accepted: %v", update)
		}
		if room.StateLen() != 0 {
			t.Fatal("invalid frame mutated state")
		}
	}
	if _, err := SyncFrames([]byte{1, 1, 2, 1}); err == nil {
		t.Fatal("truncated persisted log replayed")
	}
}

func TestEmptyRoomCompletesSynchronization(t *testing.T) {
	frames, err := SyncFrames(nil)
	if err != nil || !reflect.DeepEqual(frames, [][]byte{{MessageSync, SyncStep2, 2, 0, 0}}) {
		t.Fatalf("empty sync: %v %v", frames, err)
	}
}

func TestReplayResourceLimits(t *testing.T) {
	for _, state := range [][]byte{make([]byte, MaxReplayBytes+1), bytes.Repeat([]byte{1, 0}, MaxReplayUpdates+1)} {
		frames, err := SyncFrames(state)
		if err == nil || frames != nil {
			t.Fatal("oversized replay allocated frames")
		}
	}
	if err := validateReplay(bytes.Repeat([]byte{1, 0}, MaxReplayUpdates)); err != nil {
		t.Fatalf("boundary rejected: %v", err)
	}
}

func TestActiveHistoryRejectsBeforeMutationAndBroadcast(t *testing.T) {
	for _, kind := range []string{"bytes", "updates"} {
		t.Run(kind, func(t *testing.T) {
			peer := newFakePeer("other")
			room := &Room{documentID: uuid.New(), peers: map[string]Peer{"other": peer}}
			if kind == "bytes" {
				room.state = make([]byte, MaxReplayBytes)
			} else {
				room.replayUpdates = MaxReplayUpdates
			}
			before := len(room.state)
			sender := newFakePeer("sender")
			room.peers[sender.ID()] = sender
			err := room.HandleFrame(context.Background(), sender, []byte{MessageSync, SyncUpdate, 1, 1})
			if err == nil {
				t.Fatal("over-limit update accepted")
			}
			if len(room.state) != before || room.pending != 0 || room.dirty || len(peer.Received()) != 0 {
				t.Fatal("rejected update mutated or broadcast")
			}
		})
	}
}

func TestCompactionRealYjsConcurrentUpdateReplay(t *testing.T) {
	updates := yjsReplayVectors()
	peer := newFakePeer("writer")
	room := &Room{hub: &Hub{CompactionThreshold: 1}, peers: map[string]Peer{peer.ID(): peer}, flushCh: make(chan struct{}, 1)}
	_, nonce, requested, err := room.applyAppend(updates[0], peer.ID())
	if err != nil || !requested {
		t.Fatalf("request: %v %v", requested, err)
	}
	if _, _, _, err := room.applyAppend(updates[1], peer.ID()); err != nil {
		t.Fatal(err)
	}
	// A valid full snapshot taken before the second insertion is identical
	// to the first update for this single-client Yjs document.
	room.applySnapshot(nonce, updates[0], peer.ID())
	frames, err := SyncFrames(room.state)
	if err != nil {
		t.Fatal(err)
	}
	ints := make([][]int, len(frames))
	for i, frame := range frames {
		for _, b := range frame {
			ints[i] = append(ints[i], int(b))
		}
	}
	raw, err := json.Marshal(ints)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("YJS_COMPACTION_FRAMES=%s", raw)
	if len(frames) != 2 {
		t.Fatal("concurrent update missing from replay")
	}
}
