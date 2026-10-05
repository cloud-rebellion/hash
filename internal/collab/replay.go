// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package collab

import (
	"encoding/binary"
	"errors"
)

// encodedUpdateLength parses lib0's varUint8Array framing without interpreting
// the Yjs payload. A stored log is a sequence of these arrays, not one update.
func encodedUpdateLength(raw []byte) (int, error) {
	size, prefix := binary.Uvarint(raw)
	if prefix <= 0 || size == 0 || size > uint64(len(raw)-prefix) {
		return 0, errors.New("collab: invalid length-prefixed update")
	}
	return prefix + int(size), nil
}

func validateSingleUpdate(raw []byte) error {
	n, err := encodedUpdateLength(raw)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return errors.New("collab: trailing update data")
	}
	return nil
}

// MaxReplayBytes and MaxReplayUpdates bound reconnect allocations. Existing
// histories above these limits require operator recovery/compaction.
const MaxReplayBytes = 8 << 20
const MaxReplayUpdates = 65536

func validateReplay(state []byte) error {
	if len(state) > MaxReplayBytes {
		return errors.New("collab: replay exceeds byte limit")
	}
	count := 0
	for len(state) > 0 {
		count++
		if count > MaxReplayUpdates {
			return errors.New("collab: replay exceeds update limit")
		}
		n, err := encodedUpdateLength(state)
		if err != nil {
			return err
		}
		state = state[n:]
	}
	return nil
}

// SyncFrames replays each persisted update separately. Only the final frame is
// sync_step2 so clients mark synchronization complete after applying the log.
// Existing stored logs and compaction snapshots retain their wire format.
func SyncFrames(state []byte) ([][]byte, error) {
	if err := validateReplay(state); err != nil {
		return nil, err
	}
	if len(state) == 0 {
		// Y.encodeStateAsUpdate(new Y.Doc()) is the two-byte empty update.
		return [][]byte{{MessageSync, SyncStep2, 2, 0, 0}}, nil
	}
	var frames [][]byte
	for len(state) > 0 {
		n, err := encodedUpdateLength(state)
		if err != nil {
			return nil, err
		}
		frame := append([]byte{MessageSync, SyncUpdate}, state[:n]...)
		frames = append(frames, frame)
		state = state[n:]
	}
	frames[len(frames)-1][1] = SyncStep2
	return frames, nil
}
