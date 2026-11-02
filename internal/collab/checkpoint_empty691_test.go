// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package collab

import (
	"errors"
	"testing"
)

// M69 accepts explicit empty bytea but rejects SQL NULL. A newly joined room
// has no CRDT replay bytes before its first update; its genuine checkpoint must
// preserve that distinction when the caller passes State to native persistence.
func TestInitialEmptyCheckpointIsExplicitBytesAndCommitsOnlyAfterSuccess(t *testing.T) {
	r := checkpointRoom()
	r.state = nil
	r.pending = 0
	cp, err := r.CaptureSaveCheckpoint("alice")
	if err != nil || cp.State == nil || len(cp.State) != 0 || cp.PendingUpdates != 0 {
		t.Fatal("initial empty checkpoint would be sent as SQL NULL", err)
	}
	if r.state != nil {
		t.Fatal("capturing checkpoint changed the actual room replay")
	}
	rejected := errors.New("synthetic transaction rollback")
	if err = r.CommitSaveCheckpoint("alice", cp.Token, func(got SaveCheckpoint) error {
		if got.State == nil || len(got.State) != 0 || got.Token != cp.Token || got.Generation != cp.Generation {
			t.Fatal("empty callback checkpoint changed provenance")
		}
		return rejected
	}); !errors.Is(err, rejected) {
		t.Fatal("transaction refusal was lost", err)
	}
	if r.generation != cp.Generation || r.stateRevision != cp.Revision {
		t.Fatal("failed empty save advanced the room")
	}
	if err = r.CommitSaveCheckpoint("alice", cp.Token, func(got SaveCheckpoint) error {
		if got.State == nil || len(got.State) != 0 {
			t.Fatal("commit would still dispatch NULL replay state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r.generation != cp.Generation+1 || r.stateRevision != cp.Revision+1 {
		t.Fatal("successful empty save did not acknowledge one generation")
	}
	if err = r.CommitSaveCheckpoint("alice", cp.Token, func(SaveCheckpoint) error {
		t.Fatal("old empty checkpoint dispatched a second transaction")
		return nil
	}); !errors.Is(err, ErrSaveCheckpoint) {
		t.Fatal("empty checkpoint replay was accepted", err)
	}
}
