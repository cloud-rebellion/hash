package collab

import (
	"errors"
	"testing"
)

func TestCanonicalCheckpointAdmissionPreservesTokenScopeAndRollback(t *testing.T) {
	r := checkpointRoom()
	cp, err := r.CaptureSaveCheckpoint("alice")
	if err != nil {
		t.Fatal(err)
	}
	admitted, committed := 0, 0
	admit := func(n int) error {
		admitted++
		if n != len(r.state) {
			t.Fatal("replay credit was not the actual locked replay length")
		}
		return nil
	}
	commit := func(got SaveCheckpoint) error {
		committed++
		if got.State == nil || len(got.State) != len(r.state) || got.Token != cp.Token {
			t.Fatal("admitted checkpoint changed source or token")
		}
		got.State[0] = 99
		return nil
	}
	wrong := cp.Token
	wrong[0]++
	if err = r.CommitSaveCheckpointWithStateAdmissionV1("alice", wrong, admit, commit); !errors.Is(err, ErrSaveCheckpoint) || admitted != 0 || committed != 0 {
		t.Fatal("wrong token consumed replay work or dispatched commit", err)
	}
	if err = r.CommitSaveCheckpointWithStateAdmissionV1("bob", cp.Token, admit, commit); !errors.Is(err, ErrSaveCheckpoint) || admitted != 0 || committed != 0 {
		t.Fatal("other peer consumed replay work or dispatched commit", err)
	}
	denied := errors.New("synthetic admitted-work refusal")
	if err = r.CommitSaveCheckpointWithStateAdmissionV1("alice", cp.Token, func(n int) error { return denied }, commit); !errors.Is(err, denied) || committed != 0 || r.generation != cp.Generation || r.stateRevision != cp.Revision {
		t.Fatal("admission refusal advanced room or dispatched commit", err)
	}
	if err = r.CommitSaveCheckpointWithStateAdmissionV1("alice", cp.Token, admit, commit); err != nil || admitted != 1 || committed != 1 || r.generation != cp.Generation+1 || r.state[0] != 1 {
		t.Fatal("genuine admitted checkpoint failed to detach/commit exactly once", err)
	}
	if err = r.CommitSaveCheckpointWithStateAdmissionV1("alice", cp.Token, admit, commit); !errors.Is(err, ErrSaveCheckpoint) || admitted != 1 || committed != 1 {
		t.Fatal("replayed token admitted or committed twice", err)
	}
}
