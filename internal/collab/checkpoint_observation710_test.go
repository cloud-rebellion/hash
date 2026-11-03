// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package collab

import (
	"errors"
	"testing"
)

func TestConsumedCheckpoint710PrecedesObservationAndReplayAdmission(t *testing.T) {
	r := checkpointRoom()
	cp, err := r.CaptureSaveCheckpoint("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CommitSaveCheckpoint("alice", cp.Token, func(SaveCheckpoint) error { return nil }); err != nil {
		t.Fatal(err)
	}
	staleObservation := errors.New("synthetic stale document observation")
	observed, committed := 0, 0
	admit := func(int) error {
		observed++
		return staleObservation
	}
	commit := func(SaveCheckpoint) error {
		committed++
		return nil
	}
	if err := r.CommitSaveCheckpointWithStateAdmissionV1("alice", cp.Token, admit, commit); !errors.Is(err, ErrSaveCheckpoint) || observed != 0 || committed != 0 {
		t.Fatal("consumed checkpoint reached observation/admission/commit", err)
	}
	fresh, err := r.CaptureSaveCheckpoint("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CommitSaveCheckpointWithStateAdmissionV1("alice", fresh.Token, admit, commit); !errors.Is(err, staleObservation) || observed != 1 || committed != 0 {
		t.Fatal("fresh token bypassed original observation refusal", err)
	}
	unchanged, err := r.CaptureSaveCheckpoint("alice")
	if err != nil || unchanged.Token != fresh.Token || unchanged.Generation != fresh.Generation || unchanged.Revision != fresh.Revision {
		t.Fatal("observation refusal advanced checkpoint", err)
	}
	if err := r.CommitSaveCheckpointWithStateAdmissionV1("alice", fresh.Token, func(int) error { return nil }, commit); err != nil || committed != 1 {
		t.Fatal("same fresh checkpoint could not commit after corrected observation", err)
	}
}
