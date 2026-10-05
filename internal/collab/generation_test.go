// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package collab

import (
	"context"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type generationStoreFixture struct {
	generation int64
	row        *generated.GetCollabDocStateWithGenerationRow
	loadErr    error
	accepted   bool
	params     generated.PersistCollabDocStateForGenerationParams
	writes     int
}

func (s *generationStoreFixture) GetDocumentCollabGeneration(context.Context, generated.GetDocumentCollabGenerationParams) (int64, error) {
	return s.generation, nil
}
func (s *generationStoreFixture) GetCollabDocStateWithGeneration(context.Context, uuid.UUID) (*generated.GetCollabDocStateWithGenerationRow, error) {
	return s.row, s.loadErr
}
func (s *generationStoreFixture) PersistCollabDocStateForGeneration(_ context.Context, p generated.PersistCollabDocStateForGenerationParams) (bool, error) {
	s.writes++
	s.params = p
	return s.accepted, nil
}
func (s *generationStoreFixture) GetCollabDocState(context.Context, uuid.UUID) (*generated.CollabDocState, error) {
	panic("unassociated legacy loader used")
}
func (s *generationStoreFixture) UpsertCollabDocState(context.Context, generated.UpsertCollabDocStateParams) (*generated.CollabDocState, error) {
	panic("unconditional writer used")
}

func TestGenerationAwareLoadRejectsStaleAndLegacyHistory(t *testing.T) {
	for _, tc := range []struct {
		name        string
		association pgtype.Int8
		want        error
	}{
		{"stale", pgtype.Int8{Int64: 6, Valid: true}, ErrGeneration},
		{"legacy", pgtype.Int8{}, ErrLegacyHistory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &generationStoreFixture{generation: 7, row: &generated.GetCollabDocStateWithGenerationRow{YdocState: []byte{1, 1}, Generation: tc.association}}
			h := NewHub(nil)
			h.Queries = store
			h.FlushEvery = 0
			_, err := h.Join(context.Background(), uuid.New(), uuid.New(), newFakePeer("reader"))
			if !errors.Is(err, tc.want) || len(h.rooms) != 0 {
				t.Fatalf("error=%v rooms=%d", err, len(h.rooms))
			}
		})
	}
}

func TestGenerationAwarePersistenceAndRefusalRetainDraft(t *testing.T) {
	store := &generationStoreFixture{generation: 3, loadErr: pgx.ErrNoRows, accepted: true}
	h := NewHub(nil)
	h.Queries = store
	h.FlushEvery = 0
	doc, org := uuid.New(), uuid.New()
	peer := newFakePeer("writer")
	joined, err := h.Join(context.Background(), doc, org, peer)
	if err != nil {
		t.Fatal(err)
	}
	room := joined.Room
	if err = room.CheckGeneration(3); err != nil {
		t.Fatal(err)
	}
	room.applyAppend([]byte{1, 1})
	room.maybeFlush(context.Background())
	if store.params.Generation != 3 || store.params.DocumentID != doc || store.params.OrgID != org || room.dirty {
		t.Fatal("generation-bound persistence failed")
	}
	room.applyAppend([]byte{1, 2})
	store.accepted = false
	room.maybeFlush(context.Background())
	if !room.dirty || room.pending != 1 || !room.stale {
		t.Fatal("refused flush cleared recoverable draft")
	}
	before := len(room.state)
	room.applyAppend([]byte{1, 3})
	if len(room.state) != before {
		t.Fatal("stale room accepted more edits")
	}
	if err = room.CheckGeneration(4); !errors.Is(err, ErrGeneration) {
		t.Fatalf("generation error=%v", err)
	}
}

func TestGenerationMatchedHistoryReplays(t *testing.T) {
	store := &generationStoreFixture{generation: 7, row: &generated.GetCollabDocStateWithGenerationRow{YdocState: []byte{1, 1}, Generation: pgtype.Int8{Int64: 7, Valid: true}}}
	h := NewHub(nil)
	h.Queries = store
	h.FlushEvery = 0
	joined, err := h.Join(context.Background(), uuid.New(), uuid.New(), newFakePeer("reader"))
	if err != nil {
		t.Fatal(err)
	}
	if len(joined.InitialState) != 2 || joined.Room.generation != 7 {
		t.Fatal("matching history not loaded")
	}
	if err = h.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationFramePreservesBigint(t *testing.T) {
	room := &Room{generation: 9223372036854775807}
	want := append([]byte{MessageGeneration, 19}, []byte("9223372036854775807")...)
	if got := room.GenerationFrame(); string(got) != string(want) {
		t.Fatalf("generation frame = %v, want %v", got, want)
	}
}
