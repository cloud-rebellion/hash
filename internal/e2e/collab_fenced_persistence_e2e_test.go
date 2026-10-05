// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/collab"
	"os"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCollabPersistenceRechecksGenerationAfterDocumentLockE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	conn := stdlibConn(t, pool)
	defer conn.Close()
	must(t, mdb.RunMigrationsUpTo(conn, 69), "migrate to69")
	var org, user, doc uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO orgs(name,plan) VALUES('fenced fixture','pro') RETURNING id`).Scan(&org), "org")
	must(t, pool.QueryRow(ctx, `INSERT INTO users(org_id,email,name) VALUES($1,'fenced@example.test','fixture') RETURNING id`, org).Scan(&user), "user")
	must(t, pool.QueryRow(ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind,blocks_json,variables_json) VALUES($1,$2,'fixture','blocks','{"version":1,"blocks":[]}','{}') RETURNING id`, org, user).Scan(&doc), "document")
	const query = `SELECT hash_persist_collab_generation($1,$2,$3,$4,$5,1,$6)`
	queries := generated.New(pool)
	persist := func(generation int64, state string) bool {
		accepted, err := queries.PersistCollabDocStateForGeneration(ctx, generated.PersistCollabDocStateForGenerationParams{
			DocumentID: doc, OrgID: org, Generation: generation, YdocState: []byte(state), StateSize: int32(len(state)), UpdateCount: 1, LastUserID: pgtype.UUID{Bytes: user, Valid: true},
		})
		must(t, err, "generated persistence query")
		return accepted
	}
	if !persist(1, "old state") {
		t.Fatal("current generation refused")
	}
	tx, err := pool.Begin(ctx)
	must(t, err, "begin replacement")
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `UPDATE documents SET blocks_json='{"version":1,"blocks":[{"id":"replacement"}]}' WHERE id=$1`, doc)
	must(t, err, "replacement")
	done := make(chan struct {
		accepted bool
		err      error
	}, 1)
	go func() {
		var accepted bool
		err := pool.QueryRow(ctx, query, doc, org, int64(1), []byte("stale flush"), 11, user).Scan(&accepted)
		done <- struct {
			accepted bool
			err      error
		}{accepted, err}
	}()
	// Observe an actual PostgreSQL lock wait before committing the replacement.
	deadline := time.Now().Add(3 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		must(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT hash_persist_collab_generation%')`).Scan(&blocked), "observe blocked flush")
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("flush never reached document lock wait")
	}
	must(t, tx.Commit(ctx), "commit replacement")
	select {
	case result := <-done:
		must(t, result.err, "waiting flush result")
		if result.accepted {
			t.Fatal("old generation accepted after lock wait")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("flush remained blocked")
	}
	assertState := func(want string, wantGeneration int64) {
		var state []byte
		var generation int64
		must(t, pool.QueryRow(ctx, `SELECT s.ydoc_state,g.generation FROM collab_doc_states s JOIN collab_state_generations g USING(document_id) WHERE s.document_id=$1`, doc).Scan(&state, &generation), "read state association")
		if string(state) != want || generation != wantGeneration {
			t.Fatalf("state=%q generation=%d", state, generation)
		}
	}
	assertState("old state", 1)
	if !persist(2, "new state") {
		t.Fatal("new generation refused")
	}
	if persist(1, "obsolete") {
		t.Fatal("stale generation replaced newer state")
	}
	assertState("new state", 2)
	associated, err := queries.GetCollabDocStateWithGeneration(ctx, doc)
	must(t, err, "generated state lookup")
	if !associated.Generation.Valid || associated.Generation.Int64 != 2 {
		t.Fatal("generated lookup lost generation association")
	}
	current, err := queries.GetDocumentCollabGeneration(ctx, generated.GetDocumentCollabGenerationParams{ID: doc, OrgID: org})
	must(t, err, "generated document generation lookup")
	if current != 2 {
		t.Fatal("wrong canonical generation")
	}
	var accepted bool
	must(t, pool.QueryRow(ctx, query, doc, uuid.New(), int64(2), []byte("wrong tenant"), 12, user).Scan(&accepted), "tenant refusal")
	if accepted {
		t.Fatal("wrong tenant accepted")
	}
	assertState("new state", 2)
}

type generationAdapterPeer struct{ user uuid.UUID }

func (p generationAdapterPeer) ID() string                         { return "generation-adapter-peer" }
func (p generationAdapterPeer) UserID() uuid.UUID                  { return p.user }
func (p generationAdapterPeer) DisplayName() string                { return "fixture" }
func (p generationAdapterPeer) Send(context.Context, []byte) error { return nil }

func TestCollabRuntimeAdapterUsesGenerationFenceE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	conn := stdlibConn(t, pool)
	defer conn.Close()
	must(t, mdb.RunMigrationsUpTo(conn, 69), "migrate adapter fixture")
	var org, user, doc uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO orgs(name,plan) VALUES('adapter fixture','pro') RETURNING id`).Scan(&org), "org")
	must(t, pool.QueryRow(ctx, `INSERT INTO users(org_id,email,name) VALUES($1,'adapter@example.test','fixture') RETURNING id`, org).Scan(&user), "user")
	must(t, pool.QueryRow(ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind,blocks_json,variables_json) VALUES($1,$2,'fixture','blocks','{"version":1,"blocks":[]}','{}') RETURNING id`, org, user).Scan(&doc), "document")
	q := generated.New(pool)
	hub := collab.NewHub(q)
	hub.FlushEvery = 0
	peer := generationAdapterPeer{user}
	joined, err := hub.Join(ctx, doc, org, peer)
	must(t, err, "fresh room")
	must(t, joined.Room.HandleFrame(ctx, peer, []byte{0, 2, 1, 42}), "opaque framed update")
	hub.Leave(ctx, doc, peer.ID())
	state, err := q.GetCollabDocStateWithGeneration(ctx, doc)
	must(t, err, "first state")
	if !state.Generation.Valid || state.Generation.Int64 != 1 || !bytes.Equal(state.YdocState, []byte{1, 42}) {
		t.Fatal("runtime did not associate persisted state")
	}
	joined, err = hub.Join(ctx, doc, org, peer)
	must(t, err, "matching reconnect")
	must(t, joined.Room.HandleFrame(ctx, peer, []byte{0, 2, 1, 43}), "pending second update")
	_, err = pool.Exec(ctx, `UPDATE documents SET blocks_json='{"version":1,"blocks":[{"id":"replacement"}]}' WHERE id=$1`, doc)
	must(t, err, "canonical replacement")
	hub.Leave(ctx, doc, peer.ID())
	state, err = q.GetCollabDocStateWithGeneration(ctx, doc)
	must(t, err, "preserved state")
	if state.Generation.Int64 != 1 || !bytes.Equal(state.YdocState, []byte{1, 42}) {
		t.Fatal("stale room overwrote persisted state")
	}
	if _, err = hub.Join(ctx, doc, org, peer); !errors.Is(err, collab.ErrGeneration) {
		t.Fatalf("stale room rejoined: %v", err)
	}
	if err = hub.Shutdown(ctx); !errors.Is(err, collab.ErrGeneration) {
		t.Fatalf("stale pending flush reported clean shutdown: %v", err)
	}
}
