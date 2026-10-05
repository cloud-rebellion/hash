// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"os"
	"testing"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCanonicalCollabSaveAtomicGenerationE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	conn := stdlibConn(t, pool)
	defer conn.Close()
	must(t, mdb.RunMigrationsUpTo(conn, 70), "migrate to70")
	var org, user, doc uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO orgs(name,plan) VALUES('canonical save fixture','pro') RETURNING id`).Scan(&org), "org")
	must(t, pool.QueryRow(ctx, `INSERT INTO users(org_id,email,name) VALUES($1,'save@example.test','fixture') RETURNING id`, org).Scan(&user), "user")
	const original = `{"version":1,"blocks":[]}`
	must(t, pool.QueryRow(ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind,blocks_json,variables_json) VALUES($1,$2,'fixture','blocks',$3,'{}') RETURNING id`, org, user, original).Scan(&doc), "doc")
	q := generated.New(pool)
	observe := func() (pgtype.Timestamptz, int64, []byte) {
		var at pgtype.Timestamptz
		var gen int64
		var tree []byte
		must(t, pool.QueryRow(ctx, `SELECT d.updated_at,g.generation,d.blocks_json FROM documents d JOIN collab_document_generations g ON g.document_id=d.id WHERE d.id=$1`, doc).Scan(&at, &gen, &tree), "observe")
		return at, gen, tree
	}
	at, gen, _ := observe()
	params := generated.SaveCanonicalCollabParams{DocumentID: doc, OrgID: org, Generation: gen, ExpectedUpdatedAt: at, BlocksJson: []byte(original), YdocState: []byte{1, 42}, UpdateCount: 1, UserID: user}
	// A successful statement is still part of its caller's transaction.
	tx, err := pool.Begin(ctx)
	must(t, err, "begin")
	accepted, err := q.WithTx(tx).SaveCanonicalCollab(ctx, params)
	must(t, err, "save in rollback transaction")
	if !accepted {
		t.Fatal("current save refused")
	}
	must(t, tx.Rollback(ctx), "rollback")
	unchangedAt, unchangedGen, _ := observe()
	if unchangedGen != gen || !unchangedAt.Time.Equal(at.Time) {
		t.Fatal("rollback retained canonical transition")
	}
	var rows int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM collab_doc_states WHERE document_id=$1`, doc).Scan(&rows), "history count")
	if rows != 0 {
		t.Fatal("rollback retained history")
	}
	accepted, err = q.SaveCanonicalCollab(ctx, params)
	must(t, err, "equal tree save")
	if !accepted {
		t.Fatal("equal save refused")
	}
	nextAt, nextGen, _ := observe()
	if nextGen != 2 || !nextAt.Time.After(at.Time) {
		t.Fatal("equal tree did not advance generation/timestamp")
	}
	state, err := q.GetCollabDocStateWithGeneration(ctx, doc)
	must(t, err, "associated state")
	if !state.Generation.Valid || state.Generation.Int64 != 2 || !bytes.Equal(state.YdocState, params.YdocState) {
		t.Fatal("history association not atomic")
	}
	accepted, err = q.PersistCollabDocStateForGeneration(ctx, generated.PersistCollabDocStateForGenerationParams{DocumentID: doc, OrgID: org, Generation: 1, YdocState: []byte{1, 99}, StateSize: 2, UpdateCount: 1})
	must(t, err, "old flush")
	if accepted {
		t.Fatal("old flush accepted after equal save")
	}
	accepted, err = q.SaveCanonicalCollab(ctx, params)
	must(t, err, "old observation")
	if accepted {
		t.Fatal("stale canonical save accepted")
	}
	params.Generation = 2
	params.ExpectedUpdatedAt = nextAt
	params.BlocksJson = []byte(`{"version":1,"blocks":[{"id":"new"}]}`)
	params.YdocState = []byte{1, 43}
	accepted, err = q.SaveCanonicalCollab(ctx, params)
	must(t, err, "changed tree save")
	if !accepted {
		t.Fatal("changed save refused")
	}
	currentAt, currentGen, currentTree := observe()
	if currentGen != 3 {
		t.Fatalf("changed tree advanced %d rather than once", currentGen)
	}
	params.Generation = 3
	params.ExpectedUpdatedAt = currentAt
	params.YdocState = nil
	if _, err = q.SaveCanonicalCollab(ctx, params); err == nil {
		t.Fatal("null history accepted")
	}
	afterAt, afterGen, afterTree := observe()
	if afterGen != currentGen || !afterAt.Time.Equal(currentAt.Time) || !bytes.Equal(afterTree, currentTree) {
		t.Fatal("invalid history partially committed canonical content")
	}
	state, err = q.GetCollabDocStateWithGeneration(ctx, doc)
	must(t, err, "state after failure")
	if state.Generation.Int64 != 3 || !bytes.Equal(state.YdocState, []byte{1, 43}) {
		t.Fatal("failure changed associated history")
	}
	params.YdocState = []byte{1, 44}
	params.OrgID = uuid.New()
	accepted, err = q.SaveCanonicalCollab(ctx, params)
	must(t, err, "wrong tenant")
	if accepted {
		t.Fatal("wrong tenant accepted")
	}
}
