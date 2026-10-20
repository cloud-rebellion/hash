//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
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

func TestCanonicalCollabRecoveryPreservesUnknownAndActiveHistoryE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	conn := stdlibConn(t, pool)
	defer conn.Close()
	must(t, mdb.RunMigrationsUpToContext(ctx, conn, 71), "migrate to71")
	var org, user, doc uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO orgs(name,plan) VALUES('recovery','pro') RETURNING id`).Scan(&org), "org")
	must(t, pool.QueryRow(ctx, `INSERT INTO users(org_id,email,name,role) VALUES($1,'recovery@example.test','owner','owner') RETURNING id`, org).Scan(&user), "user")
	must(t, pool.QueryRow(ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind,blocks_json,variables_json) VALUES($1,$2,'fixture','blocks','{"version":1,"blocks":[]}','{}') RETURNING id`, org, user).Scan(&doc), "doc")
	_, err := pool.Exec(ctx, `INSERT INTO collab_doc_states(document_id,ydoc_state,state_size,update_count) VALUES($1,$2,2,1)`, doc, []byte{1, 42})
	must(t, err, "legacy unknown history")
	var at pgtype.Timestamptz
	must(t, pool.QueryRow(ctx, `UPDATE documents SET blocks_json='{"version":1,"blocks":[{"id":"replacement"}]}' WHERE id=$1 RETURNING updated_at`, doc).Scan(&at), "external canonical replacement")
	q := generated.New(pool)
	params := generated.RecoverCanonicalCollabParams{DocumentID: doc, OrgID: org, Generation: 2, ExpectedUpdatedAt: at, UserID: user, Acknowledged: true, RoomState: []byte{1, 43}, RoomGeneration: pgtype.Int8{Int64: 1, Valid: true}}
	tx, err := pool.Begin(ctx)
	must(t, err, "begin")
	generation, err := q.WithTx(tx).RecoverCanonicalCollab(ctx, params)
	must(t, err, "recovery in transaction")
	if generation != 3 {
		t.Fatal("wrong prospective generation")
	}
	must(t, tx.Rollback(ctx), "rollback")
	var count int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM collab_recovery_archives WHERE document_id=$1`, doc).Scan(&count), "archive count")
	if count != 0 {
		t.Fatal("rollback retained archives")
	}
	state, err := q.GetCollabDocStateWithGeneration(ctx, doc)
	must(t, err, "rollback history")
	if state.Generation.Valid || !bytes.Equal(state.YdocState, []byte{1, 42}) {
		t.Fatal("rollback changed unknown history")
	}
	noAck := params
	noAck.Acknowledged = false
	if _, err = q.RecoverCanonicalCollab(ctx, noAck); err == nil {
		t.Fatal("unacknowledged recovery accepted")
	}
	wrongTenant := params
	wrongTenant.OrgID = uuid.New()
	generation, err = q.RecoverCanonicalCollab(ctx, wrongTenant)
	must(t, err, "wrong tenant")
	if generation != 0 {
		t.Fatal("wrong tenant recovered")
	}
	_, err = pool.Exec(ctx, `UPDATE users SET role='sender' WHERE id=$1`, user)
	must(t, err, "demote")
	generation, err = q.RecoverCanonicalCollab(ctx, params)
	must(t, err, "nonowner")
	if generation != 0 {
		t.Fatal("sender recovered owner-only history")
	}
	_, err = pool.Exec(ctx, `UPDATE users SET role='owner' WHERE id=$1`, user)
	must(t, err, "restore fixture role")
	generation, err = q.RecoverCanonicalCollab(ctx, params)
	must(t, err, "recover")
	if generation != 3 {
		t.Fatal("recovery did not fence old generation")
	}
	state, err = q.GetCollabDocStateWithGeneration(ctx, doc)
	must(t, err, "fresh associated history")
	if state.Generation.Int64 != 3 || len(state.YdocState) != 0 {
		t.Fatal("fresh canonical history not empty/current")
	}
	rows, err := pool.Query(ctx, `SELECT origin,history_generation,ydoc_state FROM collab_recovery_archives WHERE document_id=$1 ORDER BY origin`, doc)
	must(t, err, "archives")
	seen := 0
	for rows.Next() {
		var origin string
		var oldGen pgtype.Int8
		var replay []byte
		must(t, rows.Scan(&origin, &oldGen, &replay), "archive")
		if origin == "persisted" {
			if oldGen.Valid || !bytes.Equal(replay, []byte{1, 42}) {
				t.Fatal("legacy association invented or bytes lost")
			}
		} else {
			if origin != "active_room" || oldGen.Int64 != 1 || !bytes.Equal(replay, []byte{1, 43}) {
				t.Fatal("active unpersisted state lost")
			}
		}
		seen++
	}
	must(t, rows.Err(), "iterate")
	rows.Close()
	if seen != 2 {
		t.Fatal("missing recovery histories")
	}
	accepted, err := q.PersistCollabDocStateForGeneration(ctx, generated.PersistCollabDocStateForGenerationParams{DocumentID: doc, OrgID: org, Generation: 2, YdocState: []byte{1, 99}, StateSize: 2, UpdateCount: 1})
	must(t, err, "old flush")
	if accepted {
		t.Fatal("old flush revived recovered history")
	}
	if err := mdb.RunMigrationsDownContext(ctx, conn); err == nil {
		t.Fatal("rollback discarded archives")
	}
	_, err = pool.Exec(ctx, `DELETE FROM documents WHERE id=$1`, doc)
	must(t, err, "delete parent")
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM collab_recovery_archives WHERE document_id=$1`, doc).Scan(&count), "parent cascade")
	if count != 0 {
		t.Fatal("orphan recovery data survived parent deletion")
	}
}
