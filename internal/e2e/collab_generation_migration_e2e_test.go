// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
//go:build e2e

package e2e

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/google/uuid"
)

func TestCollabGenerationTracksCanonicalCommitE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	conn := stdlibConn(t, pool)
	defer conn.Close()
	must(t, mdb.RunMigrationsUpToContext(ctx, conn, 67), "migrate to67")
	var org, doc, user uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO orgs(name,plan) VALUES('generation fixture','pro') RETURNING id`).Scan(&org), "create org")
	must(t, pool.QueryRow(ctx, `INSERT INTO users(org_id,email,name) VALUES($1,'generation@example.test','fixture') RETURNING id`, org).Scan(&user), "create sender")
	must(t, pool.QueryRow(ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind,blocks_json,variables_json) VALUES($1,$2,'fixture','blocks','{"version":1,"blocks":[]}','{}') RETURNING id`, org, user).Scan(&doc), "create existing document")
	must(t, mdb.RunMigrationsUpToContext(ctx, conn, 68), "apply generation migration")
	generation := func() int64 {
		var value int64
		must(t, pool.QueryRow(ctx, `SELECT generation FROM collab_document_generations WHERE document_id=$1`, doc).Scan(&value), "read generation")
		return value
	}
	if generation() != 1 {
		t.Fatal("existing document not backfilled")
	}
	_, err := pool.Exec(ctx, `UPDATE documents SET name='renamed',blocks_json=blocks_json WHERE id=$1`, doc)
	must(t, err, "no structural change")
	if generation() != 1 {
		t.Fatal("unchanged tree advanced generation")
	}
	tx, err := pool.Begin(ctx)
	must(t, err, "begin rollback fixture")
	_, err = tx.Exec(ctx, `UPDATE documents SET blocks_json='{"version":1,"blocks":[{"id":"rolled-back"}]}' WHERE id=$1`, doc)
	must(t, err, "uncommitted canonical update")
	must(t, tx.Rollback(ctx), "rollback canonical update")
	if generation() != 1 {
		t.Fatal("rolled back update advanced generation")
	}
	_, err = pool.Exec(ctx, `UPDATE documents SET blocks_json='{"version":1,"blocks":[{"id":"committed"}]}' WHERE id=$1`, doc)
	must(t, err, "commit canonical change")
	if generation() != 2 {
		t.Fatal("canonical change did not advance generation")
	}
	var wg sync.WaitGroup
	updates := make(chan error, 2)
	for _, raw := range []string{`{"version":1,"blocks":[{"id":"concurrent-a"}]}`, `{"version":1,"blocks":[{"id":"concurrent-b"}]}`} {
		wg.Add(1)
		go func(raw string) {
			defer wg.Done()
			_, err := pool.Exec(ctx, `UPDATE documents SET blocks_json=$2::jsonb WHERE id=$1`, doc, raw)
			updates <- err
		}(raw)
	}
	wg.Wait()
	close(updates)
	for err := range updates {
		must(t, err, "concurrent canonical update")
	}
	if generation() != 4 {
		t.Fatal("concurrent generation increment lost")
	}
	err = mdb.RunMigrationsDownToContext(ctx, conn, 67)
	if err == nil || !strings.Contains(err.Error(), "preserve advanced collaboration generations") {
		t.Fatalf("rollback guard=%v", err)
	}
	if generation() != 4 {
		t.Fatal("rollback refusal changed generation")
	}
	var inserted uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind,blocks_json,variables_json) VALUES($1,$2,'new fixture','blocks','{"version":1,"blocks":[]}','{}') RETURNING id`, org, user).Scan(&inserted), "new document")
	var value int64
	must(t, pool.QueryRow(ctx, `SELECT generation FROM collab_document_generations WHERE document_id=$1`, inserted).Scan(&value), "new generation")
	if value != 1 {
		t.Fatal("new document missing initial generation")
	}
}
