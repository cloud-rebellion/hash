//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This is a PostgreSQL component regression, not an application work grant.
// The two actual transactions overlap without goroutines or timing sleeps.
func TestHTMLSnapshotRejectsForeignEventAfterCompleteHeaderE2E(t *testing.T) {
	if os.Getenv("HASH_E2E_DB_URL") == "" {
		t.Fatal("selected event-set regression requires HASH_E2E_DB_URL")
	}
	isolateHTMLTemplateDatabaseE2E(t)
	f := setupLifecycleAuthorizationE2E(t, "owner", false, false)
	ctx, cancel := context.WithTimeout(f.ctx, 12*time.Second)
	defer cancel()
	other, err := f.q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Foreign event-set component " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if _, err := f.pool.Exec(cleanup, "DELETE FROM orgs WHERE id=$1", other.ID); err != nil { //nolint:rawsql -- exact synthetic org in disposable child database
			t.Error("foreign fixture cleanup", err)
		}
	})
	rollback := func(tx pgx.Tx) {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("actual component transaction rollback", err)
		}
	}
	a, err := f.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(a)
	query := generated.New(a)
	pins := generated.GetHTMLRevisionSnapshotSizeHeaderV1Params{DocumentID: f.doc.ID, OrgID: f.org}
	before, err := query.GetHTMLRevisionSnapshotSizeHeaderV1(ctx, pins)
	if err != nil || before.EventCount != 0 || before.MeasuredEventCount != 0 || before.EventScopeMismatchCount != 0 {
		t.Fatal("actual complete empty event-set header unavailable", before, err)
	}
	connection, err := f.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	b, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(b)
	if _, err := b.Exec(ctx, "SET LOCAL lock_timeout='1500ms'; SET LOCAL statement_timeout='2500ms'"); err != nil {
		t.Fatal(err)
	}
	_, err = b.Exec(ctx, "INSERT INTO events(org_id,document_id,kind,payload_json) VALUES($1,$2,'snapshot.foreign-component',jsonb_build_object('body',repeat('X',65536)))", other.ID, f.doc.ID) //nolint:rawsql -- controlled subject alias explicitly allowed by M43; actual M94 fence must refuse while native header is retained
	if err == nil {
		if err := b.Commit(ctx); err != nil {
			t.Fatal("foreign event insert unexpectedly failed only at commit", err)
		}
		after, readErr := query.GetHTMLRevisionSnapshotSizeHeaderV1(ctx, pins)
		t.Fatalf("foreign event committed after retained complete header: before=%+v after=%+v read_error=%v", before, after, readErr)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" || strings.Contains(pgErr.Message, "lock timeout") {
		t.Fatalf("expected immediate subject-fence refusal, got %v", err)
	}
	if err := b.Rollback(ctx); err != nil || connection.Conn().PgConn().TxStatus() != 'I' {
		t.Fatal("refused writer did not finish actual rollback", err)
	}
	after, err := query.GetHTMLRevisionSnapshotSizeHeaderV1(ctx, pins)
	if err != nil || *after != *before {
		t.Fatal("refused foreign event changed retained complete header", before, after, err)
	}
	var events int
	if err := a.QueryRow(ctx, "SELECT count(*)::integer FROM events WHERE document_id=$1", f.doc.ID).Scan(&events); err != nil || events != 0 { //nolint:rawsql -- exact controlled target, independent complete-set oracle
		t.Fatal("refused writer left an event", events, err)
	}
}
