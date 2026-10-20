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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func documentClockDown254(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../db/migrations/00111_document_finalization_update_clock.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(raw), "-- +goose Down", 2)
	if len(parts) != 2 {
		t.Fatal("forward document clock migration lacks an explicit Down")
	}
	return parts[1]
}

func documentClockLegacyBody254(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../db/migrations/00067_document_update_clock.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(raw), "AS $$", 2)
	if len(parts) != 2 {
		t.Fatal("original M67 body unavailable")
	}
	body := strings.SplitN(parts[1], "$$ LANGUAGE plpgsql;", 2)
	if len(body) != 2 {
		t.Fatal("original M67 function delimiter unavailable")
	}
	return body[0]
}

// Exercise the ACTUAL migrated function with a scoped temporary trigger. These
// rows deliberately isolate clock policy from readiness/authentication guards;
// they are not application documents, captured legal responses or native proof.
// No existing application trigger is disabled, replaced or bypassed here.
func TestDocumentFinalizationUpdateClockPolicyV1E2E(t *testing.T) {
	isolateHTMLTemplateDatabaseE2E(t)
	ctx, pool, _, _, _, _ := setupDSRE2E(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	var beforeBody string
	if err = tx.QueryRow(ctx, "SELECT prosrc FROM pg_proc WHERE oid='public.hash_advance_document_update_clock()'::regprocedure").Scan(&beforeBody); err != nil || !strings.Contains(beforeBody, "NEW.completion_effective_at") {
		t.Fatal("actual forward clock function was not migrated", err)
	}
	if _, err = tx.Exec(ctx, `CREATE TEMP TABLE document_clock_policy254 (
 id INTEGER PRIMARY KEY,status TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL,
 completion_effective_at_bound BOOLEAN,completion_effective_at TIMESTAMPTZ,pin TEXT);
 CREATE TRIGGER document_clock_policy254 BEFORE UPDATE ON document_clock_policy254
 FOR EACH ROW EXECUTE FUNCTION public.hash_advance_document_update_clock()`); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- transaction-local clock-policy table only; actual migrated function
	var old, legal time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day'").Scan(&old, &legal); err != nil {
		t.Fatal(err)
	}
	legal = legal.UTC().Truncate(time.Microsecond)
	old = old.UTC().Truncate(time.Microsecond)
	finite := pgtype.Timestamptz{Time: legal, Valid: true}
	for index, tc := range []struct {
		name, prior, next  string
		oldBound, newBound bool
		oldLegal, newLegal pgtype.Timestamptz
		wantLegal          bool
	}{
		{name: "ordinary caller future clock ignored", prior: "draft", next: "draft", oldBound: true, newBound: true},
		{name: "root first freeze reaches bound legal clock", prior: "in_progress", next: "finalizing", oldBound: true, newBound: true, newLegal: finite, wantLegal: true},
		{name: "sent child first freeze reaches same legal clock", prior: "sent", next: "finalizing", oldBound: true, newBound: true, newLegal: finite, wantLegal: true},
		{name: "unbound clock supplies no advance", prior: "in_progress", next: "finalizing", newLegal: finite},
		{name: "new flag cannot replace prior binding", prior: "sent", next: "finalizing", newBound: true, newLegal: finite},
		{name: "missing legal time supplies no advance", prior: "in_progress", next: "finalizing", oldBound: true, newBound: true},
		{name: "positive infinity supplies no advance", prior: "in_progress", next: "finalizing", oldBound: true, newBound: true, newLegal: pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.Infinity}},
		{name: "negative infinity supplies no advance", prior: "sent", next: "finalizing", oldBound: true, newBound: true, newLegal: pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.NegativeInfinity}},
		{name: "draft is not an active first freeze", prior: "draft", next: "finalizing", oldBound: true, newBound: true, newLegal: finite},
		{name: "completed historical row supplies no new freeze", prior: "completed", next: "finalizing", oldBound: true, newBound: true, oldLegal: finite, newLegal: finite},
		{name: "existing commitment is not a first freeze", prior: "in_progress", next: "finalizing", oldBound: true, newBound: true, oldLegal: finite, newLegal: finite},
		{name: "later finalizing update ignores a new legal value", prior: "finalizing", next: "finalizing", oldBound: true, newBound: true, oldLegal: finite, newLegal: finite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tx.Exec(ctx, "INSERT INTO document_clock_policy254(id,status,updated_at,completion_effective_at_bound,completion_effective_at) VALUES($1,$2,$3,$4,$5)", index, tc.prior, old, tc.oldBound, tc.oldLegal); err != nil {
				t.Fatal(err)
			}
			var advanced time.Time
			if err := tx.QueryRow(ctx, `UPDATE document_clock_policy254 SET status=$2,
 updated_at=$3,completion_effective_at_bound=$4,completion_effective_at=$5
 WHERE id=$1 RETURNING updated_at`, index, tc.next, legal.AddDate(1, 0, 0), tc.newBound, tc.newLegal).Scan(&advanced); err != nil {
				t.Fatal(err)
			}
			if !advanced.After(old) || (tc.wantLegal && !advanced.Equal(legal)) || (!tc.wantLegal && !advanced.Before(legal)) {
				t.Fatal("actual migrated clock policy trusted the wrong clock or lost the legal freeze", advanced, tc.wantLegal)
			}
		})
	}
	// An old row clock ahead of wall time must remain strictly monotonic during
	// later pin updates. A requested future updated_at still has no authority.
	if _, err = tx.Exec(ctx, "INSERT INTO document_clock_policy254(id,status,updated_at,completion_effective_at_bound,completion_effective_at) VALUES(100,'finalizing',$1,true,$1)", legal); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 2; index++ {
		var advanced time.Time
		if err = tx.QueryRow(ctx, "UPDATE document_clock_policy254 SET pin=$1,updated_at=$2 WHERE id=100 RETURNING updated_at", strings.Repeat("p", index), legal.AddDate(1, 0, 0)).Scan(&advanced); err != nil || !advanced.Equal(legal.Add(time.Duration(index)*time.Microsecond)) {
			t.Fatal("later pin update lost original monotonicity or trusted the requested clock", err)
		}
	}
	// Empty real documents permit the actual Down in this disposable transaction.
	// Its exact legacy body is checked, then ROLLBACK preserves forward policy.
	if _, err = tx.Exec(ctx, documentClockDown254(t)); err != nil {
		t.Fatal("empty scoped real estate refused clock-policy rollback", err)
	}
	var legacyBody string
	if err = tx.QueryRow(ctx, "SELECT prosrc FROM pg_proc WHERE oid='public.hash_advance_document_update_clock()'::regprocedure").Scan(&legacyBody); err != nil || legacyBody != documentClockLegacyBody254(t) {
		t.Fatal("Down did not restore the exact original M67 body", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var afterBody string
	if err = pool.QueryRow(ctx, "SELECT prosrc FROM pg_proc WHERE oid='public.hash_advance_document_update_clock()'::regprocedure").Scan(&afterBody); err != nil || afterBody != beforeBody {
		t.Fatal("scoped rollback-policy check changed the actual forward function", err)
	}
}

// A normal genuine owned source/review/Send supplies the active application row.
// Neither Down case changes its status, fabricates completion or touches history.
func TestDocumentFinalizationUpdateClockDownRefusalV1E2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	doc, _ := q.createSentV1(t)
	q.reconcileV1(t)
	var before string
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT pg_get_functiondef('public.hash_advance_document_update_clock()'::regprocedure)").Scan(&before); err != nil {
		t.Fatal(err)
	}
	checkRefusal := func(want string) {
		t.Helper()
		tx, err := q.f.pool.Begin(q.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, downErr := tx.Exec(q.f.ctx, documentClockDown254(t))
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		rollbackErr := tx.Rollback(cleanup)
		stop()
		var pgErr *pgconn.PgError
		if !errors.As(downErr, &pgErr) || pgErr.Code != want || rollbackErr != nil {
			t.Fatal("actual clock Down did not refuse the protected estate", want, downErr, rollbackErr)
		}
	}
	holder, err := q.f.pool.Begin(q.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = holder.Rollback(cleanup)
	}()
	if _, err = q.f.q.WithTx(holder).GetDocumentForUpdate(q.f.ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: q.f.org}); err != nil {
		t.Fatal(err)
	}
	checkRefusal("55P03") // Actual NOWAIT DDL lock conflict, never a sleep/timing oracle.
	if err = holder.Rollback(q.f.ctx); err != nil {
		t.Fatal(err)
	}
	checkRefusal("23514") // Actual active sent ceremony needs reviewed disposition.
	var after string
	if err = q.f.pool.QueryRow(q.f.ctx, "SELECT pg_get_functiondef('public.hash_advance_document_update_clock()'::regprocedure)").Scan(&after); err != nil || after != before {
		t.Fatal("refused clock rollback changed the installed forward policy", err)
	}
	current, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: q.f.org})
	if err != nil || current.Status != "sent" || current.UpdatedAt != doc.UpdatedAt || current.CompletionEffectiveAt.Valid || current.CompletedAt.Valid {
		t.Fatal("refused clock rollback mutated the genuine active ceremony", err)
	}
}
