//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package db_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests use an already migrated, disposable PostgreSQL owned by the
// acceptance caller. The completion cases migrate only their own legacy child;
// the caller database is never migrated/dropped. No fixture activates admission
// policy/READY. Synthetic blocks documents test direct query lock order, not a
// completed signing ceremony or immutable provider evidence. Root must retain
// the exact applied SQL tree and runtime/container provenance independently.
func recipientLockDB(t *testing.T) (context.Context, *pgxpool.Pool, *generated.Queries) {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("HASH_E2E_DB_URL is required")
	}
	if os.Getenv("HASH_E2E_RECIPIENT_LOCK_OWNED_PG") != "1" {
		t.Fatal("only an explicitly owned disposable recipient-lock PostgreSQL is permitted")
	}
	digest, versions, err := mdb.EmbeddedMigrationsIdentity()
	if err != nil || len(versions) < 88 || versions[len(versions)-1] < 88 || digest != os.Getenv("HASH_E2E_RECIPIENT_LOCK_MIGRATION_SHA256") {
		t.Fatal("the exact embedded migration tree must be bound to the owned SQL fixture")
	}
	for i, version := range versions {
		if version != int64(i+1) {
			t.Fatal("require contiguous embedded migrations")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost" && cfg.ConnConfig.Host != "::1" {
		t.Fatal("recipient-lock fixture must use the caller's loopback disposable PostgreSQL")
	}
	cfg.MaxConns = 4
	cfg.ConnConfig.RuntimeParams["application_name"] = "hash-recipient-lock-" + uuid.NewString()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var dbName string
	var applied int64
	var enabled bool
	if err := pool.QueryRow(ctx, "SELECT current_database()").Scan(&dbName); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- owned-fixture identity before any write
	if !strings.HasPrefix(dbName, "hash_recipient_lock_") {
		t.Fatal("unexpected database ownership prefix")
	}
	if err := pool.QueryRow(ctx, "SELECT max(version_id) FROM goose_db_version WHERE is_applied").Scan(&applied); err != nil || applied != versions[len(versions)-1] {
		t.Fatal("owned fixture must have exactly the bound full migration prefix")
	} //nolint:rawsql -- caller-applied schema identity
	if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='recipients'::regclass AND tgname='pdf_admission_invalidate_parties' AND tgenabled='O')").Scan(&enabled); err != nil || !enabled {
		t.Fatal("real migration88 recipient-parent trigger must remain enabled")
	} //nolint:rawsql -- no trigger-disable shortcut
	return ctx, pool, generated.New(pool)
}

type recipientLockFixture struct {
	org, doc, recipient uuid.UUID
	initial             *generated.Recipient
}

func seedRecipientLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q *generated.Queries, status string) recipientLockFixture {
	t.Helper()
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Synthetic recipient lock " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Name: "Synthetic lock owner", Email: uuid.NewString() + "@recipient-lock.test", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, SenderID: owner.ID, Name: "Synthetic lock document", BlocksJson: []byte("[]"), VariablesJson: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Name: "Synthetic party", Email: uuid.NewString() + "@recipient-lock.test", Locale: "en", MagicTokenHash: bytes.Repeat([]byte{1}, 32), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(24 * time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		if _, err := pool.Exec(ctx, "UPDATE recipients SET status=$2, signed_at=CASE WHEN $2 IN ('signed','accepted') THEN clock_timestamp() ELSE NULL END WHERE id=$1", recipient.ID, status); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- synthetic eligibility input only
	}

	recipient, err = q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	return recipientLockFixture{org: org.ID, doc: doc.ID, recipient: recipient.ID, initial: recipient}
}

func TestRecipientUpdatesAcquireParentBeforeChildE2E(t *testing.T) {
	ctx, pool, q := recipientLockDB(t)
	future := pgtype.Timestamptz{Time: time.Now().UTC().Add(2 * time.Hour).Truncate(time.Microsecond), Valid: true}
	replacement := bytes.Repeat([]byte{2}, 32)
	type queryCase struct {
		name, status string
		completed    bool
		update       func(context.Context, *generated.Queries, recipientLockFixture) error
		check        func(*generated.Recipient) bool
	}
	cases := []queryCase{
		{name: "RotateRecipientMagicToken", status: "pending", update: func(ctx context.Context, q *generated.Queries, f recipientLockFixture) error {
			return q.RotateRecipientMagicToken(ctx, generated.RotateRecipientMagicTokenParams{ID: f.recipient, DocumentID: f.doc, MagicTokenHash: replacement, MagicTokenExpiresAt: future})
		}, check: func(r *generated.Recipient) bool {
			return bytes.Equal(r.MagicTokenHash, replacement) && r.MagicTokenExpiresAt.Time.Equal(future.Time)
		}},
		{name: "SetRecipientStatus", status: "pending", update: func(ctx context.Context, q *generated.Queries, f recipientLockFixture) error {
			return q.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{ID: f.recipient, DocumentID: f.doc, Status: "viewed"})
		}, check: func(r *generated.Recipient) bool { return r.Status == "viewed" && r.FirstViewedAt.Valid }},
		{name: "MarkRecipientSent", status: "pending", update: func(ctx context.Context, q *generated.Queries, f recipientLockFixture) error {
			n, err := q.MarkRecipientSent(ctx, generated.MarkRecipientSentParams{ID: f.recipient, DocumentID: f.doc})
			if err == nil && n != 1 {
				return fmt.Errorf("affected=%d, want1", n)
			}
			return err
		}, check: func(r *generated.Recipient) bool { return r.Status == "sent" && r.SentAt.Valid }},
		{name: "InvalidateRecipientTokens", status: "pending", update: func(ctx context.Context, q *generated.Queries, f recipientLockFixture) error {
			return q.InvalidateRecipientTokens(ctx, f.doc)
		}, check: func(r *generated.Recipient) bool {
			return r.MagicTokenExpiresAt.Valid && !r.MagicTokenExpiresAt.Time.After(time.Now())
		}},
		{name: "SetCompletedArtifactTokenExpiry", status: "signed", completed: true, update: func(ctx context.Context, q *generated.Queries, f recipientLockFixture) error {
			return q.SetCompletedArtifactTokenExpiry(ctx, generated.SetCompletedArtifactTokenExpiryParams{DocumentID: f.doc, MagicTokenExpiresAt: future})
		}, check: func(r *generated.Recipient) bool {
			return r.Status == "signed" && r.SignedAt.Valid && r.MagicTokenExpiresAt.Time.Equal(future.Time)
		}},
		{name: "RotateCompletedArtifactToken", status: "signed", completed: true, update: func(ctx context.Context, q *generated.Queries, f recipientLockFixture) error {
			n, err := q.RotateCompletedArtifactToken(ctx, generated.RotateCompletedArtifactTokenParams{ID: f.recipient, DocumentID: f.doc, MagicTokenHash: replacement, MagicTokenExpiresAt: future})
			if err == nil && n != 1 {
				return fmt.Errorf("affected=%d, want1", n)
			}
			return err
		}, check: func(r *generated.Recipient) bool {
			return r.Status == "signed" && r.SignedAt.Valid && bytes.Equal(r.MagicTokenHash, replacement) && r.MagicTokenExpiresAt.Time.Equal(future.Time)
		}},
		{name: "ResetRecipientsForRevision", status: "viewed", update: func(ctx context.Context, q *generated.Queries, f recipientLockFixture) error {
			return q.ResetRecipientsForRevision(ctx, f.doc)
		}, check: func(r *generated.Recipient) bool { return r.Status == "pending" && !r.SignedAt.Valid }},
		{name: "AnonymizeRecipient", status: "pending", update: func(ctx context.Context, q *generated.Queries, f recipientLockFixture) error {
			n, err := q.AnonymizeRecipient(ctx, generated.AnonymizeRecipientParams{ID: f.recipient, OrgID: f.org, Email: "redacted@recipient-lock.test", Name: "Redacted synthetic party"})
			if err == nil && n != 1 {
				return fmt.Errorf("affected=%d, want1", n)
			}
			return err
		}, check: func(r *generated.Recipient) bool {
			return r.Email == "redacted@recipient-lock.test" && r.Name == "Redacted synthetic party"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, q := pool, q
			var f recipientLockFixture
			if tc.completed {
				pool, q, f = legacyCompletedRecipientLock(t, ctx, pool)
			} else {
				f = seedRecipientLock(t, ctx, pool, q, tc.status)
			}
			held, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			cleanupHeld := func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = held.Rollback(cleanupCtx)
			}
			defer cleanupHeld()
			if _, err := q.WithTx(held).GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: f.doc, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			var holderPID int32
			if err := held.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&holderPID); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- owned session identity
			beforeRecipient := recipientLockRowSnapshot(t, ctx, held, f.recipient)
			beforeContent := recipientLockContentSnapshot(t, ctx, held, f.doc, f.org)
			contender, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var contenderPID int32
			if err := contender.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&contenderPID); err != nil {
				_ = contender.Rollback(ctx)
				t.Fatal(err)
			} //nolint:rawsql -- owned competing session identity
			requestCtx, cancelRequest := context.WithTimeout(ctx, 8*time.Second)
			result := make(chan error, 1)
			received := false
			go func() {
				err := func() error {
					defer func() {
						cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						_ = contender.Rollback(cleanupCtx)
					}()
					if err := tc.update(requestCtx, q.WithTx(contender), f); err != nil {
						return err
					}
					return contender.Commit(requestCtx)
				}()
				result <- err
			}()
			defer func() {
				cancelRequest()
				cleanupHeld()
				if !received {
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					select {
					case <-result:
						received = true
					case <-cleanupCtx.Done():
						t.Error("owned contender did not drain after cancellation and holder release")
					}
				}
			}()
			waitCtx, cancelWait := context.WithTimeout(ctx, 3*time.Second)
			defer cancelWait()
			for {
				select {
				case err := <-result:
					received = true
					t.Fatalf("query returned before an authoritative parent wait: %v", err)
				default:
				}
				var waiting bool
				if err := held.QueryRow(waitCtx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND datname=current_database() AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)) AND position($3 in query)>0)", contenderPID, holderPID, "-- name: "+tc.name).Scan(&waiting); err != nil {
					t.Fatal("observe contender", err)
				} //nolint:rawsql -- authoritative wait on this exact query/session
				if waiting {
					break
				}
				select {
				case <-waitCtx.Done():
					t.Fatal("contender did not reach the held parent")
				case <-time.After(10 * time.Millisecond):
				}
			}
			// The key regression assertion: a child-first UPDATE has already locked this
			// row before its AFTER trigger waits on our parent, and NOWAIT fails 55P03.
			// Merely checking that a SQL string contains FOR UPDATE cannot prove this.
			var child uuid.UUID
			if err := held.QueryRow(ctx, "SELECT id FROM recipients WHERE id=$1 AND document_id=$2 FOR UPDATE NOWAIT", f.recipient, f.doc).Scan(&child); err != nil {
				t.Fatal("contender locked child before acquiring parent", err)
			} //nolint:rawsql -- real child lock-order witness
			if child != f.recipient || beforeRecipient != recipientLockRowSnapshot(t, ctx, held, f.recipient) || beforeContent != recipientLockContentSnapshot(t, ctx, held, f.doc, f.org) {
				t.Fatal("waiting direct mutation changed recipient/content/evidence")
			}
			if err := held.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				received = true
				if err != nil {
					t.Fatal("released direct update", err)
				}
			case <-requestCtx.Done():
				t.Fatal("direct update did not finish after parent release")
			}
			after, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: f.recipient, OrgID: f.org})
			if err != nil || !tc.check(after) {
				t.Fatal("query lost its legitimate update behavior", err)
			}
			allowed := map[string][]string{
				"RotateRecipientMagicToken":       {"magic_token_hash", "magic_token_expires_at"},
				"SetRecipientStatus":              {"status", "first_viewed_at"},
				"MarkRecipientSent":               {"status", "sent_at"},
				"InvalidateRecipientTokens":       {"magic_token_expires_at"},
				"SetCompletedArtifactTokenExpiry": {"magic_token_expires_at"},
				"RotateCompletedArtifactToken":    {"magic_token_hash", "magic_token_expires_at"},
				"ResetRecipientsForRevision":      {"status", "signed_at"},
				"AnonymizeRecipient":              {"email", "name"},
			}[tc.name]
			recipientLockUnchangedExcept(t, beforeRecipient, recipientLockRowSnapshot(t, ctx, pool, f.recipient), allowed)
			if beforeContent != recipientLockContentSnapshot(t, ctx, pool, f.doc, f.org) {
				t.Fatal("recipient boundary changed document content, signatures or audit evidence")
			}
		})
	}
}

func TestRecipientUpdateIdentityAndTerminalGuardsE2E(t *testing.T) {
	ctx, pool, q := recipientLockDB(t)
	t.Run("cross_tenant_anonymization", func(t *testing.T) {
		f := seedRecipientLock(t, ctx, pool, q, "pending")
		before := recipientLockRowSnapshot(t, ctx, pool, f.recipient)
		rows, err := q.AnonymizeRecipient(ctx, generated.AnonymizeRecipientParams{ID: f.recipient, OrgID: uuid.New(), Email: "not-authorized@recipient-lock.test", Name: "Not authorized"})
		if err != nil || rows != 0 || before != recipientLockRowSnapshot(t, ctx, pool, f.recipient) {
			t.Fatal("cross-tenant identity changed recipient", err)
		}
	})
	t.Run("wrong_document_rotation", func(t *testing.T) {
		f := seedRecipientLock(t, ctx, pool, q, "pending")
		before := recipientLockRowSnapshot(t, ctx, pool, f.recipient)
		if err := q.RotateRecipientMagicToken(ctx, generated.RotateRecipientMagicTokenParams{ID: f.recipient, DocumentID: uuid.New(), MagicTokenHash: bytes.Repeat([]byte{2}, 32), MagicTokenExpiresAt: f.initial.MagicTokenExpiresAt}); err != nil {
			t.Fatal(err)
		}
		if before != recipientLockRowSnapshot(t, ctx, pool, f.recipient) {
			t.Fatal("wrong document adopted recipient identity")
		}
	})
	t.Run("signed_status_cannot_reopen_or_reset", func(t *testing.T) {
		f := seedRecipientLock(t, ctx, pool, q, "signed")
		before := recipientLockRowSnapshot(t, ctx, pool, f.recipient)
		if err := q.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{ID: f.recipient, DocumentID: f.doc, Status: "viewed"}); err != nil {
			t.Fatal(err)
		}
		if err := q.ResetRecipientsForRevision(ctx, f.doc); err != nil {
			t.Fatal(err)
		}
		if before != recipientLockRowSnapshot(t, ctx, pool, f.recipient) {
			t.Fatal("terminal evidence recipient was reset")
		}
	})
	t.Run("completion_rotation_requires_completed_document", func(t *testing.T) {
		f := seedRecipientLock(t, ctx, pool, q, "signed")
		before := recipientLockRowSnapshot(t, ctx, pool, f.recipient)
		rows, err := q.RotateCompletedArtifactToken(ctx, generated.RotateCompletedArtifactTokenParams{ID: f.recipient, DocumentID: f.doc, MagicTokenHash: bytes.Repeat([]byte{2}, 32), MagicTokenExpiresAt: f.initial.MagicTokenExpiresAt})
		if err != nil || rows != 0 || before != recipientLockRowSnapshot(t, ctx, pool, f.recipient) {
			t.Fatal("non-completed document minted completion credential", err)
		}
	})
	t.Run("send_transition_counts_stale_row", func(t *testing.T) {
		f := seedRecipientLock(t, ctx, pool, q, "signed")
		before := recipientLockRowSnapshot(t, ctx, pool, f.recipient)
		rows, err := q.MarkRecipientSent(ctx, generated.MarkRecipientSentParams{ID: f.recipient, DocumentID: f.doc})
		if err != nil || rows != 0 || before != recipientLockRowSnapshot(t, ctx, pool, f.recipient) {
			t.Fatal("stale send transition lost its row-count boundary", err)
		}
	})
}

type recipientLockQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func recipientLockRowSnapshot(t *testing.T, ctx context.Context, q recipientLockQuerier, id uuid.UUID) string {
	t.Helper()
	var out string
	if err := q.QueryRow(ctx, "SELECT to_jsonb(r)::text FROM recipients r WHERE id=$1", id).Scan(&out); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- bounded synthetic row witness, never printed
	return out
}
func recipientLockContentSnapshot(t *testing.T, ctx context.Context, q recipientLockQuerier, doc, org uuid.UUID) string {
	t.Helper()
	var out string
	const sql = "SELECT jsonb_build_object('document',(SELECT to_jsonb(d) FROM documents d WHERE id=$1 AND org_id=$2),'fields',(SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM document_fields f WHERE document_id=$1),'signatures',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM signatures s WHERE document_id=$1),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM events e WHERE document_id=$1 AND org_id=$2))::text"
	if err := q.QueryRow(ctx, sql, doc, org).Scan(&out); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- exact synthetic document/evidence witness, never printed
	return out
}

func recipientLockUnchangedExcept(t *testing.T, before, after string, allowed []string) {
	t.Helper()
	var a, b map[string]json.RawMessage
	if err := json.Unmarshal([]byte(before), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(after), &b); err != nil {
		t.Fatal(err)
	}
	for _, key := range allowed {
		if _, ok := a[key]; !ok {
			t.Fatal("missing expected recipient field", key)
		}
		if _, ok := b[key]; !ok {
			t.Fatal("missing observed recipient field", key)
		}
		delete(a, key)
		delete(b, key)
	}
	aa, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aa, bb) {
		t.Fatal("direct update changed unrelated identity, state, credential or timestamp fields")
	}
}
