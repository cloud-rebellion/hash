// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package sign

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Current comment atomicity/finalizing guarantees use genuine native HTTP
// fixtures in handler/comment_{policy,finalization}_native_v1_e2e_test.go.
// The unrelated historical MarkViewed tests and shared send helpers remain.

// Simulate the lookup-to-lock window directly: the request authenticates and
// constructs evidence from epoch one, then a resend advances sent_at before the
// mutation acquires its document lock. The authoritative locked-row check must
// reject without changing recipient state or emitting a viewed event.
func TestMarkViewedRejectsPreResendNoticeEpochE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	if err := mdb.RunMigrations(migrationDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migrationDB.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := generated.New(pool)
	engine := &Engine{Pool: pool, Queries: q, Audit: audit.New(q, pool)}

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "notice epoch " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@epoch.test", Name: "Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org.ID, Name: "notice epoch", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
		VariablesJson: json.RawMessage(`{}`), SenderID: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@recipient.epoch.test", Name: "Recipient", OrderIndex: 0,
		MagicTokenHash: []byte(uuid.NewString()), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc = completeDurableSendSignE2E(t, ctx, pool, q, doc, recipient)
	rc := &RecipientContext{
		Document: doc,
		Recipient: &generated.GetRecipientByTokenHashRow{
			ID: recipient.ID, DocumentID: doc.ID, Role: recipient.Role, Status: recipient.Status,
			Email: recipient.Email, Name: recipient.Name, DocOrgID: org.ID,
		},
	}
	evidence := ParticipantResponseEvidence{Notice: testArticle13NoticeEvidence(t, rc)}

	if _, err := q.RequestChangesOnDocument(ctx, generated.RequestChangesOnDocumentParams{ID: doc.ID, OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.ReopenDocumentToDraft(ctx, generated.ReopenDocumentToDraftParams{ID: doc.ID, OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	if err := q.ResetRecipientsForRevision(ctx, doc.ID); err != nil {
		t.Fatal(err)
	}
	doc = completeDurableSendSignE2E(t, ctx, pool, q, doc, recipient)
	if !doc.SentAt.Time.After(rc.Document.SentAt.Time) {
		t.Fatalf("revised ceremony epoch = %s, want after %s", doc.SentAt.Time, rc.Document.SentAt.Time)
	}
	if err := engine.MarkViewed(ctx, rc, evidence); !errors.Is(err, ErrInvalidNoticeEvidence) {
		t.Fatalf("MarkViewed() stale epoch error = %v, want ErrInvalidNoticeEvidence", err)
	}
	freshRecipient, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	if freshRecipient.Status != "sent" {
		t.Fatalf("stale epoch mutated recipient status to %q", freshRecipient.Status)
	}
	var viewedEvents int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'document.viewed'`, doc.ID,
	).Scan(&viewedEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if viewedEvents != 0 {
		t.Fatalf("stale epoch emitted %d viewed events", viewedEvents)
	}
}

func seedCompleteFrozenBrandingSignE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, documentID uuid.UUID) {
	t.Helper()
	_, err := pool.Exec(ctx, `INSERT INTO document_branding_override (
		document_id, primary_hex, accent_hex, surface_hex, text_hex, muted_hex,
		logo_url, logo_alt, font_heading, font_body, signature_color
	) VALUES ($1, '#0F172A', '#3B82F6', '#FFFFFF', '#0F172A', '#64748B',
	          '', '', 'Inter', 'Inter', '#0F172A')
	ON CONFLICT (document_id) DO UPDATE SET
		primary_hex=EXCLUDED.primary_hex, accent_hex=EXCLUDED.accent_hex,
		surface_hex=EXCLUDED.surface_hex, text_hex=EXCLUDED.text_hex,
		muted_hex=EXCLUDED.muted_hex, logo_url=EXCLUDED.logo_url,
		logo_alt=EXCLUDED.logo_alt, font_heading=EXCLUDED.font_heading,
		font_body=EXCLUDED.font_body, signature_color=EXCLUDED.signature_color`, documentID) //nolint:rawsql
	if err != nil {
		t.Fatalf("seed complete canonical frozen branding: %v", err)
	}
}

func completeDurableSendSignE2E(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	q *generated.Queries,
	doc *generated.Document,
	recipient *generated.Recipient,
) *generated.Document {
	t.Helper()
	seedCompleteFrozenBrandingSignE2E(t, ctx, pool, doc.ID)

	sealingTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sealingTx.Rollback(ctx) }()
	sealingQ := q.WithTx(sealingTx)
	if _, err := sealingQ.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
		ActorUserID: pgtype.UUID{Bytes: doc.SenderID, Valid: true},
		ActorEmail:  "sender@comment.test", ActorIp: "127.0.0.1", Via: "e2e", Tool: "sign-comment-fixture",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sealingQ.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID}); err != nil {
		t.Fatal(err)
	}
	if err := sealingTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if rows, err := q.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	}); err != nil || rows != 1 {
		t.Fatalf("mark sign fixture send retention started: rows=%d err=%v", rows, err)
	}
	if rows, err := q.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	}); err != nil || rows != 1 {
		t.Fatalf("mark sign fixture send retention complete: rows=%d err=%v", rows, err)
	}

	publishTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publishTx.Rollback(ctx) }()
	publishQ := q.WithTx(publishTx)
	sent, err := publishQ.CompleteDocumentSendSealing(ctx, generated.CompleteDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := publishQ.MarkRecipientSent(ctx, generated.MarkRecipientSentParams{ID: recipient.ID, DocumentID: doc.ID}); err != nil || rows != 1 {
		t.Fatalf("mark sign fixture recipient sent: rows=%d err=%v", rows, err)
	}
	canonicalEpoch, err := article13.CanonicalSentAt(sent.SentAt.Time)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := audit.New(q, pool).LogTx(ctx, publishTx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindDocumentSent,
		Payload: map[string]any{
			article13.AuditRequiredNoticeSchemaKey: article13.SchemaV1,
			article13.AuditRequiredNoticeSentAtKey: canonicalEpoch,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := publishQ.DeleteSendSealingIntent(ctx, generated.DeleteSendSealingIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	}); err != nil || rows != 1 {
		t.Fatalf("delete sign fixture send intent: rows=%d err=%v", rows, err)
	}
	if err := publishTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pending)
	return sent
}

// sendCommentFixtureE2E completes the single-recipient synthetic fixture through
// the same frozen-branding and durable sealing gates used by the signing tests.
func sendCommentFixtureE2E(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	q *generated.Queries,
	doc *generated.Document,
) *generated.Document {
	t.Helper()
	recipients, err := q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		t.Fatalf("load synthetic send fixture recipients: %v", err)
	}
	if len(recipients) != 1 {
		t.Fatalf("synthetic send fixture requires one recipient, got %d", len(recipients))
	}
	return completeDurableSendSignE2E(t, ctx, pool, q, doc, recipients[0])
}

func TestMarkViewedRechecksDeadlineAfterDocumentLockE2E(t *testing.T) {
	for _, deadlineKind := range []string{"recipient", "document"} {
		t.Run(deadlineKind, func(t *testing.T) {
			dsn := os.Getenv("HASH_E2E_DB_URL")
			if dsn == "" {
				t.Skip("set HASH_E2E_DB_URL to run")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			config, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatal(err)
			}
			migrationDB := stdlib.OpenDB(*config.ConnConfig)
			if err := mdb.RunMigrations(migrationDB); err != nil {
				t.Fatal(err)
			}
			_ = migrationDB.Close()
			pool, err := pgxpool.NewWithConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			q := generated.New(pool)
			org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "expiry lock " + uuid.NewString(), Plan: "pro"})
			if err != nil {
				t.Fatal(err)
			}
			user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@expiry.test", Name: "Sender", Role: "owner"})
			if err != nil {
				t.Fatal(err)
			}
			base := time.Now().UTC()
			var clock atomic.Int64
			clock.Store(base.UnixNano())
			engine := &Engine{Pool: pool, Queries: q, Audit: audit.New(q, pool), Now: func() time.Time { return time.Unix(0, clock.Load()).UTC() }}
			params := generated.CreateBlocksDocumentParams{OrgID: org.ID, Name: "expiry boundary", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`), SenderID: user.ID}
			if deadlineKind == "document" {
				params.ExpiresAt = pgtype.Timestamptz{Time: base.Add(time.Second), Valid: true}
			}
			doc, err := q.CreateBlocksDocument(ctx, params)
			if err != nil {
				t.Fatal(err)
			}
			tokenDeadline := base.Add(time.Hour)
			if deadlineKind == "recipient" {
				tokenDeadline = base.Add(time.Second)
			}
			rec, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@recipient.expiry.test", Name: "Recipient", MagicTokenHash: []byte(uuid.NewString()), MagicTokenExpiresAt: pgtype.Timestamptz{Time: tokenDeadline, Valid: true}, Locale: "en"})
			if err != nil {
				t.Fatal(err)
			}
			doc = completeDurableSendSignE2E(t, ctx, pool, q, doc, rec)
			rc := &RecipientContext{Document: doc, Recipient: &generated.GetRecipientByTokenHashRow{ID: rec.ID, DocumentID: doc.ID, DocOrgID: org.ID, Role: rec.Role, Status: rec.Status, Email: rec.Email, Name: rec.Name, MagicTokenExpiresAt: rec.MagicTokenExpiresAt}}
			evidence := ParticipantResponseEvidence{Notice: testArticle13NoticeEvidence(t, rc)}
			if err := checkMagicLinkExpiry(rc.Recipient, doc, engine.now()); err != nil {
				t.Fatalf("admission already expired: %v", err)
			}
			lockTx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = lockTx.Rollback(context.Background()) }()
			if _, err := q.WithTx(lockTx).GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: org.ID}); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- engine.MarkViewed(ctx, rc, evidence) }()
			select {
			case err := <-result:
				t.Fatalf("mutation did not wait for the document lock: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			clock.Store(base.Add(2 * time.Second).UnixNano())
			if err := lockTx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, ErrMagicLinkExpired) {
					t.Fatalf("expired mutation result: %v", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			fresh, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: org.ID})
			if err != nil || fresh.Status != "sent" {
				t.Fatalf("expired mutation changed recipient: %v %v", fresh, err)
			}
			var events int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.viewed'`, doc.ID).Scan(&events); err != nil {
				t.Fatal(err)
			}
			if events != 0 {
				t.Fatal("expired mutation emitted viewed audit evidence")
			}
		})
	}
}
