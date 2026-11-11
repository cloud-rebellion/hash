//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package sign

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type declineEmailFixture128 struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	q        *generated.Queries
	engine   *Engine
	original *RecipientContext
	org      uuid.UUID
	sender   *generated.User
}

func newDeclineEmailFixture128E2E(t *testing.T, locale string) *declineEmailFixture128 {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	// The exact parent/digest opt-in and independently observed zero-backend
	// cleanup are the existing fixture contract; no forced database drop.
	databases := testfixture.NewOwnedPostgresFactory(dsn)
	t.Cleanup(func() {
		if err := databases.Close(); err != nil {
			t.Error(err)
		}
	})
	database := databases.Clone(t, "hash_decline_mail128_")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = database
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Decline email controller " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	sender, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@decline-owner.test", Name: "Original sender", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{Pool: pool, Queries: q, Audit: audit.New(q, pool), Mailer: dispatch.QueueingMailer{}, OrgName: org.Name, BaseURL: "https://hash.example.test"}
	bindSigningWorkRuntimeE2E(t, engine)
	// Genuine authoring, recipient and Send helpers retain their real owner,
	// source, credential and notice gates; raw rows are not upgraded to proof.
	created, err := blockauthoring.CreateV1(ctx, blockauthoring.DependenciesV1{Sessions: engine.WorkRuntime.SessionsV1(), Audit: engine.Audit},
		blockauthoring.ActorV1{OrgID: org.ID, UserID: sender.ID, Via: "rest", Authorize: signingFixtureAuthorizerE2E(org.ID, sender.ID)},
		blockauthoring.CreateInputV1{Name: "Saved decline edition fixture", DefaultLocale: locale, BlocksJSON: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJSON: json.RawMessage(`{}`)})
	if created != nil {
		t.Cleanup(created.CloseConsumerV1)
	}
	if err != nil || created == nil || created.Document == nil {
		t.Fatal("genuine locale-specific blocks creation", err)
	}
	id := created.Document.ID
	created.CloseConsumerV1()
	doc, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: id, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	recipientLocale := "en"
	if locale == "en" {
		recipientLocale = "sv"
	}
	recipient := createSigningRecipientE2E(t, ctx, engine, sender.ID, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@decline-recipient.test", Name: "Original recipient", Locale: recipientLocale, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	completeDurableSendSignE2E(t, ctx, pool, q, doc, recipient)
	original := lookupSigningViewE2E(t, ctx, engine, recipient.MagicTokenHash)
	return &declineEmailFixture128{ctx: ctx, pool: pool, q: q, engine: engine, original: original, org: org.ID, sender: sender}
}

func (f *declineEmailFixture128) saveEdition(t *testing.T, revision int64, html string) {
	t.Helper()
	if err := f.q.CreateServiceEmailTemplateRevisionV1(f.ctx, generated.CreateServiceEmailTemplateRevisionV1Params{OrgID: f.org, Kind: dispatch.KindDeclined, Revision: revision, SubjectTemplate: "Literal saved decline {{document_name}}", HtmlTemplate: html, TextTemplate: "Literal saved decline introduction"}); err != nil {
		t.Fatal(err)
	}
	if err := f.q.SetServiceEmailTemplateHeadV1(f.ctx, generated.SetServiceEmailTemplateHeadV1Params{OrgID: f.org, Kind: dispatch.KindDeclined, Revision: revision}); err != nil {
		t.Fatal(err)
	}
}

type frozenDeclineMail128 struct{ To, Subject, HTML, Text, ReplyTo, FromName string }

func (f *declineEmailFixture128) queued(t *testing.T) []frozenDeclineMail128 {
	t.Helper()
	rows, err := f.pool.Query(f.ctx, `SELECT to_email,subject,html_body,text_body,reply_to,from_name FROM email_deliveries WHERE smtp_org_id=$1 AND smtp_purpose='workspace' ORDER BY id`, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []frozenDeclineMail128
	for rows.Next() {
		var row frozenDeclineMail128
		if err := rows.Scan(&row.To, &row.Subject, &row.HTML, &row.Text, &row.ReplyTo, &row.FromName); err != nil {
			t.Fatal(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *declineEmailFixture128) assertState(t *testing.T, status string, wantMail int) {
	t.Helper()
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.original.Document.ID, OrgID: f.org})
	if err != nil || doc.Status != status {
		t.Fatalf("document status=%v error=%v want=%s", doc, err, status)
	}
	rec, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: f.original.Recipient.ID, OrgID: f.org})
	if err != nil || rec.Status != status {
		t.Fatalf("recipient status=%v error=%v want=%s", rec, err, status)
	}
	if len(f.queued(t)) != wantMail {
		t.Fatal("decline outbox was not atomic with document/recipient state")
	}
	var events int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind=$2`, doc.ID, audit.KindDocumentDeclined).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != wantMail {
		t.Fatal("decline audit count disagrees with atomic notification")
	}
	if status == "declined" && (!rec.MagicTokenExpiresAt.Valid || rec.MagicTokenExpiresAt.Time.After(time.Now())) {
		t.Fatal("decline did not expire the original links")
	}
}

func TestDeclineSavedEditionPreservesDocumentLocaleSenderAndFrozenBytes128E2E(t *testing.T) {
	for _, locale := range []string{"en", "sv"} {
		t.Run(locale, func(t *testing.T) {
			f := newDeclineEmailFixture128E2E(t, locale)
			workspaceLocale := "en"
			if locale == "en" {
				workspaceLocale = "sv"
			}
			if _, err := f.pool.Exec(f.ctx, `INSERT INTO org_email_preferences_v1(org_id,revision,locale) VALUES($1,1,$2)`, f.org, workspaceLocale); err != nil {
				t.Fatal(err)
			}
			f.saveEdition(t, 1, "<p>Saved decline edition one</p>")
			reason := "Reason <unsafe> & intact"
			evidence := ParticipantResponseEvidence{Notice: testArticle13NoticeEvidence(t, f.original), IP: "127.0.0.1", UserAgent: "Synthetic saved decline producer"}
			if err := f.engine.Decline(f.ctx, f.original, reason, evidence); err != nil {
				t.Fatal(err)
			}
			f.assertState(t, "declined", 1)
			before := f.queued(t)[0]
			if before.To != f.sender.Email || before.ReplyTo != f.sender.Email || before.FromName != f.engine.OrgName {
				t.Fatal("decline sender destination or headers changed")
			}
			if !strings.HasPrefix(before.Subject, "Literal saved decline ") || !strings.Contains(before.HTML, "Saved decline edition one") || !strings.Contains(before.Text, reason) || strings.Contains(before.HTML, "<unsafe>") {
				t.Fatal("saved intro/native reason missing or unsafe")
			}
			if locale == "sv" && !strings.Contains(before.HTML, "Dokumentets status är nu avböjt") {
				t.Fatal("workspace/recipient preference overrode locked Swedish document locale")
			}
			if locale == "en" && !strings.Contains(before.HTML, "The document has been moved to declined state") {
				t.Fatal("workspace/recipient preference overrode locked English document locale")
			}
			if _, err := f.pool.Exec(f.ctx, `UPDATE org_email_preferences_v1 SET locale=$2,revision=2,updated_at=clock_timestamp() WHERE org_id=$1`, f.org, locale); err != nil {
				t.Fatal(err)
			}
			f.saveEdition(t, 2, "<p>Later saved decline edition</p>")
			if after := f.queued(t); len(after) != 1 || after[0] != before {
				t.Fatal("already queued decline bytes changed after settings edits")
			}
			if err := f.engine.Decline(f.ctx, f.original, reason, evidence); !errors.Is(err, ErrDocumentNotSignable) {
				t.Fatal("terminal decline replay behavior changed", err)
			}
			f.assertState(t, "declined", 1)
		})
	}
}

func TestDeclineSelectedEditionFailureRollsBackOriginalCredential128E2E(t *testing.T) {
	f := newDeclineEmailFixture128E2E(t, "sv")
	f.saveEdition(t, 1, "<script>invalid selected edition</script>")
	evidence := ParticipantResponseEvidence{Notice: testArticle13NoticeEvidence(t, f.original)}
	if err := f.engine.Decline(f.ctx, f.original, "retained reason", evidence); err == nil {
		t.Fatal("invalid selected decline edition silently fell back")
	}
	f.assertState(t, "sent", 0)
	rec, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: f.original.Recipient.ID, OrgID: f.org})
	if err != nil || !rec.MagicTokenExpiresAt.Valid || !rec.MagicTokenExpiresAt.Time.After(time.Now()) {
		t.Fatal("failed edition consumed the original credential", err)
	}
	f.saveEdition(t, 2, "<p>Valid retry edition</p>")
	if err := f.engine.Decline(f.ctx, f.original, "retained reason", evidence); err != nil {
		t.Fatal(err)
	}
	f.assertState(t, "declined", 1)
}

func TestDeclineRechecksOriginalExpiryAfterSelectedEditionLockWait128E2E(t *testing.T) {
	f := newDeclineEmailFixture128E2E(t, "en")
	f.saveEdition(t, 1, "<p>Locked selected edition</p>")
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	f.engine.Now = func() time.Time { return time.Unix(0, now.Load()) }
	evidence := ParticipantResponseEvidence{Notice: testArticle13NoticeEvidence(t, f.original)}
	lock, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(context.Background()) }()
	var org uuid.UUID
	if err := lock.QueryRow(f.ctx, `SELECT org_id FROM org_email_template_heads_v1 WHERE org_id=$1 AND kind=$2 FOR UPDATE`, f.org, dispatch.KindDeclined).Scan(&org); err != nil {
		t.Fatal(err)
	}
	call, cancel := context.WithCancel(f.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.engine.Decline(call, f.original, "expires while waiting", evidence) }()
	waiting := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%org_email_template_heads_v1%')`).Scan(&waiting); err != nil {
			cancel()
			_ = lock.Rollback(f.ctx)
			<-done
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !waiting {
		cancel()
		_ = lock.Rollback(f.ctx)
		<-done
		t.Fatal("decline never waited on the actual selected edition")
	}
	now.Store(f.original.Recipient.MagicTokenExpiresAt.Time.Add(time.Second).UnixNano())
	if err := lock.Rollback(f.ctx); err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrMagicLinkExpired) {
			t.Fatal("original expiry was not rechecked after source wait", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		<-done
		t.Fatal("decline did not retire after edition lock release")
	}
	f.assertState(t, "sent", 0)
}
