// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package sign

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"os"
	"testing"
	"time"
)

func TestAutomaticReminderRollbackAndConcurrentWorkersE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migration := stdlib.OpenDB(*cfg.ConnConfig)
	if err := mdb.RunMigrations(migration); err != nil {
		t.Fatal(err)
	}
	migration.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "reminder acceptance", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@reminder.test", Name: "Owner", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, Name: "Reminder", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`), SenderID: user.ID})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@recipient.reminder.test", Name: "Recipient", Locale: "en", MagicTokenHash: []byte("original-token-hash"), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	doc = sendCommentFixtureE2E(t, ctx, pool, q, doc)
	if _, err := pool.Exec(ctx, `INSERT INTO reminders(document_id,schedule_json,next_fire_at,fires_remaining) VALUES($1,'[{"days_after_send":3},{"days_after_send":7}]',$2,2)`, doc.ID, doc.SentAt.Time.Add(3*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	engine := &send.Engine{Pool: pool, Queries: q, WorkRuntime: signingWorkRuntimeE2E(t, pool), Audit: audit.New(q, pool), Mailer: dispatch.QueueingMailer{Q: q}, PublicURL: "https://hash.example.test", Now: func() time.Time { return doc.SentAt.Time.Add(3*24*time.Hour + time.Minute) }}
	actor := send.Actor{OrgID: org.ID, Email: user.Email, Via: "worker"}
	// Reject only this recipient's insert, after schedule advancement and rotation.
	constraint := "reminder_test_" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx, `ALTER TABLE email_deliveries ADD CONSTRAINT `+constraint+` CHECK (to_email <> '`+recipient.Email+`') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(context.Background(), `ALTER TABLE email_deliveries DROP CONSTRAINT IF EXISTS `+constraint)
	if _, err := engine.Remind(ctx, actor, doc.ID, true); err == nil {
		t.Fatal("outbox failure ignored")
	}
	check, err := q.GetReminderForUpdate(ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: doc.OrgID})
	if err != nil {
		t.Fatal(err)
	}
	if check.FiresRemaining != 2 || !bytes.Equal(rec.MagicTokenHash, recipient.MagicTokenHash) {
		t.Fatal("failed outbox did not rollback schedule/token")
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE email_deliveries DROP CONSTRAINT `+constraint); err != nil {
		t.Fatal(err)
	}
	type result struct {
		count int
		err   error
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() { n, err := engine.Remind(ctx, actor, doc.ID, true); results <- result{n, err} }()
	}
	total := 0
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		total += r.count
	}
	if total != 1 {
		t.Fatalf("concurrent workers reminded %d recipients", total)
	}
	check, err = q.GetReminderForUpdate(ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if check.FiresRemaining != 1 || !check.NextFireAt.Time.Equal(doc.SentAt.Time.Add(7*24*time.Hour)) {
		t.Fatal("schedule advanced incorrectly")
	}
	var mails, audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM email_deliveries WHERE to_email=$1`, recipient.Email).Scan(&mails); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind='reminder.sent'`, doc.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if mails != 1 || audits != 1 {
		t.Fatalf("mail/audit count %d/%d", mails, audits)
	}
}
