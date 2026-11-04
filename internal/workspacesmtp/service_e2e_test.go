//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package workspacesmtp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/secretbox"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var smtpDatabases730 *testfixture.OwnedPostgresFactory

func TestMain(m *testing.M) {
	smtpDatabases730 = testfixture.NewOwnedPostgresFactory(os.Getenv("HASH_E2E_DB_URL"))
	code := m.Run()
	if e := smtpDatabases730.Close(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		code = 1
	}
	os.Exit(code)
}

type smtpConsumerFixture730 struct {
	s   Service
	a   authoring.Actor
	q   *generated.Queries
	ctx context.Context
}

func smtpConsumerFixture(t *testing.T) smtpConsumerFixture730 {
	t.Helper()
	raw := os.Getenv("HASH_E2E_DB_URL")
	if raw == "" {
		t.Skip("set HASH_E2E_DB_URL for genuine owned PostgreSQL")
	}
	u, e := url.Parse(raw)
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("invalid PostgreSQL fixture URL")
	}
	u.Path = "/" + smtpDatabases730.Clone(t, "hash_smtp_e2e_")
	u.RawPath = ""
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	pool, e := pgxpool.New(ctx, u.String())
	if e != nil {
		t.Fatal("owned PostgreSQL connection unavailable")
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	org, e := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Synthetic SMTP owner", Plan: "pro"})
	if e != nil {
		t.Fatal(e)
	}
	user, e := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@example.invalid", Name: "Synthetic owner", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if e != nil {
		t.Fatal(e)
	}
	cookies, e := auth.NewSignedCookie(strings.Repeat("73", 32))
	if e != nil {
		t.Fatal(e)
	}
	session := auth.SessionPayload{UserID: user.ID, Generation: user.SessionGeneration}
	payload, _ := json.Marshal(session)
	cookie := cookies.Mint(payload, time.Hour)
	box, e := secretbox.New(bytes.Repeat([]byte{73}, 32), nil)
	if e != nil {
		t.Fatal(e)
	}
	return smtpConsumerFixture730{Service{Pool: pool, Audit: audit.New(q, pool), Box: box}, authoring.Actor{OrgID: org.ID, UserID: user.ID, Authorize: auth.SessionTransactionAuthorization(cookies, cookie, session, org.ID)}, q, ctx}
}

type blockedSMTPConsumer730 struct{ entered, release chan struct{} }

func (m *blockedSMTPConsumer730) Send(ctx context.Context, _ dispatch.Message) error {
	close(m.entered)
	select {
	case <-m.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Real PostgreSQL locks and real owner credential checks; the final transport
// consumer is deliberately controlled, so this proves lock lifetime, not SMTP
// acceptance or mailbox delivery. Actual SMTP protocol uses net.Pipe unit tests.
func TestWorkspaceSMTP730OwnerLocksPrecedeSettingsAndSpanConsumerE2E(t *testing.T) {
	for _, operation := range []string{"edit", "disable"} {
		t.Run(operation, func(t *testing.T) {
			f := smtpConsumerFixture(t)
			user, password := "synthetic-user", "synthetic-password"
			in := Input{Host: "smtp.example.invalid", Port: 587, TLSMode: "starttls", SenderName: "Example", SenderEmail: "sender@example.invalid", CredentialsAction: "replace", Username: &user, Password: &password}
			if _, e := f.s.Save(f.ctx, f.a, in); e != nil {
				t.Fatal(e)
			}
			receipt, e := f.s.Test(f.ctx, f.a, 1)
			if e != nil {
				t.Fatal(e)
			}
			var d generated.EmailDelivery
			e = f.s.Pool.QueryRow(f.ctx, `SELECT id,smtp_org_id,smtp_purpose,to_email,subject,html_body,text_body,reply_to,from_name,headers_json FROM email_deliveries WHERE id=$1`, receipt.DeliveryID).Scan(&d.ID, &d.SmtpOrgID, &d.SmtpPurpose, &d.ToEmail, &d.Subject, &d.HtmlBody, &d.TextBody, &d.ReplyTo, &d.FromName, &d.HeadersJson)
			if e != nil {
				t.Fatal(e)
			}
			consumer := &blockedSMTPConsumer730{make(chan struct{}), make(chan struct{})}
			defer func() {
				select {
				case <-consumer.release:
				default:
					close(consumer.release)
				}
			}()
			f.s.newMailer = func(cfg dispatch.SMTPConfig) (dispatch.Mailer, error) {
				if cfg.Host != in.Host || cfg.User != user || cfg.Password != password || !cfg.PublicOnly || cfg.AllowPrivate {
					t.Error("wrong scoped transport config")
				}
				return consumer, nil
			}
			delivery := make(chan error, 1)
			go func() {
				delivery <- f.s.Deliver(f.ctx, &d, dispatch.Message{To: d.ToEmail, Subject: d.Subject, HTML: d.HtmlBody, Text: d.TextBody}, nil)
			}()
			select {
			case <-consumer.entered:
			case <-f.ctx.Done():
				t.Fatal("consumer not reached")
			}
			changed := make(chan error, 1)
			go func() {
				if operation == "disable" {
					_, e := f.s.Disable(f.ctx, f.a, 1)
					changed <- e
				} else {
					in.ExpectedRevision = 1
					in.CredentialsAction = "keep"
					in.Username = nil
					in.Password = nil
					in.SenderName = "New display"
					_, e := f.s.Save(f.ctx, f.a, in)
					changed <- e
				}
			}()
			select {
			case e := <-changed:
				t.Fatal("settings changed before retained consumer retired", e)
			case <-time.After(150 * time.Millisecond):
			}
			close(consumer.release)
			if e = <-delivery; e != nil {
				t.Fatal(e)
			}
			if e = <-changed; e != nil {
				t.Fatal("owner mutation did not finish after consumer closure", e)
			}
			fresh, e := f.s.Get(f.ctx, f.a)
			if e != nil || fresh.Revision != 2 {
				t.Fatal("settings mutation lost CAS", e)
			}
			if operation == "disable" && fresh.Configured {
				t.Fatal("disable failed")
			}
			if operation == "edit" && fresh.SenderName != "New display" {
				t.Fatal("edit failed")
			}
		})
	}
}
