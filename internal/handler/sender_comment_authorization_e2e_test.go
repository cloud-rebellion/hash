//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type senderCommentFixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	q         *generated.Queries
	s         *Server
	org       uuid.UUID
	user      *generated.User
	doc       *generated.Document
	recipient *generated.Recipient
}

func setupSenderCommentE2E(t *testing.T, role string) senderCommentFixture {
	t.Helper()
	ctx, pool, q, s, org, userID := setupDSRE2E(t)
	user, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: userID, OrgID: org, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org, SenderID: userID, Name: "Sender comment " + uuid.NewString(),
		BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Name: "Comment recipient", Email: uuid.NewString() + "@comment.test",
		MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM email_deliveries WHERE to_email=$1`, recipient.Email); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM orgs WHERE id=$1`, org); err != nil {
			t.Error(err)
		}
	})
	if _, err = q.ConfirmDocumentLawfulBasis(ctx, generated.ConfirmDocumentLawfulBasisParams{
		DocumentID: doc.ID, OrgID: org, LawfulBasis: "contract", Via: "test", ConfirmedBy: pgtype.UUID{Bytes: userID, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	// Establish the actual sent-state database commitments with synthetic
	// sealing receipts. This fixture has no SMTP worker or storage provider.
	doc = sendDSRDocumentE2E(t, ctx, pool, q, doc, recipient)
	s.Sign = &sign.Engine{Pool: pool, Queries: q, Audit: s.Audit, Mailer: dispatch.QueueingMailer{Q: q}, OrgName: "Comment fixture", BaseURL: s.PublicURL}
	return senderCommentFixture{ctx: ctx, pool: pool, q: q, s: s, org: org, user: user, doc: doc, recipient: recipient}
}

func (f senderCommentFixture) submit(body, cookie string) *httptest.ResponseRecorder {
	encoded, _ := json.Marshal(createCommentInput{Body: body})
	return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/comments", string(encoded), cookie)
}

func (f senderCommentFixture) assertEffects(t *testing.T, comments, events, emails int) {
	t.Helper()
	var actualComments, actualEvents, actualEmails int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM document_comments WHERE document_id=$1`, f.doc.ID).Scan(&actualComments); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind=$2`, f.doc.ID, audit.KindCommentPosted).Scan(&actualEvents); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM email_deliveries WHERE to_email=$1`, f.recipient.Email).Scan(&actualEmails); err != nil {
		t.Fatal(err)
	}
	if actualComments != comments || actualEvents != events || actualEmails != emails {
		t.Fatalf("comment effects comments/audits/outbox=%d/%d/%d want=%d/%d/%d", actualComments, actualEvents, actualEmails, comments, events, emails)
	}
}

func TestSenderCommentRechecksAuthorizationAfterDocumentWaitE2E(t *testing.T) {
	for _, change := range []string{"demotion", "revocation", "expiry"} {
		t.Run(change, func(t *testing.T) {
			f := setupSenderCommentE2E(t, "sender")
			owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err = f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			ttl := time.Hour
			if change == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit("must not survive stale authorization", cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
			wantStatus := http.StatusForbidden
			switch change {
			case "demotion":
				ownerCookie := dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour)
				response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, ownerCookie)
				if response.Code != http.StatusOK {
					t.Fatalf("actual member demotion=%d %s", response.Code, response.Body.String())
				}
			case "revocation":
				response := submitSessionOperationE2E(f.s, http.MethodPost, "/auth/logout", "", cookie)
				if response.Code != http.StatusOK {
					t.Fatalf("actual session logout=%d %s", response.Code, response.Body.String())
				}
			case "expiry":
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				wantStatus = http.StatusUnauthorized
			}
			if err = blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			if response.Code != wantStatus {
				t.Fatalf("stale sender comment=%d want=%d %s", response.Code, wantStatus, response.Body.String())
			}
			f.assertEffects(t, 0, 0, 0)
		})
	}
}

type senderCommentDeliverySpy struct{ calls atomic.Int32 }

func (s *senderCommentDeliverySpy) Send(context.Context, dispatch.Message) error {
	s.calls.Add(1)
	return nil
}

func TestSenderCommentExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	for _, mode := range []string{"transactional-outbox", "direct-adapter"} {
		t.Run(mode, func(t *testing.T) {
			f := setupSenderCommentE2E(t, "sender")
			spy := &senderCommentDeliverySpy{}
			if mode == "direct-adapter" {
				f.s.Sign.Mailer = spy
			}
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err = f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit("must roll back after audit wait", cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, f.s, cookie)
			if err = blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("expired sender comment=%d %s", response.Code, response.Body.String())
			}
			f.assertEffects(t, 0, 0, 0)
			if delivered := spy.calls.Load(); delivered != 0 {
				t.Fatalf("expired comment invoked direct delivery %d times", delivered)
			}
		})
	}
}

func TestSenderCommentUsesCanonicalActorAfterDocumentWaitE2E(t *testing.T) {
	for _, role := range []string{"sender", "owner"} {
		t.Run(role, func(t *testing.T) {
			f := setupSenderCommentE2E(t, role)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err = f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			const body = "Canonical sender response"
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit(body, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
			name := "Canonical sender name"
			email := uuid.NewString() + "@canonical.comment.test"
			wantAuthor := name
			if role == "owner" {
				name = ""
				wantAuthor = email
			}
			if _, err = f.pool.Exec(f.ctx, `UPDATE users SET name=$2,email=$3 WHERE id=$1`, f.user.ID, name, email); err != nil {
				t.Fatal(err)
			}
			if err = blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			if response.Code != http.StatusCreated {
				t.Fatalf("authorized %s comment=%d %s", role, response.Code, response.Body.String())
			}
			f.assertEffects(t, 1, 1, 1)
			comments, err := f.q.ListComments(f.ctx, f.doc.ID)
			if err != nil || len(comments) != 1 || comments[0].Body != body || comments[0].AuthorName != wantAuthor || comments[0].AuthorSide != "sender" || !comments[0].UserID.Valid || uuid.UUID(comments[0].UserID.Bytes) != f.user.ID || comments[0].RecipientID.Valid {
				t.Fatalf("canonical actor lost: comments=%+v err=%v", comments, err)
			}
			var actor uuid.UUID
			if err = f.pool.QueryRow(f.ctx, `SELECT actor_user_id FROM events WHERE document_id=$1 AND kind=$2`, f.doc.ID, audit.KindCommentPosted).Scan(&actor); err != nil || actor != f.user.ID {
				t.Fatalf("comment audit actor=%s err=%v", actor, err)
			}
			var pending int
			if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM email_deliveries WHERE to_email=$1 AND status='pending' AND attempts=0 AND sent_at IS NULL AND strpos(text_body,$2)>0 AND strpos(text_body,$3)>0`, f.recipient.Email, body, wantAuthor).Scan(&pending); err != nil || pending != 1 {
				t.Fatalf("canonical comment outbox=%d err=%v", pending, err)
			}
		})
	}
}

func TestSenderCommentInternalFailuresAreGenericAndAtomicE2E(t *testing.T) {
	for _, stage := range []string{"comment", "audit", "audit-no-row", "outbox"} {
		t.Run(stage, func(t *testing.T) {
			f := setupSenderCommentE2E(t, "owner")
			name := "hash_comment_failure_" + strings.ReplaceAll(f.doc.ID.String(), "-", "")
			table, condition := "document_comments", fmt.Sprintf("NEW.document_id='%s'::uuid", f.doc.ID)
			switch stage {
			case "audit", "audit-no-row":
				table, condition = "events", fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.kind='document.comment_posted'", f.doc.ID)
			case "outbox":
				table, condition = "email_deliveries", fmt.Sprintf("NEW.to_email='%s'", f.recipient.Email)
			}
			const marker = "fixture sender-comment internal SQL failure"
			failure := "RAISE EXCEPTION '" + marker + "'"
			if stage == "audit-no-row" {
				failure = "RETURN NULL"
			}
			if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF %s THEN %s; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, condition, failure, name, table, name)); err != nil { //nolint:rawsql,gosec -- identifiers, predicates, and messages use fixture constants and generated UUIDs only
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s()`, name, table, name)); err != nil { //nolint:rawsql,gosec
					t.Error(err)
				}
			})
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			response := f.submit("must roll back on internal failure", cookie)
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("internal %s failure=%d %s", stage, response.Code, response.Body.String())
			}
			for _, detail := range []string{marker, name, "SQLSTATE", "PL/pgSQL"} {
				if strings.Contains(response.Body.String(), detail) {
					t.Fatalf("internal failure exposed %q: %s", detail, response.Body.String())
				}
			}
			f.assertEffects(t, 0, 0, 0)
		})
	}
	t.Run("missing document retains 404", func(t *testing.T) {
		f := setupSenderCommentE2E(t, "owner")
		cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
		response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+uuid.NewString()+"/comments", `{"body":"Missing document comment"}`, cookie)
		if response.Code != http.StatusNotFound {
			t.Fatalf("missing comment document=%d %s", response.Code, response.Body.String())
		}
		f.assertEffects(t, 0, 0, 0)
	})
}

func TestSenderCommentDirectEngineAuthorizationInvariantsE2E(t *testing.T) {
	t.Run("nil guard refuses before dependencies", func(t *testing.T) {
		spy := &senderCommentDeliverySpy{}
		engine := &sign.Engine{Mailer: spy}
		comment, err := engine.SenderCommentWithAuthorization(context.Background(), uuid.Nil, uuid.Nil, uuid.Nil, "untrusted actor", "valid comment", nil)
		if !errors.Is(err, sign.ErrSenderCommentNotAuthorized) || comment != nil || spy.calls.Load() != 0 {
			t.Fatalf("nil guard reached dependencies: comment=%+v deliveries=%d err=%v", comment, spy.calls.Load(), err)
		}
	})
	t.Run("viewer cannot use unguarded method", func(t *testing.T) {
		f := setupSenderCommentE2E(t, "viewer")
		spy := &senderCommentDeliverySpy{}
		f.s.Sign.Mailer = spy
		comment, err := f.s.Sign.SenderComment(f.ctx, f.org, f.doc.ID, f.user.ID, "Spoofed actor", "unauthorized direct engine comment")
		if !errors.Is(err, sign.ErrSenderCommentNotAuthorized) || comment != nil || spy.calls.Load() != 0 {
			t.Fatalf("viewer engine admission: comment=%+v deliveries=%d err=%v", comment, spy.calls.Load(), err)
		}
		f.assertEffects(t, 0, 0, 0)
	})
	t.Run("foreign user cannot use unguarded method", func(t *testing.T) {
		f := setupSenderCommentE2E(t, "owner")
		foreignOrg, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Foreign comment actor " + uuid.NewString(), Plan: "pro"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := f.pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, foreignOrg.ID); err != nil {
				t.Error(err)
			}
		})
		foreignUser, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Email: uuid.NewString() + "@foreign.comment.test", Name: "Foreign owner", Role: "owner"})
		if err != nil {
			t.Fatal(err)
		}
		spy := &senderCommentDeliverySpy{}
		f.s.Sign.Mailer = spy
		comment, err := f.s.Sign.SenderComment(f.ctx, f.org, f.doc.ID, foreignUser.ID, "Spoofed actor", "foreign direct engine comment")
		if !errors.Is(err, sign.ErrSenderCommentNotAuthorized) || comment != nil || spy.calls.Load() != 0 {
			t.Fatalf("foreign engine admission: comment=%+v deliveries=%d err=%v", comment, spy.calls.Load(), err)
		}
		f.assertEffects(t, 0, 0, 0)
	})
	t.Run("unguarded method uses only canonical author", func(t *testing.T) {
		f := setupSenderCommentE2E(t, "owner")
		const spoofed = "Spoofed author name"
		comment, err := f.s.Sign.SenderComment(f.ctx, f.org, f.doc.ID, f.user.ID, spoofed, "Direct engine response")
		if err != nil || comment == nil || comment.AuthorName != f.user.Name || comment.AuthorName == spoofed || !comment.UserID.Valid || uuid.UUID(comment.UserID.Bytes) != f.user.ID {
			t.Fatalf("spoofed engine author escaped: comment=%+v err=%v", comment, err)
		}
		f.assertEffects(t, 1, 1, 1)
		var actor uuid.UUID
		if err = f.pool.QueryRow(f.ctx, `SELECT actor_user_id FROM events WHERE document_id=$1 AND kind=$2`, f.doc.ID, audit.KindCommentPosted).Scan(&actor); err != nil || actor != f.user.ID {
			t.Fatalf("direct comment audit actor=%s err=%v", actor, err)
		}
		var spoofedNotifications int
		if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM email_deliveries WHERE to_email=$1 AND (strpos(text_body,$2)>0 OR strpos(html_body,$2)>0)`, f.recipient.Email, spoofed).Scan(&spoofedNotifications); err != nil || spoofedNotifications != 0 {
			t.Fatalf("spoofed notification authors=%d err=%v", spoofedNotifications, err)
		}
	})
}
