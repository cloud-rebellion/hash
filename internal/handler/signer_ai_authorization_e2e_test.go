//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type signerAIFixture struct {
	guardedAIAppsFixture
	token, digest string
}

func setupSignerAIAuthE2E(t *testing.T, blocking bool) signerAIFixture {
	t.Helper()
	f := setupGuardedAIAppsRESTE2E(t, true, blocking)
	f.s.Sign = &sign.Engine{Pool: f.pool, Queries: f.q, Audit: f.s.Audit}
	f.s.OperatorName = "Fixture processor"
	f.s.PrivacyContact = "privacy@example.test"
	f.s.SupervisoryAuthority = "IMY"
	f.s.PrivacyPolicyURL = "https://hash.example.test/privacy"
	// Expose a synthetic token for this real sent ceremony; no external email
	// consumer runs against the disposable DB and no production token is used.
	token, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.q.RotateRecipientMagicToken(f.ctx, generated.RotateRecipientMagicTokenParams{ID: f.recipient.ID, DocumentID: f.doc.ID, MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}); err != nil {
		t.Fatal(err)
	}
	shield, err := ai.NewLocalShield(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	rt := ai.New(f.q, shield, nil, f.provider)
	f.s.Clarifier = &aiapps.Clarifier{Runtime: rt}
	rc, err := f.s.Sign.LookupByToken(f.ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	notice, err := f.s.signerPrivacyNotice(httptest.NewRequest(http.MethodGet, f.s.PublicURL+"/sign/"+token, nil), rc)
	if err != nil {
		t.Fatal(err)
	}
	return signerAIFixture{f, token, notice.NoticeDigest}
}
func (f signerAIFixture) submitSigner(ctx context.Context, digest string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", f.s.PublicURL+"/sign/"+f.token+"/clarify", strings.NewReader(`{"block_id":"agreement","selection_text":"Lifecycle signer alice@example.com payment date","question":"Please explain"}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.s.PublicURL)
	if digest != "" {
		req.Header.Set(signerNoticeDigestHeader, digest)
	}
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, req)
	return w
}
func waitSignerAITokenExpiryE2E(t *testing.T, f signerAIFixture) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		var expired bool
		if err := f.pool.QueryRow(f.ctx, `SELECT magic_token_expires_at<=clock_timestamp() FROM recipients WHERE id=$1`, f.recipient.ID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			return
		}
		time.Sleep(10 * time.Millisecond)
	} //nolint:rawsql
	t.Fatal("signer AI token did not expire")
}
func assertSignerAIReceiptE2E(t *testing.T, f signerAIFixture, answered bool) uuid.UUID {
	t.Helper()
	var request uuid.UUID
	var users, requests, usage, costs, answers int
	if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT id FROM events WHERE org_id=$1 AND kind='ai.requested'),
 (SELECT count(*) FROM events WHERE org_id=$1 AND kind IN ('ai.requested','ai.completed','clarifier.requested','clarifier.answered') AND actor_user_id IS NOT NULL),
 (SELECT count(*) FROM events WHERE org_id=$1 AND kind='clarifier.requested' AND recipient_id=$2),
 (SELECT count(*) FROM ai_completion_audit a JOIN events e ON e.id=a.id AND e.org_id=a.org_id AND e.document_id=a.document_id AND e.actor_user_id IS NULL AND e.recipient_id=$2 AND e.kind='ai.requested' WHERE a.org_id=$1 AND a.actor_user_id IS NULL AND a.input_tokens=23 AND a.output_tokens=11 AND a.shield_active),
 (SELECT count(*) FROM events WHERE org_id=$1 AND kind='ai.completed' AND recipient_id=$2),
 (SELECT count(*) FROM events WHERE org_id=$1 AND kind='clarifier.answered' AND recipient_id=$2)`, f.org, f.recipient.ID).Scan(&request, &users, &requests, &usage, &costs, &answers); err != nil || users != 0 || requests != 1 || usage != 1 || costs != 1 {
		t.Fatalf("signer truthful receipt invalid req%s users%d reqs%d usage%d cost%d err%v", request, users, requests, usage, costs, err)
	} //nolint:rawsql -- exact fixture recipient attribution
	want := 0
	if answered {
		want = 1
	}
	if answers != want {
		t.Fatalf("signer answer evidence=%d want%d", answers, want)
	}
	rows, err := f.q.ListEventsByDocumentChronological(f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: f.doc.ID, Valid: true}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = evidence.BuildCeremonyEventsJSON(f.doc.ID, rows); err != nil {
		t.Fatalf("signer AI broke independent notice/evidence verification: %v", err)
	}
	assertStaffAIChainE2E(t, f.guardedAIAppsFixture)
	return request
}

func TestSignerAIOriginalTokenAfterDocumentAndRecipientWaitE2E(t *testing.T) {
	for _, wait := range []string{"document", "recipient"} {
		for _, change := range []string{"rotation", "expiry"} {
			t.Run(wait+"/"+change, func(t *testing.T) {
				f := setupSignerAIAuthE2E(t, false)
				if change == "expiry" {
					if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, f.recipient.ID); err != nil {
						t.Fatal(err)
					}
				} //nolint:rawsql
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				query := "-- name: GetDocumentForShare"
				if wait == "document" {
					_, err = f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org})
				} else {
					_, err = blocked.Exec(f.ctx, `SELECT id FROM recipients WHERE id=$1 FOR UPDATE`, f.recipient.ID)
					query = "-- name: GetRecipientForShare" //nolint:rawsql -- intentional fixture-controlled recipient wait
				}
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- f.submitSigner(f.ctx, f.digest) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, query, "transactionid")
				if change == "rotation" {
					_, hash, err := auth.MintMagicToken()
					if err != nil {
						t.Fatal(err)
					}
					target := f.q
					if wait == "recipient" {
						target = target.WithTx(blocked)
					}
					if err = target.RotateRecipientMagicToken(f.ctx, generated.RotateRecipientMagicTokenParams{ID: f.recipient.ID, DocumentID: f.doc.ID, MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}); err != nil {
						t.Fatal(err)
					}
				} else {
					waitSignerAITokenExpiryE2E(t, f)
				}
				before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
				if err = blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				w := receiveSessionOperationE2E(t, done)
				if w.Code != http.StatusGone {
					t.Fatalf("stale signer AI=%d %s", w.Code, w.Body.String())
				}
				if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
					t.Fatal("stale signer dispatched or wrote AI evidence")
				}
			})
		}
	}
}

func TestSignerAIProviderExpiryAndCancellationPreserveRecipientCostE2E(t *testing.T) {
	for _, failure := range []string{"expiry", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			f := setupSignerAIAuthE2E(t, true)
			if failure == "expiry" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, f.recipient.ID); err != nil {
					t.Fatal(err)
				}
			} //nolint:rawsql
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- f.submitSigner(ctx, f.digest) }()
			req := awaitAIProviderE2E(t, f.provider)
			if strings.Contains(req.User, "Lifecycle signer") || strings.Contains(req.User, "alice@example.com") {
				t.Fatal("public signer runtime lost Shield/party context")
			}
			want := http.StatusGone
			if failure == "expiry" {
				waitSignerAITokenExpiryE2E(t, f)
				close(f.provider.release)
			} else {
				cancel()
				want = http.StatusInternalServerError
			}
			w := receiveSessionOperationE2E(t, done)
			if w.Code != want || strings.Contains(w.Body.String(), "Reviewed AI suggestion") {
				t.Fatalf("refused signer result=%d %s", w.Code, w.Body.String())
			}
			assertSignerAIReceiptE2E(t, f, false)
		})
	}
}

func TestSignerAIRequiredNoticeRequestResultAuditsAndReceiptScopeE2E(t *testing.T) {
	f := setupSignerAIAuthE2E(t, false)
	before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
	for _, digest := range []string{"", strings.Repeat("0", 64)} {
		if w := f.submitSigner(f.ctx, digest); w.Code != http.StatusPreconditionRequired {
			t.Fatalf("unacknowledged signer processing=%d %s", w.Code, w.Body.String())
		}
	}
	if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
		t.Fatal("missing notice dispatched or audited synthetic acknowledgment")
	}
	drop := aiAppAuditFaultE2E(t, f.guardedAIAppsFixture, "ai.requested", true)
	if w := f.submitSigner(f.ctx, f.digest); w.Code != http.StatusInternalServerError {
		t.Fatalf("request receipt no-row=%d", w.Code)
	}
	drop()
	if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
		t.Fatal("partial request receipt committed or dispatched")
	}
	drop = aiAppAuditFaultE2E(t, f.guardedAIAppsFixture, "clarifier.answered", true)
	w := f.submitSigner(f.ctx, f.digest)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "Reviewed AI suggestion") {
		t.Fatalf("missing answer audit=%d %s", w.Code, w.Body.String())
	}
	drop()
	receipt := assertSignerAIReceiptE2E(t, f, false)
	other := setupSignerAIAuthE2E(t, false)
	params := generated.InsertRequestedSignerAICompletionAuditParams{RequestEventID: receipt, OrgID: f.org, DocumentID: f.doc.ID, RecipientID: f.recipient.ID, Provider: f.provider.Name(), Model: f.provider.Model(), PromptName: "duplicate", Success: true, TransferJurisdiction: "local"}
	for _, change := range []string{"duplicate", "org", "document", "recipient", "missing"} {
		bad := params
		switch change {
		case "org":
			bad.OrgID = other.org
		case "document":
			bad.DocumentID = other.doc.ID
		case "recipient":
			bad.RecipientID = other.recipient.ID
		case "missing":
			bad.RequestEventID = uuid.New()
		}
		if _, err := f.q.InsertRequestedSignerAICompletionAudit(f.ctx, bad); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("foreign signer accounting receipt accepted", change, err)
		}
	}
	// A successful fresh ceremony proves normal answer/evidence rendering.
	success := setupSignerAIAuthE2E(t, false)
	if w = success.submitSigner(success.ctx, success.digest); w.Code != http.StatusOK || !json.Valid(w.Body.Bytes()) {
		t.Fatalf("fresh signer AI=%d %s", w.Code, w.Body.String())
	}
	assertSignerAIReceiptE2E(t, success, true)
}

func TestSignerAIPrivacyAndAuditDiagnosticsFailClosedE2E(t *testing.T) {
	t.Run("privacy", func(t *testing.T) {
		f := setupSignerAIAuthE2E(t, false)
		if _, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, DocumentID: pgtype.UUID{Bytes: f.doc.ID, Valid: true}, SubjectEmail: "privacy@example.test", SubjectName: "Fixture", Kind: "erasure", RequestedVia: "sender", PayloadJson: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
		before := authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture)
		if w := f.submitSigner(f.ctx, f.digest); w.Code != http.StatusConflict {
			t.Fatalf("privacy-held signer AI=%d %s", w.Code, w.Body.String())
		}
		if f.provider.calls.Load() != 0 || authoringMCPStateE2E(t, f.lifecycleAuthorizationFixture) != before {
			t.Fatal("privacy-held signer dispatched or mutated")
		}
	})
	t.Run("private audit error", func(t *testing.T) {
		f := setupSignerAIAuthE2E(t, false)
		drop := aiAppAuditFaultE2E(t, f.guardedAIAppsFixture, "ai.completed", false)
		capture := &webhookLogCapture{}
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(capture, nil)))
		defer slog.SetDefault(previous)
		w := f.submitSigner(f.ctx, f.digest)
		drop()
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("cost event failure=%d", w.Code)
		}
		for _, marker := range []string{"fixture private AI upstream credential", "SQLSTATE", "Reviewed AI suggestion"} {
			if strings.Contains(w.Body.String(), marker) || strings.Contains(capture.String(), marker) {
				t.Fatal("private signer diagnostic/result leaked", marker)
			}
		}
		var costs int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM ai_completion_audit WHERE org_id=$1 AND actor_user_id IS NULL`, f.org).Scan(&costs); err != nil || costs != 1 {
			t.Fatal("canonical cost-event failure discarded incurred usage", costs, err)
		} //nolint:rawsql
	})
}

func TestSignerAIRevalidatesOriginalNoticeAfterDocumentWaitE2E(t *testing.T) {
	f := setupSignerAIAuthE2E(t, false)
	blocked := holdAuthoringDocumentMCPE2E(t, f.lifecycleAuthorizationFixture, f.doc.ID)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f.submitSigner(f.ctx, f.digest) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForShare", "transactionid")
	// Complete a legal evidence-safe revision while this older acknowledged
	// request waits. Revision and resend are separate commits; attempting to
	// bundle their active epochs into one fixture transaction is itself rejected
	// by the database's deferred immutable-notice constraints.
	q := f.q.WithTx(blocked)
	if _, err := q.RequestChangesOnDocument(f.ctx, generated.RequestChangesOnDocumentParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.ReopenDocumentToDraft(f.ctx, generated.ReopenDocumentToDraftParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}

	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	w := receiveSessionOperationE2E(t, done)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("stale acknowledged epoch=%d %s", w.Code, w.Body.String())
	}
	// Only the canonical revision should have committed.
	var requests int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind IN ('ai.requested','clarifier.requested')`, f.org).Scan(&requests); err != nil || requests != 0 || f.provider.calls.Load() != 0 {
		t.Fatal("stale notice dispatched or generated evidence", requests, err)
	} //nolint:rawsql
}

func TestSignerAIAndStaffShareSmallPoolAccountingAdmissionE2E(t *testing.T) {
	f := setupSignerAIAuthE2E(t, true)
	cfg := f.pool.Config()
	cfg.MaxConns = 3
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.pool = pool
	f.q = generated.New(pool)
	f.s.Pool = pool
	f.s.Queries = f.q
	f.s.Audit = audit.New(f.q, pool)
	f.s.Sign = &sign.Engine{Pool: pool, Queries: f.q, Audit: f.s.Audit}
	shield, err := ai.NewLocalShield(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	// Separate runtime objects share the actual pool's admission gate. This
	// exercises the stronger boundary than relying on one process runtime clone.
	f.s.Clarifier = &aiapps.Clarifier{Runtime: ai.New(f.q, shield, nil, f.provider)}
	f.s.Negotiator = &aiapps.Negotiator{Runtime: ai.New(f.q, shield, nil, f.provider)}
	lease, err := pool.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	first := make(chan *httptest.ResponseRecorder, 1)
	second := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- f.submitSigner(f.ctx, f.digest) }()
	awaitAIProviderE2E(t, f.provider)
	if pool.Stat().AcquiredConns() != 3 {
		t.Fatal("fixture does not occupy constrained pool")
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	op := staffAIActionForE2E(t, f.guardedAIAppsFixture, "suggest")
	go func() { second <- staffAISubmitE2E(f.guardedAIAppsFixture, f.ctx, op, cookie) }()
	close(f.provider.release)
	if w := receiveSessionOperationE2E(t, first); w.Code != http.StatusOK {
		t.Fatalf("constrained signer result=%d %s", w.Code, w.Body.String())
	}
	if w := receiveSessionOperationE2E(t, second); w.Code != http.StatusOK {
		t.Fatalf("constrained staff result=%d %s", w.Code, w.Body.String())
	}
	var recipients, staff int
	if err = pool.QueryRow(f.ctx, `SELECT count(*) FILTER (WHERE a.actor_user_id IS NULL AND e.recipient_id=$2),count(*) FILTER (WHERE a.actor_user_id=$3 AND e.recipient_id IS NULL) FROM ai_completion_audit a JOIN events e ON e.id=a.id AND e.kind='ai.requested' AND e.org_id=a.org_id AND e.document_id=a.document_id WHERE a.org_id=$1 AND a.input_tokens=23 AND a.output_tokens=11`, f.org, f.recipient.ID, f.user.ID).Scan(&recipients, &staff); err != nil || recipients != 1 || staff != 1 || f.provider.calls.Load() != 2 {
		t.Fatal("constrained cross-protocol cost attribution missing", recipients, staff, err)
	} //nolint:rawsql -- exact fixture-owned incurred usage
	rows, err := f.q.ListEventsByDocumentChronological(f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: f.doc.ID, Valid: true}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = evidence.BuildCeremonyEventsJSON(f.doc.ID, rows); err != nil {
		t.Fatal("mixed staff/recipient notice evidence invalid", err)
	}
	assertStaffAIChainE2E(t, f.guardedAIAppsFixture)
}
