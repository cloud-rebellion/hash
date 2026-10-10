//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
)

func newNegotiationCredentialE2E(t *testing.T) *multipartyPDFFixture {
	t.Helper()
	if os.Getenv("HASH_E2E_DB_URL") == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	workerPath := os.Getenv("HASH_E2E_PDF_WORKER_PATH")
	if workerPath == "" {
		t.Fatal("set HASH_E2E_PDF_WORKER_PATH to the source-built isolated PDF worker")
	}
	// The shared fixture constructs synthetic source/renderer PDFs in the
	// parent. Prevent those constructors from writing a config directory;
	// processing those PDFs still uses the mandatory production worker.
	pdfapi.DisableConfigDir()
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := sanitize.ConfigurePDFWorker(cleanupCtx, "", "development"); err != nil {
			t.Error("reset isolated PDF worker fixture:", err)
		}
	})
	setupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := sanitize.ConfigurePDFWorker(setupCtx, workerPath, "production"); err != nil {
		t.Fatal("configure isolated PDF worker fixture:", err)
	}
	return newMultipartyPDFE2E(t, false)
}

// These public actions must keep the credential admitted before a lock wait,
// rather than borrowing a replacement token or its later deadline. The PDF
// fixture uses real PostgreSQL, durable send and the production action engines;
// its object storage and renderer remain synthetic adapters.
func TestNegotiationActionsRecheckOriginalCredentialsAfterWaitsE2E(t *testing.T) {
	for _, action := range []negotiationCredentialAction{"request_changes", "comment", "decline"} {
		t.Run(string(action), func(t *testing.T) {
			for _, scenario := range []string{
				"rotation_during_document_wait",
				"original_recipient_deadline_extended",
				"original_document_deadline_extended",
				"recipient_expiry_during_audit_wait",
				"document_expiry_during_audit_wait",
			} {
				t.Run(scenario, func(t *testing.T) {
					f := newNegotiationCredentialE2E(t)
					base := time.Now().UTC().Truncate(time.Microsecond)
					var clock atomic.Int64
					clock.Store(base.UnixNano())
					f.engine.Now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
					if strings.Contains(scenario, "recipient") {
						if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=$2 WHERE magic_token_hash=$1`, auth.HashMagicToken(f.tokens[0]), base.Add(time.Second)); err != nil { //nolint:rawsql -- synthetic credential deadline
							t.Fatal(err)
						}
					} else if strings.Contains(scenario, "document_deadline") || strings.HasPrefix(scenario, "document_expiry") {
						if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET expires_at=$2 WHERE id=$1`, f.docID, base.Add(time.Second)); err != nil { //nolint:rawsql -- synthetic document deadline
							t.Fatal(err)
						}
					}
					rc := f.context(t, 0)
					notice := testArticle13NoticeEvidence(t, rc)
					held, err := f.pool.Begin(f.ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						_ = held.Rollback(cleanupCtx)
					}()
					query, event := "-- name: AcquireOrgChainLock", "advisory"
					if strings.HasSuffix(scenario, "audit_wait") {
						if err := f.q.WithTx(held).AcquireOrgChainLock(f.ctx, f.orgID.String()); err != nil {
							t.Fatal(err)
						}
					} else {
						if _, err := f.q.WithTx(held).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.docID, OrgID: f.orgID}); err != nil {
							t.Fatal(err)
						}
						query, event = "-- name: GetDocumentForUpdate", "transactionid"
					}
					var holderPID int32
					if err := held.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&holderPID); err != nil { //nolint:rawsql -- inspect the owned fixture lock
						t.Fatal(err)
					}
					requestCtx, cancelRequest := context.WithTimeout(f.ctx, 10*time.Second)
					result := make(chan error, 1)
					received := false
					go func() { result <- action.run(requestCtx, f.engine, rc, notice) }()
					// Cancellation, lock release and result draining precede fixture
					// pool cleanup, including t.Fatal paths and already-released waits.
					defer func() {
						cancelRequest()
						cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						_ = held.Rollback(cleanupCtx)
						if !received {
							select {
							case <-result:
								received = true
							case <-cleanupCtx.Done():
								t.Error("negotiation action did not drain after cancellation and owned lock release")
							}
						}
					}()
					waitCtx, cancelWait := context.WithTimeout(f.ctx, 3*time.Second)
					defer cancelWait()
					for {
						select {
						case err := <-result:
							received = true
							t.Fatalf("action returned before its authoritative lock wait: %v", err)
						default:
						}
						var waiting bool
						if err := f.pool.QueryRow(waitCtx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a
							WHERE datname=current_database() AND application_name=$4
							AND position($1 in query)>0 AND wait_event=$2
							AND $3=ANY(pg_blocking_pids(a.pid)))`, query, event, holderPID, f.pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&waiting); err != nil { //nolint:rawsql -- prove this request's real lock wait
							t.Fatalf("observe authoritative lock wait: %v", err)
						}
						if waiting {
							break
						}
						select {
						case <-waitCtx.Done():
							t.Fatal("negotiation action never reached the owned lock")
						case <-time.After(10 * time.Millisecond):
						}
					}
					if scenario == "rotation_during_document_wait" {
						newToken, newHash, err := auth.MintMagicToken()
						if err != nil {
							t.Fatal(err)
						}
						if err := f.q.RotateRecipientMagicToken(f.ctx, generated.RotateRecipientMagicTokenParams{ID: rc.Recipient.ID, DocumentID: f.docID, MagicTokenHash: newHash,
							MagicTokenExpiresAt: pgtype.Timestamptz{Time: base.Add(time.Hour), Valid: true}}); err != nil {
							t.Fatal(err)
						}
						f.tokens[0] = newToken
					} else {
						if scenario == "original_recipient_deadline_extended" {
							if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1`, rc.Recipient.ID, base.Add(time.Hour)); err != nil { //nolint:rawsql -- another admission's legitimate extension
								t.Fatal(err)
							}
						} else if scenario == "original_document_deadline_extended" {
							if _, err := held.Exec(f.ctx, `UPDATE documents SET expires_at=$2 WHERE id=$1`, f.docID, base.Add(time.Hour)); err != nil { //nolint:rawsql -- the lock holder's legitimate extension
								t.Fatal(err)
							}
						}
						clock.Store(base.Add(2 * time.Second).UnixNano())
					}
					// Read before releasing the holder: this includes its deadline
					// update, but cannot race an erroneously successful action.
					before := negotiationCredentialSnapshot(t, f.ctx, held, f)
					if err := held.Commit(f.ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-result:
						received = true
						if !errors.Is(err, ErrMagicLinkExpired) {
							t.Fatalf("stale negotiation credential error=%v, want ErrMagicLinkExpired", err)
						}
					case <-requestCtx.Done():
						t.Fatal("negotiation action did not finish after releasing its lock")
					}
					if before != negotiationCredentialSnapshot(t, f.ctx, f.pool, f) {
						t.Fatal("stale action changed document/recipients/tokens/fields, requests/comments, audit or owner/recipient outbox")
					}
					if !strings.HasSuffix(scenario, "audit_wait") {
						fresh := f.context(t, 0)
						if err := action.run(f.ctx, f.engine, fresh, testArticle13NoticeEvidence(t, fresh)); err != nil {
							t.Fatalf("freshly admitted replacement/extended credential refused: %v", err)
						}
					}
				})
			}
		})
	}
}

func TestNegotiationActionsPreserveValidBehaviorE2E(t *testing.T) {
	t.Run("comments", func(t *testing.T) {
		f := newNegotiationCredentialE2E(t)
		rc := f.context(t, 0)
		before := negotiationCredentialCounts(t, f)
		for i := 0; i < 2; i++ {
			if err := negotiationCredentialAction("comment").run(f.ctx, f.engine, rc, testArticle13NoticeEvidence(t, rc)); err != nil {
				t.Fatal(err)
			}
		}
		after := negotiationCredentialCounts(t, f)
		if after.comments-before.comments != 2 || after.requests != before.requests || after.events-before.events != 2 || after.ownerMail-before.ownerMail != 2 {
			t.Fatal("valid comments lost their rows, audit or owning sender notifications")
		}
		doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
		if err != nil || doc.Status != "sent" {
			t.Fatalf("comments changed active ceremony: status=%v error=%v", statusOfNegotiationDocument(doc), err)
		}
	})
	t.Run("multiple_requests_during_pause", func(t *testing.T) {
		f := newNegotiationCredentialE2E(t)
		rc := f.context(t, 0)
		before := negotiationCredentialCounts(t, f)
		for i := 0; i < 2; i++ {
			if err := negotiationCredentialAction("request_changes").run(f.ctx, f.engine, rc, testArticle13NoticeEvidence(t, rc)); err != nil {
				t.Fatal(err)
			}
		}
		paused := f.context(t, 0)
		if err := negotiationCredentialAction("comment").run(f.ctx, f.engine, paused, testArticle13NoticeEvidence(t, paused)); err != nil {
			t.Fatalf("comment during negotiated pause: %v", err)
		}
		after := negotiationCredentialCounts(t, f)
		if after.requests-before.requests != 2 || after.comments-before.comments != 1 || after.events-before.events != 3 || after.ownerMail-before.ownerMail != 3 {
			t.Fatal("multiple paused requests/comments lost rows, audit or owning sender notifications")
		}
		doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
		if err != nil || doc.Status != "changes_requested" {
			t.Fatalf("repeated requests lost negotiated pause: status=%v error=%v", statusOfNegotiationDocument(doc), err)
		}
	})
	t.Run("decline_invalidates_all_links", func(t *testing.T) {
		f := newNegotiationCredentialE2E(t)
		rc := f.context(t, 0)
		before := negotiationCredentialCounts(t, f)
		if err := negotiationCredentialAction("decline").run(f.ctx, f.engine, rc, testArticle13NoticeEvidence(t, rc)); err != nil {
			t.Fatal(err)
		}
		after := negotiationCredentialCounts(t, f)
		if after.comments != before.comments || after.requests != before.requests || after.events-before.events != 1 || after.ownerMail-before.ownerMail != 1 {
			t.Fatal("valid decline lost its audit/owning sender notification or created unrelated rows")
		}
		doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
		if err != nil || doc.Status != "declined" {
			t.Fatalf("decline did not terminate ceremony: status=%v error=%v", statusOfNegotiationDocument(doc), err)
		}
		recipients, err := f.q.ListRecipientsByDocument(f.ctx, f.docID)
		if err != nil {
			t.Fatal(err)
		}
		declined := 0
		for _, rec := range recipients {
			if rec.Status == "declined" {
				declined++
				if rec.ID != rc.Recipient.ID || rec.DeclinedReason.String != "Synthetic declined terms" {
					t.Fatal("decline changed the wrong party or lost the reason")
				}
			}
			if !rec.MagicTokenExpiresAt.Valid || rec.MagicTokenExpiresAt.Time.After(time.Now()) {
				t.Fatal("decline left a ceremony credential live")
			}
		}
		if declined != 1 {
			t.Fatalf("declined parties=%d, want 1", declined)
		}
		for _, token := range f.tokens {
			if _, err := f.engine.LookupByToken(f.ctx, auth.HashMagicToken(token)); err == nil {
				t.Fatal("terminal ceremony still admitted a magic link")
			}
		}
	})
}

type negotiationCredentialAction string

func (action negotiationCredentialAction) run(ctx context.Context, engine *Engine, rc *RecipientContext, notice Article13NoticeEvidence) error {
	evidence := ParticipantResponseEvidence{Notice: notice, IP: "127.0.0.1", UserAgent: "Synthetic negotiation credential fixture"}
	switch action {
	case "request_changes":
		return engine.RequestChanges(ctx, rc, ChangeRequestInput{Message: "Synthetic requested terms", Proposed: "Synthetic proposed terms", Notice: notice, IP: evidence.IP, UserAgent: evidence.UserAgent})
	case "comment":
		_, err := engine.SignerComment(ctx, rc, "Synthetic contract comment", evidence)
		return err
	case "decline":
		return engine.Decline(ctx, rc, "Synthetic declined terms", evidence)
	default:
		return errors.New("unknown synthetic negotiation action")
	}
}

type negotiationCredentialQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func negotiationCredentialSnapshot(t *testing.T, ctx context.Context, q negotiationCredentialQuerier, f *multipartyPDFFixture) string {
	t.Helper()
	var state string
	if err := q.QueryRow(ctx, `SELECT jsonb_build_object(
		'document',(SELECT to_jsonb(d) FROM documents d WHERE id=$1),
		'recipients',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM recipients r WHERE document_id=$1),
		'fields',(SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM document_fields f WHERE document_id=$1),
		'signatures',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM signatures s WHERE document_id=$1),
		'requests',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM change_requests c WHERE document_id=$1),
		'comments',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM document_comments c WHERE document_id=$1),
		'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM events e WHERE org_id=$2),
		'sealing',(SELECT jsonb_agg(to_jsonb(i) ORDER BY document_id) FROM send_sealing_intents i WHERE document_id=$1),
		'finalization',(SELECT jsonb_agg(to_jsonb(i) ORDER BY document_id) FROM document_finalization_intents i WHERE document_id=$1),
		'outbox',(SELECT jsonb_agg(to_jsonb(ed) ORDER BY id) FROM email_deliveries ed
			WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1
				UNION SELECT u.email FROM users u JOIN documents d ON d.sender_id=u.id WHERE d.id=$1)))::text`, f.docID, f.orgID).Scan(&state); err != nil { //nolint:rawsql -- compare all persisted effects without exposing hashes/addresses
		t.Fatal(err)
	}
	return state
}

type negotiationCounts struct{ comments, requests, events, ownerMail int }

func negotiationCredentialCounts(t *testing.T, f *multipartyPDFFixture) negotiationCounts {
	t.Helper()
	var counts negotiationCounts
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM document_comments WHERE document_id=$1),
		(SELECT count(*) FROM change_requests WHERE document_id=$1),
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind=ANY($2::text[])),
		(SELECT count(*) FROM email_deliveries WHERE to_email=(SELECT u.email FROM users u JOIN documents d ON d.sender_id=u.id WHERE d.id=$1))`,
		f.docID, []string{audit.KindChangesRequested, audit.KindCommentPosted, audit.KindDocumentDeclined}).Scan(&counts.comments, &counts.requests, &counts.events, &counts.ownerMail); err != nil { //nolint:rawsql -- witness rows and owning sender notifications
		t.Fatal(err)
	}
	return counts
}

func statusOfNegotiationDocument(doc *generated.Document) string {
	if doc == nil {
		return "missing"
	}
	return doc.Status
}
