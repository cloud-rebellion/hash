//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type nativeNegotiationCredentialFixture263 struct {
	ctx          context.Context
	pool         *pgxpool.Pool
	q            *generated.Queries
	engine       *sign.Engine
	orgID, docID uuid.UUID
	tokens       []string
	owned        *ownedPublicReadFixtureV1
}

// The old two-party PDF shape is retained with concrete public import, distinct
// named parties, visible per-party fields and actual normal Send. One original
// native runtime and production PDF worker own the original read/mutation work;
// storage, renderer and queued-mail peers remain synthetic and bounded.
func newNativeNegotiationCredential263(t *testing.T) *nativeNegotiationCredentialFixture263 {
	t.Helper()
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	// Keep the old multiparty fixture's60s outer request/source budget. The
	// shared constructor's existing runtime/cleanup allocation is not replaced.
	ctx, cancel := context.WithTimeout(q.f.ctx, 60*time.Second)
	t.Cleanup(cancel)
	q.f.ctx = ctx
	ownedCreationPrepareProPlanV1(t, q)
	q.f.s.Sign.Storage = q.f.s.Storage
	if err := malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	doc := packageImported220(t, q, "Native original negotiation credential PDF")
	for i, role := range []string{"customer", "provider"} {
		body, err := json.Marshal(map[string]any{"email": role + "@negotiation-credential.test", "name": "Native negotiation " + role, "role": role, "locale": "en"})
		if err != nil {
			t.Fatal(err)
		}
		r := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/recipients", string(body), q.cookie)
		var person recipientResponse
		if r.Code != http.StatusCreated || json.Unmarshal(r.Body.Bytes(), &person) != nil || person.ID == uuid.Nil || person.DocumentID != doc.ID || person.Role != role {
			t.Fatal("genuine named ordinary PDF party absent", r.Code)
		}
		field := httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(field, ownedPlainRequestV1(t, q, "REST", "add_document_field", "", map[string]any{"document_id": doc.ID.String(), "recipient_id": person.ID.String(), "type": "signature", "page": 1, "required": true, "label": "Signature " + role, "x_pct": 10, "y_pct": 55 + 15*i, "w_pct": 60, "h_pct": 10}, nil))
		if field.Code != http.StatusCreated {
			t.Fatal("genuine named ordinary PDF field absent", field.Code)
		}
	}
	r := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/send", `{"lawful_basis":"contract"}`, q.cookie)
	var sent sendDocumentResponse
	if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &sent) != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatal("genuine two-party ordinary normal Send failed", r.Code)
	}
	f := &nativeNegotiationCredentialFixture263{ctx: q.f.ctx, pool: q.f.pool, q: q.f.q, engine: q.f.s.Sign, orgID: q.f.org, docID: doc.ID, owned: q}
	for _, link := range sent.Links {
		u, err := url.Parse(link.URL)
		if err != nil || !strings.HasPrefix(u.Path, "/sign/") {
			t.Fatal("actual two-party invitation absent", err)
		}
		f.tokens = append(f.tokens, strings.TrimPrefix(u.Path, "/sign/"))
	}
	nativeBindingMeasurement259(t, q.f, doc.ID)
	q.assertObserversOnlyV1(t)
	return f
}

func (f *nativeNegotiationCredentialFixture263) context(t *testing.T, index int) *sign.RecipientContext {
	t.Helper()
	return f.owned.lookupV1(t, f.tokens[index])
}

func nativeNegotiationCredentialNotice263(t *testing.T, f *nativeNegotiationCredentialFixture263, rc *sign.RecipientContext, index int) sign.Article13NoticeEvidence {
	t.Helper()
	notice, err := f.owned.f.s.signerPrivacyNotice(signerReadRequestE2E(f.tokens[index], ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

type nativeNegotiationCredentialAction263 string

func (action nativeNegotiationCredentialAction263) run(ctx context.Context, engine *sign.Engine, rc *sign.RecipientContext, notice sign.Article13NoticeEvidence) error {
	evidence := sign.ParticipantResponseEvidence{Notice: notice, IP: "127.0.0.1", UserAgent: "Synthetic negotiation credential fixture"}
	switch action {
	case "request_changes":
		return engine.RequestChanges(ctx, rc, sign.ChangeRequestInput{Message: "Synthetic requested terms", Proposed: "Synthetic proposed terms", Notice: notice, IP: evidence.IP, UserAgent: evidence.UserAgent})
	case "decline":
		// Decline is the original generic producer. Genuine Send/read provenance
		// does not turn its new event into M94 or native writer qualification.
		return engine.Decline(ctx, rc, "Synthetic declined terms", evidence)
	default:
		return errors.New("unknown synthetic negotiation action")
	}
}

type nativeNegotiationCredentialQuerier263 interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func nativeNegotiationCredentialSnapshot263(t *testing.T, ctx context.Context, q nativeNegotiationCredentialQuerier263, f *nativeNegotiationCredentialFixture263) string {
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
		'measurements',(SELECT jsonb_agg(to_jsonb(m) ORDER BY event_id) FROM html_snapshot_event_payload_sizes_v1 m WHERE org_id=$2),
		'policy',(SELECT to_jsonb(m) FROM document_signing_policy_sizes_v1 m WHERE document_id=$1),
		'response',(SELECT to_jsonb(m) FROM html_creation_response_sizes_v1 m WHERE document_id=$1),
		'report',(SELECT to_jsonb(m) FROM document_read_report_sizes_v1 m WHERE document_id=$1),
		'field_sizes',(SELECT jsonb_agg(to_jsonb(m) ORDER BY field_id) FROM field_signing_policy_sizes_v1 m WHERE document_id=$1),
		'versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM document_versions v WHERE document_id=$1),
		'retired',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM html_document_materialization_snapshots s WHERE document_id=$1),
		'sealing',(SELECT jsonb_agg(to_jsonb(i) ORDER BY document_id) FROM send_sealing_intents i WHERE document_id=$1),
		'finalization',(SELECT jsonb_agg(to_jsonb(i) ORDER BY document_id) FROM document_finalization_intents i WHERE document_id=$1),
		'outbox',(SELECT jsonb_agg(to_jsonb(ed) ORDER BY id) FROM email_deliveries ed
			WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1
				UNION SELECT u.email FROM users u JOIN documents d ON d.sender_id=u.id WHERE d.id=$1)))::text`, f.docID, f.orgID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

type nativeNegotiationCounts263 struct{ comments, requests, events, ownerMail int }

func nativeNegotiationCredentialCounts263(t *testing.T, f *nativeNegotiationCredentialFixture263) nativeNegotiationCounts263 {
	t.Helper()
	var counts nativeNegotiationCounts263
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM document_comments WHERE document_id=$1),
		(SELECT count(*) FROM change_requests WHERE document_id=$1),
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind=ANY($2::text[])),
		(SELECT count(*) FROM email_deliveries WHERE to_email=(SELECT u.email FROM users u JOIN documents d ON d.sender_id=u.id WHERE d.id=$1))`,
		f.docID, []string{audit.KindChangesRequested, audit.KindCommentPosted, audit.KindDocumentDeclined}).Scan(&counts.comments, &counts.requests, &counts.events, &counts.ownerMail); err != nil {
		t.Fatal(err)
	}
	return counts
}

func nativeNegotiationCredentialStatus263(doc *generated.Document) string {
	if doc == nil {
		return "missing"
	}
	return doc.Status
}

func TestNegotiationActionsRecheckOriginalCredentialsAfterWaitsE2E(t *testing.T) {
	for _, action := range []nativeNegotiationCredentialAction263{"request_changes", "decline"} {
		t.Run(string(action), func(t *testing.T) {
			for _, scenario := range []string{
				"rotation_during_document_wait",
				"original_recipient_deadline_extended",
				"original_document_deadline_extended",
				"recipient_expiry_during_audit_wait",
				"document_expiry_during_audit_wait",
			} {
				t.Run(scenario, func(t *testing.T) {
					f := newNativeNegotiationCredential263(t)
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
					notice := nativeNegotiationCredentialNotice263(t, f, rc, 0)
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
						if action == "request_changes" {
							query = "-- name: GetHTMLCeremonyWorkflowAccessV1"
						}
					}
					var holderPID int32
					if err := held.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&holderPID); err != nil { //nolint:rawsql -- inspect the owned fixture lock
						t.Fatal(err)
					}
					requestCtx, cancelRequest := context.WithTimeout(f.ctx, 10*time.Second)
					result := make(chan error, 1)
					finished := make(chan struct{})
					received := false
					go func() { defer close(finished); result <- action.run(requestCtx, f.engine, rc, notice) }()
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
						select {
						case <-finished:
						case <-cleanupCtx.Done():
							t.Error("negotiation action goroutine did not join")
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
						if err := f.q.WithTx(held).RotateRecipientMagicToken(f.ctx, generated.RotateRecipientMagicTokenParams{ID: rc.Recipient.ID, DocumentID: f.docID, MagicTokenHash: newHash,
							MagicTokenExpiresAt: pgtype.Timestamptz{Time: base.Add(time.Hour), Valid: true}}); err != nil {
							t.Fatal(err)
						}
						f.tokens[0] = newToken
					} else {
						if scenario == "original_recipient_deadline_extended" {
							if _, err := held.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1`, rc.Recipient.ID, base.Add(time.Hour)); err != nil { //nolint:rawsql -- another admission's legitimate extension
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
					before := nativeNegotiationCredentialSnapshot263(t, f.ctx, held, f)
					if err := held.Commit(f.ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-result:
						received = true
						if !errors.Is(err, sign.ErrMagicLinkExpired) {
							t.Fatalf("stale negotiation credential error=%v, want sign.ErrMagicLinkExpired", err)
						}
					case <-requestCtx.Done():
						t.Fatal("negotiation action did not finish after releasing its lock")
					}
					if err := rc.CloseReadV1(); err != nil {
						t.Fatal(err)
					}
					f.owned.assertObserversOnlyV1(t)
					if before != nativeNegotiationCredentialSnapshot263(t, f.ctx, f.pool, f) {
						t.Fatal("stale action changed document/recipients/tokens/fields, requests/comments, audit or owner/recipient outbox")
					}
					if !strings.HasSuffix(scenario, "audit_wait") {
						fresh := f.context(t, 0)
						if err := action.run(f.ctx, f.engine, fresh, nativeNegotiationCredentialNotice263(t, f, fresh, 0)); err != nil {
							t.Fatalf("freshly admitted replacement/extended credential refused: %v", err)
						}
						if err := fresh.CloseReadV1(); err != nil {
							t.Fatal(err)
						}
						if action == "request_changes" {
							nativeBindingMeasurement259(t, f.owned.f, f.docID)
						}
						f.owned.assertObserversOnlyV1(t)
					}
				})
			}
		})
	}
}

func TestNegotiationActionsPreserveValidBehaviorE2E(t *testing.T) {
	// Comment credential/repeated-pause guarantees migrated to genuine native
	// handler/comment_credentials_native_v1_e2e_test.go; no raw writer fallback.
	t.Run("multiple_requests_during_pause", func(t *testing.T) {
		f := newNativeNegotiationCredential263(t)
		rc := f.context(t, 0)
		before := nativeNegotiationCredentialCounts263(t, f)
		for i := 0; i < 2; i++ {
			if err := nativeNegotiationCredentialAction263("request_changes").run(f.ctx, f.engine, rc, nativeNegotiationCredentialNotice263(t, f, rc, 0)); err != nil {
				t.Fatal(err)
			}
		}
		after := nativeNegotiationCredentialCounts263(t, f)
		if after.requests-before.requests != 2 || after.comments != before.comments || after.events-before.events != 2 || after.ownerMail-before.ownerMail != 2 {
			t.Fatal("multiple paused requests lost rows, audit or owning sender notifications")
		}
		doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
		if err != nil || doc.Status != "changes_requested" {
			t.Fatalf("repeated requests lost negotiated pause: status=%v error=%v", nativeNegotiationCredentialStatus263(doc), err)
		}
		if err := rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
		nativeBindingMeasurement259(t, f.owned.f, f.docID)
		f.owned.assertObserversOnlyV1(t)
	})
	t.Run("decline_invalidates_all_links", func(t *testing.T) {
		f := newNativeNegotiationCredential263(t)
		rc := f.context(t, 0)
		before := nativeNegotiationCredentialCounts263(t, f)
		if err := nativeNegotiationCredentialAction263("decline").run(f.ctx, f.engine, rc, nativeNegotiationCredentialNotice263(t, f, rc, 0)); err != nil {
			t.Fatal(err)
		}
		after := nativeNegotiationCredentialCounts263(t, f)
		if after.comments != before.comments || after.requests != before.requests || after.events-before.events != 1 || after.ownerMail-before.ownerMail != 1 {
			t.Fatal("valid decline lost its audit/owning sender notification or created unrelated rows")
		}
		doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
		if err != nil || doc.Status != "declined" {
			t.Fatalf("decline did not terminate ceremony: status=%v error=%v", nativeNegotiationCredentialStatus263(doc), err)
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
		if err := rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
		for _, token := range f.tokens {
			if unexpected, err := f.engine.LookupByToken(f.ctx, auth.HashMagicToken(token)); err == nil {
				_ = unexpected.CloseReadV1()
				t.Fatal("terminal ceremony still admitted a magic link")
			}
		}
		f.owned.assertObserversOnlyV1(t)
	})
}
