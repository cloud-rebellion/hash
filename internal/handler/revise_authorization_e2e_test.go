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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type reviseAuthorizationFixture struct {
	changeResolutionFixture
	owned              *ownedPublicReadFixtureV1
	recipientMail      int
	recipientMailState string
	doc                *generated.Document
	request            *generated.ChangeRequest
	recipient          *generated.Recipient
	user               *generated.User
}

func setupReviseAuthorizationE2E(t *testing.T, role string) reviseAuthorizationFixture {
	t.Helper()
	return nativeNegotiationAuthorizationBirth263(t, role)
}

// The original payment-term assertions now start from genuine public source,
// party/field authoring, normal Send, original notice and RequestChanges. There
// is one real runtime, the original128/64 allocation and no seeded sent/request/
// event/cache row. Role changes happen only after this actual owner journey.
func nativeNegotiationAuthorizationBirth263(t *testing.T, role string) reviseAuthorizationFixture {
	t.Helper()
	q, document := nativeBindingDocument259(t, false)
	if !document.UpdatedAt.Valid {
		t.Fatal("actual draft edit clock absent")
	}
	patch, err := json.Marshal(updateDocumentInput{ExpectedUpdatedAt: document.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), BlocksJSON: json.RawMessage(`{"version":1,"blocks":[{"id":"payment-term","type":"paragraph","text":"Original payment term"},{"id":"sign","type":"signature_field","attrs":{"recipient_role":"signer"}}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if r := submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/documents/"+document.ID.String(), string(patch), q.cookie); r.Code != http.StatusOK {
		t.Fatal("genuine payment-term authoring failed", r.Code)
	}
	r := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+document.ID.String()+"/send", `{"lawful_basis":"contract"}`, q.cookie)
	var sent sendDocumentResponse
	if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &sent) != nil || sent.Status != "sent" || len(sent.Links) != 1 {
		t.Fatal("genuine authorization normal Send failed", r.Code)
	}
	u, err := url.Parse(sent.Links[0].URL)
	if err != nil || !strings.HasPrefix(u.Path, "/sign/") {
		t.Fatal("genuine authorization invitation absent", err)
	}
	token := strings.TrimPrefix(u.Path, "/sign/")
	bootstrap := q.requestV1(token, "")
	var page signerContextResponse
	if bootstrap.Code != http.StatusOK || json.Unmarshal(bootstrap.Body.Bytes(), &page) != nil || page.Privacy.NoticeDigest == "" {
		t.Fatal("genuine authorization notice absent", bootstrap.Code)
	}
	body := `{"message":"Revise the payment term.","block_id":"payment-term","quote":"Original payment term","proposed":"Revised payment term"}`
	request := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/sign/"+token+"/request-changes", strings.NewReader(body)).WithContext(q.f.ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", q.f.s.PublicURL)
	request.Header.Set(signerNoticeDigestHeader, page.Privacy.NoticeDigest)
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, request)
	if w.Code != http.StatusOK {
		t.Fatal("genuine authorization pause failed", w.Code)
	}
	document, err = q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: document.ID, OrgID: q.f.org})
	if err != nil || document.Status != "changes_requested" {
		t.Fatal("genuine paused document absent", err)
	}
	changes, err := q.f.q.ListChangeRequests(q.f.ctx, document.ID)
	if err != nil || len(changes) != 1 || changes[0].Status != "open" {
		t.Fatal("genuine original change request absent", err)
	}
	change, err := q.f.q.GetChangeRequest(q.f.ctx, generated.GetChangeRequestParams{ID: changes[0].ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	people, err := q.f.q.ListRecipientsByDocument(q.f.ctx, document.ID)
	if err != nil || len(people) != 1 || people[0].ID != sent.Links[0].RecipientID {
		t.Fatal("genuine original recipient absent", err)
	}
	user, err := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	base := changeResolutionFixture{ctx: q.f.ctx, pool: q.f.pool, q: q.f.q, s: q.f.s, org: q.f.org, owner: user.ID, cookie: dsrSessionCookieE2E(t, q.f.s, user.ID, user.SessionGeneration, time.Hour)}
	f := reviseAuthorizationFixture{changeResolutionFixture: base, owned: q, doc: document, request: change, recipient: people[0], user: user}
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,coalesce(jsonb_agg(to_jsonb(ed) ORDER BY ed.id),'[]'::jsonb)::text FROM email_deliveries ed WHERE to_email=$1`, f.recipient.Email).Scan(&f.recipientMail, &f.recipientMailState); err != nil || f.recipientMail != 1 {
		t.Fatal("genuine original invitation baseline absent", err)
	}
	nativeBindingMeasurement259(t, q.f, document.ID)
	q.assertObserversOnlyV1(t)
	return f
}

// These are additional refusal witnesses, not source/cache creation authority.
// The original full document/party/request/evidence/audit/outbox snapshot is
// retained by each caller; cache/history rows are now required exact as well.
func nativeNegotiationAuthorizationCaches263(t *testing.T, q *ownedPublicReadFixtureV1, document uuid.UUID) string {
	t.Helper()
	var state string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object(
	 'policy',(SELECT to_jsonb(m) FROM document_signing_policy_sizes_v1 m WHERE document_id=$1),
	 'response',(SELECT to_jsonb(m) FROM html_creation_response_sizes_v1 m WHERE document_id=$1),
	 'report',(SELECT to_jsonb(m) FROM document_read_report_sizes_v1 m WHERE document_id=$1),
	 'event_sizes',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY event_id),'[]'::jsonb) FROM html_snapshot_event_payload_sizes_v1 m WHERE document_id=$1),
	 'field_sizes',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY field_id),'[]'::jsonb) FROM field_signing_policy_sizes_v1 m WHERE document_id=$1),
	 'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM document_versions v WHERE document_id=$1),
	 'retired',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM html_document_materialization_snapshots s WHERE document_id=$1))::text`, document).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// Every async operation has a cancellation owner, exact lock release and a
// finite completion join registered after the fixture's own cleanup. The
// original engine10s, wait3s and result4s bounds are unchanged.
func nativeNegotiationHTTPJob263(t *testing.T, original context.Context, held pgx.Tx, run func(context.Context) *httptest.ResponseRecorder) <-chan *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithCancel(original)
	result := make(chan *httptest.ResponseRecorder, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		_ = held.Rollback(cleanup)
		stop()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("native negotiation HTTP operation did not join before fixture cleanup")
		}
	})
	go func() {
		defer close(done)
		result <- run(ctx)
	}()
	return result
}

func awaitNativeNegotiationLock263(t *testing.T, q *ownedPublicReadFixtureV1, holder pgx.Tx, query, event string) {
	t.Helper()
	var pid int32
	if err := holder.QueryRow(q.f.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(q.f.ctx, 3*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var count int
		err := q.f.pool.QueryRow(ctx, `SELECT count(*)::integer FROM pg_stat_activity a
		 WHERE datname=current_database() AND state='active' AND query LIKE $1 AND wait_event=$2
		 AND $3=ANY(pg_blocking_pids(a.pid)) AND application_name=$4`, "%"+query+"%", event, pid, q.f.pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			return
		}
		if count > 1 {
			t.Fatal("multiple requests reached the exact native negotiation blocker")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("negotiation did not wait on its exact %s %s blocker", query, event)
}

func (f reviseAuthorizationFixture) submit(cookie string) *httptest.ResponseRecorder {
	return f.submitContext(context.Background(), cookie)
}
func (f reviseAuthorizationFixture) submitContext(ctx context.Context, cookie string) *httptest.ResponseRecorder {
	return submitSessionOperationContextE2E(ctx, f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/revise", "", cookie)
}

// Include the full legal rows and credentials, not just the document status.
// Comparing one database snapshot catches a partial reset or audit/outbox
// commit when authorization expires late in the transaction.
func (f reviseAuthorizationFixture) snapshot(t *testing.T) string {
	t.Helper()
	var state string
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'document', (SELECT to_jsonb(d) FROM documents d WHERE d.id=$1),
		'recipients', (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb) FROM recipients r WHERE r.document_id=$1),
		'requests', (SELECT coalesce(jsonb_agg(to_jsonb(cr) ORDER BY cr.id),'[]'::jsonb) FROM change_requests cr WHERE cr.document_id=$1),
		'fields', (SELECT coalesce(jsonb_agg(to_jsonb(df) ORDER BY df.id),'[]'::jsonb) FROM document_fields df WHERE df.document_id=$1),
		'signatures', (SELECT coalesce(jsonb_agg(to_jsonb(sg) ORDER BY sg.id),'[]'::jsonb) FROM signatures sg WHERE sg.document_id=$1),
		'events', (SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM events e WHERE e.document_id=$1),
		'outbox', (SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY ed.id),'[]'::jsonb) FROM email_deliveries ed WHERE ed.to_email IN (SELECT email FROM recipients WHERE document_id=$1))
	)::text`, f.doc.ID).Scan(&state) //nolint:rawsql -- assert exact synthetic fixture state atomically
	if err != nil {
		t.Fatal(err)
	}
	return state + "\n" + nativeNegotiationAuthorizationCaches263(t, f.owned, f.doc.ID)
}

func (f reviseAuthorizationFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before {
		t.Fatal("refused revision changed document content, recipients, tokens, change requests, legal evidence, audit, or outbox")
	}
	f.owned.assertObserversOnlyV1(t)
}

func TestReviseRechecksAuthorizationAfterDocumentWaitE2E(t *testing.T) {
	for _, change := range []string{"demotion", "revocation", "expiry"} {
		t.Run(change, func(t *testing.T) {
			f := setupReviseAuthorizationE2E(t, "sender")
			owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			ttl := time.Hour
			if change == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			result := nativeNegotiationHTTPJob263(t, f.ctx, blocked, func(ctx context.Context) *httptest.ResponseRecorder { return f.submitContext(ctx, cookie) })
			awaitNativeNegotiationLock263(t, f.owned, blocked, "-- name: GetHTMLCeremonyWorkflowAccessV1", "transactionid")
			want := http.StatusForbidden
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
				want = http.StatusUnauthorized
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			if response.Code != want {
				t.Fatalf("stale revision=%d want=%d %s", response.Code, want, response.Body.String())
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestReviseExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	f := setupReviseAuthorizationE2E(t, "sender")
	before := f.snapshot(t)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
	result := nativeNegotiationHTTPJob263(t, f.ctx, blocked, func(ctx context.Context) *httptest.ResponseRecorder { return f.submitContext(ctx, cookie) })
	awaitNativeNegotiationLock263(t, f.owned, blocked, "-- name: AcquireOrgChainLock", "advisory")
	awaitSessionCookieExpiryE2E(t, f.s, cookie)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	response := receiveSessionOperationE2E(t, result)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revision expired during audit=%d %s", response.Code, response.Body.String())
	}
	f.assertUnchanged(t, before)
}

func TestReviseSenderAndOwnerCommitAtomicallyE2E(t *testing.T) {
	for _, role := range []string{"sender", "owner"} {
		t.Run(role, func(t *testing.T) {
			f := setupReviseAuthorizationE2E(t, role)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			response := f.submit(cookie)
			if response.Code != http.StatusOK {
				t.Fatalf("valid revision=%d %s", response.Code, response.Body.String())
			}
			doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
			if err != nil || doc.Status != "draft" || doc.SentAt.Valid || string(doc.BlocksJson) != string(f.doc.BlocksJson) || string(doc.VariablesJson) != string(f.doc.VariablesJson) || doc.Article13NoticeEpochAt != f.doc.Article13NoticeEpochAt {
				t.Fatalf("revision did not preserve content and previous notice epoch: err=%v", err)
			}
			recipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: f.recipient.ID, OrgID: f.org})
			if err != nil || recipient.Status != "pending" || !recipient.MagicTokenExpiresAt.Valid || recipient.MagicTokenExpiresAt.Time.After(time.Now()) || string(recipient.MagicTokenHash) != string(f.recipient.MagicTokenHash) {
				t.Fatalf("revision did not reset recipient and expire the old credential: err=%v", err)
			}
			request, err := f.q.GetChangeRequest(f.ctx, generated.GetChangeRequestParams{ID: f.request.ID, OrgID: f.org})
			if err != nil || request.Status != "resolved" || !request.ResolvedAt.Valid {
				t.Fatalf("revision did not resolve paused requests: err=%v", err)
			}
			var actor uuid.UUID
			if err := f.pool.QueryRow(f.ctx, `SELECT actor_user_id FROM events WHERE document_id=$1 AND kind=$2`, f.doc.ID, audit.KindDocumentRevised).Scan(&actor); err != nil || actor != f.user.ID { //nolint:rawsql
				t.Fatalf("revision audit actor=%s err=%v", actor, err)
			}
			var emails int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM email_deliveries WHERE to_email=$1`, f.recipient.Email).Scan(&emails); err != nil || emails != f.recipientMail { //nolint:rawsql
				t.Fatalf("revision unexpectedly delivered email: count=%d err=%v", emails, err)
			}
			var mailState string
			if err := f.pool.QueryRow(f.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY ed.id),'[]'::jsonb)::text FROM email_deliveries ed WHERE to_email=$1`, f.recipient.Email).Scan(&mailState); err != nil || mailState != f.recipientMailState {
				t.Fatal("revision changed the actual preexisting invitation rows", err)
			}
			nativeBindingMeasurement259(t, f.owned.f, f.doc.ID)
			f.owned.assertObserversOnlyV1(t)
		})
	}
}

func TestRevisePreservesCapturedEvidenceE2E(t *testing.T) {
	for _, evidence := range []string{"signature", "acceptance", "field"} {
		t.Run(evidence, func(t *testing.T) {
			f := setupReviseAuthorizationE2E(t, "owner")
			if evidence == "acceptance" {
				if err := f.q.SetRecipientStatus(f.ctx, generated.SetRecipientStatusParams{ID: f.recipient.ID, DocumentID: f.doc.ID, Status: "accepted"}); err != nil {
					t.Fatal(err)
				}
			} else {
				var fieldID uuid.UUID
				fieldType := "text"
				if evidence == "signature" {
					fieldType = "signature"
				}
				if err := f.pool.QueryRow(f.ctx, `INSERT INTO document_fields (document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required,options_json)
					VALUES($1,$2,$3,1,0,0,20,5,true,'[]'::jsonb) RETURNING id`, f.doc.ID, f.recipient.ID, fieldType).Scan(&fieldID); err != nil { //nolint:rawsql -- synthetic partial ceremony evidence
					t.Fatal(err)
				}
				if evidence == "signature" {
					if _, err := f.q.InsertSignature(f.ctx, generated.InsertSignatureParams{
						DocumentID: f.doc.ID, RecipientID: f.recipient.ID, FieldID: fieldID, Font: "serif", TypedName: "Captured legal signer",
						ImageStorageKey: "org/" + f.org.String() + "/documents/" + f.doc.ID.String() + "/signatures/" + f.recipient.ID.String() + ".png",
						ImageSha256:     make([]byte, 32), ImageVersionID: pgtype.Text{String: "revision-fixture-image-1", Valid: true},
					}); err != nil {
						t.Fatal(err)
					}
				} else {
					// An empty value is still captured evidence; the guard must not
					// reduce this to a nonempty-string check.
					if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET value='',completed_at=now() WHERE id=$1`, fieldID); err != nil { //nolint:rawsql
						t.Fatal(err)
					}
				}
			}
			before := f.snapshot(t)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			response := f.submit(cookie)
			if response.Code != http.StatusConflict {
				t.Fatalf("captured %s revision=%d %s", evidence, response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestReviseFailureFidelityAndRollbackE2E(t *testing.T) {
	for _, fault := range []string{"audit", "audit-no-row", "document-no-row"} {
		t.Run(fault, func(t *testing.T) {
			f := setupReviseAuthorizationE2E(t, "owner")
			before := f.snapshot(t)
			name := "hash_revision_failure_" + strings.ReplaceAll(f.doc.ID.String(), "-", "")
			table, operation, predicate := "events", "INSERT", fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.kind='%s'", f.doc.ID, audit.KindDocumentRevised)
			failure := "RAISE EXCEPTION 'fixture revision failure';"
			if fault == "audit-no-row" {
				failure = "RETURN NULL;"
			}
			if fault == "document-no-row" {
				table, operation, predicate, failure = "documents", "UPDATE", fmt.Sprintf("NEW.id='%s'::uuid AND NEW.status='draft'", f.doc.ID), "RETURN NULL;"
			}
			if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF %s THEN %s END IF; RETURN NEW; END $$;
				CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, predicate, failure, name, operation, table, name)); err != nil { //nolint:rawsql,gosec -- only generated UUIDs and fixed fixture constants
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
			response := f.submit(cookie)
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("failed revision=%d want500 %s", response.Code, response.Body.String())
			}
			for _, detail := range []string{"fixture revision failure", name, "SQLSTATE", "PL/pgSQL"} {
				if strings.Contains(response.Body.String(), detail) {
					t.Fatalf("internal revision failure exposed %q", detail)
				}
			}
			f.assertUnchanged(t, before)
		})
	}
	t.Run("missing document", func(t *testing.T) {
		f := setupReviseAuthorizationE2E(t, "owner")
		before := f.snapshot(t)
		response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+uuid.NewString()+"/revise", "", f.cookie)
		if response.Code != http.StatusNotFound {
			t.Fatalf("missing revision document=%d %s", response.Code, response.Body.String())
		}
		f.assertUnchanged(t, before)
	})
	t.Run("wrong state", func(t *testing.T) {
		f := setupReviseAuthorizationE2E(t, "owner")
		if _, err := f.q.ReopenDocumentToDraft(f.ctx, generated.ReopenDocumentToDraftParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
			t.Fatal(err)
		}
		before := f.snapshot(t)
		response := f.submit(f.cookie)
		if response.Code != http.StatusConflict {
			t.Fatalf("nonpaused revision=%d %s", response.Code, response.Body.String())
		}
		f.assertUnchanged(t, before)
	})
}

func TestReviseAuthenticatedEngineAndTrustedCallerE2E(t *testing.T) {
	t.Run("missing authenticated guard refuses before dependencies", func(t *testing.T) {
		engine := &sign.Engine{}
		for _, missing := range []string{"callback", "actor"} {
			actor := uuid.New()
			var authorize auth.TransactionAuthorization
			if missing == "actor" {
				actor = uuid.Nil
				authorize = func(context.Context, pgx.Tx, *generated.User) error {
					t.Fatal("invalid actor reached callback")
					return nil
				}
			}
			doc, err := engine.ReviseWithAuthorization(context.Background(), uuid.New(), uuid.New(), actor, authorize)
			if doc != nil || !errors.Is(err, sign.ErrRevisionNotAuthorized) {
				t.Fatalf("missing %s revision=%v err=%v", missing, doc, err)
			}
		}
	})
	t.Run("trusted internal method remains transport neutral", func(t *testing.T) {
		f := setupReviseAuthorizationE2E(t, "owner")
		doc, err := f.s.Sign.Revise(f.ctx, f.org, f.doc.ID)
		if err != nil || doc == nil || doc.Status != "draft" {
			t.Fatalf("trusted internal revision failed: err=%v", err)
		}
		doc.CloseConsumerV1()
		nativeBindingMeasurement259(t, f.owned.f, f.doc.ID)
		f.owned.assertObserversOnlyV1(t)
	})
}
