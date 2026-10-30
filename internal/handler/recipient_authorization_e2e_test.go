//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type recipientAuthorizationFixture struct {
	lifecycleAuthorizationFixture
	newEmail      string
	originalAudit authoringAuditBaseline621
}

// The request must wait on THIS held parent's backend, in its actual selected
// pool/native application. A matching historical SQL label in another session
// is not evidence of reaching the authorization recheck under test.
func awaitAuthoringParentWait624E2E(t *testing.T, f lifecycleAuthorizationFixture, held pgx.Tx, query string, native bool) {
	t.Helper()
	var holder int32
	if err := held.QueryRow(f.ctx, "SELECT pg_backend_pid()").Scan(&holder); err != nil || holder <= 0 {
		t.Fatal("actual parent holder identity unavailable", err)
	}
	application := f.pool.Config().ConnConfig.RuntimeParams["application_name"]
	if native {
		if configured, ok := htmlAuthoringNativeApplicationsE2E.Load(f.s.HTMLCreationSessions); ok {
			var valid bool
			application, valid = configured.(string)
			if !valid {
				t.Fatal("configured native backend identity is invalid")
			}
		} else if f.s.Send == nil || f.s.Send.WorkRuntime == nil || !f.s.Send.WorkRuntime.MatchesPoolV1(f.pool) || f.s.Send.WorkRuntime.SessionsV1() != f.s.HTMLCreationSessions {
			t.Fatal("native backend identity is not bound to the actual fixture pool")
		}
	}
	if application == "" {
		t.Fatal("actual authoring application identity unavailable")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		err := f.pool.QueryRow(f.ctx, `SELECT count(*)::integer FROM pg_stat_activity a
 WHERE a.datname=current_database() AND a.application_name=$1 AND a.state='active'
 AND a.wait_event_type='Lock' AND a.wait_event IN('transactionid','tuple') AND a.query LIKE $2
 AND ($3=ANY(pg_blocking_pids(a.pid)) OR EXISTS(SELECT 1 FROM unnest(pg_blocking_pids(a.pid)) blocked(pid) WHERE $3=ANY(pg_blocking_pids(blocked.pid))))`, application, "%"+query+"%", holder).Scan(&waiting) //nolint:rawsql -- exact fixture-held parent and actual native/pool identity
		if err != nil {
			t.Fatal(err)
		}
		if waiting == 1 {
			return
		}
		if waiting > 1 {
			t.Fatal("unexpected extra request waiting on the same parent")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("actual authoring operation did not wait on its held parent via %s", query)
}

func startAuthoringParentRequest624E2E(t *testing.T, held pgx.Tx, result chan<- *httptest.ResponseRecorder, request func() *httptest.ResponseRecorder) {
	t.Helper()
	finished := make(chan struct{})
	// Test failure releases only this test's held lock and joins its real request
	// before the original native fixture's cleanup assertions; no debt refund.
	t.Cleanup(func() { joinHTMLAuthoringRequestE2E(t, func() {}, finished, held) })
	go func() { defer close(finished); result <- request() }()
}

func setupRecipientAuthorizationE2E(t *testing.T, role string) recipientAuthorizationFixture {
	t.Helper()
	f := setupNativeLifecycleAuthorization256(t, role, false, false)
	return recipientAuthorizationWithFieldE2E(t, f)
}

// Scope adversaries must exist in the SAME owned database as the admitted
// actor. They are deliberately raw foreign rows, never successful producer or
// runtime evidence. A second owned fixture would silently put them in another DB.
func setupForeignRecipientAuthorizationE2E(t *testing.T) recipientAuthorizationFixture {
	t.Helper()
	return recipientAuthorizationWithFieldE2E(t, setupLifecycleAuthorizationE2E(t, "owner", false, false))
}

func recipientAuthorizationWithFieldE2E(t *testing.T, f lifecycleAuthorizationFixture) recipientAuthorizationFixture {
	t.Helper()
	// An uncompleted assigned field makes deletion rollback meaningful: its
	// cascade must be restored together with the original recipient and token.
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO document_fields(document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required,options_json)
		VALUES($1,$2,'text',1,0,0,20,5,false,'[]'::jsonb)`, f.doc.ID, f.recipient.ID); err != nil { //nolint:rawsql -- synthetic draft field
		t.Fatal(err)
	}
	return recipientAuthorizationFixture{lifecycleAuthorizationFixture: f, newEmail: uuid.NewString() + "@recipient.test", originalAudit: authoringAuditBaselineE2E(t, f)}
}

type authoringAuditBaseline621 struct {
	events         map[uuid.UUID]string
	documentEvents int
}

func authoringAuditBaselineE2E(t *testing.T, f lifecycleAuthorizationFixture) authoringAuditBaseline621 {
	t.Helper()
	baseline := authoringAuditBaseline621{events: blockOriginalEventsE2E(t, f)}
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM events WHERE document_id=$1", f.doc.ID).Scan(&baseline.documentEvents); err != nil {
		t.Fatal(err)
	}
	return baseline
}

func (b authoringAuditBaseline621) ids() []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(b.events))
	for id := range b.events {
		ids = append(ids, id)
	}
	return ids
}

func (b authoringAuditBaseline621) assertAdded(t *testing.T, f lifecycleAuthorizationFixture, added int) {
	t.Helper()
	current := blockOriginalEventsE2E(t, f)
	for id, digest := range b.events {
		if current[id] != digest {
			t.Fatal("authoring mutation changed genuine native setup history")
		}
	}
	var documentEvents int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM events WHERE document_id=$1", f.doc.ID).Scan(&documentEvents); err != nil {
		t.Fatal(err)
	}
	if len(current) != len(b.events)+added || documentEvents != b.documentEvents+added {
		t.Fatalf("authoring audit delta differs: org=%d/%d document=%d/%d", len(current), len(b.events)+added, documentEvents, b.documentEvents+added)
	}
}

// These live/reopened cases use the original same-pool Send and Sign runtime;
// no synthetic retention markers, evidence measurements or replacement engine.
func sendRecipientAuthorizationNativeE2E(t *testing.T, f lifecycleAuthorizationFixture) *generated.Document {
	t.Helper()
	response := nativeLifecycleSubmit256(f.ctx, f, "send", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
	var sent sendDocumentResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &sent) != nil || sent.Status != "sent" || len(sent.Links) != 1 || sent.Links[0].RecipientID != f.recipient.ID {
		t.Fatalf("actual authoring fixture Send=%d %s", response.Code, response.Body.String())
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil || doc.Status != "sent" {
		t.Fatal("native authoring Send document readback", err)
	}
	recipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: f.recipient.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	*f.recipient = *recipient
	return doc
}

func createAuthoringSiblingE2E(t *testing.T, f lifecycleAuthorizationFixture, name string) *generated.Document {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": name, "source_kind": "blocks", "blocks_json": map[string]any{"version": 1, "blocks": []any{}}, "variables_json": map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	response := submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPost, "/api/v1/documents", string(body), dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
	var created struct{ ID uuid.UUID }
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil || created.ID == uuid.Nil {
		t.Fatalf("actual authoring sibling creation=%d %s", response.Code, response.Body.String())
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: created.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func (f recipientAuthorizationFixture) submit(operation, cookie string) *httptest.ResponseRecorder {
	return f.submitScoped(operation, f.doc.ID, f.recipient.ID, cookie)
}

func (f recipientAuthorizationFixture) submitScoped(operation string, doc, recipient uuid.UUID, cookie string) *httptest.ResponseRecorder {
	method, body := http.MethodDelete, ""
	path := "/api/v1/documents/" + doc.String() + "/recipients"
	if operation == "create" {
		method = http.MethodPost
		encoded, _ := json.Marshal(createRecipientInput{Email: f.newEmail, Name: "New fixture signer"})
		body = string(encoded)
	} else {
		path += "/" + recipient.String()
		if operation == "update" {
			method = http.MethodPatch
			encoded, _ := json.Marshal(map[string]any{"email": f.newEmail, "name": "Updated fixture signer", "locale": "en-US", "order_index": 0})
			body = string(encoded)
		}
	}
	return submitSessionOperationE2E(f.s, method, path, body, cookie)
}

func (f recipientAuthorizationFixture) snapshot(t *testing.T) string {
	t.Helper()
	var state string
	err := f.pool.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
		SELECT jsonb_build_object(
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
		'fields',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM document_fields f WHERE document_id IN (SELECT id FROM owned)),
		'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM signatures s WHERE document_id IN (SELECT id FROM owned)),
		'privacy_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$1),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE document_id IN (SELECT id FROM owned)),
		'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY id),'[]'::jsonb) FROM email_deliveries ed WHERE to_email=$2 OR to_email IN (SELECT email FROM recipients WHERE document_id IN (SELECT id FROM owned)))
		)::text`, f.org, f.newEmail).Scan(&state) //nolint:rawsql -- one exact snapshot of this fixture's complete draft rows
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func (f recipientAuthorizationFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before {
		t.Fatal("refused recipient mutation changed draft, recipient credentials, assigned fields, legal evidence, audit, or outbox")
	}
}

func recipientSuccessStatus(operation string) int {
	switch operation {
	case "create":
		return http.StatusCreated
	case "update":
		return http.StatusOK
	default:
		return http.StatusNoContent
	}
}

func recipientAuditKind(operation string) string {
	switch operation {
	case "create":
		return audit.KindRecipientCreated
	case "update":
		return audit.KindRecipientUpdated
	default:
		return audit.KindRecipientDeleted
	}
}

func TestRecipientMutationRechecksSessionAfterDocumentWaitE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		for _, change := range []string{"demotion", "revocation", "expiry"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupRecipientAuthorizationE2E(t, "sender")
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
				result := make(chan *httptest.ResponseRecorder, 1)
				startAuthoringParentRequest624E2E(t, blocked, result, func() *httptest.ResponseRecorder { return f.submit(operation, cookie) })
				awaitAuthoringParentWait624E2E(t, f.lifecycleAuthorizationFixture, blocked, "-- name: GetRecipientMutationSourceHeaderV1", true)
				want := http.StatusForbidden
				switch change {
				case "demotion":
					response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
					if response.Code != http.StatusOK {
						t.Fatalf("actual member demotion=%d %s", response.Code, response.Body.String())
					}
				case "revocation":
					response := submitSessionOperationE2E(f.s, http.MethodPost, "/auth/logout", "", cookie)
					if response.Code != http.StatusOK {
						t.Fatalf("actual logout=%d %s", response.Code, response.Body.String())
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
					t.Fatalf("stale recipient %s=%d want%d %s", operation, response.Code, want, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestRecipientMutationExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupRecipientAuthorizationE2E(t, "sender")
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
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit(operation, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, f.s, cookie)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("recipient %s expired during audit=%d %s", operation, response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
			response = f.submit(operation, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
			if response.Code != recipientSuccessStatus(operation) {
				t.Fatalf("fresh recipient %s retry=%d %s", operation, response.Code, response.Body.String())
			}
		})
	}
}

func TestRecipientMutationSenderAndOwnerCommitAtomicallyE2E(t *testing.T) {
	for _, role := range []string{"sender", "owner"} {
		for _, operation := range []string{"create", "update", "delete"} {
			t.Run(role+"/"+operation, func(t *testing.T) {
				f := setupRecipientAuthorizationE2E(t, role)
				response := f.submit(operation, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
				if response.Code != recipientSuccessStatus(operation) {
					t.Fatalf("valid recipient %s=%d %s", operation, response.Code, response.Body.String())
				}
				var actor, subject uuid.UUID
				if err := f.pool.QueryRow(f.ctx, `SELECT actor_user_id,recipient_id FROM events WHERE document_id=$1 AND kind=$2 AND NOT (id=ANY($3::uuid[]))`, f.doc.ID, recipientAuditKind(operation), f.originalAudit.ids()).Scan(&actor, &subject); err != nil || actor != f.user.ID { //nolint:rawsql
					t.Fatalf("recipient %s canonical audit actor=%s err=%v", operation, actor, err)
				}
				if operation == "delete" {
					var recipients, fields int
					if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM recipients WHERE id=$1),(SELECT count(*) FROM document_fields WHERE recipient_id=$1)`, f.recipient.ID).Scan(&recipients, &fields); err != nil || recipients != 0 || fields != 0 || subject != f.recipient.ID { //nolint:rawsql
						t.Fatalf("recipient deletion/cascade/audit subject=%d/%d/%s err=%v", recipients, fields, subject, err)
					}
				} else {
					var body recipientResponse
					if json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Email != f.newEmail || body.Role != "signer" || body.Locale != "en" || body.ID != subject {
						t.Fatal("recipient response did not use canonical values/audit subject")
					}
					current, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: body.ID, OrgID: f.org})
					if err != nil || len(current.MagicTokenHash) != 32 || !current.MagicTokenExpiresAt.Valid || !current.MagicTokenExpiresAt.Time.After(time.Now()) {
						t.Fatalf("recipient credential missing: err=%v", err)
					}
				}
				f.originalAudit.assertAdded(t, f.lifecycleAuthorizationFixture, 1)
				rows, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
				if err != nil {
					t.Fatal(err)
				}
				verifier := audit.NewChainVerifier()
				verifier.VerifyPage(rows)
				if result := verifier.Result(); !result.OK || !result.Complete || result.TotalChecked != len(f.originalAudit.events)+1 {
					t.Fatalf("recipient mutation broke audit chain: %+v", result)
				}
			})
		}
	}
}

func TestRecipientCreateInheritsLockedDocumentDefaultsE2E(t *testing.T) {
	f := setupRecipientAuthorizationE2E(t, "owner")
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	q := f.q.WithTx(blocked)
	if _, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	startAuthoringParentRequest624E2E(t, blocked, result, func() *httptest.ResponseRecorder { return f.submit("create", cookie) })
	awaitAuthoringParentWait624E2E(t, f.lifecycleAuthorizationFixture, blocked, "-- name: GetRecipientMutationSourceHeaderV1", true)
	if _, err := q.SetDocumentDefaultLocale(f.ctx, generated.SetDocumentDefaultLocaleParams{ID: f.doc.ID, OrgID: f.org, DefaultLocale: "sv"}); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Truncate(time.Microsecond).Add(3 * time.Hour)
	if _, err := blocked.Exec(f.ctx, `UPDATE documents SET expires_at=$2 WHERE id=$1`, f.doc.ID, expires); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- fixture default changed while caller awaits parent lock
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	response := receiveSessionOperationE2E(t, result)
	var body recipientResponse
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Locale != "sv" {
		t.Fatalf("recipient inherited stale locale: status=%d", response.Code)
	}
	current, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: body.ID, OrgID: f.org})
	if err != nil || !current.MagicTokenExpiresAt.Valid || !current.MagicTokenExpiresAt.Time.Equal(expires) {
		t.Fatalf("recipient inherited stale deadline: err=%v", err)
	}
}

func TestRecipientMutationInternalFailuresRollBackAndRetryE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		for _, fault := range []string{"audit", "audit-no-row", "mutation-no-row"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f := setupRecipientAuthorizationE2E(t, "owner")
				before := f.snapshot(t)
				name := "hash_recipient_failure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
				table, event, predicate := "events", "INSERT", fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.kind='%s'", f.doc.ID, recipientAuditKind(operation))
				failure := "RAISE EXCEPTION 'fixture recipient failure';"
				if fault == "audit-no-row" {
					failure = "RETURN NULL;"
				}
				if fault == "mutation-no-row" {
					table, failure = "recipients", "RETURN NULL;"
					switch operation {
					case "create":
						event, predicate = "INSERT", fmt.Sprintf("NEW.document_id='%s'::uuid", f.doc.ID)
					case "update":
						event, predicate = "UPDATE", fmt.Sprintf("NEW.id='%s'::uuid", f.recipient.ID)
					case "delete":
						event, predicate = "DELETE", fmt.Sprintf("OLD.id='%s'::uuid", f.recipient.ID)
					}
				}
				returnRow := "NEW"
				if event == "DELETE" {
					returnRow = "OLD"
				}
				if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF %s THEN %s END IF; RETURN %s; END $$;
					CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, predicate, failure, returnRow, name, event, table, name)); err != nil {
					t.Fatal(err)
				} //nolint:rawsql,gosec -- fixed fixture constants and generated UUID identifiers
				dropFault := func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if _, err := f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s()`, name, table, name)); err != nil {
						t.Error(err)
					} //nolint:rawsql,gosec
				}
				t.Cleanup(dropFault)
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				response := f.submit(operation, cookie)
				if response.Code != http.StatusInternalServerError {
					t.Fatalf("internal %s/%s status=%d want500 %s", operation, fault, response.Code, response.Body.String())
				}
				for _, leak := range []string{"fixture recipient failure", name, "SQLSTATE", "PL/pgSQL"} {
					if strings.Contains(response.Body.String(), leak) {
						t.Fatalf("recipient internal error exposed %q", leak)
					}
				}
				f.assertUnchanged(t, before)
				dropFault()
				response = f.submit(operation, cookie)
				if response.Code != recipientSuccessStatus(operation) {
					t.Fatalf("recipient retry after %s=%d %s", fault, response.Code, response.Body.String())
				}
			})
		}
	}
}

func TestRecipientMutationScopesParentAndRecipientE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupRecipientAuthorizationE2E(t, "owner")
			foreign := setupForeignRecipientAuthorizationE2E(t)
			before, foreignBefore := f.snapshot(t), foreign.snapshot(t)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			for _, parent := range []uuid.UUID{uuid.New(), foreign.doc.ID} {
				if response := f.submitScoped(operation, parent, f.recipient.ID, cookie); response.Code != http.StatusNotFound {
					t.Fatalf("scoped recipient %s parent=%d", operation, response.Code)
				}
			}
			if operation != "create" {
				sibling := createAuthoringSiblingE2E(t, f.lifecycleAuthorizationFixture, "Recipient sibling fixture")
				before = f.snapshot(t)
				for _, target := range []struct{ doc, recipient uuid.UUID }{{f.doc.ID, uuid.New()}, {f.doc.ID, foreign.recipient.ID}, {sibling.ID, f.recipient.ID}} {
					if response := f.submitScoped(operation, target.doc, target.recipient, cookie); response.Code != http.StatusNotFound {
						t.Fatalf("scoped recipient %s target=%d", operation, response.Code)
					}
				}
			}
			f.assertUnchanged(t, before)
			foreign.assertUnchanged(t, foreignBefore)
		})
	}
}

func TestRecipientMutationPreservesRetainedDraftEvidenceE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		for _, evidence := range []string{"signature", "acceptance", "field"} {
			t.Run(operation+"/"+evidence, func(t *testing.T) {
				f := setupRecipientAuthorizationE2E(t, "owner")
				if evidence == "acceptance" {
					if err := f.q.SetRecipientStatus(f.ctx, generated.SetRecipientStatusParams{ID: f.recipient.ID, DocumentID: f.doc.ID, Status: "accepted"}); err != nil {
						t.Fatal(err)
					}
				} else if evidence == "field" {
					// Even an empty captured answer is retained evidence. A delete
					// must not cascade this completed field away.
					if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET value='',completed_at=now() WHERE document_id=$1`, f.doc.ID); err != nil { //nolint:rawsql -- synthetic captured field
						t.Fatal(err)
					}
				} else {
					var fieldID uuid.UUID
					if err := f.pool.QueryRow(f.ctx, `INSERT INTO document_fields(document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required,options_json)
						VALUES($1,$2,'signature',1,0,0,20,5,true,'[]'::jsonb) RETURNING id`, f.doc.ID, f.recipient.ID).Scan(&fieldID); err != nil { //nolint:rawsql -- synthetic partially captured ceremony
						t.Fatal(err)
					}
					if _, err := f.q.InsertSignature(f.ctx, generated.InsertSignatureParams{
						DocumentID: f.doc.ID, RecipientID: f.recipient.ID, FieldID: fieldID, Font: "serif", TypedName: "Captured fixture signer",
						ImageStorageKey: "org/" + f.org.String() + "/documents/" + f.doc.ID.String() + "/signatures/" + f.recipient.ID.String() + ".png",
						ImageSha256:     make([]byte, 32), ImageVersionID: pgtype.Text{String: "recipient-fixture-signature-1", Valid: true},
					}); err != nil {
						t.Fatal(err)
					}
				}
				before := f.snapshot(t)
				response := f.submit(operation, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
				if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "retained signing evidence") {
					t.Fatalf("retained %s recipient %s=%d %s", evidence, operation, response.Code, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestRecipientMutationRequiresLiveDraftE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		for _, state := range []string{"sealing", "sent", "soft-deleted"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				f := setupRecipientAuthorizationE2E(t, "owner")
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				want := http.StatusConflict
				if state == "sealing" {
					pending, err := f.pool.Begin(f.ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer pending.Rollback(context.Background())
					q := f.q.WithTx(pending)
					if _, err := q.CreateSendSealingIntent(f.ctx, generated.CreateSendSealingIntentParams{
						DocumentID: f.doc.ID, OrgID: f.org, ActorUserID: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ActorEmail: f.user.Email,
						ActorIp: "127.0.0.1", Via: "e2e", Tool: "recipient-sealing-fixture",
					}); err != nil {
						t.Fatal(err)
					}
					seedCompleteFrozenBrandingHandlerE2E(t, f.ctx, pending, f.doc.ID)
					if _, err := q.BeginDocumentSendSealing(f.ctx, generated.BeginDocumentSendSealingParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
						t.Fatal(err)
					}
					if err := pending.Commit(f.ctx); err != nil {
						t.Fatal(err)
					}
				} else if state == "sent" {
					// The existing fixture establishes a constraint-valid sent
					// ceremony with its durable retention and Article 13 receipts.
					f.doc = sendRecipientAuthorizationNativeE2E(t, f.lifecycleAuthorizationFixture)
				} else {
					if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET deleted_at=now() WHERE id=$1`, f.doc.ID); err != nil { //nolint:rawsql -- synthetic soft-deleted draft
						t.Fatal(err)
					}
					want = http.StatusNotFound
				}
				before := f.snapshot(t)
				if response := f.submit(operation, cookie); response.Code != want {
					t.Fatalf("%s recipient %s=%d want%d %s", state, operation, response.Code, want, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestRecipientMutationAllowsReopenedDraftHistoryE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupRecipientAuthorizationE2E(t, "owner")
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			f.doc = sendRecipientAuthorizationNativeE2E(t, f.lifecycleAuthorizationFixture)
			if _, err := f.q.RequestChangesOnDocument(f.ctx, generated.RequestChangesOnDocumentParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			if response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/revise", "", cookie); response.Code != http.StatusOK {
				t.Fatalf("bootstrap actual revision=%d %s", response.Code, response.Body.String())
			}
			before, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
			if err != nil || before.Status != "draft" || !before.Article13NoticeEpochAt.Valid || before.SentAt.Valid {
				t.Fatalf("reopened draft lacks historical epoch: err=%v", err)
			}
			response := f.submit(operation, cookie)
			if response.Code != recipientSuccessStatus(operation) {
				t.Fatalf("reopened draft recipient %s=%d %s", operation, response.Code, response.Body.String())
			}
			after, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
			if err != nil || !after.Article13NoticeEpochAt.Time.Equal(before.Article13NoticeEpochAt.Time) {
				t.Fatalf("recipient edit lost historical notice epoch: err=%v", err)
			}
		})
	}
}

func TestRecipientMutationPreservesPatchAndValidationSemanticsE2E(t *testing.T) {
	t.Run("omitted update fields preserve existing values and token", func(t *testing.T) {
		f := setupRecipientAuthorizationE2E(t, "sender")
		cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
		response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/documents/"+f.doc.ID.String()+"/recipients/"+f.recipient.ID.String(), `{"name":"  Updated canonical name  "}`, cookie)
		if response.Code != http.StatusOK {
			t.Fatalf("partial patch=%d %s", response.Code, response.Body.String())
		}
		current, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: f.recipient.ID, OrgID: f.org})
		if err != nil || current.Name != "Updated canonical name" || current.Email != f.recipient.Email || current.Role != f.recipient.Role || current.OrderIndex != f.recipient.OrderIndex || current.Locale != f.recipient.Locale || string(current.MagicTokenHash) != string(f.recipient.MagicTokenHash) || !current.MagicTokenExpiresAt.Time.Equal(f.recipient.MagicTokenExpiresAt.Time) {
			t.Fatalf("partial patch changed omitted values or token: err=%v", err)
		}
	})
	for _, invalid := range []struct{ name, method, body string }{
		{"empty email", http.MethodPatch, `{"email":""}`},
		{"unsupported update role", http.MethodPatch, `{"role":"viewer"}`},
		{"unsupported create role", http.MethodPost, `{"email":"fixture@recipient.test","name":"Fixture","role":"cc"}`},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			f := setupRecipientAuthorizationE2E(t, "sender")
			before := f.snapshot(t)
			path := "/api/v1/documents/" + f.doc.ID.String() + "/recipients"
			if invalid.method == http.MethodPatch {
				path += "/" + f.recipient.ID.String()
			}
			response := submitSessionOperationE2E(f.s, invalid.method, path, invalid.body, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("invalid recipient %s=%d %s", invalid.name, response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestRecipientMutationPreservesPendingPrivacyReviewE2E(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		for _, review := range []string{"linked", "global", "changing"} {
			t.Run(operation+"/"+review, func(t *testing.T) {
				f := setupRecipientAuthorizationE2E(t, "owner")
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				var requestID uuid.UUID
				if review == "changing" {
					pending, err := f.pool.Begin(f.ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer pending.Rollback(context.Background())
					// The pending-global trigger holds the same exclusive privacy
					// fence until this request transaction finishes.
					if _, err := f.q.WithTx(pending).CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{
						OrgID: f.org, SubjectEmail: f.recipient.Email, SubjectName: f.recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`),
					}); err != nil {
						t.Fatal(err)
					}
				} else {
					input := map[string]any{"kind": "erasure", "subject_email": f.recipient.Email, "subject_name": f.recipient.Name}
					if review == "linked" {
						input["document_id"], input["recipient_id"] = f.doc.ID.String(), f.recipient.ID.String()
					}
					encoded, _ := json.Marshal(input)
					response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/dsr", string(encoded), cookie)
					var body struct {
						ID uuid.UUID `json:"id"`
					}
					if response.Code != http.StatusAccepted || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.ID == uuid.Nil {
						t.Fatalf("bootstrap actual %s privacy request=%d %s", review, response.Code, response.Body.String())
					}
					requestID = body.ID
				}
				before := f.snapshot(t)
				response := f.submit(operation, cookie)
				if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "privacy") {
					t.Fatalf("%s privacy review recipient %s=%d %s", review, operation, response.Code, response.Body.String())
				}
				f.assertUnchanged(t, before)
				if review == "linked" {
					request, err := f.q.GetDataSubjectRequest(f.ctx, generated.GetDataSubjectRequestParams{ID: requestID, OrgID: f.org})
					if err != nil || !request.DocumentID.Valid || uuid.UUID(request.DocumentID.Bytes) != f.doc.ID || !request.RecipientID.Valid || uuid.UUID(request.RecipientID.Bytes) != f.recipient.ID || request.SubjectEmail != f.recipient.Email || request.SubjectName != f.recipient.Name {
						t.Fatalf("recipient mutation orphaned or changed privacy subject: err=%v", err)
					}
				}
			})
		}
	}
}
