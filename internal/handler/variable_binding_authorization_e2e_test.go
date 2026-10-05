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
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type bindingAuthorizationSource struct {
	calls atomic.Int32
	refs  chan resolver.Ref
}

func (*bindingAuthorizationSource) Kind() resolver.SourceKind { return resolver.SourceCRMDeal }
func (s *bindingAuthorizationSource) Fetch(_ context.Context, ref resolver.Ref) (string, error) {
	s.calls.Add(1)
	s.refs <- ref
	return "Synthetic CRM customer", nil
}

type variableBindingAuthorizationFixture struct {
	lifecycleAuthorizationFixture
	source *bindingAuthorizationSource
}

func setupVariableBindingAuthorizationE2E(t *testing.T, role string) variableBindingAuthorizationFixture {
	t.Helper()
	f := setupLifecycleAuthorizationE2E(t, role, false, false)
	if _, err := f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{
		DocumentID: f.doc.ID, VariableName: "customer", SourceKind: string(resolver.SourceCRMDeal), SourceRef: "deal_original", SourcePath: "deal.name", Fallback: "Original fallback",
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.q.UpdateVariableBindingResolved(f.ctx, generated.UpdateVariableBindingResolvedParams{DocumentID: f.doc.ID, VariableName: "customer", LastValue: "Original observation"}); err != nil {
		t.Fatal(err)
	}
	source := &bindingAuthorizationSource{refs: make(chan resolver.Ref, 16)}
	f.s.Resolver = resolver.New(f.q, source)
	return variableBindingAuthorizationFixture{f, source}
}

func (f variableBindingAuthorizationFixture) body() string {
	return `{"source_kind":"crm.deal","source_ref":"deal_updated","source_path":"deal.name","fallback":"New fallback"}`
}

func (f variableBindingAuthorizationFixture) submit(operation, cookie string) *httptest.ResponseRecorder {
	return f.submitScoped(operation, f.doc.ID, "customer", f.body(), cookie)
}

func (f variableBindingAuthorizationFixture) submitScoped(operation string, docID uuid.UUID, name, body, cookie string) *httptest.ResponseRecorder {
	method := http.MethodPut
	if operation == "delete" {
		method, body = http.MethodDelete, ""
	}
	return submitSessionOperationE2E(f.s, method, "/api/v1/documents/"+docID.String()+"/variable-bindings/"+url.PathEscape(name), body, cookie)
}

func (f variableBindingAuthorizationFixture) snapshot(t *testing.T) string {
	return f.snapshotDB(t, f.pool)
}
func (f variableBindingAuthorizationFixture) snapshotDB(t *testing.T, db generated.DBTX) string {
	t.Helper()
	var state string
	if err := db.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
		SELECT jsonb_build_object(
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY document_id,variable_name),'[]'::jsonb) FROM document_variable_bindings b WHERE document_id IN (SELECT id FROM owned)),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
		'fields',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM document_fields f WHERE document_id IN (SELECT id FROM owned)),
		'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM signatures s WHERE document_id IN (SELECT id FROM owned)),
		'privacy',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$1),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1),
		'intents',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY document_id),'[]'::jsonb) FROM send_sealing_intents i WHERE org_id=$1),
		'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY id),'[]'::jsonb) FROM email_deliveries ed WHERE to_email IN (SELECT email FROM recipients WHERE document_id IN (SELECT id FROM owned)))
		)::text`, f.org).Scan(&state); err != nil { //nolint:rawsql -- complete fixture-owned authoring state; admitted key use is intentionally separate
		t.Fatal(err)
	}
	return state
}

func (f variableBindingAuthorizationFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before || f.source.calls.Load() != 0 {
		t.Fatal("refused binding mutation changed content, bindings, observations, credentials, evidence, privacy linkage, audit/outbox or fetched a source")
	}
}

func bindingAuthorizationStatus(operation string) int {
	if operation == "delete" {
		return http.StatusNoContent
	}
	return http.StatusOK
}

func holdBindingParentE2E(t *testing.T, f variableBindingAuthorizationFixture) pgx.Tx {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := f.q.WithTx(tx).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestVariableBindingRESTSessionRecheckedAfterDocumentWaitE2E(t *testing.T) {
	for _, operation := range []string{"upsert", "delete"} {
		for _, change := range []string{"demotion", "logout", "expiry"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupVariableBindingAuthorizationE2E(t, "sender")
				owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
				before := f.snapshot(t)
				blocked := holdBindingParentE2E(t, f)
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- f.submit(operation, cookie) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
				want := http.StatusForbidden
				switch change {
				case "demotion":
					if response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour)); response.Code != http.StatusOK {
						t.Fatalf("actual member demotion=%d %s", response.Code, response.Body.String())
					}
				case "logout":
					if response := submitSessionOperationE2E(f.s, http.MethodPost, "/auth/logout", "", cookie); response.Code != http.StatusOK {
						t.Fatalf("actual logout=%d", response.Code)
					}
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
					want = http.StatusUnauthorized
				}
				// Membership/key management may append an organization audit of its
				// own. Capture that intentional change before releasing the parent.
				before = f.snapshot(t)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if response := receiveSessionOperationE2E(t, result); response.Code != want {
					t.Fatalf("stale binding=%d want%d %s", response.Code, want, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestVariableBindingRESTCancellationDuringAuditWaitRollsBackE2E(t *testing.T) {
	for _, operation := range []string{"upsert", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupVariableBindingAuthorizationE2E(t, "sender")
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			method, body := http.MethodPut, f.body()
			if operation == "delete" {
				method, body = http.MethodDelete, ""
			}
			request := httptest.NewRequest(method, f.s.PublicURL+"/api/v1/documents/"+f.doc.ID.String()+"/variable-bindings/customer", strings.NewReader(body)).WithContext(ctx)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", f.s.PublicURL)
			request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)})
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				response := httptest.NewRecorder()
				f.s.Routes().ServeHTTP(response, request)
				result <- response
			}()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			cancel()
			if response := receiveSessionOperationE2E(t, result); response.Code != http.StatusInternalServerError {
				t.Fatalf("canceled binding=%d %s", response.Code, response.Body.String())
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			f.assertUnchanged(t, before)
			if response := f.submit(operation, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)); response.Code != bindingAuthorizationStatus(operation) {
				t.Fatalf("binding retry after cancellation=%d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestVariableBindingRESTAuditWaitExpiryRollsBackE2E(t *testing.T) {
	for _, operation := range []string{"upsert", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupVariableBindingAuthorizationE2E(t, "sender")
			before := f.snapshot(t)
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if err := f.q.WithTx(tx).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit(operation, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, f.s, cookie)
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if response := receiveSessionOperationE2E(t, result); response.Code != http.StatusUnauthorized {
				t.Fatalf("late binding expiry=%d %s", response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
			if response := f.submit(operation, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)); response.Code != bindingAuthorizationStatus(operation) {
				t.Fatalf("fresh binding retry=%d %s", response.Code, response.Body.String())
			}
		})
	}
}

// Scope each fault to the exact synthetic document. Audit RETURN NULL exercises
// raw pgx.ErrNoRows; delete itself remains an idempotent exec primitive.
func installBindingMutationFaultE2E(t *testing.T, f variableBindingAuthorizationFixture, operation, fault string) func() {
	t.Helper()
	name := "hash_binding_fault_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	table, event, predicate, failure, returned := "events", "INSERT", fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.kind='document.updated'", f.doc.ID), "RAISE EXCEPTION 'fixture binding failure';", "NEW"
	if fault == "audit-no-row" {
		failure = "RETURN NULL;"
	}
	if strings.HasPrefix(fault, "mutation") {
		table, predicate = "document_variable_bindings", fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.variable_name='customer'", f.doc.ID)
		if operation == "delete" {
			event, predicate, returned = "DELETE", fmt.Sprintf("OLD.document_id='%s'::uuid AND OLD.variable_name='customer'", f.doc.ID), "OLD"
		}
		if fault == "mutation-no-row" {
			failure = "RETURN NULL;"
		}
	}
	if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF %s THEN %s END IF; RETURN %s; END $$; CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, predicate, failure, returned, name, event, table, name)); err != nil {
		t.Fatal(err)
	} //nolint:rawsql,gosec -- fixed SQL plus synthetic UUIDs
	drop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s()`, name, table, name)); err != nil {
			t.Error(err)
		} //nolint:rawsql,gosec
	}
	t.Cleanup(drop)
	return drop
}

func TestVariableBindingRESTInternalFailuresRollBackAndRetryE2E(t *testing.T) {
	for _, operation := range []string{"upsert", "delete"} {
		faults := []string{"audit", "audit-no-row", "mutation"}
		if operation == "upsert" {
			faults = append(faults, "mutation-no-row")
		}
		for _, fault := range faults {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f := setupVariableBindingAuthorizationE2E(t, "owner")
				before := f.snapshot(t)
				drop := installBindingMutationFaultE2E(t, f, operation, fault)
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				response := f.submit(operation, cookie)
				if response.Code != http.StatusInternalServerError {
					t.Fatalf("binding fault=%d %s", response.Code, response.Body.String())
				}
				for _, leak := range []string{"fixture binding failure", "SQLSTATE", "PL/pgSQL", "no rows", "hash_binding_fault"} {
					if strings.Contains(response.Body.String(), leak) {
						t.Fatalf("binding error leaked %q", leak)
					}
				}
				f.assertUnchanged(t, before)
				drop()
				if response := f.submit(operation, cookie); response.Code != bindingAuthorizationStatus(operation) {
					t.Fatalf("binding fault retry=%d %s", response.Code, response.Body.String())
				}
			})
		}
	}
}

func seedBindingAuthoringRefusalE2E(t *testing.T, f variableBindingAuthorizationFixture, state string) int {
	t.Helper()
	switch state {
	case "evidence":
		if err := f.q.SetRecipientStatus(f.ctx, generated.SetRecipientStatusParams{ID: f.recipient.ID, DocumentID: f.doc.ID, Status: "accepted"}); err != nil {
			t.Fatal(err)
		}
	case "linked-privacy", "global-privacy":
		doc := pgtype.UUID{}
		if state == "linked-privacy" {
			doc = pgtype.UUID{Bytes: f.doc.ID, Valid: true}
		}
		if _, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, DocumentID: doc, SubjectEmail: f.recipient.Email, Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	case "privacy-changing":
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		if _, err := f.q.WithTx(tx).CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, SubjectEmail: f.recipient.Email, Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	case "sent":
		_ = sendDSRDocumentE2E(t, f.ctx, f.pool, f.q, f.doc, f.recipient)
	case "soft-deleted":
		if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET deleted_at=now() WHERE id=$1`, f.doc.ID); err != nil {
			t.Fatal(err)
		} //nolint:rawsql
		return http.StatusNotFound
	default:
		t.Fatalf("unknown refusal fixture %s", state)
	}
	return http.StatusConflict
}

func TestVariableBindingRESTPreservesEvidencePrivacyAndDraftStateE2E(t *testing.T) {
	for _, operation := range []string{"upsert", "delete"} {
		for _, state := range []string{"evidence", "linked-privacy", "global-privacy", "privacy-changing", "sent", "soft-deleted"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				f := setupVariableBindingAuthorizationE2E(t, "owner")
				want := seedBindingAuthoringRefusalE2E(t, f, state)
				before := f.snapshot(t)
				if response := f.submit(operation, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)); response.Code != want {
					t.Fatalf("binding refusal %s=%d %s", state, response.Code, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestVariableBindingRESTSoftDeleteAfterParentWaitE2E(t *testing.T) {
	for _, operation := range []string{"upsert", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupVariableBindingAuthorizationE2E(t, "sender")
			blocked := holdBindingParentE2E(t, f)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit(operation, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
			if _, err := blocked.Exec(f.ctx, `UPDATE documents SET deleted_at=now() WHERE id=$1`, f.doc.ID); err != nil {
				t.Fatal(err)
			} //nolint:rawsql
			expected := f.snapshotDB(t, blocked)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if response := receiveSessionOperationE2E(t, result); response.Code != http.StatusNotFound {
				t.Fatalf("soft-deleted binding parent=%d %s", response.Code, response.Body.String())
			}
			f.assertUnchanged(t, expected)
		})
	}
}

func assertBindingCanonicalAuditE2E(t *testing.T, f variableBindingAuthorizationFixture, via, tool string, count int) {
	t.Helper()
	var actor uuid.UUID
	var loggedVia, loggedTool string
	if err := f.pool.QueryRow(f.ctx, `SELECT actor_user_id,payload_json->>'via',payload_json->>'tool' FROM events WHERE document_id=$1 AND kind='document.updated' ORDER BY id DESC LIMIT 1`, f.doc.ID).Scan(&actor, &loggedVia, &loggedTool); err != nil || actor != f.user.ID || loggedVia != via || loggedTool != tool {
		t.Fatalf("binding audit actor/transport/tool mismatch: %s/%s/%s err=%v", actor, loggedVia, loggedTool, err)
	} //nolint:rawsql
	rows, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(rows)
	if result := verifier.Result(); !result.OK || !result.Complete || result.TotalChecked != count {
		t.Fatalf("binding audit chain invalid: %+v", result)
	}
}

func TestVariableBindingRESTCanonicalSuccessResolverReadbackAndIdempotentDeleteE2E(t *testing.T) {
	for _, role := range []string{"sender", "owner"} {
		for _, operation := range []string{"upsert", "delete"} {
			t.Run(role+"/"+operation, func(t *testing.T) {
				f := setupVariableBindingAuthorizationE2E(t, role)
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				response := f.submit(operation, cookie)
				if response.Code != bindingAuthorizationStatus(operation) || f.source.calls.Load() != 0 {
					t.Fatalf("valid binding mutation=%d %s; source calls=%d", response.Code, response.Body.String(), f.source.calls.Load())
				}
				tool, count := "upsert_variable_binding", 1
				if operation == "upsert" {
					var dto bindingDTO
					if json.Unmarshal(response.Body.Bytes(), &dto) != nil || dto.Variable != "customer" || dto.SourceKind != "crm.deal" || dto.SourceRef != "deal_updated" || dto.SourcePath != "deal.name" || dto.Fallback != "New fallback" {
						t.Fatal("binding DTO lost original source identity")
					}
					read := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+f.doc.ID.String()+"/resolve-preview", "", cookie)
					var preview struct {
						Variables map[string]string `json:"variables"`
						Frozen    bool              `json:"frozen"`
					}
					if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &preview) != nil || preview.Variables["customer"] != "Synthetic CRM customer" || preview.Frozen || f.source.calls.Load() != 1 {
						t.Fatalf("synthetic CRM resolve read=%d %s", read.Code, read.Body.String())
					}
					ref := <-f.source.refs
					if ref.OrgID != f.org || ref.DocID != f.doc.ID || ref.Source != "deal_updated" || ref.Path != "deal.name" {
						t.Fatalf("resolver source lost binding tenant/ref/path: %+v", ref)
					}
				} else {
					tool, count = "delete_variable_binding", 2
					if response := f.submit(operation, cookie); response.Code != http.StatusNoContent {
						t.Fatalf("idempotent binding delete=%d %s", response.Code, response.Body.String())
					}
					bindings, err := f.q.ListVariableBindings(f.ctx, f.doc.ID)
					if err != nil || len(bindings) != 0 {
						t.Fatalf("deleted binding remains: count%d err%v", len(bindings), err)
					}
				}
				assertBindingCanonicalAuditE2E(t, f, "rest", tool, count)
			})
		}
	}
}

func TestVariableBindingRESTTenantScopeAndInputLimitsE2E(t *testing.T) {
	f := setupVariableBindingAuthorizationE2E(t, "owner")
	foreign := setupVariableBindingAuthorizationE2E(t, "owner")
	before, foreignBefore := f.snapshot(t), foreign.snapshot(t)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	for _, operation := range []string{"upsert", "delete"} {
		for _, docID := range []uuid.UUID{uuid.New(), foreign.doc.ID} {
			if response := f.submitScoped(operation, docID, "customer", f.body(), cookie); response.Code != http.StatusNotFound {
				t.Fatalf("binding scoped document=%d %s", response.Code, response.Body.String())
			}
		}
	}
	for _, input := range []struct{ name, body string }{
		{"1customer", f.body()}, {strings.Repeat("a", 129), f.body()},
		{"customer", `{"source_kind":"crm.deal","source_ref":"../admin"}`},
		{"customer", `{"source_kind":"agent.computed","source_path":"bad\u0000path"}`},
		{"customer", `{"source_kind":"static","fallback":"private\u0000fallback"}`},
		{"customer", `{"source_kind":"unknown"}`},
		{"customer", `{"source_kind":"static","fallback":"` + strings.Repeat("x", 17*1024) + `"}`},
	} {
		if response := f.submitScoped("upsert", f.doc.ID, input.name, input.body, cookie); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid binding input=%d %s", response.Code, response.Body.String())
		}
	}
	f.assertUnchanged(t, before)
	foreign.assertUnchanged(t, foreignBefore)
	if response := f.submitScoped("upsert", f.doc.ID, "customer", `{"source_kind":"crm.deal","source_ref":"deal_updated","source_path":"","fallback":"Line one\nLine two"}`, cookie); response.Code != http.StatusOK {
		t.Fatalf("compatible empty REST path/multiline fallback=%d %s", response.Code, response.Body.String())
	}
}
