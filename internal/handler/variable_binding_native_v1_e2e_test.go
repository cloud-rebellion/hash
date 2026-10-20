//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func nativeBindingDocument259(t *testing.T, pdf bool) (*ownedPublicReadFixtureV1, *generated.Document) {
	t.Helper()
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.Sign.Storage = f.s.Storage
	source := resolver.New(f.q, &resolver.OrgSettingSource{Q: f.q, Plans: f.s.Billing})
	f.s.Resolver = source
	f.s.Send.Resolver = source
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage, Billing: f.s.Billing, Resolver: source, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: f.s.PublicURL})
	var id uuid.UUID
	if pdf {
		if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
				t.Error(err)
			}
		})
		id = packageImported220(t, q, "Original native binding PDF").ID
	} else {
		created := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents", `{"name":"Native binding source","source_kind":"blocks","blocks_json":{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"Agreed terms for {{customer}}"},{"id":"sign","type":"signature_field","attrs":{"recipient_role":"signer"}}]},"variables_json":{}}`, q.cookie)
		var out struct{ ID uuid.UUID }
		if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &out) != nil || out.ID == uuid.Nil {
			t.Fatal("genuine binding document birth", created.Code, created.Body.String())
		}
		id = out.ID
	}
	base := "/api/v1/documents/" + id.String()
	response := submitSessionOperationE2E(f.s, http.MethodPost, base+"/recipients", `{"email":"binding-native@example.test","name":"Native Binding Signer","role":"signer","locale":"en"}`, q.cookie)
	var recipient recipientResponse
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &recipient) != nil {
		t.Fatal("genuine binding party", response.Code, response.Body.String())
	}
	if pdf {
		w := httptest.NewRecorder()
		f.s.Routes().ServeHTTP(w, ownedPlainRequestV1(t, q, "REST", "add_document_field", "", map[string]any{"document_id": id.String(), "recipient_id": recipient.ID.String(), "type": "signature", "page": 1, "required": true, "label": "Signature", "x_pct": 20, "y_pct": 65, "w_pct": 40, "h_pct": 10}, nil))
		if w.Code != http.StatusCreated {
			t.Fatal("genuine manual signature placement", w.Code, w.Body.String())
		}
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.q.ListVariableBindings(f.ctx, id)
	if err != nil || len(rows) != 0 {
		t.Fatal("new native source must have no synthetic binding", err)
	}
	q.f.doc = doc
	return q, doc
}
func nativeBindingPublic259(q *ownedPublicReadFixtureV1, ctx context.Context, id uuid.UUID, method, body, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, q.f.s.PublicURL+"/api/v1/documents/"+id.String()+"/variable-bindings/customer", strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", q.f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, r)
	return w
}
func nativeBindingMeasurement259(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) {
	t.Helper()
	var total, measured int
	err := f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,count(*) FILTER(WHERE m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer)::integer FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.document_id=$1 AND e.org_id=$2`, id, f.org).Scan(&total, &measured)
	if err != nil || total == 0 || total != measured {
		t.Fatal("actual public journey omitted original native event measurement", total, measured, err)
	}
	rows, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(rows)
	if result := verifier.Result(); !result.OK || !result.Complete || result.TotalChecked != len(rows) {
		t.Fatal("actual binding event chain differs", result)
	}
}
func nativeBindingSnapshot259(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) string {
	t.Helper()
	var out string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object('document',(SELECT to_jsonb(d) FROM documents d WHERE id=$1 AND org_id=$2),'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.variable_name),'[]'::jsonb) FROM document_variable_bindings b WHERE b.document_id=$1),'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.created_at,e.id),'[]'::jsonb) FROM events e WHERE e.document_id=$1 AND e.org_id=$2),'measurements',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.event_id),'[]'::jsonb) FROM html_snapshot_event_payload_sizes_v1 m WHERE m.document_id=$1 AND m.org_id=$2),'reports',(SELECT coalesce(jsonb_agg(to_jsonb(p)),'[]'::jsonb) FROM document_participant_reports_v1 p WHERE p.document_id=$1 AND p.org_id=$2))::text`, id, q.f.org).Scan(&out)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Public unresolved creation precedes normal native Send and actual signing.
// The mandatory report must consume that exact new event, without reader repair.
func TestNativeVariableBindingPublicSendAndMandatoryReportV1E2E(t *testing.T) {
	for _, via := range []string{"REST", "MCP"} {
		for _, pdf := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/pdf=%v", via, pdf), func(t *testing.T) {
				q, doc := nativeBindingDocument259(t, pdf)
				f := q.f
				org, err := f.q.GetOrg(f.ctx, f.org)
				if err != nil {
					t.Fatal(err)
				}
				if via == "REST" {
					response := nativeBindingPublic259(q, f.ctx, doc.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, q.cookie)
					var dto bindingDTO
					if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &dto) != nil || dto.Variable != "customer" || dto.SourceKind != "org.setting" || dto.LastResolved != "" || dto.LastValue != "" {
						t.Fatal("genuine unresolved REST binding", response.Code, response.Body.String())
					}
				} else {
					key, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
					fixture := variableBindingAuthorizationFixture{lifecycleAuthorizationFixture: f}
					fieldMCPTextE2E(t, submitVariableBindingMCPE2E(fixture, f.ctx, "bind_variable_to_org_setting", key.Plaintext, map[string]any{"document_id": doc.ID.String(), "variable": "customer", "path": "org.name"}), false)
				}
				bindings, err := f.q.ListVariableBindings(f.ctx, doc.ID)
				if err != nil || len(bindings) != 1 || bindings[0].LastResolved.Valid || bindings[0].LastValue != "" || bindings[0].LastError != "" || bindings[0].Fallback != "" {
					t.Fatal("public binding was not actually unresolved", err)
				}
				nativeBindingMeasurement259(t, f, doc.ID)
				// The public report commits the original event row rather than
				// publishing private binding payload fields as narrative text.
				// Bind its exact original four-key payload to the signed tuple.
				events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
				if err != nil {
					t.Fatal(err)
				}
				var bindingEvent *generated.Event
				tool := "upsert_variable_binding"
				if via == "MCP" {
					tool = "bind_variable_to_org_setting"
				}
				for _, event := range events {
					if event.OrgID != f.org || !event.DocumentID.Valid || uuid.UUID(event.DocumentID.Bytes) != doc.ID || event.Kind != audit.KindDocumentUpdated {
						continue
					}
					var fields map[string]any
					if json.Unmarshal(event.PayloadHashed, &fields) != nil {
						t.Fatal("invalid actual hashed event payload")
					}
					if fields["variable"] != "customer" {
						continue
					}
					row, rowErr := audit.RecomputeEventRowHash(event)
					if bindingEvent != nil || len(fields) != 4 || fields["source_kind"] != "org.setting" || fields["via"] != strings.ToLower(via) || fields["tool"] != tool || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != f.user.ID || rowErr != nil || !bytes.Equal(row, event.RowHash) {
						t.Fatal("actual binding event lost exact original payload or actor association", rowErr)
					}
					bindingEvent = event
				}
				if bindingEvent == nil {
					t.Fatal("actual public binding event absent")
				}
				response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/send", `{"lawful_basis":"contract"}`, q.cookie)
				var sent sendDocumentResponse
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &sent) != nil || len(sent.Links) != 1 {
					t.Fatal("public binding native Send", response.Code, response.Body.String())
				}
				frozen, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
				if err != nil {
					t.Fatal(err)
				}
				var values map[string]string
				bindings, err = f.q.ListVariableBindings(f.ctx, doc.ID)
				if json.Unmarshal(frozen.VariablesJson, &values) != nil || values["customer"] != org.Name || err != nil || len(bindings) != 1 || bindings[0].LastValue != org.Name || !bindings[0].LastResolved.Valid {
					t.Fatal("native Send omitted real frozen source/observation", err)
				}
				u, err := url.Parse(sent.Links[0].URL)
				if err != nil {
					t.Fatal(err)
				}
				token := strings.TrimPrefix(u.Path, "/sign/")
				terminal, err := ordinaryPreparationSign249(t, q, token, sent.Links[0].Name)
				if err != nil || terminal == nil || !terminal.Completed {
					t.Fatal("binding event prevented genuine completion/report", err)
				}
				completed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
				if err != nil || completed.Status != "completed" {
					t.Fatal("actual completed document absent", err)
				}
				payload, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID)
				if err != nil {
					t.Fatal(err)
				}
				signature, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID)
				if err != nil {
					t.Fatal(err)
				}
				claims, err := evidence.ParseCertificateCommitments(payload)
				if err != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || claims.ParticipantReportRows < 3 || !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
					t.Fatal("mandatory report/actual detached signature absent", err)
				}
				report := assertFreshParticipantReport406(t, f, completed, payload)
				wantEvent := render.ParticipantReportEventV1{ID: bindingEvent.ID.String(), DocumentID: doc.ID.String(), Kind: audit.KindDocumentUpdated, At: bindingEvent.CreatedAt.Time.UTC().Format(time.RFC3339Nano), ActorID: f.user.ID.String(), RecipientID: "", RowSHA256: hex.EncodeToString(bindingEvent.RowHash)}
				matches := 0
				for _, event := range report.Events {
					if event.Event.ID == bindingEvent.ID.String() {
						if event.Event != wantEvent {
							t.Fatal("signed report binding event differs from original hashed row")
						}
						matches++
					}
				}
				if matches != 1 {
					t.Fatal("signed report omitted or duplicated actual public binding event", matches)
				}
				var reports int
				var exact bool
				if err = f.pool.QueryRow(f.ctx, "SELECT count(*)::integer,coalesce(bool_and(encode(report_sha256,'hex')=$3 AND final_pdf_sha256=$4 AND audit_payload_sha256=$5),false) FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, f.org, claims.ParticipantReportSHA256, completed.FinalPdfSha, completed.AuditPayloadSha256).Scan(&reports, &exact); err != nil || reports != 1 || !exact {
					t.Fatal("actual mandatory report receipt lost exact artifact association", err)
				}
				w := httptest.NewRecorder()
				f.s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, terminal.AuditCertURL, nil).WithContext(f.ctx))
				if w.Code != http.StatusOK || !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF-")) {
					t.Fatal("mandatory report public download", w.Code)
				}
				nativeBindingMeasurement259(t, f, doc.ID)
				q.assertObserversOnlyV1(t)
			})
		}
	}
}

func TestNativeVariableBindingChildSourceAndIdempotentDeleteV1E2E(t *testing.T) {
	f := setupNativeLifecycleAuthorization256(t, "owner", false, true)
	// The child journey uses the concrete supported native source itself.
	f.s.Send.Resolver = resolver.New(f.q, &resolver.OrgSettingSource{Q: f.q})
	org, err := f.q.GetOrg(f.ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	children, err := f.s.Envelopes.Children(f.ctx, f.doc.ID, f.org)
	if err != nil || len(children) != 2 {
		t.Fatal(err)
	}
	id := children[0].ID
	put := func(name string) *httptest.ResponseRecorder {
		return submitSessionOperationE2E(f.s, http.MethodPut, "/api/v1/documents/"+id.String()+"/variable-bindings/"+name, `{"source_kind":"org.setting","source_path":"org.name"}`, cookie)
	}
	if r := put("bound_customer"); r.Code != http.StatusOK {
		t.Fatal("actual child binding", r.Code, r.Body.String())
	}
	if r := put("discarded"); r.Code != http.StatusOK {
		t.Fatal(r.Code, r.Body.String())
	}
	for range 2 {
		if r := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/documents/"+id.String()+"/variable-bindings/discarded", "", cookie); r.Code != http.StatusNoContent {
			t.Fatal("native delete no longer idempotent", r.Code, r.Body.String())
		}
	}
	var deletes int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='document.updated' AND payload_json->>'tool'='delete_variable_binding'", id).Scan(&deletes); err != nil || deletes != 2 {
		t.Fatal("original idempotent delete audit count changed", err)
	}
	response := f.submit("send", cookie)
	if response.Code != http.StatusOK {
		t.Fatal("actual root Send after child source mutation", response.Code, response.Body.String())
	}
	child, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	var values map[string]string
	if err != nil || child.Status != "sent" || json.Unmarshal(child.VariablesJson, &values) != nil || values["bound_customer"] != org.Name {
		t.Fatal("genuine logical child source did not freeze", err)
	}
	bindings, err := f.q.ListVariableBindings(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var observed bool
	for _, binding := range bindings {
		if binding.VariableName == "bound_customer" {
			observed = binding.LastResolved.Valid && binding.LastValue == org.Name && binding.LastError == ""
		}
	}
	if !observed {
		t.Fatal("real child source observation absent")
	}
	nativeBindingMeasurement259(t, f, id)
}

func TestNativeVariableBindingMeasurementFailureAndAuditExpiryRollbackV1E2E(t *testing.T) {
	t.Run("fresh measurement failure", func(t *testing.T) {
		q, doc := nativeBindingDocument259(t, false)
		f := q.f
		before := nativeBindingSnapshot259(t, q, doc.ID)
		name := "binding_measurement_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.document_id='%s'::uuid THEN RAISE EXCEPTION 'fixture fresh binding measurement failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON html_snapshot_event_payload_sizes_v1 FOR EACH ROW EXECUTE FUNCTION %s()`, name, doc.ID, name, name)); err != nil {
			t.Fatal(err)
		}
		drop := func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err := f.pool.Exec(cleanup, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON html_snapshot_event_payload_sizes_v1; DROP FUNCTION IF EXISTS %s()", name, name)); err != nil {
				t.Error(err)
			}
		}
		t.Cleanup(drop)
		r := nativeBindingPublic259(q, f.ctx, doc.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, q.cookie)
		if r.Code != http.StatusInternalServerError {
			t.Fatal("missing fresh event receipt was accepted", r.Code, r.Body.String())
		}
		if nativeBindingSnapshot259(t, q, doc.ID) != before {
			t.Fatal("failed fresh measurement changed source/definition/event/cache/report")
		}
		drop()
		if r = nativeBindingPublic259(q, f.ctx, doc.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, q.cookie); r.Code != http.StatusOK {
			t.Fatal("fresh authorized retry", r.Code, r.Body.String())
		}
		nativeBindingMeasurement259(t, f, doc.ID)
	})
	t.Run("original cookie expires after audit wait", func(t *testing.T) {
		q, doc := nativeBindingDocument259(t, false)
		f := q.f
		before := nativeBindingSnapshot259(t, q, doc.ID)
		blocker, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.q.WithTx(blocker).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
			nativeReminderRollback255(t, blocker)
			t.Fatal(err)
		}
		cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
		result, cancel, joined := nativeReminderAsyncHTTP255(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder {
			return nativeBindingPublic259(q, ctx, doc.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, cookie)
		})
		defer nativeReminderCleanupHTTP255(t, blocker, cancel, joined)
		awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
		awaitSessionCookieExpiryE2E(t, f.s, cookie)
		if err = blocker.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		r := receiveSessionOperationE2E(t, result)
		if r.Code != http.StatusUnauthorized {
			t.Fatal("original expired credential survived audit wait", r.Code, r.Body.String())
		}
		if nativeBindingSnapshot259(t, q, doc.ID) != before {
			t.Fatal("expired original credential changed binding/evidence/cache")
		}
	})
}

// Deliberately old observation source data is a separate body-sizing control,
// not a claim that a resolver, signature or historical measurement produced it.
// Only the subsequent public mutation and its fresh event are qualified here.
func TestNativeVariableBindingOwnsPreexistingObservationBeforeReturningV1E2E(t *testing.T) {
	q, doc := nativeBindingDocument259(t, false)
	f := q.f
	response := nativeBindingPublic259(q, f.ctx, doc.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, q.cookie)
	if response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	rows, err := f.q.ListVariableBindings(f.ctx, doc.ID)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	old := rows[0]
	value := strings.Repeat("Legacy observation Å<&\n", 4096)
	if count, err := f.q.UpdateVariableBindingResolved(f.ctx, generated.UpdateVariableBindingResolvedParams{DocumentID: doc.ID, OrgID: f.org, VariableName: "customer", LastValue: value, ExpectedDocumentUpdatedAt: doc.UpdatedAt, ExpectedBindingCreatedAt: old.CreatedAt, ExpectedBindingUpdatedAt: old.UpdatedAt}); err != nil || count != 1 {
		t.Fatal("fixture-owned old observation source", count, err)
	}
	rows, err = f.q.ListVariableBindings(f.ctx, doc.ID)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	old = rows[0]
	if count, err := f.q.UpdateVariableBindingError(f.ctx, generated.UpdateVariableBindingErrorParams{DocumentID: doc.ID, OrgID: f.org, VariableName: "customer", LastError: "Legacy observation failure", ExpectedDocumentUpdatedAt: doc.UpdatedAt, ExpectedBindingCreatedAt: old.CreatedAt, ExpectedBindingUpdatedAt: old.UpdatedAt}); err != nil || count != 1 {
		t.Fatal("fixture-owned old error source", count, err)
	}
	rows, err = f.q.ListVariableBindings(f.ctx, doc.ID)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	old = rows[0]
	response = nativeBindingPublic259(q, f.ctx, doc.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.id","source_ref":"new definition"}`, q.cookie)
	var dto bindingDTO
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &dto) != nil || dto.LastValue != value || dto.LastError != old.LastError || dto.LastResolved == "" || dto.SourcePath != "org.id" || dto.SourceRef != "new definition" {
		t.Fatal("native public RETURNING lost actual old observation", response.Code)
	}
	rows, err = f.q.ListVariableBindings(f.ctx, doc.ID)
	if err != nil || len(rows) != 1 || rows[0].CreatedAt != old.CreatedAt || rows[0].LastValue != old.LastValue || rows[0].LastError != old.LastError || rows[0].LastResolved != old.LastResolved {
		t.Fatal("binding definition mutation changed original observation semantics", err)
	}
	nativeBindingMeasurement259(t, f, doc.ID)
	q.assertObserversOnlyV1(t)
}

func TestNativeVariableBindingRetainsAllOrgSenderPolicyAndScopedUnbindV1E2E(t *testing.T) {
	q, doc := nativeBindingDocument259(t, false)
	f := q.f
	sender, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@binding-sender.test", Name: "Another sender", Role: "sender"})
	if err != nil || sender.ID == doc.SenderID {
		t.Fatal("distinct actual sender fixture unavailable", err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, sender.ID, sender.SessionGeneration, time.Hour)
	response := nativeBindingPublic259(q, f.ctx, doc.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, cookie)
	if response.Code != http.StatusOK {
		t.Fatal("original all-org sender policy was narrowed", response.Code, response.Body.String())
	}
	before := nativeBindingSnapshot259(t, q, doc.ID)
	viewer, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@binding-viewer.test", Name: "Actual viewer", Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		response = nativeBindingPublic259(q, f.ctx, doc.ID, method, `{"source_kind":"org.setting","source_path":"org.name"}`, dsrSessionCookieE2E(t, f.s, viewer.ID, viewer.SessionGeneration, time.Hour))
		if response.Code != http.StatusForbidden {
			t.Fatal("viewer mutated native binding", response.Code)
		}
	}
	fixture := variableBindingAuthorizationFixture{lifecycleAuthorizationFixture: f}
	scoped, _ := mintRecipientMCPKeyE2E(t, f, true, 0)
	fieldMCPTextE2E(t, submitVariableBindingMCPE2E(fixture, f.ctx, "unbind_variable", scoped.Plaintext, map[string]any{"document_id": uuid.NewString(), "variable": "customer"}), true)
	if nativeBindingSnapshot259(t, q, doc.ID) != before {
		t.Fatal("role/sandbox refusal changed native binding/evidence")
	}
	fieldMCPTextE2E(t, submitVariableBindingMCPE2E(fixture, f.ctx, "unbind_variable", scoped.Plaintext, map[string]any{"document_id": doc.ID.String(), "variable": "customer"}), false)
	rows, err := f.q.ListVariableBindings(f.ctx, doc.ID)
	if err != nil || len(rows) != 0 {
		t.Fatal("actual scoped unbind did not commit", err)
	}
	nativeBindingMeasurement259(t, f, doc.ID)
	q.assertObserversOnlyV1(t)
}
