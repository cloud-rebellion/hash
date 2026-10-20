//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// No source/cache fixtures are inserted: template upload and fields PATCH are
// the real public malware/worker/source producers. Creator uses actual native
// SQL and original parser/binder/quota/event loops in both transports.
func ownedPDFMaterializationTemplateV1(t *testing.T, q *ownedPublicReadFixtureV1, parties, fields int) (*generated.Template, []pdflayout.Binding) {
	t.Helper()
	request := ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Genuine reusable source for original PDF party layout"))
	request.URL.Path = "/api/v1/templates"
	request.RequestURI = request.URL.Path
	response := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("actual reusable PDF upload=%d %s", response.Code, response.Body.String())
	}
	var created templateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.ID == uuid.Nil {
		t.Fatal("actual uploaded template missing identity", err)
	}
	layout := pdflayout.Layout{Version: 1, Parties: make([]pdflayout.Party, parties), Fields: make([]pdflayout.Field, fields)}
	bindings := make([]pdflayout.Binding, parties)
	for i := range layout.Parties {
		role := fmt.Sprintf("s%060d%03d", 0, i)
		layout.Parties[i] = pdflayout.Party{Role: role, Label: fmt.Sprintf("Original party %d", i)}
		bindings[i] = pdflayout.Binding{Role: role, Name: strings.Repeat("😀", 200), Email: fmt.Sprintf("party%03d@pdf-layout.example.test", i), Locale: "en"}
	}
	for i := range layout.Fields {
		layout.Fields[i] = pdflayout.Field{PartyRole: layout.Parties[i%parties].Role, Type: "signature", Page: 1, XPct: 10.1234, YPct: 20.5678, WPct: 20, HPct: 5, Required: true, Label: strings.Repeat("f", 64)}
	}
	raw, err := json.Marshal(map[string]any{"fields_json": layout})
	if err != nil {
		t.Fatal(err)
	}
	response = submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/templates/"+created.ID.String(), string(raw), q.cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("actual named-party layout update=%d %s", response.Code, response.Body.String())
	}
	template, err := q.f.q.GetTemplate(q.f.ctx, generated.GetTemplateParams{ID: created.ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	ownedPDFTemplateExactSourceV1(t, q, template.ID)
	ownedPlainAssertDrainedV1(t, q)
	return template, bindings
}
func ownedPDFMaterializationRequestV1(t *testing.T, q *ownedPublicReadFixtureV1, via, key string, template *generated.Template, bindings []pdflayout.Binding, name string) *http.Request {
	t.Helper()
	args := map[string]any{"name": name, "source_kind": "pdf", "template_id": template.ID.String(), "expected_template_version": template.Version, "parties": bindings, "variables_json": map[string]string{"contract.reference": "Actual exact source"}}
	if via == "MCP" {
		return ownedPlainRequestV1(t, q, "MCP", "create_document", key, args, nil)
	}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/api/v1/documents", bytes.NewReader(raw)).WithContext(q.f.ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", q.f.s.PublicURL)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
	return request
}
func ownedPDFMaterializationExactV1(t *testing.T, q *ownedPublicReadFixtureV1, template *generated.Template, id uuid.UUID, parties, fields int) {
	t.Helper()
	document, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: id, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	if document.SourceKind != "pdf" || document.Status != "draft" || !document.TemplateID.Valid || uuid.UUID(document.TemplateID.Bytes) != template.ID || document.SenderID != q.f.user.ID || document.PdfStorageKey != template.PdfStorageKey || document.PdfStorageVersionID != template.PdfStorageVersionID || document.EvidenceVersionPinsRequired != template.EvidenceVersionPinRequired || !bytes.Equal(document.PdfSha256, template.PdfSha256) || len(document.HtmlSourceJson) != 0 || len(document.HtmlCurrentSourceJson) != 0 || len(document.BlocksJson) != 0 {
		t.Fatal("actual template creator changed source identity or historical PDF pins")
	}
	var variables map[string]string
	if err = json.Unmarshal(document.VariablesJson, &variables); err != nil || variables["contract.reference"] != "Actual exact source" {
		t.Fatal("actual template variables override lost", err)
	}
	var exact bool
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT
 p.org_id=d.org_id AND p.html_origin_wire_bytes=0 AND p.html_current_wire_bytes=0 AND p.variables_wire_bytes=octet_length(d.variables_json::text)
 AND r.org_id=d.org_id AND r.blocks_wire_bytes=0 AND r.metadata_wire_bytes=octet_length(d.metadata::text)
 AND s.org_id=d.org_id AND s.report_wire_bytes=octet_length(d.metadata_redaction_report::text) AND s.report_wire_bytes>2
 AND p.measurement_server_version_num=current_setting('server_version_num')::integer AND r.measurement_server_version_num=p.measurement_server_version_num AND s.measurement_server_version_num=p.measurement_server_version_num
 FROM documents d JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id JOIN html_creation_response_sizes_v1 r ON r.document_id=d.id JOIN document_read_report_sizes_v1 s ON s.document_id=d.id WHERE d.id=$1 AND d.org_id=$2`, id, q.f.org).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("fresh actual template document lacks exact native M91/M92/M93", err)
	} //nolint:rawsql -- actual output oracle, never insertion or measurement
	rows, err := q.f.q.ListRecipientsByDocument(q.f.ctx, id)
	if err != nil || len(rows) != parties {
		t.Fatal("actual bound recipient set unavailable", err)
	}
	for i, row := range rows {
		role := fmt.Sprintf("s%060d%03d", 0, i)
		if row == nil || row.Role != role || row.Name != strings.Repeat("😀", 200) || row.Email != fmt.Sprintf("party%03d@pdf-layout.example.test", i) || row.OrderIndex != int32(i) || row.Locale != "en" || row.Status != "pending" || len(row.MagicTokenHash) != 32 {
			t.Fatal("actual fresh identities/order/token/locale differ from original canonical binder", i)
		}
	}
	var count int
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT count(*)::integer,bool_and(r.document_id=$1 AND r.status='pending' AND r.magic_token_hash IS NOT NULL AND r.locale='en') FROM recipients r WHERE r.document_id=$1`, id).Scan(&count, &exact)
	if err != nil || count != parties || !exact {
		t.Fatal("original normalized party materialization changed", count, err)
	} //nolint:rawsql -- actual fresh output oracle
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT count(*)::integer,bool_and(f.type='signature' AND f.required AND f.page=1 AND f.x_pct=10.1234 AND f.y_pct=20.5678 AND f.w_pct=20 AND f.h_pct=5 AND r.document_id=f.document_id AND c.field_id IS NOT NULL AND c.field_id=f.id AND c.document_id=f.document_id AND c.org_id=$2 AND c.options_wire_bytes=octet_length(f.options_json::text) AND c.measurement_server_version_num=current_setting('server_version_num')::integer)
 FROM document_fields f JOIN recipients r ON r.id=f.recipient_id LEFT JOIN field_signing_policy_sizes_v1 c ON c.field_id=f.id WHERE f.document_id=$1`, id, q.f.org).Scan(&count, &exact)
	if err != nil || count != fields || !exact {
		t.Fatal("actual original fields lost geometry/assignment/fresh native M91", count, err)
	} //nolint:rawsql -- every real newly inserted field, not synthetic cache rows
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT count(*)::integer,bool_and(e.org_id=$2 AND e.actor_user_id=$3 AND c.event_id IS NOT NULL AND c.event_id=e.id AND c.document_id=e.document_id AND c.org_id=e.org_id AND c.payload_wire_bytes=octet_length(e.payload_json::text) AND c.measurement_server_version_num=current_setting('server_version_num')::integer) FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 c ON c.event_id=e.id WHERE e.document_id=$1`, id, q.f.org, q.f.user.ID).Scan(&count, &exact)
	if err != nil || count != parties+fields+1 || !exact {
		t.Fatal("actual atomic template events lost original event or fresh native M94", count, err)
	} //nolint:rawsql -- exact complete real event set
}

type ownedPDFMaterializationHooksV1 struct {
	mu                       sync.Mutex
	document                 uuid.UUID
	expected                 int
	entries                  map[uuid.UUID]audit.Entry
	ready, release, returned chan struct{}
	once                     sync.Once
	returns                  atomic.Int64
}

func newOwnedPDFMaterializationHooksV1(expected int) *ownedPDFMaterializationHooksV1 {
	return &ownedPDFMaterializationHooksV1{expected: expected, entries: make(map[uuid.UUID]audit.Entry, expected), ready: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{})}
}
func (h *ownedPDFMaterializationHooksV1) unblock() { h.once.Do(func() { close(h.release) }) }
func (h *ownedPDFMaterializationHooksV1) hook(_ context.Context, id uuid.UUID, entry audit.Entry) {
	if entry.DocumentID == nil || (entry.Kind != audit.KindDocumentCreated && entry.Kind != audit.KindRecipientCreated && entry.Kind != "document.field_added") {
		return
	}
	h.mu.Lock()
	if h.document == uuid.Nil {
		h.document = *entry.DocumentID
	}
	if h.document != *entry.DocumentID {
		h.mu.Unlock()
		return
	}
	h.entries[id] = entry
	if len(h.entries) == h.expected {
		close(h.ready)
	}
	h.mu.Unlock()
	<-h.release
	if h.returns.Add(1) == int64(h.expected) {
		close(h.returned)
	}
}
func ownedPDFMaterializationAuditV1(t *testing.T, q *ownedPublicReadFixtureV1, h *ownedPDFMaterializationHooksV1, parties, fields int, via string) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.entries) != parties+fields+1 {
		t.Fatal("actual joined hook count lost event")
	}
	kinds := map[string]int{}
	for id, entry := range h.entries {
		if entry.OrgID != q.f.org || entry.DocumentID == nil || *entry.DocumentID != h.document || entry.ActorUserID == nil || *entry.ActorUserID != q.f.user.ID {
			t.Fatal("actual original event scope/actor changed")
		}
		kinds[entry.Kind]++
		event, err := q.f.q.GetEventByID(q.f.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := audit.RecomputeEventRowHash(event)
		raw, marshalErr := json.Marshal(entry.Payload)
		if err != nil || marshalErr != nil || !bytes.Equal(hash, event.RowHash) || !bytes.Equal(raw, event.PayloadHashed) {
			t.Fatal("original event chain/hash/actual joined payload bytes changed", err, marshalErr)
		}
		switch entry.Kind {
		case audit.KindRecipientCreated:
			if entry.RecipientID == nil || len(entry.Payload) != 5 || entry.Payload["via"] != via || entry.Payload["template_layout_version"] != 1 {
				t.Fatal("original layout recipient audit shape changed")
			}
		case "document.field_added":
			if entry.RecipientID != nil || len(entry.Payload) != 7 || entry.Payload["via"] != via || entry.Payload["type"] != "signature" || entry.Payload["required"] != true {
				t.Fatal("original assigned field audit shape changed")
			}
		case audit.KindDocumentCreated:
			expected := 6
			if via == "mcp" {
				expected = 8
			}
			if len(entry.Payload) != expected || entry.Payload["source_kind"] != "pdf" || entry.Payload["layout_version"] != 1 || entry.Payload["party_count"] != parties {
				t.Fatal("original template document audit shape changed")
			}
		}
	}
	if kinds[audit.KindDocumentCreated] != 1 || kinds[audit.KindRecipientCreated] != parties || kinds["document.field_added"] != fields {
		t.Fatal("original event kinds/cardinality changed", kinds)
	}
}
func ownedPDFMaterializationEstateV1(t *testing.T, q *ownedPublicReadFixtureV1) string {
	t.Helper()
	var state string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object('documents',(SELECT count(*) FROM documents WHERE org_id=$1),'recipients',(SELECT count(*) FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1),'fields',(SELECT count(*) FROM document_fields f JOIN documents d ON d.id=f.document_id WHERE d.org_id=$1),'policy',(SELECT count(*) FROM document_signing_policy_sizes_v1 WHERE org_id=$1),'response',(SELECT count(*) FROM html_creation_response_sizes_v1 WHERE org_id=$1),'reports',(SELECT count(*) FROM document_read_report_sizes_v1 WHERE org_id=$1),'field_measures',(SELECT count(*) FROM field_signing_policy_sizes_v1 WHERE org_id=$1),'events',(SELECT count(*) FROM events WHERE org_id=$1),'event_measures',(SELECT count(*) FROM html_snapshot_event_payload_sizes_v1 WHERE org_id=$1),'chain_head',(SELECT encode(row_hash,'hex') FROM events WHERE org_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1))::text`, q.f.org).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state //nolint:rawsql -- bounded synthetic disposable estate rollback oracle, no row/cache creation
}
func TestOwnedPDFTemplateActualRESTMCPAndOriginalMaximumAtomicLayoutE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	q.f.s.MCP = mcp.New(mcp.Deps{Pool: q.f.pool, Queries: q.f.q, Audit: q.f.s.Audit, Storage: q.f.s.Storage, Billing: q.f.s.Billing, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: q.f.s.PublicURL})
	if err := malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	key, _ := mintRecipientMCPKeyE2E(t, q.f, false, 0)
	small, smallBindings := ownedPDFMaterializationTemplateV1(t, q, 2, 2)
	var active atomic.Pointer[ownedPDFMaterializationHooksV1]
	q.f.s.Audit.Subscribe(func(ctx context.Context, id uuid.UUID, entry audit.Entry) {
		if h := active.Load(); h != nil {
			h.hook(ctx, id, entry)
		}
	})
	cases := []struct {
		via             string
		parties, fields int
		template        *generated.Template
		bindings        []pdflayout.Binding
	}{{"REST", 2, 2, small, smallBindings}, {"MCP", 2, 2, small, smallBindings}}
	for _, scenario := range cases {
		t.Run(scenario.via, func(t *testing.T) {
			hooks := newOwnedPDFMaterializationHooksV1(scenario.parties + scenario.fields + 1)
			active.Store(hooks)
			t.Cleanup(hooks.unblock)
			response := newOwnedPlainResponseGateV1()
			t.Cleanup(response.unblock)
			done := make(chan struct{})
			request := ownedPDFMaterializationRequestV1(t, q, scenario.via, key.Plaintext, scenario.template, scenario.bindings, "Actual native PDF template "+scenario.via)
			go func() { defer close(done); q.f.s.Routes().ServeHTTP(response, request) }()
			ownedPlainAwaitV1(t, response.started, "actual template creation response")
			refused := scenario.via == "REST" && response.Code != http.StatusCreated
			if scenario.via == "MCP" {
				var envelope struct {
					Result struct {
						IsError bool `json:"isError"`
					} `json:"result"`
					Error json.RawMessage `json:"error"`
				}
				if json.Unmarshal(response.preview, &envelope) != nil || envelope.Result.IsError || len(envelope.Error) > 0 {
					refused = true
				}
			}
			if refused {
				response.unblock()
				ownedPlainAwaitV1(t, done, "actual refused template response")
				t.Fatalf("actual %s template creation=%d %s", scenario.via, response.Code, response.Body.String())
			}
			ownedPlainAwaitV1(t, hooks.ready, "every actual layout audit hook")
			ownedPDFMaterializationExactV1(t, q, scenario.template, hooks.document, scenario.parties, scenario.fields)
			ownedPDFMaterializationAuditV1(t, q, hooks, scenario.parties, scenario.fields, strings.ToLower(scenario.via))
			ownedPlainAssertRetainedV1(t, q, "actual PDF template output and every audit hook")
			if scenario.via == "REST" {
				response.unblock()
				ownedPlainAwaitV1(t, done, "actual REST template response last use")
				ownedPlainAssertRetainedV1(t, q, "layout source after body while real hooks remain")
				hooks.unblock()
				ownedPlainAwaitV1(t, hooks.returned, "all actual REST layout hooks returned")
			} else {
				hooks.unblock()
				ownedPlainAwaitV1(t, hooks.returned, "all actual MCP layout hooks returned")
				ownedPlainAssertRetainedV1(t, q, "layout source after hooks while MCP serializer remains")
				response.unblock()
				ownedPlainAwaitV1(t, done, "actual MCP serializer last use")
				fieldMCPTextE2E(t, response.ResponseRecorder, false)
			}
			active.Store(nil)
			ownedPlainAssertDrainedV1(t, q)
		})
	}
	// Original admitted key is rechecked after the genuine template-parent wait,
	// before any fresh document/party write; revocation is not a cache exception.
	raceKey, raceID := mintRecipientMCPKeyE2E(t, q.f, false, 0)
	blocked, err := q.f.pool.Begin(q.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	var locked uuid.UUID
	if err = blocked.QueryRow(q.f.ctx, "SELECT id FROM templates WHERE id=$1 AND org_id=$2 FOR UPDATE", small.ID, q.f.org).Scan(&locked); err != nil || locked != small.ID {
		t.Fatal(err)
	} //nolint:rawsql -- actual scalar template lock only
	refused := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		out := httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(out, ownedPDFMaterializationRequestV1(t, q, "MCP", raceKey.Plaintext, small, smallBindings, "Original admitted key revocation"))
		refused <- out
	}()
	awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, "-- name: GetPDFTemplateSourceHeaderForShareV1", "transactionid")
	revoked := submitSessionOperationE2E(q.f.s, http.MethodDelete, "/api/v1/api-keys/"+raceID.String(), "", q.cookie)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("actual key revocation=%d %s", revoked.Code, revoked.Body.String())
	}
	revokedState := ownedPDFMaterializationEstateV1(t, q)
	if err = blocked.Commit(q.f.ctx); err != nil {
		t.Fatal(err)
	}
	rejected := receiveSessionOperationE2E(t, refused)
	if text := fieldMCPTextE2E(t, rejected, true); !strings.Contains(text, auth.ErrMutationPermissionRevoked.Error()) {
		t.Fatal("creator lost original admitted-credential revocation verdict", text)
	}
	if ownedPDFMaterializationEstateV1(t, q) != revokedState {
		t.Fatal("creator wrote document/party/audit/cache after original credential revocation")
	}
	ownedPlainAssertDrainedV1(t, q)
	maximum, bindings := ownedPDFMaterializationTemplateV1(t, q, pdflayout.MaxParties, pdflayout.MaxFields)
	hooks := newOwnedPDFMaterializationHooksV1(1101)
	active.Store(hooks)
	t.Cleanup(hooks.unblock)
	response := newOwnedPlainResponseGateV1()
	t.Cleanup(response.unblock)
	done := make(chan struct{})
	go func() {
		defer close(done)
		q.f.s.Routes().ServeHTTP(response, ownedPDFMaterializationRequestV1(t, q, "REST", "", maximum, bindings, "Original100 parties1000 fields"))
	}()
	ownedPlainAwaitV1(t, response.started, "original maximum atomic layout response")
	if response.Code != http.StatusCreated {
		response.unblock()
		ownedPlainAwaitV1(t, done, "refused original maximum response")
		t.Fatalf("original100/1000 native creation=%d %s", response.Code, response.Body.String())
	}
	ownedPlainAwaitV1(t, hooks.ready, "all1101 original actual joined audit hooks")
	ownedPDFMaterializationExactV1(t, q, maximum, hooks.document, 100, 1000)
	ownedPDFMaterializationAuditV1(t, q, hooks, 100, 1000, "rest")
	snapshot, err := q.runtime.SnapshotV1(q.f.org)
	pending := q.runtime.SessionsV1().PendingV1()
	if err != nil || snapshot.Global.ParentBytes <= 0 || snapshot.Global.DBStagingBytes <= 0 || snapshot.OrganisationGrants > 64 || snapshot.GlobalGrants > 128 || pending.HTMLAdmissions != 1 || pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.ObserverSessions != 2 {
		t.Fatal("1101 real events did not retain one bounded source admission under unchanged limits", snapshot, pending, err)
	}
	response.unblock()
	ownedPlainAwaitV1(t, done, "maximum response actual last use")
	ownedPlainAssertRetainedV1(t, q, "all1101 actual hooks after response last use")
	hooks.unblock()
	ownedPlainAwaitV1(t, hooks.returned, "all1101 actual hooks returned")
	active.Store(nil)
	ownedPlainAssertDrainedV1(t, q)
	// The same actual pro plan permits200 recipients. A second100-party insert
	// crosses it only inside the original prospective loop; every preceding fresh
	// document/party/event/cache write must roll back together, with no repair.
	before := ownedPDFMaterializationEstateV1(t, q)
	response2 := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response2, ownedPDFMaterializationRequestV1(t, q, "REST", "", maximum, bindings, "Actual atomic quota rollback"))
	if response2.Code != http.StatusPaymentRequired {
		t.Fatalf("original prospective quota refusal=%d %s", response2.Code, response2.Body.String())
	}
	if ownedPDFMaterializationEstateV1(t, q) != before {
		t.Fatal("refused layout left partial document, recipients, fields, audit chain or measurements")
	}
	ownedPlainAssertDrainedV1(t, q)
	// Current template version, original complete role map, and source cache are
	// real preconditions; normal authoring neither repairs nor fabricates them.
	stale := *small
	stale.Version--
	before = ownedPDFMaterializationEstateV1(t, q)
	response2 = httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response2, ownedPDFMaterializationRequestV1(t, q, "REST", "", &stale, smallBindings, "Actual stale template refusal"))
	if response2.Code != http.StatusPreconditionFailed || ownedPDFMaterializationEstateV1(t, q) != before {
		t.Fatal("actual template version precondition/order/atomicity changed", response2.Code, response2.Body.String())
	}
	ownedPlainAssertDrainedV1(t, q)
	response2 = httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response2, ownedPDFMaterializationRequestV1(t, q, "REST", "", small, smallBindings[:1], "Actual incomplete party map"))
	if response2.Code != http.StatusBadRequest || ownedPDFMaterializationEstateV1(t, q) != before {
		t.Fatal("original exact party map policy/atomicity changed", response2.Code, response2.Body.String())
	}
	ownedPlainAssertDrainedV1(t, q)
	if tag, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM pdf_template_source_sizes_v1 WHERE template_id=$1 AND org_id=$2", small.ID, q.f.org); err != nil || tag.RowsAffected() != 1 {
		t.Fatal(err)
	} //nolint:rawsql -- explicit negative cache removal only
	response2 = httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response2, ownedPDFMaterializationRequestV1(t, q, "MCP", key.Plaintext, small, smallBindings, "Actual missing template source"))
	if text := fieldMCPTextE2E(t, response2, true); !strings.Contains(text, "PDF template source") {
		t.Fatal("missing native source did not refuse", text)
	}
	var absent int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM pdf_template_source_sizes_v1 WHERE template_id=$1", small.ID).Scan(&absent); err != nil || absent != 0 {
		t.Fatal("normal creator repaired missing source", err)
	}
	if ownedPDFMaterializationEstateV1(t, q) != before {
		t.Fatal("missing source creator changed original estate")
	}
	ownedPlainAssertDrainedV1(t, q) //nolint:rawsql -- continued actual absence oracle only
}
