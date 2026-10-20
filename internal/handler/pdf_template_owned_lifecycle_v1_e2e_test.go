//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
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
	"sync/atomic"
	"testing"
)

func ownedPDFTemplateExactSourceV1(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) {
	t.Helper()
	var exact bool
	header, err := q.f.q.GetPDFTemplateSourceHeaderForShareV1(q.f.ctx, generated.GetPDFTemplateSourceHeaderForShareV1Params{TemplateID: id, OrgID: q.f.org})
	if err != nil || header == nil || header.ID != id || header.OrgID != q.f.org || header.SourceKind != "pdf" || header.RawTextBytes < 0 || header.MeasurementServerVersionNum != header.ServerVersionNum {
		t.Fatal("actual PDF source header unavailable", err)
	}
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT c.org_id=t.org_id AND t.source_kind='pdf' AND c.source_kind=t.source_kind
 AND c.template_created_at=t.created_at AND c.template_updated_at=t.updated_at AND c.template_version=t.version
 AND $3::bigint=octet_length(t.name)::bigint+octet_length(t.source_kind)+COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)+COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0)
 AND c.master_wire_bytes=COALESCE(octet_length(t.html_master_json::text),0) AND c.blocks_wire_bytes=COALESCE(octet_length(t.blocks_json::text),0)
 AND c.variables_wire_bytes=COALESCE(octet_length(t.variables_json::text),0) AND c.fields_wire_bytes=COALESCE(octet_length(t.fields_json::text),0)
 AND c.sanitization_wire_bytes=COALESCE(octet_length(t.pdf_sanitization_report::text),0) AND c.measurement_server_version_num=current_setting('server_version_num')::integer
 FROM templates t JOIN pdf_template_source_sizes_v1 c ON c.template_id=t.id WHERE t.id=$1 AND t.org_id=$2`, id, q.f.org, header.RawTextBytes).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("actual native PDF template source/cache identity/stamps/all5JSON/server measurement mismatch", err)
	} //nolint:rawsql -- genuine fresh/update source oracle only
}
func ownedPDFTemplateStateV1(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) string {
	t.Helper()
	var state string
	if err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object('template',(SELECT to_jsonb(t) FROM templates t WHERE id=$1 AND org_id=$2),'source',(SELECT to_jsonb(c) FROM pdf_template_source_sizes_v1 c WHERE template_id=$1 AND org_id=$2),'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM events e WHERE org_id=$2 AND payload_json->>'template_id'=$1::text))::text`, id, q.f.org).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state //nolint:rawsql -- actual target refusal snapshot only
}
func TestOwnedPDFTemplateFieldsUpdateReadAndOriginalPolicyE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
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
	request := ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Actual reusable PDF source with named-party slots"))
	request.URL.Path = "/api/v1/templates"
	request.RequestURI = request.URL.Path
	response := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("actual PDF template upload=%d %s", response.Code, response.Body.String())
	}
	var template templateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &template); err != nil || template.ID == uuid.Nil {
		t.Fatal("actual template upload omitted ID", err)
	}
	original, err := q.f.q.GetTemplate(q.f.ctx, generated.GetTemplateParams{ID: template.ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	ownedPDFTemplateExactSourceV1(t, q, original.ID)
	ownedCreationAssertDrainedV1(t, q, 1)
	layout := pdflayout.Layout{Version: 1, Parties: []pdflayout.Party{{Role: "buyer", Label: "Buyer"}, {Role: "seller", Label: "Seller"}}, Fields: []pdflayout.Field{{PartyRole: "buyer", Type: "signature", Page: 1, XPct: 10, YPct: 55, WPct: 30, HPct: 8, Required: true, Label: "Buyer signature"}, {PartyRole: "seller", Type: "signature", Page: 1, XPct: 10, YPct: 70, WPct: 30, HPct: 8, Required: true, Label: "Seller signature"}}}
	raw, err := json.Marshal(map[string]any{"name": "Original PDF branch ignores this name", "fields_json": layout})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPatch, q.f.s.PublicURL+"/api/v1/templates/"+original.ID.String(), bytes.NewReader(raw)).WithContext(q.f.ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", q.f.s.PublicURL)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
	var current atomic.Pointer[ownedPlainAuditGateV1]
	hook := newOwnedPlainAuditGateV1(audit.KindTemplateUpdated)
	current.Store(hook)
	t.Cleanup(hook.unblock)
	q.f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, entry audit.Entry) {
		g := current.Load()
		if g == nil || entry.Kind != audit.KindTemplateUpdated {
			return
		}
		g.eventID = id
		g.entry = entry
		close(g.started)
		<-g.release
		close(g.returned)
	})
	gate := newOwnedPlainResponseGateV1()
	t.Cleanup(gate.unblock)
	done := make(chan struct{})
	go func() { defer close(done); q.f.s.Routes().ServeHTTP(gate, request) }()
	ownedPlainAwaitV1(t, gate.started, "actual PDF fields update response")
	if gate.Code != http.StatusOK {
		gate.unblock()
		ownedPlainAwaitV1(t, done, "actual refused PDF fields update")
		t.Fatalf("native template update=%d %s", gate.Code, gate.Body.String())
	}
	ownedPlainAwaitV1(t, hook.started, "actual org-only template.updated hook")
	if hook.entry.OrgID != q.f.org || hook.entry.ActorUserID == nil || *hook.entry.ActorUserID != q.f.user.ID || hook.entry.DocumentID != nil || hook.entry.RecipientID != nil || len(hook.entry.Payload) != 2 || hook.entry.Payload["template_id"] != original.ID || hook.entry.Payload["source_kind"] != "pdf" {
		t.Fatal("original org-only template updated event changed")
	}
	event, err := q.f.q.GetEventByID(q.f.ctx, hook.eventID)
	if err != nil {
		t.Fatal(err)
	}
	rowHash, err := audit.RecomputeEventRowHash(event)
	hookRaw, marshalErr := json.Marshal(hook.entry.Payload)
	if err != nil || marshalErr != nil || !bytes.Equal(rowHash, event.RowHash) || !bytes.Equal(hookRaw, event.PayloadHashed) {
		t.Fatal("org-only PDF update changed original chain/hash/hook bytes", err, marshalErr)
	}
	ownedPDFTemplateExactSourceV1(t, q, original.ID)
	ownedPlainAssertRetainedV1(t, q, "template updated response and hook")
	gate.unblock()
	ownedPlainAwaitV1(t, done, "actual template fields response last use")
	ownedPlainAssertRetainedV1(t, q, "actual PDF template source after response while joined hook remains")
	hook.unblock()
	ownedPlainAwaitV1(t, hook.returned, "template updated hook actual return")
	current.Store(nil)
	ownedCreationAssertDrainedV1(t, q, 1)
	updated, err := q.f.q.GetTemplate(q.f.ctx, generated.GetTemplateParams{ID: original.ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := pdflayout.Parse(updated.FieldsJson, updated.PageCount.Int32)
	if err != nil || parsed == nil || len(parsed.Parties) != 2 || len(parsed.Fields) != 2 || updated.Version != original.Version+1 || updated.Name != original.Name || updated.PdfStorageKey != original.PdfStorageKey || updated.PdfStorageVersionID != original.PdfStorageVersionID || !bytes.Equal(updated.PdfSha256, original.PdfSha256) || !bytes.Equal(updated.PdfSanitizationReport, original.PdfSanitizationReport) {
		t.Fatal("native fields update changed original source/name/report or lost canonical named-party layout", err)
	}
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.f.q.CreateAPIKey(q.f.ctx, generated.CreateAPIKeyParams{OrgID: q.f.org, UserID: q.f.user.ID, Name: "PDF template read fixture", KeyPrefix: key.Prefix, KeyHash: key.Hash, Scopes: []string{"read"}}); err != nil {
		t.Fatal(err)
	}
	for _, via := range []string{"REST", "MCP"} {
		response = httptest.NewRecorder()
		if via == "REST" {
			response = submitSessionOperationE2E(q.f.s, http.MethodGet, "/api/v1/templates/"+original.ID.String(), "", q.cookie)
		} else {
			q.f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "MCP", "get_template", key.Plaintext, map[string]any{"id": original.ID.String()}, nil))
		}
		var got generated.Template
		if via == "REST" {
			if response.Code != http.StatusOK {
				t.Fatalf("native PDF get=%d %s", response.Code, response.Body.String())
			}
			var detail templateResponse
			if err = json.Unmarshal(response.Body.Bytes(), &detail); err != nil || detail.ID != updated.ID || detail.Version != updated.Version {
				t.Fatal("native REST template response changed", err)
			}
		} else {
			if err = json.Unmarshal([]byte(fieldMCPTextE2E(t, response, false)), &got); err != nil || got.ID != updated.ID {
				t.Fatal("native MCP full template read changed actual identity", err)
			}
			var a, b bytes.Buffer
			if json.Compact(&a, got.FieldsJson) != nil || json.Compact(&b, updated.FieldsJson) != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
				t.Fatal("native MCP full template read changed actual source")
			}
		}
		ownedCreationAssertDrainedV1(t, q, 1)
	}
	response = submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/templates/"+original.ID.String(), `{"name":"Still ignored"}`, q.cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("original omitted-fields update=%d %s", response.Code, response.Body.String())
	}
	omitted, err := q.f.q.GetTemplate(q.f.ctx, generated.GetTemplateParams{ID: original.ID, OrgID: q.f.org})
	if err != nil || omitted.Name != original.Name || omitted.Version != updated.Version+1 || !bytes.Equal(omitted.FieldsJson, updated.FieldsJson) {
		t.Fatal("omitted fields/name original PDF policy changed", err)
	}
	ownedPDFTemplateExactSourceV1(t, q, original.ID)
	ownedCreationAssertDrainedV1(t, q, 1)
	if tag, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM pdf_template_source_sizes_v1 WHERE template_id=$1 AND org_id=$2", original.ID, q.f.org); err != nil || tag.RowsAffected() != 1 {
		t.Fatal(err)
	} //nolint:rawsql -- explicit negative source-cache deletion only
	before := ownedPDFTemplateStateV1(t, q, original.ID)
	blocked, err := q.f.pool.Begin(q.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	var locked uuid.UUID
	if err = blocked.QueryRow(q.f.ctx, "SELECT id FROM templates WHERE id=$1 AND org_id=$2 FOR UPDATE", original.ID, q.f.org).Scan(&locked); err != nil || locked != original.ID {
		t.Fatal(err)
	} //nolint:rawsql -- actual scalar template lock only
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/templates/"+original.ID.String(), "{}", q.cookie)
	}()
	awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, "-- name: GetNonHTMLTemplateSourceHeaderForShareV1", "transactionid")
	if _, err = q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if err = blocked.Commit(q.f.ctx); err != nil {
		t.Fatal(err)
	}
	response = receiveSessionOperationE2E(t, result)
	if response.Code != http.StatusForbidden {
		t.Fatalf("actual template author/cache order=%d %s", response.Code, response.Body.String())
	}
	if _, err = q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "owner"}); err != nil {
		t.Fatal(err)
	}
	ownedCreationAssertDrainedV1(t, q, 1)
	response = submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/templates/"+original.ID.String(), "{}", q.cookie)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing actual template source did not refuse=%d %s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "MCP", "get_template", key.Plaintext, map[string]any{"id": original.ID.String()}, nil))
	if got := fieldMCPTextE2E(t, response, true); !strings.Contains(got, "owned PDF template source unavailable") {
		t.Fatalf("missing source MCP read=%q", got)
	}
	if ownedPDFTemplateStateV1(t, q, original.ID) != before {
		t.Fatal("normal template read/update repaired missing cache or changed original source/audit")
	}
	ownedCreationAssertDrainedV1(t, q, 1)
}
