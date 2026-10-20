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
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func ownedBlocksTemplateRequestV1(t *testing.T, f lifecycleAuthorizationFixture, cookie, method, route string, body any) *http.Request {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, f.s.PublicURL+route, bytes.NewReader(raw)).WithContext(f.ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	return r
}
func ownedBlocksTemplateCallV1(t *testing.T, f lifecycleAuthorizationFixture, cookie, method, route string, body any) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, ownedBlocksTemplateRequestV1(t, f, cookie, method, route, body))
	return w
}
func ownedBlocksTemplateCacheV1(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) string {
	t.Helper()
	var state string
	err := f.pool.QueryRow(f.ctx, "SELECT COALESCE((SELECT row_to_json(c)::text FROM pdf_template_source_sizes_v1 c WHERE c.template_id=$1),'missing')", id).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func ownedBlocksTemplateExactSourceV1(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) {
	t.Helper()
	var exact bool
	var expectedRaw int64
	err := f.pool.QueryRow(f.ctx, `SELECT c.source_kind='blocks' AND t.source_kind='blocks' AND c.org_id=t.org_id
 AND c.template_created_at=t.created_at AND c.template_updated_at=t.updated_at AND c.template_version=t.version

 AND c.master_wire_bytes=COALESCE(octet_length(t.html_master_json::text),0) AND c.variables_wire_bytes=octet_length(t.variables_json::text)
 AND c.blocks_wire_bytes=octet_length(t.blocks_json::text) AND c.fields_wire_bytes=octet_length(t.fields_json::text)
 AND c.sanitization_wire_bytes=COALESCE(octet_length(t.pdf_sanitization_report::text),0)
 AND c.measurement_server_version_num=current_setting('server_version_num')::integer,
 (octet_length(t.name)::numeric+octet_length(t.source_kind)+COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)+COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint
 FROM templates t JOIN pdf_template_source_sizes_v1 c ON c.template_id=t.id WHERE t.id=$1 AND t.org_id=$2`, id, f.org).Scan(&exact, &expectedRaw)
	if err != nil || !exact {
		t.Fatal("genuine block template source measurement absent or stale", err)
	}
	header, err := f.q.GetNonHTMLTemplateSourceHeaderForShareV1(f.ctx, generated.GetNonHTMLTemplateSourceHeaderForShareV1Params{TemplateID: id, OrgID: f.org})
	if err != nil || header == nil || header.ID != id || header.OrgID != f.org || header.SourceKind != "blocks" || header.RawTextBytes != expectedRaw || header.MeasurementServerVersionNum != header.ServerVersionNum {
		t.Fatal("actual protected template raw source header differs", err)
	}
}

// Actual public REST template creation/update/detail and REST/MCP document
// instantiation share genuine fresh M97 sources. Direct SQL is only an
// independent exact observation or a negative role/cache stimulus, never repair.
func TestOwnedBlocksTemplateActualLifecycleAndSeedE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			ownedCreationPrepareProPlanV1(t, q)
			f := q.f
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			credential := cookie
			if transport == "mcp" {
				f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
				f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: versions.New(f.q), Billing: f.s.Billing, Send: f.s.Send, PDFCreationSessions: q.runtime.SessionsV1()})
				key, err := auth.MintAPIKey()
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, Name: "Owned template fixture read and authoring", KeyPrefix: key.Prefix, KeyHash: key.Hash, Scopes: []string{"read", "write:authoring"}}); err != nil {
					t.Fatal(err)
				}
				credential = key.Plaintext
			}
			hook := newOwnedPlainAuditGateV1(audit.KindTemplateCreated)
			t.Cleanup(hook.unblock)
			f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, e audit.Entry) {
				if e.Kind != audit.KindTemplateCreated {
					return
				}
				hook.eventID = id
				hook.entry = e
				close(hook.started)
				<-hook.release
				close(hook.returned)
			})
			body := map[string]any{"name": "Reusable exact block contract", "blocks_json": json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Customer {{customer}}"},{"type":"signature_field","attrs":{"recipient_role":"buyer"}}]}`), "variables_json": map[string]string{"customer": "Original template customer"}}
			response := newOwnedPlainResponseGateV1()
			t.Cleanup(response.unblock)
			done := make(chan struct{})
			defer func() {
				response.unblock()
				hook.unblock()
				ownedPlainAwaitV1(t, done, "template handler actual exit on cleanup")
				ownedCreationAssertDrainedV1(t, q, 2)
			}()
			request := ownedBlocksTemplateRequestV1(t, f, cookie, http.MethodPost, "/api/v1/templates", body)
			go func() { defer close(done); f.s.Routes().ServeHTTP(response, request) }()
			ownedPlainAwaitV1(t, response.started, "actual block template response")
			ownedPlainAwaitV1(t, hook.started, "actual template audit hook")
			id, ok := hook.entry.Payload["template_id"].(uuid.UUID)
			if !ok || id == uuid.Nil || hook.entry.DocumentID != nil || hook.entry.ActorUserID == nil || *hook.entry.ActorUserID != f.user.ID {
				t.Fatal("template org-only audit scope changed")
			}
			ownedBlocksTemplateExactSourceV1(t, f, id)
			ownedPlainAssertRetainedV1(t, q, "template response and actual hook")
			response.unblock()
			ownedPlainAwaitV1(t, done, "template response last use")
			if response.Code != http.StatusCreated {
				t.Fatalf("create template=%d %s", response.Code, response.Body.String())
			}
			ownedPlainAssertRetainedV1(t, q, "template hook after response returned")
			hook.unblock()
			ownedPlainAwaitV1(t, hook.returned, "template actual hook return")
			ownedCreationAssertDrainedV1(t, q, 2)
			var initial templateResponse
			if err := json.Unmarshal(response.Body.Bytes(), &initial); err != nil {
				t.Fatal(err)
			}
			if initial.ID != id || len(initial.ContentSHA256) != 64 {
				t.Fatal("original template response/digest missing")
			}
			original, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: id, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			tree, err := blocks.ParseCanonicalTree(original.BlocksJson)
			if err != nil || len(tree.Blocks) != 2 || tree.Blocks[0].ID == "" {
				t.Fatal("original authoring normalizer IDs/defaults not persisted", err)
			}
			get := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodGet, "/api/v1/templates/"+id.String(), nil)
			if get.Code != http.StatusOK {
				t.Fatalf("native block get=%d %s", get.Code, get.Body.String())
			}
			var detail templateResponse
			if err := json.Unmarshal(get.Body.Bytes(), &detail); err != nil || detail.ContentSHA256 != initial.ContentSHA256 {
				t.Fatal("protected source changed original canonical digest", err)
			}
			if transport == "mcp" {
				read := submitRecipientMCPE2E(f, "get_template", credential, map[string]any{"id": id})
				var rpc struct {
					Result struct {
						IsError bool
						Content []struct{ Text string }
					}
				}
				if err := json.Unmarshal(read.Body.Bytes(), &rpc); err != nil || rpc.Result.IsError || len(rpc.Result.Content) != 1 {
					t.Fatalf("native MCP get_template %v %s", err, read.Body.String())
				}
				var tpl generated.Template
				if err := json.Unmarshal([]byte(rpc.Result.Content[0].Text), &tpl); err != nil || tpl.ID != id {
					t.Fatal("MCP original full template response changed", err)
				}
			}
			instantiate := func(name string, variables any) *generated.Document {
				t.Helper()
				args := map[string]any{"name": name, "source_kind": "blocks", "template_id": id}
				if variables != nil {
					args["variables_json"] = variables
				}
				doc := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, transport, credential, args), transport)
				stored, e := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
				if e != nil {
					t.Fatal(e)
				}
				if !stored.TemplateID.Valid || uuid.UUID(stored.TemplateID.Bytes) != id || !bytes.Equal(stored.BlocksJson, original.BlocksJson) {
					t.Fatal("actual native seed lost referenced template or exact canonical blocks")
				}
				var counts int
				if e = f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM document_signing_policy_sizes_v1 WHERE document_id=$1)+(SELECT count(*) FROM html_creation_response_sizes_v1 WHERE document_id=$1)+(SELECT count(*) FROM document_read_report_sizes_v1 WHERE document_id=$1)", doc.ID).Scan(&counts); e != nil || counts != 3 {
					t.Fatal("actual seeded document did not derive own three measurements", e)
				}
				return stored
			}
			seeded := instantiate("Original template seed", nil)
			if !bytes.Equal(seeded.VariablesJson, original.VariablesJson) {
				t.Fatal("omitted document variables did not use actual locked template")
			}
			overridden := instantiate("Explicit customer override", map[string]string{"customer": "Override exact customer"})
			if bytes.Equal(overridden.VariablesJson, original.VariablesJson) {
				t.Fatal("explicit variables override ignored")
			}
			changed := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, "/api/v1/templates/"+id.String(), map[string]any{"variables_json": map[string]string{"customer": "Revised template customer"}})
			if changed.Code != http.StatusOK {
				t.Fatalf("native block template update=%d %s", changed.Code, changed.Body.String())
			}
			updated, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: id, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			if updated.Version != original.Version+1 || updated.Name != original.Name || !bytes.Equal(updated.BlocksJson, original.BlocksJson) || bytes.Equal(updated.VariablesJson, original.VariablesJson) {
				t.Fatal("partial template update lost locked omitted source or version")
			}
			ownedBlocksTemplateExactSourceV1(t, f, id)
			latest := instantiate("Latest actual template", nil)
			if !bytes.Equal(latest.VariablesJson, updated.VariablesJson) {
				t.Fatal("fresh document seeded stale template variables")
			}
			oldcache := ownedBlocksTemplateCacheV1(t, f, id)
			if _, err = f.pool.Exec(f.ctx, "UPDATE users SET role='viewer' WHERE id=$1 AND org_id=$2", f.user.ID, f.org); err != nil {
				t.Fatal(err)
			}
			denied := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, "/api/v1/templates/"+id.String(), map[string]any{"name": "Forbidden rewrite"})
			if denied.Code != http.StatusForbidden {
				t.Fatalf("live viewer update=%d %s", denied.Code, denied.Body.String())
			}
			if ownedBlocksTemplateCacheV1(t, f, id) != oldcache {
				t.Fatal("role refusal altered source cache")
			}
			if _, err = f.pool.Exec(f.ctx, "UPDATE users SET role=$3 WHERE id=$1 AND org_id=$2", f.user.ID, f.org, f.user.Role); err != nil {
				t.Fatal(err)
			}
			var beforeDocs, beforeEvents int
			if err = f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM documents WHERE org_id=$1),(SELECT count(*) FROM events WHERE org_id=$1)", f.org).Scan(&beforeDocs, &beforeEvents); err != nil {
				t.Fatal(err)
			}
			if tag, e := f.pool.Exec(f.ctx, "DELETE FROM pdf_template_source_sizes_v1 WHERE template_id=$1 AND org_id=$2", id, f.org); e != nil || tag.RowsAffected() != 1 {
				t.Fatal("negative actual M97 delete", e)
			}
			unavailable := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodGet, "/api/v1/templates/"+id.String(), nil)
			if unavailable.Code != http.StatusServiceUnavailable {
				t.Fatalf("missing M97 normal read=%d %s", unavailable.Code, unavailable.Body.String())
			}
			refused := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, "/api/v1/templates/"+id.String(), map[string]any{"name": "No implicit repair"})
			if refused.Code != http.StatusServiceUnavailable {
				t.Fatalf("missing M97 update=%d %s", refused.Code, refused.Body.String())
			}
			failedSeed := submitDocumentCreationE2E(f, f.ctx, transport, credential, map[string]any{"name": "Must not materialize", "source_kind": "blocks", "template_id": id})
			if transport == "rest" {
				if failedSeed.Code != http.StatusServiceUnavailable {
					t.Fatalf("missing M97 seed=%d %s", failedSeed.Code, failedSeed.Body.String())
				}
			} else {
				var rpc struct{ Result struct{ IsError bool } }
				if err := json.Unmarshal(failedSeed.Body.Bytes(), &rpc); err != nil || !rpc.Result.IsError {
					t.Fatalf("missing M97 MCP seed %v %s", err, failedSeed.Body.String())
				}
			}
			var afterDocs, afterEvents int
			if err = f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM documents WHERE org_id=$1),(SELECT count(*) FROM events WHERE org_id=$1)", f.org).Scan(&afterDocs, &afterEvents); err != nil || afterDocs != beforeDocs || afterEvents != beforeEvents || ownedBlocksTemplateCacheV1(t, f, id) != "missing" {
				t.Fatal("missing-cache operation repaired or mutated application state", err)
			}
			persisted, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: id, OrgID: f.org})
			if err != nil || persisted.Name != updated.Name || persisted.Version != updated.Version || !bytes.Equal(persisted.BlocksJson, updated.BlocksJson) || !bytes.Equal(persisted.VariablesJson, updated.VariablesJson) {
				t.Fatal("negative operation changed actual template", err)
			}
			ownedCreationAssertDrainedV1(t, q, 2)
		})
	}
}
