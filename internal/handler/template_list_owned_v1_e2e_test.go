//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/google/uuid"
	"net/http"
	"testing"
	"time"
)

func ownedTemplateListCacheStateV1(t *testing.T, f lifecycleAuthorizationFixture) string {
	t.Helper()
	var state string
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(c ORDER BY template_id) FROM pdf_template_source_sizes_v1 c WHERE org_id=$1),(SELECT jsonb_agg(c ORDER BY template_id) FROM html_authoring_template_sizes_v1 c WHERE org_id=$1))::text`, f.org).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// Genuine two block M97 producers plus a native HTML M92 producer prove the
// actual mixed page projection, original pagination/readonly roles/scopes,
// response last use, source cache refusal and scalar archival recovery.
func TestOwnedTemplateListActualMixedPageAndNoRepairE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	create := func(name string) templateResponse {
		t.Helper()
		w := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPost, "/api/v1/templates", map[string]any{"name": name, "blocks_json": json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Exact {{customer}} template"}]}`), "variables_json": map[string]string{"customer": name}})
		if w.Code != http.StatusCreated {
			t.Fatalf("actual list source create=%d %s", w.Code, w.Body.String())
		}
		var out templateResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	first, second := create("First exact template"), create("Second exact template")
	html := q.template // The genuine native fixture already created and approved this HTML template.
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Billing: f.s.Billing, Send: f.s.Send, PDFCreationSessions: q.runtime.SessionsV1()})
	mint, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, Name: "Actual template list read fixture", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"read"}}); err != nil {
		t.Fatal(err)
	}
	read := func(path string) ([]templateResponse, int64) {
		t.Helper()
		w := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodGet, path, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("actual template list=%d %s", w.Code, w.Body.String())
		}
		var out struct {
			Templates []templateResponse
			Total     int64
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Templates, out.Total
	}
	before := ownedTemplateListCacheStateV1(t, f)
	gate := newOwnedPlainResponseGateV1()
	t.Cleanup(gate.unblock)
	done := make(chan struct{})
	request := ownedBlocksTemplateRequestV1(t, f, cookie, http.MethodGet, "/api/v1/templates?limit=500", nil)
	defer func() {
		gate.unblock()
		ownedPlainAwaitV1(t, done, "template list handler actual cleanup")
		ownedCreationAssertDrainedV1(t, q, 2)
	}()
	go func() { defer close(done); f.s.Routes().ServeHTTP(gate, request) }()
	ownedPlainAwaitV1(t, gate.started, "actual template list response")
	ownedPlainAssertRetainedV1(t, q, "mixed page actual serialization")
	gate.unblock()
	ownedPlainAwaitV1(t, done, "mixed page response last use")
	if gate.Code != http.StatusOK {
		t.Fatalf("mixed list=%d %s", gate.Code, gate.Body.String())
	}
	ownedCreationAssertDrainedV1(t, q, 2)
	var page struct {
		Templates     []templateResponse
		Total         int64
		Limit, Offset int32
	}
	if err := json.Unmarshal(gate.Body.Bytes(), &page); err != nil || len(page.Templates) != 3 || page.Total != 3 || page.Limit != 500 || page.Offset != 0 {
		t.Fatalf("original list metadata/page changed: rows=%d total=%d limit=%d offset=%d err=%v body=%s", len(page.Templates), page.Total, page.Limit, page.Offset, err, gate.Body.String())
	}
	seen := map[uuid.UUID]templateResponse{}
	for _, row := range page.Templates {
		seen[row.ID] = row
		if len(row.HTMLMasterJSON) != 0 {
			t.Fatal("list copied excluded HTML inline master")
		}
	}
	if seen[first.ID].ContentSHA256 != first.ContentSHA256 || seen[second.ID].ContentSHA256 != second.ContentSHA256 || seen[html.ID].ContentSHA256 == "" {
		t.Fatal("mixed-kind native list changed original content commitments")
	}
	one, total := read("/api/v1/templates?limit=1")
	next, _ := read("/api/v1/templates?limit=1&offset=1")
	if len(one) != 1 || len(next) != 1 || total != 3 || one[0].ID == next[0].ID {
		t.Fatal("original actual page/offset changed")
	}
	rpc := submitRecipientMCPE2E(f, "list_templates", mint.Plaintext, map[string]any{"limit": 200})
	var call struct {
		Result struct {
			IsError bool
			Content []struct{ Text string }
		}
	}
	if err := json.Unmarshal(rpc.Body.Bytes(), &call); err != nil || call.Result.IsError || len(call.Result.Content) != 1 {
		t.Fatalf("actual read-scoped MCP list=%v %s", err, rpc.Body.String())
	}
	var listed struct {
		Templates []*generated.ListTemplatesRow
		Count     int
	}
	if err := json.Unmarshal([]byte(call.Result.Content[0].Text), &listed); err != nil || listed.Count != 3 || len(listed.Templates) != 3 {
		t.Fatal("original MCP list projection changed", err)
	}
	for _, row := range listed.Templates {
		if len(row.HtmlMasterJson) != 0 || len(row.PdfSanitizationReport) != 0 {
			t.Fatal("MCP list copied excluded cold source")
		}
	}
	if ownedTemplateListCacheStateV1(t, f) != before {
		t.Fatal("normal list remeasured source caches")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE users SET role='viewer' WHERE id=$1 AND org_id=$2", f.user.ID, f.org); err != nil {
		t.Fatal(err)
	}
	viewer, _ := read("/api/v1/templates")
	if len(viewer) != 3 {
		t.Fatal("original viewer list access lost")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE users SET role=$3 WHERE id=$1 AND org_id=$2", f.user.ID, f.org, f.user.Role); err != nil {
		t.Fatal(err)
	}
	writeOnly, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
	denied := submitRecipientMCPE2E(f, "list_templates", writeOnly.Plaintext, map[string]any{})
	ownedPlainDraftRPCRefusedV1(t, denied.Body.Bytes())
	if ownedTemplateListCacheStateV1(t, f) != before {
		t.Fatal("read scope refusal touched source caches")
	}
	if tag, e := f.pool.Exec(f.ctx, "DELETE FROM pdf_template_source_sizes_v1 WHERE template_id=$1 AND org_id=$2", second.ID, f.org); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("negative genuine M97 deletion", e)
	}
	missing := ownedTemplateListCacheStateV1(t, f)
	unavailable := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodGet, "/api/v1/templates", nil)
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing M97 page=%d %s", unavailable.Code, unavailable.Body.String())
	}
	missingRPC := submitRecipientMCPE2E(f, "list_templates", mint.Plaintext, map[string]any{})
	ownedPlainDraftRPCRefusedV1(t, missingRPC.Body.Bytes())
	if ownedTemplateListCacheStateV1(t, f) != missing {
		t.Fatal("normal page read repaired missing M97")
	}
	archived := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodDelete, "/api/v1/templates/"+second.ID.String(), nil)
	if archived.Code != http.StatusNoContent {
		t.Fatalf("scalar archive of uncached source=%d %s", archived.Code, archived.Body.String())
	}
	remaining, total := read("/api/v1/templates?limit=500")
	if len(remaining) != 2 || total != 2 {
		t.Fatal("archived template remained in active page")
	}
	if tag, e := f.pool.Exec(f.ctx, "DELETE FROM html_authoring_template_sizes_v1 WHERE template_id=$1 AND org_id=$2", html.ID, f.org); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("negative genuine HTML M92 deletion", e)
	}
	missingHTML := ownedTemplateListCacheStateV1(t, f)
	htmlAbsent := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodGet, "/api/v1/templates", nil)
	if htmlAbsent.Code != http.StatusServiceUnavailable || ownedTemplateListCacheStateV1(t, f) != missingHTML {
		t.Fatalf("missing HTML page cache did not refuse without repair=%d %s", htmlAbsent.Code, htmlAbsent.Body.String())
	}
	// No request/response, event or backend credit is forced during cleanup.
	ownedCreationAssertDrainedV1(t, q, 2)
}
