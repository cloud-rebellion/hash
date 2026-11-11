//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/mcp"
)

// Native MCP protocol coverage for move_document_to_design_version: an agent
// credential moves a draft only to a human-approved newer version, with every
// pin, and the move resets review.
func TestMCPDesignMoveDocumentToDesignVersionE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage, Billing: f.s.Billing, Versions: f.s.Versions, Send: f.s.Send, PDF: f.s.Sign.PDF, PDFCreationSessions: q.runtime.SessionsV1(), Design: f.s.MCPDesignBridgeV1()})
	key, _ := automationDocumentKeyE2E(t, q, "read", "write:authoring")
	master := htmlmaster.Master{SchemaVersion: 1, HTML: `<main><h1>First</h1><p><span data-hash-value="customer"></span></p></main>`, CSS: `@page{size:A4;margin:20mm;}`, Values: []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 200}}}
	var design struct {
		TemplateID uuid.UUID `json:"template_id"`
		Version    int32     `json:"version"`
		SHA        string    `json:"content_sha256"`
	}
	callDesign783(t, f, key, "create_design_template", map[string]any{"input": map[string]any{"name": "Movable design", "html_master_json": master, "variables_json": map[string]string{"customer": "Example customer"}}}, &design, false)
	template, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: design.TemplateID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	approveHTMLCreationTemplateE2E(t, f, template)
	var created struct {
		Document struct {
			ID uuid.UUID `json:"id"`
		} `json:"document"`
	}
	callDesign783(t, f, key, "create_document_from_design", map[string]any{"purpose": "document", "template_id": design.TemplateID, "input": map[string]any{"name": "Movable proposal", "request_id": uuid.New(), "expected_template_version": 1, "expected_template_content_sha256": design.SHA}}, &created, false)
	id := created.Document.ID
	readSource := func() htmlDocumentSourceResponse {
		var source struct {
			Declared htmlDocumentSourceResponse `json:"declared_source"`
		}
		callDesign783(t, f, key, "get_document_design_source", map[string]any{"document_id": id}, &source, false)
		return source.Declared
	}
	before := readSource()
	second := master
	second.HTML = `<main><h1>Second</h1><p><span data-hash-value="customer"></span></p></main>`
	var next struct {
		Version int32  `json:"version"`
		SHA     string `json:"content_sha256"`
	}
	callDesign783(t, f, key, "update_design_template", map[string]any{"template_id": design.TemplateID, "input": map[string]any{"name": "Movable design", "html_master_json": second, "variables_json": map[string]string{"customer": "Example customer"}, "expected_version": 1}}, &next, false)
	// move returns the tool's text: the refusal sentence on an error, so each
	// refusal is pinned by its content and not only by IsError.
	move := func(version int32, sha, updatedAt string, extra map[string]any, wantError bool) string {
		t.Helper()
		in := map[string]any{"expected_updated_at": updatedAt, "expected_html_source_commitment": before.HTMLSourceCommitment, "template_version": version, "expected_template_content_sha256": sha}
		for k, v := range extra {
			in[k] = v
		}
		return mcpToolTextE2E(t, f, key, "move_document_to_design_version", map[string]any{"document_id": id, "input": in}, wantError)
	}
	wantText := func(name, got, want string) {
		t.Helper()
		if !strings.Contains(got, want) {
			t.Fatalf("%s: refusal text %q does not contain %q", name, got, want)
		}
		if strings.Contains(got, "native design operation unavailable or refused") {
			t.Fatalf("%s: got the generic refusal %q", name, got)
		}
	}
	// An agent cannot approve, so version 2 is still unapproved: refused.
	wantText("unapproved target", move(next.Version, next.SHA, before.UpdatedAt, nil, true), "not an approved revision")
	template, err = f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: design.TemplateID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	approveHTMLCreationTemplateE2E(t, f, template) // a human approves
	wantText("stale updated_at", move(next.Version, next.SHA, "2000-01-01T00:00:00Z", nil, true), "reload its exact source")
	wantText("not forward", move(1, design.SHA, before.UpdatedAt, nil, true), "newer template version")
	wantText("undeclared value", move(next.Version, next.SHA, before.UpdatedAt, map[string]any{"values": map[string]string{"not_declared": "x"}}, true), "not declared")
	// U1: version 2 is approved but a newer approved version 3 now exists, so
	// the agent is told the target is superseded and not the generic refusal.
	third := second
	third.HTML = `<main><h1>Third</h1><p><span data-hash-value="customer"></span></p></main>`
	var latest struct {
		Version int32  `json:"version"`
		SHA     string `json:"content_sha256"`
	}
	callDesign783(t, f, key, "update_design_template", map[string]any{"template_id": design.TemplateID, "input": map[string]any{"name": "Movable design", "html_master_json": third, "variables_json": map[string]string{"customer": "Example customer"}, "expected_version": next.Version}}, &latest, false)
	template, err = f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: design.TemplateID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	approveHTMLCreationTemplateE2E(t, f, template)
	wantText("superseded target", move(next.Version, next.SHA, before.UpdatedAt, nil, true), "not the template's current version")
	next = latest
	if after := readSource(); after.TemplateVersion != 1 || after.HTMLSourceCommitment != before.HTMLSourceCommitment {
		t.Fatal("refused moves changed the document")
	}
	move(next.Version, next.SHA, before.UpdatedAt, map[string]any{"summary": "Agent moved to design two"}, false)
	after := readSource()
	if after.TemplateVersion != 3 || after.TemplateContentSHA256 != next.SHA || after.MaterializationRevision != before.MaterializationRevision+1 || after.HTMLSourceCommitment == before.HTMLSourceCommitment {
		t.Fatal("move did not append a revision on the approved version")
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	if err != nil || doc.HtmlReviewedAt.Valid || doc.Status != "draft" || doc.SentAt.Valid {
		t.Fatal("move kept a review or advanced the workflow", err)
	}
	// The PDF really was replaced, and the new state is not the old one.
	if hex.EncodeToString(doc.PdfSha256) != after.PDFSHA256 || after.PDFSHA256 == before.PDFSHA256 {
		t.Fatal("move did not replace the PDF", before.PDFSHA256, after.PDFSHA256)
	}
	// PostgreSQL re-serializes jsonb with spaces, so decode instead of matching text.
	var origin struct {
		TemplateVersion int32 `json:"template_version"`
	}
	if err = json.Unmarshal(doc.HtmlSourceJson, &origin); err != nil || origin.TemplateVersion != 1 {
		t.Fatal("immutable origin was rewritten", err, origin.TemplateVersion)
	}
	// F10: the audit event records that an agent made the move.
	var payload []byte
	if err = f.pool.QueryRow(f.ctx, `SELECT payload_json FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.updated' ORDER BY created_at DESC, id DESC LIMIT 1`, id, f.org).Scan(&payload); err != nil { //nolint:rawsql -- audit payload inspection
		t.Fatal(err)
	}
	var event map[string]any
	if json.Unmarshal(payload, &event) != nil || event["template_move"] != true || event["via"] != "mcp" || event["template_version"] != float64(3) {
		t.Fatalf("move audit event does not record via=mcp: %s", payload)
	}
	var via string
	if err = f.pool.QueryRow(f.ctx, `SELECT created_via FROM document_versions WHERE document_id=$1 AND org_id=$2 ORDER BY version_no DESC LIMIT 1`, id, f.org).Scan(&via); err != nil || via != "mcp" { //nolint:rawsql -- snapshot provenance inspection
		t.Fatal("agent move was not recorded as via mcp", via, err)
	}
}

// mcpToolTextE2E calls an MCP tool and returns its single text content, which
// is the refusal sentence when wantError is set.
func mcpToolTextE2E(t *testing.T, f lifecycleAuthorizationFixture, key, tool string, args map[string]any, wantError bool) string {
	t.Helper()
	w := submitRecipientMCPE2E(f, tool, key, args)
	var reply struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || len(reply.Error) > 0 || reply.Result.IsError != wantError || len(reply.Result.Content) != 1 {
		t.Fatalf("%s result differs: HTTP %d %s", tool, w.Code, w.Body.String())
	}
	return reply.Result.Content[0].Text
}
