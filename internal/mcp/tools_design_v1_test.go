// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/google/uuid"
)

// These are transport/delegation tests, not a substitute for the native PG/
// renderer workflow. The real RequireAPIKey installs its private admission;
// no fake transaction or test constructor supplies that receipt.
type designDelegation783 struct {
	DesignBridgeV1
	calls, closed int
	actor         DesignActorV1
	id            uuid.UUID
	selection     DesignTemplateReadInputV1
	failure       error
	beforeClose   bool
}
type designMarshal783 struct{ d *designDelegation783 }

func (m designMarshal783) MarshalJSON() ([]byte, error) {
	if m.d.closed != 0 {
		return nil, errors.New("native consumer closed before serialization")
	}
	m.d.beforeClose = true
	return []byte(`{"declared_source":"exact read"}`), nil
}
func (d *designDelegation783) DocumentSourceV1(_ context.Context, a DesignActorV1, id uuid.UUID) (DesignResultV1, error) {
	d.calls++
	d.actor = a
	d.id = id
	return DesignResultV1{Value: designMarshal783{d}, Release: func() { d.closed++ }}, d.failure
}
func (d *designDelegation783) ReadTemplateV1(_ context.Context, a DesignActorV1, id uuid.UUID, selection DesignTemplateReadInputV1) (DesignResultV1, error) {
	d.selection = selection
	return d.DocumentSourceV1(context.Background(), a, id)
}
func designTransport783(t *testing.T) (*Server, *serviceEmailCredentialFixture, *designDelegation783) {
	t.Helper()
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	v := &serviceEmailCredentialFixture{key: key, id: uuid.New(), user: uuid.New(), org: uuid.New(), role: "owner", scopes: []string{"read", "write:authoring"}}
	d := &designDelegation783{}
	s := NewServer()
	registerDesignToolsV1(s, Deps{Design: d})
	return s, v, d
}
func TestDesignMCP783OriginalCredentialAndResponseLastUse(t *testing.T) {
	for _, errorPath := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "error"}[errorPath], func(t *testing.T) {
			s, v, d := designTransport783(t)
			id := uuid.New()
			if errorPath {
				d.failure = errors.New("controlled refusal")
			}
			resp := serviceEmailCall(t, s, v, "get_document_design_source", `{"document_id":"`+id.String()+`"}`)
			if resp.Error != nil {
				t.Fatal(resp.Error)
			}
			result := decodedToolResult(t, resp)
			if result.IsError != errorPath || d.calls != 1 || d.closed != 1 || (!errorPath && !d.beforeClose) {
				t.Fatal("delegation/error serialization lost original consumer", d, result)
			}
			if d.actor.KeyID != v.id || d.actor.UserID != v.user || d.actor.OrgID != v.org || d.actor.Authorize == nil || d.id != id {
				t.Fatal("original verified actor/key/document not preserved")
			}
		})
	}
}
func TestDesignMCP783ScopeAndExplicitReviewRefusals(t *testing.T) {
	for _, kind := range []string{"wrong-scope", "wrong-document", "org-tool-document-token", "unreviewed", "forged-tenant"} {
		t.Run(kind, func(t *testing.T) {
			s, v, d := designTransport783(t)
			id := uuid.New()
			name := "get_document_design_source"
			args := `{"document_id":"` + id.String() + `"}`
			switch kind {
			case "wrong-scope":
				v.scopes = []string{"write:authoring"}
			case "wrong-document":
				v.document = uuid.New()
			case "org-tool-document-token":
				v.document = id
				name = "get_design_template"
				args = `{"template_id":"` + uuid.NewString() + `"}`
			case "unreviewed":
				name = "review_document_design"
				args = `{"document_id":"` + id.String() + `","visually_reviewed":false,"reviewed_pages":[1],"input":{}}`
			case "forged-tenant":
				args = `{"document_id":"` + id.String() + `","org_id":"` + uuid.NewString() + `"}`
			}
			resp := serviceEmailCall(t, s, v, name, args)
			if resp.Error == nil && !decodedToolResult(t, resp).IsError {
				t.Fatal("unsafe operation admitted")
			}
			if d.calls != 0 {
				t.Fatal("refused operation reached native adapter")
			}
		})
	}
}

func TestDesignMCP783ExactRetainedSelectionAndLastUse(t *testing.T) {
	id := uuid.New()
	sha := strings.Repeat("a", 64)
	for _, pinned := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "retained"}[pinned], func(t *testing.T) {
			s, v, d := designTransport783(t)
			args := map[string]any{"template_id": id}
			want := DesignTemplateReadInputV1{}
			if pinned {
				args["version"], args["expected_content_sha256"] = 1, sha
				want = DesignTemplateReadInputV1{Version: 1, ExpectedContentSHA256: sha}
			}
			raw, _ := json.Marshal(args)
			resp := serviceEmailCall(t, s, v, "get_design_template", string(raw))
			if resp.Error != nil || decodedToolResult(t, resp).IsError || d.selection != want || d.id != id || d.calls != 1 || !d.beforeClose || d.closed != 1 || d.actor.KeyID != v.id {
				t.Fatal("exact retained selection or native consumer lifetime lost", d, resp)
			}
		})
	}
	for _, bad := range []string{`"version":1`, `"expected_content_sha256":"` + sha + `"`, `"version":0,"expected_content_sha256":"` + sha + `"`, `"version":null,"expected_content_sha256":"` + sha + `"`, `"version":1,"expected_content_sha256":null`, `"version":1,"expected_content_sha256":"` + strings.Repeat("A", 64) + `"`, `"version":1,"expected_content_sha256":"` + strings.Repeat("z", 64) + `"`} {
		s, v, d := designTransport783(t)
		resp := serviceEmailCall(t, s, v, "get_design_template", `{"template_id":"`+id.String()+`",`+bad+`}`)
		if (resp.Error == nil && !decodedToolResult(t, resp).IsError) || d.calls != 0 {
			t.Fatal("partial or malformed retained pins reached native read", bad)
		}
	}
}
func TestDesignMCP783RegistrationAndGuidance(t *testing.T) {
	s := New(Deps{})
	for _, name := range []string{"create_design_template", "get_design_template", "update_design_template", "preview_design_template", "create_document_from_design", "get_document_design_source", "get_document_design_history", "download_document_pdf", "revise_document_design_values", "review_document_design", "move_document_to_design_version"} {
		tool, ok := s.tools[name]
		if !ok || mcpToolRequiredScopes[name] == "" || tool.InputSchema["additionalProperties"] != false {
			t.Fatal("design tool missing or open", name)
		}
	}
	// Template approval is human-only: no MCP tool, scope or guidance may offer it.
	if _, ok := s.tools["approve_design_template"]; ok || mcpToolRequiredScopes["approve_design_template"] != "" {
		t.Fatal("agents can approve design templates")
	}
	for _, uri := range []string{"hash://schema/html-master", "hash://guides/designed-documents"} {
		if _, ok := s.resources[uri]; !ok || !docScopeSafeResources[uri] {
			t.Fatal("design schema/guide unavailable", uri)
		}
	}
	for _, term := range []string{"EVERY PAGE", "NOT visual proof", "missing material", "new document", "simple", "page-break"} {
		if term == "page-break" {
			term = "break-before"
		}
		if !strings.Contains(designedDocumentGuideV1, term) {
			t.Fatal("missing design boundary", term)
		}
	}
	if !strings.Contains(s.tools["create_pdf_document"].Description, "NOT retained") || !strings.Contains(s.tools["create_document"].Description, "prefer the versioned design tools") {
		t.Fatal("compatibility intake still presented as preferred design source")
	}
}
func TestDesignMCP783EveryPageCoverage(t *testing.T) {
	for _, p := range [][]int{nil, {1}, {1, 1}, {0, 2}, {1, 3}, {1, 2, 3}} {
		if DesignPageCoverageV1(p, 2) == nil {
			t.Fatal("incomplete/duplicate/outside page coverage accepted", p)
		}
	}
	if err := DesignPageCoverageV1([]int{2, 1}, 2); err != nil {
		t.Fatal(err)
	}
	if DesignPageCoverageV1(nil, 0) == nil || DesignPageCoverageV1(make([]int, 501), 501) == nil {
		t.Fatal("invalid native page count accepted")
	}
}
func TestDesignMCP783PromptPreservesTermsWithoutMaterialDefaults(t *testing.T) {
	s := New(Deps{})
	brief := "Report for an internal audience. Use supplied figures unchanged; missing price and law remain open."
	for _, style := range []string{"designed", "simple"} {
		messages, err := s.prompts["draft_branded_document"].Renderer(map[string]string{"brief": brief, "style": style})
		if err != nil || len(messages) != 1 || !strings.Contains(messages[0].Content.Text, brief) || !strings.Contains(messages[0].Content.Text, "Requested style: "+style) {
			t.Fatal("brief or explicit route lost", err)
		}
	}
	messages, err := s.prompts["draft_consulting_agreement"].Renderer(map[string]string{"client_name": "Example customer", "provider_name": "Example provider", "monthly_fee": "provided amount and currency"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(messages[0].Content.Text, "€provided") || strings.Contains(messages[0].Content.Text, "term_months = 12") || strings.Contains(messages[0].Content.Text, "governing_law = Sweden") {
		t.Fatal("material commercial defaults invented")
	}
	var p DesignPreviewInputV1
	for _, raw := range []string{`{"values":null}`, `{"sections":null}`, `{"values":{"a":4}}`, `{"org_id":"forged"}`} {
		if designDecodeV1(json.RawMessage(raw), &p) == nil {
			t.Fatal("invalid declared-text input accepted", raw)
		}
	}
}
