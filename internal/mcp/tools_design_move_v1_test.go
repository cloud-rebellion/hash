// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestMoveDocumentToDesignVersionRegistrationSchemaAndScope(t *testing.T) {
	s := New(Deps{})
	tool, ok := s.tools["move_document_to_design_version"]
	if !ok || !tool.Write || tool.InputSchema["additionalProperties"] != false {
		t.Fatal("move tool missing, read-only or open")
	}
	if mcpToolRequiredScopes["move_document_to_design_version"] != mcpScopeWriteAuthoring || !docScopeSafeTools["move_document_to_design_version"] {
		t.Fatal("move tool needs write:authoring and must be usable with a document-scoped token")
	}
	input := designInputSchemaV1("move_document_to_design_version")
	required, _ := input["required"].([]string)
	for _, want := range []string{"expected_updated_at", "expected_html_source_commitment", "expected_template_content_sha256", "template_version"} {
		found := false
		for _, r := range required {
			found = found || r == want
		}
		if !found {
			t.Fatal("pin is not required in the schema:", want)
		}
	}
	props, _ := input["properties"].(map[string]any)
	for _, name := range []string{"values", "sections", "summary"} {
		if _, ok := props[name]; !ok {
			t.Fatal("optional field missing:", name)
		}
	}
	if !strings.Contains(tool.Description, "carried over exactly") || !strings.Contains(tool.Description, "fresh human review") {
		t.Fatal("description does not state the refusal and human review consequences")
	}
}

// A valid move needs the native input owner, which a transport fake cannot
// mint; the PostgreSQL e2e root covers the success path. Here only refusals
// that must never reach the bridge are checked.
func TestMoveDocumentToDesignVersionRefusalsNeverReachBridge(t *testing.T) {
	s, v, d := designTransport783(t)
	id := uuid.New()
	sha := strings.Repeat("a", 64)
	args := `{"document_id":"` + id.String() + `","input":{"expected_updated_at":"2026-11-07T10:00:00Z","expected_html_source_commitment":"` + sha + `","template_version":3,"expected_template_content_sha256":"` + sha + `"}}`
	for name, raw := range map[string]string{
		"unknown top-level field": strings.Replace(args, `"input"`, `"org_id":"forged","input"`, 1),
		"missing input":           `{"document_id":"` + id.String() + `"}`,
		"missing document":        `{"input":{}}`,
	} {
		resp := serviceEmailCall(t, s, v, "move_document_to_design_version", raw)
		if (resp.Error == nil && !decodedToolResult(t, resp).IsError) || d.calls != 0 {
			t.Fatal("malformed move reached the bridge:", name)
		}
	}
	// Control: with the scope the request passes the scope gate and fails later
	// (the fake transport has no native input owner), so a missing scope check
	// cannot hide behind that later failure.
	resp := serviceEmailCall(t, s, v, "move_document_to_design_version", args)
	control := decodedToolResult(t, resp)
	if !control.IsError || strings.Contains(control.Content[0].Text, "requires the 'write:authoring' scope") {
		t.Fatalf("control request must pass the scope gate: %+v", control)
	}
	v.scopes = []string{"read"}
	resp = serviceEmailCall(t, s, v, "move_document_to_design_version", args)
	denied := decodedToolResult(t, resp)
	if !denied.IsError || !strings.Contains(denied.Content[0].Text, "requires the 'write:authoring' scope") || d.calls != 0 {
		t.Fatalf("read-only key must be refused by the scope gate: %+v", denied)
	}
}
