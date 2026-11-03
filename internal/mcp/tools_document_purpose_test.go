// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDocumentPurposeToolContractV1(t *testing.T) {
	s := New(Deps{})
	tool, ok := s.tools["set_document_purpose"]
	if !ok || !tool.Write {
		t.Fatal("purpose write tool missing")
	}
	if mcpToolRequiredScopes["set_document_purpose"] != mcpScopeWriteAuthoring {
		t.Fatal("wrong purpose scope")
	}
	for _, name := range []string{"create_document", "create_pdf_document"} {
		properties := s.tools[name].InputSchema["properties"].(map[string]any)
		p := properties["purpose"].(map[string]any)
		if len(p["enum"].([]string)) != 3 {
			t.Fatal("missing explicit enum", name)
		}
		if _, ok := p["default"]; ok {
			t.Fatal("new inferred creation default", name)
		}
	}
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(""))
	if _, err := tool.Handler(req, json.RawMessage(`{"document_id":"00000000-0000-0000-0000-000000000001","expected_updated_at":"now","purpose":"document"}`)); err == nil {
		t.Fatal("unauthenticated purpose mutation accepted")
	}
}
