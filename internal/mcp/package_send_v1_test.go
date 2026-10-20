// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
)

const exactPackageSendArgsV1 = `{"document_id":"7691a386-97e8-42c9-a204-6b0ea8b00c73","lawful_basis":"contract","package_send":{"expected_updated_at":"2026-10-19T12:03:04.123456Z","package_id":"4e972fb2-ae22-4c84-a52d-93d66507b080","generation":"9007199254740993"}}`

func TestMCPPackageSendExactRuntimeArgumentsV1(t *testing.T) {
	parsed, err := parsePackageSendArgumentsV1([]byte(exactPackageSendArgsV1))
	if err != nil || !parsed.selection.ValidV1() || parsed.selection.Generation != 9007199254740993 {
		t.Fatal("exact package observation was rounded or omitted", err)
	}
	for _, raw := range []string{
		strings.Replace(exactPackageSendArgsV1, `"package_send":`, `"PACKAGE_SEND":`, 1),
		strings.Replace(exactPackageSendArgsV1, `"lawful_basis":"contract"`, `"lawful_basis":"contract","lawful_basis":"contract"`, 1),
		strings.Replace(exactPackageSendArgsV1, `"generation":"9007199254740993"`, `"generation":"7","generation":"8"`, 1),
		strings.Replace(exactPackageSendArgsV1, `"generation":"9007199254740993"`, `"generation":9007199254740993`, 1),
		strings.Replace(exactPackageSendArgsV1, `"generation":"9007199254740993"`, `"generation":"7","consent":true`, 1),
		strings.Replace(exactPackageSendArgsV1, `"package_send":{`, `"unexpected":1,"package_send":{`, 1),
		`{"document_id":"7691a386-97e8-42c9-a204-6b0ea8b00c73","lawful_basis":"contract","package_send":null}`,
		exactPackageSendArgsV1 + ` {}`, `null`, strings.Repeat(" ", 2049),
	} {
		if _, err := parsePackageSendArgumentsV1([]byte(raw)); err == nil {
			t.Fatal("ambiguous or ignored Send input accepted", raw)
		}
	}
	ordinary, err := parsePackageSendArgumentsV1([]byte(`{"document_id":"7691a386-97e8-42c9-a204-6b0ea8b00c73","lawful_basis":"contract"}`))
	if err != nil || ordinary.selection.PresentV1() {
		t.Fatal("ordinary omission changed", err)
	}
}

func TestMCPPackageSendOutcomesNeverInventLinksV1(t *testing.T) {
	document, attempt := uuid.New(), uuid.New()
	for _, status := range []string{"sealing", "sent", "completed", "expired"} {
		out, err := packageSendToolOutcomeFromV1(document, send.SendResult{Status: status, PackageAttemptID: attempt}, true)
		if err != nil || len(out.Links) != 0 || out.Links == nil || out.PackageSend == nil || out.PackageSend.AttemptID != attempt || out.PackageSend.ReconciliationRequired != (status == "sealing") {
			t.Fatal("async state was misrepresented", out, err)
		}
	}
	for _, result := range []send.SendResult{{Status: "sent"}, {Status: "draft", PackageAttemptID: attempt}, {Status: "sealing", PackageAttemptID: attempt, Links: []send.SignLink{{URL: "invented"}}}} {
		if _, err := packageSendToolOutcomeFromV1(document, result, true); err == nil {
			t.Fatal("inconsistent package result accepted")
		}
	}
	if _, ok := packageSendErrorResultV1("void_document", &packageSendToolErrorV1{document: document, attempt: attempt}); ok {
		t.Fatal("package error leaked through another tool")
	}
	if _, ok := packageSendErrorResultV1("send_document", errors.New("database credential must never be serialized")); ok {
		t.Fatal("generic error adopted selector path")
	}
}

type packageSendLastUseWriterV1 struct {
	*httptest.ResponseRecorder
	result **send.SendResult
	t      *testing.T
}

func (w packageSendLastUseWriterV1) Write(raw []byte) (int, error) {
	if *w.result == nil || (*w.result).Links == nil {
		w.t.Error("Send owner retired before ResponseWriter use")
	}
	return w.ResponseRecorder.Write(raw)
}

func TestMCPUnknownPackageCommitSerializesSafeSelectorBeforeClosingOwnerV1(t *testing.T) {
	s := NewServer()
	document, attempt := uuid.New(), uuid.New()
	var retained *send.SendResult
	s.RegisterTool(ToolDef{Name: "send_document", Write: true, Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
		retained = &send.SendResult{PackageAttemptID: attempt, Links: []send.SignLink{{URL: "must-never-leak"}}}
		if !workflowSendResponseFromV1(r).retainV1(retained) {
			t.Fatal("missing real dispatcher response owner")
		}
		return nil, &packageSendToolErrorV1{document: document, attempt: attempt}
	}})
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "send_document", "arguments": map[string]any{}}})
	r := withTokenScopes(withSessionContext(httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(raw)), uuid.New(), uuid.New(), "owner", "owner@example.test"), "write:workflow")
	w := packageSendLastUseWriterV1{ResponseRecorder: httptest.NewRecorder(), result: &retained, t: t}
	s.Handler().ServeHTTP(w, r)
	var envelope response
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil {
		t.Fatal("invalid JSON-RPC")
	}
	result := decodedToolResult(t, &envelope)
	if !result.IsError || len(result.Content) != 1 || strings.Contains(result.Content[0].Text, "must-never-leak") {
		t.Fatal("unknown commit became success or disclosed links", result)
	}
	var outcome packageSendToolOutcomeV1
	if json.Unmarshal([]byte(result.Content[0].Text), &outcome) != nil || outcome.Status != "unknown" || outcome.PackageSend == nil || outcome.PackageSend.AttemptID != attempt || !outcome.PackageSend.ReconciliationRequired {
		t.Fatal("safe exact inspection selector absent", outcome)
	}
	if retained == nil || retained.Links != nil {
		t.Fatal("actual dispatcher did not close retained result after writing")
	}
}

func TestMCPPackageInspectionScopeAndSchemaV1(t *testing.T) {
	s := New(Deps{})
	tool, ok := s.tools["get_document_send_attempt"]
	if !ok || tool.Write || tool.MinRole != "sender" || mcpToolRequiredScopes[tool.Name] != mcpScopeRead || !docScopeSafeTools[tool.Name] {
		t.Fatal("inspection lacks reviewed read/RBAC/document policy")
	}
	if s.tools["send_document"].InputSchema["additionalProperties"] != false {
		t.Fatal("Send schema advertises ignored fields")
	}
	for _, scope := range []string{"write:authoring", "write:workflow"} {
		result := decodedToolResult(t, rpcToolWithScopes(t, s.Handler(), "get_document_send_attempt", []string{scope}, false))
		if !result.IsError || len(result.Content) != 1 || !strings.Contains(result.Content[0].Text, "requires the 'read' scope") {
			t.Fatal("inspection accepted write-only credential", result)
		}
	}
}
