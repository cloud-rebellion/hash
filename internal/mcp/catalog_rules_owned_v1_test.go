// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
)

type catalogRuleLifetimeWriterV1 struct {
	*httptest.ResponseRecorder
	during func()
}

func (w *catalogRuleLifetimeWriterV1) Write(b []byte) (int, error) {
	w.during()
	return w.ResponseRecorder.Write(b)
}

func TestCatalogRuleActualMCPSerializationOwnsSuccessAndErrorV1(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "original full rule", true: "original refusal"}[fail], func(t *testing.T) {
			released := 0
			owned := &catalogRuleOwnedResultV1{state: &catalogRuleOwnedResultStateV1{value: map[string]any{"id": uuid.NewString(), "predicate_json": json.RawMessage(`{"field":"country","op":"==","value":"SE"}`)}, release: func() { released++ }}}
			copy := *owned
			s := NewServer()
			s.RegisterTool(ToolDef{Name: "create_eidas_rule", Write: true, Handler: func(*http.Request, json.RawMessage) (any, error) {
				if fail {
					return owned, errors.New("synthetic original refusal")
				}
				return owned, nil
			}})
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_eidas_rule","arguments":{}}}`)
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
			req = withSessionContext(req, uuid.New(), uuid.New(), "owner", "owner@example.test")
			req = withTokenScopes(req, mcpScopeWriteAuthoring)
			writes := 0
			w := &catalogRuleLifetimeWriterV1{ResponseRecorder: httptest.NewRecorder(), during: func() {
				writes++
				owned.state.mu.Lock()
				defer owned.state.mu.Unlock()
				if released != 0 || owned.state.closed || owned.state.value == nil {
					t.Error("actual MCP response serialized after its original consumer was closed")
				}
			}}
			s.Handler().ServeHTTP(w, req)
			if writes == 0 || released != 1 || !owned.state.closed || owned.state.value != nil {
				t.Fatal("actual response/error did not clear and retire its result consumer", writes, released, owned.state.closed)
			}
			copy.CloseConsumerV1()
			if released != 1 {
				t.Fatal("same original last use released twice")
			}
			var result response
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			decoded := decodedToolResult(t, &result)
			if decoded.IsError != fail {
				t.Fatal("original MCP success/refusal semantics changed", decoded)
			}
		})
	}
}
