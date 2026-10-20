// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type refusedToolOutput295 struct {
	closed bool
	t      *testing.T
}

func (o *refusedToolOutput295) MarshalJSON() ([]byte, error) {
	if o.closed {
		o.t.Error("owner closed before actual serialization")
	}
	return nil, errors.New("private-295@example.test Bearer synthetic-private")
}
func (o *refusedToolOutput295) CloseConsumerV1() { o.closed = true }
func TestMCPFailedOwnedSerializationReturnsErrorAndKeepsConsumer295(t *testing.T) {
	server := NewServer()
	owner := &refusedToolOutput295{t: t}
	server.RegisterTool(ToolDef{Name: "ai_runtime_status", Handler: func(*http.Request, json.RawMessage) (any, error) { return owner, nil }})
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ai_runtime_status","arguments":{}}}`))
	request = withSessionContext(request, uuid.New(), uuid.New(), "owner", "sender@example.test")
	writer := httptest.NewRecorder()
	server.Handler().ServeHTTP(writer, request)
	var envelope struct {
		Result ToolResult `json:"result"`
	}
	if json.Unmarshal(writer.Body.Bytes(), &envelope) != nil || !envelope.Result.IsError || len(envelope.Result.Content) != 1 || envelope.Result.Content[0].Text != "tool result unavailable" {
		t.Fatal("refused actual Marshaler became false success", writer.Body.String())
	}
	if strings.Contains(writer.Body.String(), "private-295") || strings.Contains(writer.Body.String(), "synthetic-private") {
		t.Fatal("private marshaler diagnostic escaped")
	}
	if !owner.closed {
		t.Fatal("actual failed output consumer did not close")
	}
}
