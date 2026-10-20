// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sentry "github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type mcpSignalTransport344 struct {
	mu     sync.Mutex
	events [][]byte
}

func (*mcpSignalTransport344) Configure(sentry.ClientOptions)        {}
func (*mcpSignalTransport344) Flush(time.Duration) bool              { return true }
func (*mcpSignalTransport344) FlushWithContext(context.Context) bool { return true }
func (*mcpSignalTransport344) Close()                                {}
func (s *mcpSignalTransport344) SendEvent(e *sentry.Event) {
	raw, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	s.events = append(s.events, raw)
	s.mu.Unlock()
}

// These are actual HTTP200 JSON-RPC/tool failures. Transport-only HTTP status
// monitoring cannot detect them, and private diagnostics must reach neither
// the caller nor the independently encoded fixed-data monitoring event.
func TestMCPInternalFailuresReportSafeSignals344(t *testing.T) {
	const private = "private-contract-344@example.test Bearer private-token-344"
	for _, test := range []struct {
		name       string
		method     string
		params     string
		register   func(*Server)
		tool       bool
		wantSignal bool
	}{
		{"tool SQL error", "tools/call", `{"name":"ai_runtime_status","arguments":{"note":"` + private + `"}}`, func(s *Server) {
			s.RegisterTool(ToolDef{Name: "ai_runtime_status", Handler: func(*http.Request, json.RawMessage) (any, error) {
				return nil, &pgconn.PgError{Code: "XX000", Message: private}
			}})
		}, true, true},
		{"tool serialization", "tools/call", `{"name":"ai_runtime_status","arguments":{}}`, func(s *Server) {
			s.RegisterTool(ToolDef{Name: "ai_runtime_status", Handler: func(*http.Request, json.RawMessage) (any, error) { return &refusedToolOutput295{t: t}, nil }})
		}, true, true},
		{"resource load", "resources/read", `{"uri":"hash://schema/blocks"}`, func(s *Server) {
			s.RegisterResource(Resource{URI: "hash://schema/blocks", Loader: func(*http.Request) (any, error) { return nil, errors.New(private) }})
		}, false, true},
		{"resource serialization", "resources/read", `{"uri":"hash://schema/blocks"}`, func(s *Server) {
			s.RegisterResource(Resource{URI: "hash://schema/blocks", Loader: func(*http.Request) (any, error) { return &refusedToolOutput295{t: t}, nil }})
		}, false, true},
		{"prompt renderer", "prompts/get", `{"name":"greet","arguments":{}}`, func(s *Server) {
			s.RegisterPrompt(Prompt{Name: "greet", Renderer: func(map[string]string) ([]PromptMessage, error) { return nil, errors.New(private) }})
		}, false, true},
		{"expected validation", "tools/call", `{"name":"ai_runtime_status","arguments":{}}`, func(s *Server) {
			s.RegisterTool(ToolDef{Name: "ai_runtime_status", Handler: func(*http.Request, json.RawMessage) (any, error) { return nil, errors.New("invalid arguments") }})
		}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &mcpSignalTransport344{}
			client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://public@flare.invalid/1", Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			hub := sentry.NewHub(client, sentry.NewScope())
			server := NewServer()
			test.register(server)
			r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+test.method+`","params":`+test.params+`}`))
			r = withSessionContext(r, uuid.New(), uuid.New(), "owner", "synthetic-344@example.test")
			r = r.WithContext(sentry.SetHubOnContext(r.Context(), hub))
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, r)
			var envelope struct {
				Result ToolResult `json:"result"`
				Error  *rpcError  `json:"error"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &envelope) != nil {
				t.Fatal("not actual HTTP200 JSON-RPC", w.Code, w.Body.String())
			}
			if test.tool && !envelope.Result.IsError || !test.tool && (envelope.Error == nil || envelope.Error.Code != codeInternalError || envelope.Error.Message != "internal error") {
				t.Fatal("failure became success or leaked internal response", w.Body.String())
			}
			if strings.Contains(w.Body.String(), "private-contract-344") || strings.Contains(w.Body.String(), "private-token-344") || strings.Contains(w.Body.String(), "synthetic-private") {
				t.Fatal("private diagnostic reached caller")
			}
			transport.mu.Lock()
			defer transport.mu.Unlock()
			want := 0
			if test.wantSignal {
				want = 1
			}
			if len(transport.events) != want {
				t.Fatalf("monitoring signals=%d want=%d", len(transport.events), want)
			}
			for _, raw := range transport.events {
				if strings.Contains(string(raw), "private-contract-344") || strings.Contains(string(raw), "private-token-344") || strings.Contains(string(raw), "private-295") || strings.Contains(string(raw), "synthetic-private") {
					t.Fatal("private diagnostic reached Flare")
				}
				var event sentry.Event
				if json.Unmarshal(raw, &event) != nil || event.Tags["operation"] != "mcp" || event.Tags["failure_category"] != "internal" || event.Level != sentry.LevelError {
					t.Fatal("missing useful fixed failure attribution", string(raw))
				}
			}
		})
	}
}
