//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	sentry "github.com/getsentry/sentry-go"
	"github.com/google/uuid"
)

type mcpPreviewZeroReaderV1 struct{}

func (mcpPreviewZeroReaderV1) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// Real registered tools/call, API-key middleware, native input/read ownership,
// PG source pins and isolated PDF worker. The renderer and SDK receiver are
// explicitly synthetic; this proves neither Chromium layout nor Flare delivery.
func TestMCPPreviewUnexpectedFailuresReportHTTP200SignalsV1E2E(t *testing.T) {
	t.Setenv("FLARE_TRACES_SAMPLE_RATE", "1")
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	const private = "PRIVATE_PREVIEW_HTML_AUTH_AND_PARSER_V1"
	var mode, dispatches atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 20<<20))
		dispatches.Add(1)
		switch mode.Load() {
		case 1:
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = io.WriteString(w, "not a PDF "+private)
		case 2:
			http.Error(w, private, http.StatusServiceUnavailable)
		case 3:
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = io.CopyN(w, mcpPreviewZeroReaderV1{}, int64(sanitize.MaxPDFBytes)+1)
		case 4:
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = io.CopyN(w, mcpPreviewZeroReaderV1{}, (60<<20)+1)
		default:
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write(ownedA4ProtocolPDFV1())
		}
	}))
	t.Cleanup(peer.Close)
	q.f.s.Sign.PDF = render.NewGotenberg(peer.URL)
	q.f.s.MCP = mcp.New(mcp.Deps{Pool: q.f.pool, Queries: q.f.q, Audit: q.f.s.Audit, Storage: q.f.s.Storage,
		Billing: q.f.s.Billing, PDFCreationSessions: q.runtime.SessionsV1(), Design: q.f.s.MCPDesignBridgeV1()})
	key, _ := automationDocumentKeyE2E(t, q, "read", "write:authoring")
	wrongScope, _ := automationDocumentKeyE2E(t, q, "write:authoring")
	master := htmlmaster.Master{SchemaVersion: 1, HTML: `<p>` + private + ` <span data-hash-value="customer"></span></p>`,
		Values: []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 200}}}
	var design struct {
		ID      uuid.UUID `json:"template_id"`
		Version int32     `json:"version"`
		SHA     string    `json:"content_sha256"`
	}
	callDesign783(t, q.f, key, "create_design_template", map[string]any{"input": map[string]any{
		"name": "Synthetic private preview telemetry", "html_master_json": master, "variables_json": map[string]string{},
	}}, &design, false)
	baseline := automationDocumentRuntimeBaselineV1(t, q)
	// The fixture database is independently owned. Preview may use the original
	// key, but must not create business rows or send/queue any notification.
	snapshot := func() string {
		t.Helper()
		var value string
		if err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_array(
 (SELECT count(*) FROM documents),(SELECT count(*) FROM recipients),
 (SELECT count(*) FROM templates),(SELECT count(*) FROM html_template_revisions),
 (SELECT count(*) FROM events),(SELECT count(*) FROM email_deliveries))::text`).Scan(&value); err != nil {
			t.Fatal("preview fixture snapshot", err)
		}
		return value
	} //nolint:rawsql -- read-only scalar counts in this test's uniquely owned database
	before := snapshot()
	for _, test := range []struct {
		name, category string
		mode           int32
		refusal        string
		policy         bool
	}{
		{"generated-invalid-PDF", "internal", 1, "", false},
		{"renderer-unavailable", "dependency", 2, "", false},
		{"generated-byte-policy", "", 3, "", true},
		{"renderer-response-byte-policy", "", 4, "", true},
		{"success", "", 0, "", false},
		{"missing-required-input", "", 0, "input", false},
		{"stale-source", "", 0, "stale", false},
		{"scope-refusal", "", 0, "scope", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode.Store(test.mode)
			callsBefore := dispatches.Load()
			input := map[string]any{"expected_version": design.Version, "expected_content_sha256": design.SHA,
				"values": map[string]string{"customer": private}}
			usedKey := key
			switch test.refusal {
			case "input":
				delete(input, "values")
			case "stale":
				input["expected_content_sha256"] = strings.Repeat("f", 64)
			case "scope":
				usedKey = wrongScope
			}
			body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": private, "method": "tools/call",
				"params": map[string]any{"name": "preview_design_template", "arguments": map[string]any{"template_id": design.ID, "input": input}}})
			if err != nil {
				t.Fatal(err)
			}
			hub, wire := mcpPreviewSignalHubV1(t)
			hub.Scope().SetUser(sentry.User{Email: private})
			hub.Scope().SetContext("private", sentry.Context{"body": private})
			r := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/mcp", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+usedKey)
			r.Header.Set("X-Request-Id", private)
			r.Header.Set("sentry-trace", strings.Repeat("1", 32)+"-"+strings.Repeat("2", 16)+"-1")
			r = r.WithContext(sentry.SetHubOnContext(q.f.ctx, hub))
			w := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(w, r)
			var reply struct {
				Result mcp.ToolResult  `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &reply) != nil || len(reply.Error) > 0 ||
				reply.Result.IsError != (test.category != "" || test.refusal != "" || test.policy) {
				t.Fatal("registered MCP preview status or semantic result differs", w.Code)
			}
			if (test.category != "" || test.policy) && (len(reply.Result.Content) != 1 || reply.Result.Content[0].Text != "native design operation unavailable or refused") {
				t.Fatal("public operational failure changed or leaked private cause")
			}
			if test.category == "" && test.refusal == "" && !test.policy {
				var preview struct {
					Pages int    `json:"page_count"`
					SHA   string `json:"pdf_sha256"`
					PDF   string `json:"pdf_base64"`
				}
				if len(reply.Result.Content) != 1 || json.Unmarshal([]byte(reply.Result.Content[0].Text), &preview) != nil ||
					preview.Pages != 1 || !htmlPreviewSHA256(preview.SHA) || preview.PDF == "" {
					t.Fatal("successful route did not return actual worker-processed preview")
				}
			}
			if test.refusal != "" && dispatches.Load() != callsBefore {
				t.Fatal("expected input/scope/source refusal reached renderer")
			}
			wantCalls := int32(1)
			if test.mode == 2 {
				wantCalls = 3 // the unchanged renderer 503 retry policy
			}
			if test.refusal == "" && dispatches.Load() != callsBefore+wantCalls {
				t.Fatal("preview did not exercise the bounded actual renderer response policy")
			}
			events := wire.failureEvents(t)
			want := 0
			if test.category != "" {
				want = 1
			}
			if len(events) != want {
				t.Fatalf("actual HTTP200 preview events=%d want=%d", len(events), want)
			}
			for _, event := range events {
				if event.Tags["operation"] != "mcp" || event.Tags["failure_category"] != test.category {
					t.Fatal("preview fixed diagnostic missing", event.Tags)
				}
				if value := event.Contexts["trace"]["trace_id"]; value != strings.Repeat("1", 32) {
					t.Fatal("request-safe trace identity lost")
				}
			}
			wire.mu.Lock()
			for _, raw := range wire.events {
				if strings.Contains(string(raw), private) || strings.Contains(string(raw), usedKey) {
					t.Error("private HTML, arguments, RPC/header ID or credential reached SDK")
				}
			}
			wire.mu.Unlock()
			assertAutomationDocumentRuntimeBaselineE2E(t, q, baseline)
			if snapshot() != before {
				t.Fatal("preview changed document/recipient/template/revision/event/delivery stores")
			}
		})
	}
}
