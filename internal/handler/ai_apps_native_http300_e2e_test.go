//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/google/uuid"
)

// Only staff authorization tests opt into this real HTTP provider. The generic
// constructor and guardedAIProviderE2E stay unchanged for signer/pool consumers.
func setupStaffAIAppsHTTP300E2E(t *testing.T, sent, blocking bool) guardedAIAppsFixture {
	t.Helper()
	f := setupGuardedAIAppsMCPE2E(t, sent, blocking)
	f.nativeProvider = newStaffAIHTTPProvider300E2E(t, f.provider)
	shield, err := ai.NewLocalShield(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	runtime := ai.New(f.q, shield, nil, f.nativeProvider)
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, PublicURL: f.s.PublicURL,
		Clarifier: &aiapps.Clarifier{Runtime: runtime}, Negotiator: &aiapps.Negotiator{Runtime: runtime},
		RiskAnalyzer: &aiapps.RiskAnalyzer{Runtime: runtime}, Bilingual: &aiapps.Bilingual{Runtime: runtime},
		PDFCreationSessions: f.owned.runtime.SessionsV1()})
	return f
}

func newStaffAIHTTPProvider300E2E(t *testing.T, observed *guardedAIProviderE2E) *ai.MistralProvider {
	t.Helper()
	// Select the old canned response from the ACTUAL rendered system message.
	// No test name, user-data marker, private request value or prompt side channel
	// chooses the response. The versioned registry is the real runtime registry.
	type promptIdentity struct {
		name    string
		version int
	}
	systems := make(map[string]promptIdentity)
	registry := ai.NewPromptRegistry()
	for _, name := range []string{"signer_clarifier", "negotiation_counter", "risk_analyzer", "bilingual_equivalence"} {
		prompt, err := registry.Get(name, 0)
		if err != nil {
			t.Fatal(err)
		}
		rendered, err := prompt.Render(map[string]string{})
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := systems[rendered.System]; exists {
			t.Fatal("staff HTTP prompt identity collision")
		}
		systems[rendered.System] = promptIdentity{name: name, version: prompt.Version}
	}
	stopping := make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer synthetic-ai-300" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("staff HTTP provider request envelope differs")
			http.Error(w, "fixture request refused", http.StatusBadRequest)
			return
		}
		var wire struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Temperature float64 `json:"temperature"`
			MaxTokens   int     `json:"max_tokens"`
		}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&wire); err != nil {
			t.Error("staff HTTP provider body is not JSON", err)
			http.Error(w, "fixture body refused", http.StatusBadRequest)
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			t.Error("staff HTTP provider body has trailing JSON")
			http.Error(w, "fixture body refused", http.StatusBadRequest)
			return
		}
		if wire.Model != observed.Model() || len(wire.Messages) != 2 || wire.Messages[0].Role != "system" || wire.Messages[1].Role != "user" {
			t.Error("staff HTTP provider model/messages differ")
			http.Error(w, "fixture messages refused", http.StatusBadRequest)
			return
		}
		identity, found := systems[wire.Messages[0].Content]
		if !found {
			t.Error("staff HTTP provider received an unknown rendered system prompt")
			http.Error(w, "fixture prompt refused", http.StatusBadRequest)
			return
		}
		actual := ai.Request{System: wire.Messages[0].Content, User: wire.Messages[1].Content,
			Temperature: wire.Temperature, MaxTokens: wire.MaxTokens,
			PromptName: identity.name, PromptVersion: identity.version}
		observed.calls.Add(1)
		select {
		case observed.entered <- actual:
		case <-r.Context().Done():
			return
		case <-stopping:
			return
		}
		if observed.release != nil {
			select {
			case <-observed.release:
			case <-r.Context().Done():
				return
			case <-stopping:
				return
			}
		}
		// A canceled request receives no synthetic response/usage. Its real
		// Mistral Complete therefore reports 0/0, not an invented 23/11.
		if r.Context().Err() != nil {
			return
		}
		text := "Reviewed AI suggestion\nRationale: fixture"
		switch identity.name {
		case "risk_analyzer":
			text = "[{\"block_id\":\"agreement\",\"category\":\"payment_terms\",\"severity\":\"low\",\"summary\":\"Review payment dates\",\"suggestion\":\"Specify due date\"}]"
		case "bilingual_equivalence":
			text = "{\"equivalent\":true,\"drift\":[],\"confidence\":0.95}"
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"model":   observed.Model(),
			"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": text}}},
			"usage":   map[string]int{"prompt_tokens": 23, "completion_tokens": 11},
		}); err != nil && r.Context().Err() == nil {
			t.Error("staff HTTP provider response could not be written", err)
		}
	}))
	native := ai.NewMistralProvider(peer.URL+"/v1/chat/completions", "synthetic-ai-300", observed.Model(), true)
	t.Cleanup(func() {
		// Stop sends/blocked handlers BEFORE Server.Close. Existing tests may
		// already have released the channel; cleanup never closes it twice.
		close(stopping)
		if observed.release != nil {
			select {
			case <-observed.release:
			default:
				close(observed.release)
			}
		}
		if client, ok := native.Client.(*http.Client); ok {
			client.CloseIdleConnections()
		}
		peer.CloseClientConnections()
		peer.Close() // joins all actual handlers after both blocking paths end
	})
	return native
}

func assertStaffAIHTTPReceiptCost300E2E(t *testing.T, f guardedAIAppsFixture, eventCount int) uuid.UUID {
	t.Helper()
	return assertStaffAIHTTPNumericCost300E2E(t, f, eventCount, 23, 11)
}

func assertStaffAIHTTPNumericCost300E2E(t *testing.T, f guardedAIAppsFixture, eventCount, wantInput, wantOutput int) uuid.UUID {
	t.Helper()
	if f.nativeProvider == nil {
		t.Fatal("staff HTTP accounting has no actual native provider")
	}
	var id uuid.UUID
	var in, out, count int
	var actor, doc uuid.UUID
	var provider, model string
	var active bool
	if err := f.pool.QueryRow(f.ctx, `SELECT a.id,a.input_tokens,a.output_tokens,a.actor_user_id,a.document_id,a.provider,a.model,a.shield_active FROM ai_completion_audit a JOIN events e ON e.id=a.id AND e.org_id=a.org_id AND e.document_id=a.document_id AND e.actor_user_id=a.actor_user_id AND e.kind='ai.requested' WHERE a.org_id=$1`, f.org).Scan(&id, &in, &out, &actor, &doc, &provider, &model, &active); err != nil || in != wantInput || out != wantOutput || actor != f.user.ID || doc != f.doc.ID || provider != f.nativeProvider.Name() || model != f.nativeProvider.Model() || !active {
		t.Fatalf("truthful receipt-linked usage invalid: %s %d %d %v", id, in, out, err)
	} //nolint:rawsql
	assertAISetupEventsUnchangedE2E(t, f)
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1`, f.org).Scan(&count); err != nil || count-len(f.baselineEvents) != eventCount {
		t.Fatalf("AI request/cost/result event count=%d want%d err%v", count-len(f.baselineEvents), eventCount, err)
	} //nolint:rawsql
	return id
}

func assertStaffAIHTTPFailedUsage300E2E(t *testing.T, f guardedAIAppsFixture, receipt uuid.UUID) {
	t.Helper()
	var success bool
	var diagnostic string
	if err := f.pool.QueryRow(f.ctx, `SELECT success,error FROM ai_completion_audit WHERE id=$1 AND org_id=$2 AND document_id=$3 AND actor_user_id=$4`, receipt, f.org, f.doc.ID, f.user.ID).Scan(&success, &diagnostic); err != nil || success || diagnostic != "completion failed" {
		t.Fatal("actual unreceived HTTP cancellation was not recorded as a generic failed completion")
	} //nolint:rawsql -- exact observed request receipt and actual fixture identities
}
