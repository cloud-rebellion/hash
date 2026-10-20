//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

const nativeOrgProviderKey308 = "synthetic-ai-300"

type nativeOrgProviderFixture308 struct {
	f                guardedAIAppsFixture
	byo              *guardedAIProviderE2E
	expected         *generated.OrgAiSetting
	resolves, legacy atomic.Int32
}

// This covers the actual public settings writer, native header/body reader,
// AES-GCM decrypt and supported HTTP constructor through the shared actual
// production resolver. Process boot/configured service acceptance stays separate.
func setupNativeOrgProvider308(t *testing.T, enabled bool, maximum int32, blocking bool) *nativeOrgProviderFixture308 {
	t.Helper()
	return setupNativeOrgProviderAllocation315(t, enabled, maximum, blocking, nativeOrgProviderOverlapLimits315())
}

func setupNativeOrgProviderAllocation315(t *testing.T, enabled bool, maximum int32, blocking bool, limits workguard.LimitsV1) *nativeOrgProviderFixture308 {
	t.Helper()
	t.Setenv("HASH_ENVIRONMENT", "development")
	state := &nativeOrgProviderFixture308{}
	if maximum == 0 {
		state.f = setupGuardedAIAppsRESTE2E(t, false, false)
	} else if maximum == 1 {
		state.f = setupNativeStaffPool315E2E(t, blocking, limits)
	} else {
		t.Fatal("unsupported explicit native organization pool profile")
	}
	f := &state.f
	f.s.PublicURL = "http://localhost:30800"
	f.s.Environment = "development"
	f.s.AISealKey = bytes.Repeat([]byte{0x73}, 32)
	var err error
	f.user, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "owner"})
	if err != nil {
		t.Fatal("actual fixture owner unavailable", err)
	}
	// No post-birth pool or coordinator replacement is permitted.
	f.owned.f = f.lifecycleAuthorizationFixture
	state.byo = &guardedAIProviderE2E{entered: make(chan ai.Request, 16)}
	if blocking {
		state.byo.release = make(chan struct{})
	}
	endpoint := newStaffAIHTTPProvider300E2E(t, state.byo)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	input, err := json.Marshal(map[string]any{"provider": "mistral", "base_url": endpoint.Endpoint(), "model": endpoint.Model(), "api_key": nativeOrgProviderKey308, "enabled": enabled})
	if err != nil {
		t.Fatal(err)
	}
	response := submitSessionOperationE2E(f.s, http.MethodPut, "/api/v1/ai/provider", string(input), cookie)
	var public orgAIProviderResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &public) != nil || !public.Configured || !public.ByoaiAvailable || public.Enabled != enabled || public.Provider != "mistral" || public.BaseURL != endpoint.Endpoint() || public.Model != endpoint.Model() || public.KeyLast4 != "-300" {
		t.Fatal("actual public organization provider write failed", response.Code, response.Body.String())
	}
	state.expected, err = f.q.GetOrgAISettings(f.ctx, f.org)
	if err != nil || state.expected == nil || bytes.Equal(state.expected.ApiKeyCt, []byte(nativeOrgProviderKey308)) {
		t.Fatal("actual organization settings were not stored as ciphertext", err)
	}
	plain, err := ai.AESDecrypt(f.s.AISealKey, state.expected.ApiKeyCt)
	if err != nil || string(plain) != nativeOrgProviderKey308 {
		t.Fatal("actual public settings ciphertext does not decrypt", err)
	}
	read := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/ai/provider", "", cookie)
	var fields map[string]any
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &fields) != nil || bytes.Contains(read.Body.Bytes(), []byte(nativeOrgProviderKey308)) || fields["api_key"] != nil || fields["api_key_ct"] != nil {
		t.Fatal("actual settings read leaked a stored credential", read.Code, read.Body.String())
	}
	shield, err := ai.NewLocalShield(f.s.AISealKey)
	if err != nil {
		t.Fatal(err)
	}
	runtime := ai.New(f.q, shield, nil, f.nativeProvider)
	// Non-nil opts in to BYOAI. The native branch MUST use its native reader,
	// never this generic pooled callback; a fallback here is an actual failure.
	runtime.ResolveOrgProvider = func(context.Context, uuid.UUID, *generated.Queries) (ai.Provider, bool, error) {
		state.legacy.Add(1)
		return nil, false, errors.New("private pooled resolver must not execute")
	}
	runtime.ResolveNativeOrgProvider = func(ctx context.Context, row *generated.OrgAiSetting) (ai.Provider, bool, error) {
		state.resolves.Add(1)
		expected := state.expected
		if ai.NativeWorkflowFromContextV1(ctx) == nil || row == nil || row.OrgID != f.org || row.Provider != expected.Provider || row.BaseUrl != expected.BaseUrl || row.Model != expected.Model || row.Enabled != expected.Enabled || row.KeyLast4 != expected.KeyLast4 || !bytes.Equal(row.ApiKeyCt, expected.ApiKeyCt) || !row.CreatedAt.Time.Equal(expected.CreatedAt.Time) || !row.UpdatedAt.Time.Equal(expected.UpdatedAt.Time) {
			return nil, false, errors.New("actual native organization settings differ")
		}
		provider, available, err := ai.ResolveOrganizationProviderV1(row, f.s.AISealKey, true)
		if err != nil {
			return nil, false, fmt.Errorf("private-308@example.test %s: %w", nativeOrgProviderKey308, err)
		}
		if actual, ok := provider.(*ai.MistralProvider); ok {
			t.Cleanup(func() {
				if client, ok := actual.Client.(*http.Client); ok {
					client.CloseIdleConnections()
				}
			})
		}
		return provider, available, nil
	}
	f.s.Negotiator = &aiapps.Negotiator{Runtime: runtime}
	return state
}

func nativeOrgProviderCounts308(t *testing.T, state *nativeOrgProviderFixture308, requests, completions int) {
	t.Helper()
	f := state.f
	var requested, cost, ready int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE kind='ai.requested')::integer,count(*) FILTER(WHERE kind='ai.completed')::integer,count(*) FILTER(WHERE kind='ai.result_ready')::integer FROM events WHERE org_id=$1 AND document_id=$2`, f.org, f.doc.ID).Scan(&requested, &cost, &ready); err != nil || requested != requests || cost != completions || ready != completions {
		t.Fatal("actual native request/cost/result counts differ", requested, cost, ready, err)
	} //nolint:rawsql -- fixture-owned original event identities, no repair/backfill
	var total, matched int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,count(*) FILTER(WHERE e.id=a.id AND e.org_id=a.org_id AND e.document_id=a.document_id AND e.actor_user_id=a.actor_user_id AND e.kind='ai.requested' AND a.provider='mistral' AND a.model=$4 AND a.shield_active AND a.input_tokens=23 AND a.output_tokens=11 AND a.success AND a.error='')::integer FROM ai_completion_audit a LEFT JOIN events e ON e.id=a.id WHERE a.org_id=$1 AND a.document_id=$2 AND a.actor_user_id=$3`, f.org, f.doc.ID, f.user.ID, state.expected.Model).Scan(&total, &matched); err != nil || total != completions || matched != completions {
		t.Fatal("actual native request-bound durable usage differs", total, matched, err)
	} //nolint:rawsql -- actual usage from real supported HTTP responses
	if state.legacy.Load() != 0 {
		t.Fatal("native settings path fell back to pooled resolver", state.legacy.Load())
	}
	assertAISetupEventsUnchangedE2E(t, f)
	nativeBindingMeasurement259(t, f.lifecycleAuthorizationFixture, f.doc.ID)
	assertStaffAIChainE2E(t, f)
	assertNativeOrgEventBindings315(t, state, completions)
	ownedPlainAssertDrainedV1(t, f.owned)
	assertNativeOrgDrained315(t, state)
}

func TestNativeStaffOrganizationProviderEnabledAndDisabledV1E2E(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			state := setupNativeOrgProvider308(t, enabled, 0, false)
			f := state.f
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			w := staffAISubmitE2E(f, f.ctx, staffAIActionForE2E(t, f, "suggest"), cookie)
			if w.Code != http.StatusOK {
				t.Fatal("actual native organization suggestion failed", w.Code, w.Body.String())
			}
			wantBYO, wantDefault := int32(1), int32(0)
			if !enabled {
				wantBYO, wantDefault = 0, 1
			}
			if state.resolves.Load() != 1 || state.byo.calls.Load() != wantBYO || f.provider.calls.Load() != wantDefault {
				t.Fatal("actual enabled/disabled setting selected wrong HTTP provider", state.resolves.Load(), state.byo.calls.Load(), f.provider.calls.Load())
			}
			nativeOrgProviderCounts308(t, state, 1, 1)
		})
	}
}

func TestNativeStaffOrganizationCredentialRefusalNoFallbackAndRecoveryV1E2E(t *testing.T) {
	state := setupNativeOrgProvider308(t, true, 0, false)
	f := state.f
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	op := staffAIActionForE2E(t, f, "suggest")
	originalKey := bytes.Clone(f.s.AISealKey)
	f.s.AISealKey = bytes.Repeat([]byte{0x74}, 32)
	w := staffAISubmitE2E(f, f.ctx, op, cookie)
	if w.Code != http.StatusInternalServerError || bytes.Contains(w.Body.Bytes(), []byte(nativeOrgProviderKey308)) || bytes.Contains(w.Body.Bytes(), []byte("private-308")) || bytes.Contains(w.Body.Bytes(), []byte("authentication failed")) {
		t.Fatal("actual credential refusal escaped diagnostic boundary", w.Code, w.Body.String())
	}
	if state.resolves.Load() != 1 || state.byo.calls.Load() != 0 || f.provider.calls.Load() != 0 {
		t.Fatal("actual failed organization key silently fell back or dispatched")
	}
	nativeOrgProviderCounts308(t, state, 1, 0)
	f.s.AISealKey = originalKey
	if w = staffAISubmitE2E(f, f.ctx, op, cookie); w.Code != http.StatusOK {
		t.Fatal("restored actual organization key could not recover", w.Code, w.Body.String())
	}
	if state.resolves.Load() != 2 || state.byo.calls.Load() != 1 || f.provider.calls.Load() != 0 {
		t.Fatal("actual recovered organization key selected wrong provider")
	}
	nativeOrgProviderCounts308(t, state, 2, 1)
}

func TestNativeStaffOneApplicationConnectionConcurrentBYOAIV1E2E(t *testing.T) {
	state := setupNativeOrgProvider308(t, true, 1, true)
	f := state.f
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	op := staffAIActionForE2E(t, f, "suggest")
	var release sync.Once
	unblock := func() { release.Do(func() { close(state.byo.release) }) }
	defer unblock()
	first, cancelFirst, joinedFirst := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return staffAISubmitE2E(f, ctx, op, cookie) })
	defer guardedAICleanup264(t, nil, cancelFirst, joinedFirst)
	awaitAIProviderE2E(t, state.byo)
	second, cancelSecond, joinedSecond := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return staffAISubmitE2E(f, ctx, op, cookie) })
	defer guardedAICleanup264(t, nil, cancelSecond, joinedSecond)
	awaitAIProviderE2E(t, state.byo)
	assertNativeAIOverlap315E2E(t, state)
	// Both requests have completed original pooled authentication and genuinely
	// reached the HTTP provider before the only application connection is held.
	// Native accounting/audit/result phases must use their original owned SQL.
	lease, err := f.pool.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if f.pool.Config().MaxConns != 1 || f.pool.Stat().AcquiredConns() != 1 {
		t.Fatal("actual single application connection was not occupied")
	}
	unblock()
	for _, result := range []<-chan *httptest.ResponseRecorder{first, second} {
		if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusOK {
			t.Fatal("actual native single-pool concurrent request failed", w.Code, w.Body.String())
		}
	}
	lease.Release()
	if state.resolves.Load() != 2 || state.byo.calls.Load() != 2 || f.provider.calls.Load() != 0 {
		t.Fatal("actual concurrent organization provider work fell back or disappeared")
	}
	nativeOrgProviderCounts308(t, state, 2, 2)
}
