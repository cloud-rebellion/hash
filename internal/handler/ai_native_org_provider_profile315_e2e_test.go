//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// The fixed fixture owns one process-control observer and one tenant observer.
// The process observer charges only global SQL/grants; the tenant observer
// charges both global and organization SQL/grants. Pending counts both.
const (
	nativeOrgProviderProcessObservers315 = 1
	nativeOrgProviderTenantObservers315  = 1
)

// Named test allocation only. Bytes, global SQL and grant caps stay original.
// Two held HTTP calls require2streams: global2observers+accounting2+dispatch2=6SQL,
// organization1observer+accounting2+dispatch2=5SQL. Simultaneous independent
// cost phases can require two more slots: global8/organization7. With poolMax1
// born before runtime, existing globalSQL8 requires DBallocation1+8=9.
func nativeOrgProviderOverlapLimits315() workguard.LimitsV1 {
	return workguard.LimitsV1{
		Global:       workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 2},
		Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 7, ProviderStreams: 2},
		MaxGrants:    128, MaxOrganisationGrants: 64,
	}
}
func nativeOrgProviderConstrainedLimits315() workguard.LimitsV1 {
	limits := nativeOrgProviderOverlapLimits315()
	limits.Organisation.SQLSessions = 4
	limits.Global.ProviderStreams, limits.Organisation.ProviderStreams = 1, 1
	return limits
}

// Uses actual allocated fixture, public creator, recipient and proposal APIs.
// No pool-only DSN parameter reaches direct observer/witness configuration.
func setupNativeStaffPool315E2E(t *testing.T, blocking bool, limits workguard.LimitsV1) guardedAIAppsFixture {
	t.Helper()
	owned := newOwnedPublicReadFixtureAllocatedPool315V1(t, false, limits, 1)
	f := setupNativeLifecycleAuthorizationWithFixture257d(t, "sender", false, false, owned)
	if f.pool.Config().MaxConns != 1 || !owned.runtime.MatchesPoolV1(f.pool) {
		t.Fatal("original application pool/runtime was not born with one connection")
	}
	observed := &guardedAIProviderE2E{entered: make(chan ai.Request, 16)}
	if blocking {
		observed.release = make(chan struct{})
	}
	native := newStaffAIHTTPProvider300E2E(t, observed)
	shield, err := ai.NewLocalShield(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	runtime := ai.New(f.q, shield, nil, native)
	f.s.Negotiator = &aiapps.Negotiator{Runtime: runtime}
	f.s.Bilingual = &aiapps.Bilingual{Runtime: runtime}
	f.s.RiskAnalyzer = &aiapps.RiskAnalyzer{Runtime: runtime}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/proposals", `{"block_id":"agreement","proposal_kind":"counter","proposed_text":"Reviewed original proposal","rationale":"fixture"}`, cookie)
	var proposal struct{ ID uuid.UUID }
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &proposal) != nil || proposal.ID == uuid.Nil {
		t.Fatal("actual profile original proposal absent", response.Code, response.Body.String())
	}
	f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return guardedAIAppsFixture{lifecycleAuthorizationFixture: f, provider: observed, nativeProvider: native, proposalID: proposal.ID, baselineEvents: aiAppEventSnapshotE2E(t, f), owned: owned}
}

func assertNativeAIOverlap315E2E(t *testing.T, state *nativeOrgProviderFixture308) {
	t.Helper()
	f := state.f
	if f.pool.Config().MaxConns != 1 || !f.owned.runtime.MatchesPoolV1(f.pool) {
		t.Fatal("overlap used a replacement pool or mismatched runtime")
	}
	pending := f.owned.runtime.SessionsV1().PendingV1()
	snapshot, err := f.owned.runtime.SnapshotV1(f.org)
	if err != nil || pending.ObserverSessions != nativeOrgProviderProcessObservers315+nativeOrgProviderTenantObservers315 || snapshot.Global.SQLSessions != int64(nativeOrgProviderProcessObservers315+nativeOrgProviderTenantObservers315+4) || snapshot.Organisation.SQLSessions != int64(nativeOrgProviderTenantObservers315+4) || snapshot.Global.ProviderStreams != 2 || snapshot.Organisation.ProviderStreams != 2 || snapshot.Global.ParentBytes <= 0 || snapshot.Global.DBStagingBytes <= 0 || snapshot.GlobalGrants > 128 || snapshot.OrganisationGrants > 64 {
		t.Fatal("actual two-provider phase lacks exact admitted ownership", snapshot, pending, err)
	}
	if state.byo.calls.Load() != 2 || state.resolves.Load() != 2 || state.legacy.Load() != 0 {
		t.Fatal("two-provider overlap lost native settings ownership")
	}
}

func assertNativeOrgEventBindings315(t *testing.T, state *nativeOrgProviderFixture308, want int) {
	t.Helper()
	f := state.f
	var usage, cost, ready int
	var eachExact bool
	err := f.pool.QueryRow(f.ctx, `WITH bindings AS (SELECT a.id,count(DISTINCT c.id)::integer AS cost_count,count(DISTINCT r.id)::integer AS ready_count FROM ai_completion_audit a JOIN events q ON q.id=a.id AND q.org_id=a.org_id AND q.document_id=a.document_id AND q.actor_user_id=a.actor_user_id AND q.kind='ai.requested' LEFT JOIN events c ON c.org_id=a.org_id AND c.document_id=a.document_id AND c.actor_user_id=a.actor_user_id AND c.kind='ai.completed' AND c.payload_json->>'request_event_id'=a.id::text AND c.payload_json->>'usage_id'=a.id::text AND c.payload_json->>'input_tokens'='23' AND c.payload_json->>'output_tokens'='11' LEFT JOIN events r ON r.org_id=a.org_id AND r.document_id=a.document_id AND r.actor_user_id=a.actor_user_id AND r.kind='ai.result_ready' AND r.payload_json->>'request_event_id'=a.id::text WHERE a.org_id=$1 AND a.document_id=$2 AND a.actor_user_id=$3 GROUP BY a.id) SELECT count(*)::integer,coalesce(sum(cost_count),0)::integer,coalesce(sum(ready_count),0)::integer,coalesce(bool_and(cost_count=1 AND ready_count=1),true) FROM bindings`, f.org, f.doc.ID, f.user.ID).Scan(&usage, &cost, &ready, &eachExact)
	if err != nil || usage != want || cost != want || ready != want || !eachExact {
		t.Fatal("actual M94 cost/result bindings do not match original request/usage IDs", usage, cost, ready, err)
	} //nolint:rawsql -- exact actual fixture identities and genuine persisted tuples
}

// Original constrained allocation refuses overlap, then recovers without a
// limit change. The separate positive top still requires TWO held HTTP calls.
func TestNativeStaffConstrainedAllocationRefusesThenRecoversV1E2E(t *testing.T) {
	state := setupNativeOrgProviderAllocation315(t, true, 1, true, nativeOrgProviderConstrainedLimits315())
	f := state.f
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	op := staffAIActionForE2E(t, f, "suggest")
	first, cancelFirst, joinedFirst := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return staffAISubmitE2E(f, ctx, op, cookie) })
	defer guardedAICleanup264(t, nil, cancelFirst, joinedFirst)
	defer func() {
		select {
		case <-state.byo.release:
		default:
			close(state.byo.release)
		}
	}()
	awaitAIProviderE2E(t, state.byo)
	held, err := f.owned.runtime.SnapshotV1(f.org)
	if err != nil || held.Global.ProviderStreams != 1 || held.Organisation.ProviderStreams != 1 || held.Organisation.SQLSessions != 3 {
		t.Fatal("first constrained request has no exact held phase", held, err)
	}
	second, cancelSecond, joinedSecond := guardedAIAsync264(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return staffAISubmitE2E(f, ctx, op, cookie) })
	defer guardedAICleanup264(t, nil, cancelSecond, joinedSecond)
	refused := receiveSessionOperationE2E(t, second)
	if refused.Code != http.StatusInternalServerError || state.byo.calls.Load() != 1 || state.resolves.Load() != 1 || state.legacy.Load() != 0 {
		t.Fatal("constrained allocation did not refuse before another provider", refused.Code, refused.Body.String())
	}
	var requests, usage int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*)::integer FROM events WHERE org_id=$1 AND document_id=$2 AND kind='ai.requested'),(SELECT count(*)::integer FROM ai_completion_audit WHERE org_id=$1 AND document_id=$2)`, f.org, f.doc.ID).Scan(&requests, &usage); err != nil || requests < 1 || requests > 2 || usage != 0 {
		t.Fatal("constrained refusal fabricated completion or lost actual request", requests, usage, err)
	} //nolint:rawsql -- observed count, no guessed second request commit
	lease, err := f.pool.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if f.pool.Config().MaxConns != 1 || f.pool.Stat().AcquiredConns() != 1 {
		t.Fatal("original sole application connection was not held")
	}
	close(state.byo.release)
	if response := receiveSessionOperationE2E(t, first); response.Code != http.StatusOK {
		t.Fatal("first constrained request did not complete under held application lease", response.Code, response.Body.String())
	}
	lease.Release()
	nativeOrgProviderCounts308(t, state, requests, 1)
	if response := staffAISubmitE2E(f, f.ctx, op, cookie); response.Code != http.StatusOK {
		t.Fatal("unchanged constrained allocation did not recover after real retirement", response.Code, response.Body.String())
	}
	if state.byo.calls.Load() != 2 || state.resolves.Load() != 2 || state.legacy.Load() != 0 {
		t.Fatal("constrained retry lost actual native provider")
	}
	nativeOrgProviderCounts308(t, state, requests+1, 2)
}

func assertNativeOrgDrained315(t *testing.T, state *nativeOrgProviderFixture308) {
	t.Helper()
	f := state.f
	pending := f.owned.runtime.SessionsV1().PendingV1()
	snapshot, err := f.owned.runtime.SnapshotV1(f.org)
	expectedObservers := nativeOrgProviderProcessObservers315 + nativeOrgProviderTenantObservers315
	expectedGlobal := workguard.VectorV1{SQLSessions: int64(expectedObservers)}
	expectedOrg := workguard.VectorV1{SQLSessions: int64(nativeOrgProviderTenantObservers315)}
	if err != nil || pending.ObserverSessions != expectedObservers || snapshot.Global != expectedGlobal || snapshot.Organisation != expectedOrg || snapshot.GlobalGrants != int64(expectedObservers) || snapshot.OrganisationGrants != int64(nativeOrgProviderTenantObservers315) || pending.DocumentAIAccountings != 0 {
		t.Fatal("actual request loans did not conserve the original observer-only state", snapshot, pending, err)
	}
}
