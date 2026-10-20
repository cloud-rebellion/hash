//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This is a separate single-organization integration experiment. The original
// default/package fixtures retain global128/org64. Only this explicitly named
// test allocation gives this one organization up to the unchanged global128.
// All byte, child, CPU, stream, SQL, fixture and backend deadline limits stay
// identical. This neither selects a production default nor proves sufficiency.
func newOwnedOrgSourceSingleOrganisationFixture257d(t *testing.T, tracer pgx.QueryTracer) *ownedPublicReadFixtureV1 {
	t.Helper()
	limits := workguard.LimitsV1{
		Global:       workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 1},
		Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 1},
		MaxGrants:    128, MaxOrganisationGrants: 128,
	}
	return newOwnedPublicReadFixtureAllocated257dV1(t, false, limits, tracer)
}

// The actual native factory copies this already-installed pool tracer into its
// own connections. Observe only existing numeric runtime snapshots at actual
// query boundaries and explicit caller checkpoints. Return the identical query
// context; keep no SQL, arguments, identities, bodies or errors. No new worker,
// coordinator, polling goroutine, loan or resource refund is introduced.
// Fixed phase aggregation bounds memory/logs independently of query count.
// A sampled maximum is a lower bound, NOT a continuous locked-core exact peak.
type nativeOrgSourceGrantTrace257d struct {
	mu      sync.Mutex
	runtime *pdfadmission.WorkRuntimeV1
	org     uuid.UUID
	active  bool
	err     error
	count   uint64
	phase   [14]nativeOrgSourceGrantPhase257d
}

type nativeOrgSourceGrantPhase257d struct {
	samples                                     uint64
	maxOrg                                      workguard.SnapshotV1
	maxGlobalGrants, maxParentBytes, maxDBBytes int64
}

var nativeOrgSourceGrantPhaseNames257d = [...]string{
	"before-http", "state-lock", "collections", "org-header", "org-body", "branding-header", "branding-body",
	"plan-header", "plan-body", "subscription-header", "subscription-body", "other-query", "http-response", "joined-observers-only",
}

func (p *nativeOrgSourceGrantTrace257d) beginV1(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	p.mu.Lock()
	p.runtime, p.org, p.active = q.runtime, q.f.org, true
	p.mu.Unlock()
	t.Cleanup(func() { p.reportV1(t) })
	p.observeV1(0)
}

func (p *nativeOrgSourceGrantTrace257d) checkpointV1(name string) {
	phase := 13
	if name == "http-response" {
		phase = 12
	}
	p.observeV1(phase)
	if phase == 12 {
		p.mu.Lock()
		p.active = false
		p.mu.Unlock()
	}
}

func (p *nativeOrgSourceGrantTrace257d) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	p.mu.Lock()
	active := p.active
	p.mu.Unlock()
	if !active {
		return ctx
	}
	phase := 11
	switch {
	case strings.HasPrefix(data.SQL, "-- name: GetHTMLSendDocumentStateHeaderV1 "):
		phase = 1
	case strings.HasPrefix(data.SQL, "-- name: GetHTMLSendCollectionReadHeaderV1 "), strings.HasPrefix(data.SQL, "-- name: ListHTMLSend"), strings.HasPrefix(data.SQL, "-- name: ReadHTMLSendInitialPolicyV1 "):
		phase = 2
	case strings.HasPrefix(data.SQL, "-- name: GetLegacySendOrgSourceReadHeaderV1 "), strings.HasPrefix(data.SQL, "-- name: GetHTMLSendOrgSourceReadHeaderV1 "):
		phase = 3
	case strings.HasPrefix(data.SQL, "-- name: ReadLegacySendOrgSourceV1 "), strings.HasPrefix(data.SQL, "-- name: ReadHTMLSendOrgSourceV1 "):
		phase = 4
	case strings.HasPrefix(data.SQL, "-- name: GetLegacySendOrgBrandingSourceReadHeaderV1 "), strings.HasPrefix(data.SQL, "-- name: GetHTMLSendOrgBrandingSourceReadHeaderV1 "):
		phase = 5
	case strings.HasPrefix(data.SQL, "-- name: ReadLegacySendOrgBrandingSourceV1 "), strings.HasPrefix(data.SQL, "-- name: ReadHTMLSendOrgBrandingSourceV1 "):
		phase = 6
	case strings.HasPrefix(data.SQL, "-- name: GetPlanSourceHeaderByIDV1 "), strings.HasPrefix(data.SQL, "-- name: GetPlanSourceHeaderBySlugV1 "):
		phase = 7
	case strings.HasPrefix(data.SQL, "-- name: ReadPlanSourceV1 "):
		phase = 8
	case strings.HasPrefix(data.SQL, "-- name: GetPlanSourceSubscriptionHeaderV1 "):
		phase = 9
	case strings.HasPrefix(data.SQL, "-- name: ReadPlanSourceSubscriptionV1 "):
		phase = 10
	}
	p.observeV1(phase)
	return ctx
}

func (p *nativeOrgSourceGrantTrace257d) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
	p.mu.Lock()
	active := p.active
	p.mu.Unlock()
	if active {
		p.observeV1(11)
	}
}

func (p *nativeOrgSourceGrantTrace257d) observeV1(phase int) {
	p.mu.Lock()
	runtime, org := p.runtime, p.org
	p.mu.Unlock()
	if runtime == nil {
		return
	}
	s, err := runtime.SnapshotV1(org) // Numeric coordinator lock only; no SQL.
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.err = err
		return
	}
	// Bound the measurement independently; saturation fails the measurement,
	// never silently truncates it or changes application admission authority.
	if p.count >= 65536 {
		p.err = fmt.Errorf("numeric query observation bound reached")
		return
	}
	p.count++
	b := &p.phase[phase]
	b.samples++
	if b.samples == 1 || s.OrganisationGrants > b.maxOrg.OrganisationGrants {
		b.maxOrg = s
	}
	b.maxGlobalGrants = max(b.maxGlobalGrants, s.GlobalGrants)
	b.maxParentBytes = max(b.maxParentBytes, s.Global.ParentBytes)
	b.maxDBBytes = max(b.maxDBBytes, s.Global.DBStagingBytes)
}

func (p *nativeOrgSourceGrantTrace257d) reportV1(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = false
	if p.err != nil || p.count == 0 || p.phase[0].samples != 1 || p.phase[12].samples != 1 {
		t.Errorf("bounded numeric observation incomplete: count=%d err=%v", p.count, p.err)
	}
	for i, b := range p.phase {
		if b.samples == 0 {
			continue
		}
		t.Logf("257d sampled lower bounds; phase=%s samples=%d maxObservedOrgGrants=%d maxObservedGlobalGrants=%d maxObservedGlobalParentBytes=%d maxObservedGlobalDBBytes=%d actualSnapshotAtMaxOrg=%+v; not an exact continuous peak", nativeOrgSourceGrantPhaseNames257d[i], b.samples, b.maxOrg.OrganisationGrants, b.maxGlobalGrants, b.maxParentBytes, b.maxDBBytes, b.maxOrg)
	}
}

// The strict original lifecycle snapshot covers documents, recipients and
// credential/notice fields, bindings/LastResolved, versions, lawful basis,
// sealing intents, reminders, events and recipient outbox. These additional
// read-only digests cover source rows, immutable producer measurements, fields,
// branding, signatures, package/report/finalization records and the ENTIRE
// disposable fixture outbox (including sender destinations). No snapshot body,
// source value, credential or stored object is logged.
func nativeOrgSourceLegalDigests257d(t *testing.T, f lifecycleAuthorizationFixture) map[string][32]byte {
	t.Helper()
	state := map[string][32]byte{"original-lifecycle": sha256.Sum256([]byte(f.snapshot(t)))}
	for _, c := range []struct{ table, predicate string }{
		{"orgs", "id=$1"}, {"org_branding", "org_id=$1"}, {"org_subscriptions", "org_id=$1"},
		{"document_fields", "document_id IN (SELECT id FROM documents WHERE org_id=$1)"},
		{"document_branding_override", "document_id IN (SELECT id FROM documents WHERE org_id=$1)"},
		{"signatures", "document_id IN (SELECT id FROM documents WHERE org_id=$1)"},
		{"document_signing_policy_sizes_v1", "org_id=$1"},
		{"field_signing_policy_sizes_v1", "org_id=$1"},
		{"html_snapshot_event_payload_sizes_v1", "org_id=$1"}, {"html_revision_snapshot_sizes_v1", "org_id=$1"},
		{"document_finalization_intents", "org_id=$1"},
		{"document_ordinary_finalization_preparations_v1", "org_id=$1"}, {"document_ordinary_finalization_outputs_v1", "org_id=$1"}, {"document_ordinary_finalization_legacy_intents_v1", "org_id=$1"},
		{"document_packages_v1", "org_id=$1"}, {"document_attachment_drafts_v1", "org_id=$1"},
		{"document_package_captures_v1", "org_id=$1"}, {"document_package_capture_members_v1", "org_id=$1"},
		{"document_package_send_attempts_v1", "org_id=$1"}, {"document_package_send_member_retention_v1", "org_id=$1"},
		{"document_package_send_initial_invite_receipts_v1", "org_id=$1"}, {"document_package_send_completions_v1", "org_id=$1"}, {"document_package_responses_v1", "org_id=$1"},
		{"document_participant_reports_v1", "org_id=$1"}, {"document_participant_report_legacy_intents_v1", "org_id=$1"}, {"document_participant_report_deliveries_v1", "org_id=$1"},
		{"email_deliveries", "$1::uuid IS NOT NULL"},
		{"webhook_deliveries", "$1::uuid IS NOT NULL"},
	} {
		// Both identifier and predicate come only from the fixed table above.
		query := "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)), '[]'::jsonb)::text FROM " + c.table + " r WHERE " + c.predicate
		var raw string
		if err := f.pool.QueryRow(f.ctx, query, f.org).Scan(&raw); err != nil {
			t.Fatal("read actual legal rollback witness", c.table, err)
		} //nolint:rawsql -- read-only exact synthetic family and artifact witness
		if len(raw) > 1<<20 {
			t.Fatal("fixed synthetic legal rollback witness exceeds its test bound", c.table)
		}
		state[c.table] = sha256.Sum256([]byte(raw))
	}
	return state
}

type nativeOrgSourceEffects257d struct {
	puts, deletes, rendererCalls int
	objects                      map[string][32]byte
}

func nativeOrgSourceEffectsSnapshot257d(q *ownedPublicReadFixtureV1) nativeOrgSourceEffects257d {
	p := q.storagePeer.importStoragePeer
	p.mu.Lock()
	s := nativeOrgSourceEffects257d{puts: p.puts, deletes: p.deletes, objects: make(map[string][32]byte, len(p.objects))}
	for key, body := range p.objects {
		s.objects[key] = sha256.Sum256(body)
	}
	p.mu.Unlock()
	q.renderer.protocol.mu.Lock()
	s.rendererCalls = len(q.renderer.protocol.html)
	q.renderer.protocol.mu.Unlock()
	return s
}

func TestNativeChildOrgPlanOriginalGrantLimitRollbackV1E2E(t *testing.T) {
	for _, subscription := range []bool{false, true} {
		name := "operator"
		if subscription {
			name = "subscription"
		}
		t.Run(name, func(t *testing.T) {
			trace := new(nativeOrgSourceGrantTrace257d)
			// EXACT original profile: global128/org64; chosen before the pool.
			q := newOwnedPublicReadFixtureProfileV1(t, false, false, trace)
			f, cookie, _, _ := nativeOrgSourcePrepare257d(t, q, nativeOrgSourceCase257d{path: "org.plan", want: "pro", family: true, child: true, twice: true, subscription: subscription})
			before := nativeOrgSourceLegalDigests257d(t, f)
			effects := nativeOrgSourceEffectsSnapshot257d(q)
			trace.beginV1(t, q)
			response := f.submit("send", cookie) // One actual normal HTTP Send.
			trace.checkpointV1("http-response")
			if response.Code != http.StatusServiceUnavailable {
				t.Fatal("original allocation must retain actual bounded child-plan refusal", response.Code)
			}
			after := nativeOrgSourceLegalDigests257d(t, f)
			for table, digest := range before {
				if after[table] != digest {
					t.Fatal("refused Send changed actual legal/source/evidence/effects state", table)
				}
			}
			actual := nativeOrgSourceEffectsSnapshot257d(q)
			if actual.puts != effects.puts || actual.deletes != effects.deletes || actual.rendererCalls != effects.rendererCalls || len(actual.objects) != len(effects.objects) {
				t.Fatal("refused Send dispatched or changed an external renderer/storage effect")
			}
			for key, digest := range effects.objects {
				if actual.objects[key] != digest {
					t.Fatal("refused Send changed an actual stored object")
				}
			}
			// Logical refusal alone never credits admission. This original
			// oracle reconciles real client/backend retirement, retains both
			// actual observers and requires every work/resource grant to retire.
			q.assertObserversOnlyV1(t)
			trace.checkpointV1("joined-observers-only")
		})
	}
}
