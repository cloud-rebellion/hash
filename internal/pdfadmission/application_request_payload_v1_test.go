// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This fixture contains private synthetic session/observer seams. It exercises
// the REAL shared coordinator and real private consumer-loan bookkeeping only;
// the zero pgx handle never dispatches SQL or proves backend retirement/M90.
func applicationRequestLoanFixtureV1(t *testing.T) (*applicationFixtureV1, *ApplicationSessionV1, *workguard.CoordinatorV1) {
	t.Helper()
	f := applicationFixtureForTestV1(t, false)
	c, w := workAdmissionTestV1(t)
	f.adapter.acquire = w.ApplicationV1
	now := time.Now().UTC()
	f.adapter.fence.identity = applicationBackendIdentityV1{pid: 1234, backendStart: now, databaseOID: 42, userOID: 43, address: "192.0.2.1", port: 5432, postmasterStart: now.Add(-time.Hour)}
	p := &applicationSessionFactoryStateV1{work: w, sessions: make(map[*applicationOwnedSessionV1]struct{})}
	s := &applicationOwnedSessionV1{factory: p, org: f.scope.OrgID, document: f.scope.DocumentID, changed: make(chan struct{}), dialed: true, tx: &applicationSessionTxTestV1{}, conn: &pgx.Conn{}, fence: f.adapter.fence, admission: f.adapter}
	p.sessions[s] = struct{}{}
	return f, &ApplicationSessionV1{state: s}, c
}
func applicationRequestBudgetTestV1(t *testing.T, phase string, scope ApplicationScopeV1, recipient uuid.UUID) ApplicationBudgetV1 {
	t.Helper()
	b := ApplicationBudgetV1{Phase: phase, OrgID: scope.OrgID, DocumentID: scope.DocumentID, AdmissionID: scope.AdmissionID, RecipientID: recipient}
	switch phase {
	case "locked-request-header":
		b.AdmissionID = uuid.Nil
		b.WorkingBytes = 8 << 20
		b.DBStagingBytes = 8 << 20
	case "locked-request-payload":
		b.RequestOriginBytes = 2000
		b.RequestIntentBytes = 7000
		b.RequestRawContextBytes = 10000
		b.WorkingBytes = 8*9000 + 8192 + 10000
		b.DBStagingBytes = 9000
	case "locked-request-capture", "locked-request-read":
		b.RequestOriginBytes = 2000
		b.RequestIntentBytes = 7000
		b.RequestAuthorityBytes = 11000
		b.RequestSpanBytes = 13000
		b.RequestCurrentContextBytes = 17000
		b.RequestOriginalRawContextBytes = 19000
		b.RequestPolicyBytes = 23000
		b.WorkingBytes = 16*(2000+7000+11000+13000+17000+19000+23000) + (8 << 20)
		b.DBStagingBytes = 16*(2000+7000+11000+13000+23000) + 17000
	default:
		t.Fatal("unknown test phase")
	}
	return b
}
func TestApplicationRequestWorkV1FixedKnownCostsAndSharedCapacity(t *testing.T) {
	c, w := workAdmissionTestV1(t)
	ctx := applicationTestContextV1(t)
	scope := ApplicationScopeV1{OrgID: uuid.New(), DocumentID: uuid.New(), AdmissionID: uuid.New()}
	recipient := uuid.New()
	for _, phase := range []string{"locked-request-header", "locked-request-payload", "locked-request-capture", "locked-request-read"} {
		t.Run(phase, func(t *testing.T) {
			b := applicationRequestBudgetTestV1(t, phase, scope, recipient)
			closeCost, err := w.ApplicationV1(ctx, b)
			if err != nil {
				t.Fatal(err)
			}
			defer closeCost()
			s := c.SnapshotV1(scope.OrgID)
			if s.Global.ParentBytes != b.WorkingBytes || s.Global.DBStagingBytes != b.DBStagingBytes || s.Global.SQLSessions != 0 || s.Global.ProviderStreams != 0 || s.Global.PDFWorkers != 0 {
				t.Fatal("wrong fixed request cost vector", s)
			}
			before := s
			for _, mutate := range []func(*ApplicationBudgetV1){func(b *ApplicationBudgetV1) { b.WorkingBytes-- }, func(b *ApplicationBudgetV1) { b.DBStagingBytes-- }, func(b *ApplicationBudgetV1) { b.RecipientID = uuid.Nil }, func(b *ApplicationBudgetV1) { b.RequestOriginBytes++ }, func(b *ApplicationBudgetV1) { b.OriginalPDFBytes = 1 }, func(b *ApplicationBudgetV1) { b.SourceBytes = 1 }, func(b *ApplicationBudgetV1) { b.Phase = "caller-work" }} {
				bad := b
				mutate(&bad)
				r, err := w.ApplicationV1(ctx, bad)
				if err == nil || r != nil {
					if r != nil {
						r()
					}
					t.Fatal("reported/invented cost admitted")
				}
				if c.SnapshotV1(scope.OrgID) != before {
					t.Fatal("refused cost changed shared counters")
				}
			}
			closeCost()
			if c.SnapshotV1(scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("cost owner did not release once")
			}
		})
	}
	// A request cost competes with the SAME existing PDF/basis/session grants.
	b := applicationRequestBudgetTestV1(t, "locked-request-payload", scope, recipient)
	small, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: b.WorkingBytes, DBStagingBytes: b.DBStagingBytes}, Organisation: workguard.VectorV1{ParentBytes: b.WorkingBytes, DBStagingBytes: b.DBStagingBytes}, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewWorkAdmissionV1(small)
	if err != nil {
		t.Fatal(err)
	}
	held, err := same.ApplicationV1(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	if next, err := same.ApplicationV1(ctx, b); next != nil || err == nil {
		if next != nil {
			next()
		}
		t.Fatal("same resource capacity was duplicated")
	}
	other := b
	other.OrgID = uuid.New()
	if next, err := same.ApplicationV1(ctx, other); next != nil || err == nil {
		if next != nil {
			next()
		}
		t.Fatal("different org escaped global capacity")
	}
	held()
	again, err := same.ApplicationV1(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	again()
}
func TestApplicationRequestWorkV1PublicOverflowAndSupportedBounds(t *testing.T) {
	base := ApplicationRequestPayloadCostV1{OriginBytes: MaxApplicationRequestOriginBytesV1, IntentBytes: MaxApplicationAcceptedIntentBytesV1, RawContextBytes: 1 << 20}
	r, err := ApplicationRequestPayloadResourcesForV1(base)
	if err != nil || r.WorkingBytes != 8*(base.OriginBytes+base.IntentBytes)+8192+base.RawContextBytes || r.DBStagingBytes != base.OriginBytes+base.IntentBytes {
		t.Fatal("full legal/name range was shortened")
	}
	for _, mutate := range []func(*ApplicationRequestPayloadCostV1){func(b *ApplicationRequestPayloadCostV1) { b.OriginBytes++ }, func(b *ApplicationRequestPayloadCostV1) { b.IntentBytes++ }, func(b *ApplicationRequestPayloadCostV1) { b.OriginBytes = 0 }, func(b *ApplicationRequestPayloadCostV1) { b.RawContextBytes = -1 }, func(b *ApplicationRequestPayloadCostV1) { b.RawContextBytes = math.MaxInt64 }} {
		bad := base
		mutate(&bad)
		if _, err := ApplicationRequestPayloadResourcesForV1(bad); err == nil {
			t.Fatal("invalid or wrapping public metadata accepted")
		}
	}
	journal := ApplicationRequestJournalCostV1{Kind: ApplicationRequestJournalCaptureV1, OriginBytes: base.OriginBytes, IntentBytes: base.IntentBytes, AuthorityBytes: manualfit.MaxAuthorityBytesV1, SpanBytes: manualfit.MaxSpanBytesV1, CurrentContextBytes: 1 << 20, OriginalRawContextBytes: 1 << 20, PolicyBytes: 1 << 20}
	r, err = ApplicationRequestJournalResourcesForV1(journal)
	bodies := journal.OriginBytes + journal.IntentBytes + journal.AuthorityBytes + journal.SpanBytes
	if err != nil || r.WorkingBytes != 16*(bodies+journal.PolicyBytes+journal.CurrentContextBytes+journal.OriginalRawContextBytes)+(8<<20) || r.DBStagingBytes != 16*(bodies+journal.PolicyBytes)+journal.CurrentContextBytes {
		t.Fatal("supported journal max/multiplier mismatch")
	}
	for _, mutate := range []func(*ApplicationRequestJournalCostV1){func(b *ApplicationRequestJournalCostV1) { b.Kind = "caller-defined" }, func(b *ApplicationRequestJournalCostV1) { b.AuthorityBytes++ }, func(b *ApplicationRequestJournalCostV1) { b.SpanBytes++ }, func(b *ApplicationRequestJournalCostV1) { b.CurrentContextBytes = 8191 }, func(b *ApplicationRequestJournalCostV1) { b.CurrentContextBytes = math.MaxInt64 }, func(b *ApplicationRequestJournalCostV1) { b.OriginalRawContextBytes = -1 }, func(b *ApplicationRequestJournalCostV1) { b.OriginalRawContextBytes = math.MaxInt64 }, func(b *ApplicationRequestJournalCostV1) { b.PolicyBytes = -1 }, func(b *ApplicationRequestJournalCostV1) { b.PolicyBytes = math.MaxInt64 }, func(b *ApplicationRequestJournalCostV1) { b.IntentBytes = -1 }} {
		bad := journal
		mutate(&bad)
		if _, err := ApplicationRequestJournalResourcesForV1(bad); err == nil {
			t.Fatal("invalid journal/overflow metadata accepted")
		}
	}
}
func TestApplicationRequestWorkV1ConsumerAndPhysicalRetirementConjunction(t *testing.T) {
	for _, order := range []string{"consumer-first", "physical-first"} {
		t.Run(order, func(t *testing.T) {
			f, h, c := applicationRequestLoanFixtureV1(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			recipient := uuid.New()
			payload := ApplicationRequestPayloadCostV1{OriginBytes: 2000, IntentBytes: 7000, RawContextBytes: 10000}
			consumer, err := h.AcquireRequestPayloadV1(ctx, f.scope, recipient, payload)
			if err != nil {
				t.Fatal(err)
			}
			before := c.SnapshotV1(f.scope.OrgID)
			if before.GlobalGrants != 1 || f.adapter.PendingV1().Loans != 1 {
				t.Fatal("real coordinator loan missing")
			}
			cancel()
			if c.SnapshotV1(f.scope.OrgID) != before {
				t.Fatal("request cancellation credited live ownership")
			}
			reconcile := applicationTestContextV1(t)
			gone := false
			observed := 0
			f.adapter.fence.observe = func(context.Context, applicationBackendIdentityV1) (bool, error) { observed++; return gone, nil }
			if pending, err := f.adapter.ReconcileCleanupV1(reconcile); err != nil || pending != 1 || observed != 0 {
				t.Fatal("uncleaned client triggered proof or credit")
			}
			if order == "consumer-first" {
				consumer()
				consumer()
			}
			close(f.done)
			if pending, err := f.adapter.ReconcileCleanupV1(reconcile); err != nil || pending != 1 || c.SnapshotV1(f.scope.OrgID) != before {
				t.Fatal("client cleanup/live backend was credited")
			}
			gone = true
			pending, err := f.adapter.ReconcileCleanupV1(reconcile)
			if err != nil {
				t.Fatal(err)
			}
			if order == "physical-first" {
				if pending != 1 || c.SnapshotV1(f.scope.OrgID) != before {
					t.Fatal("physical retirement freed live consumer")
				}
				consumer()
				consumer()
				pending, err = f.adapter.ReconcileCleanupV1(reconcile)
			}
			if err != nil || pending != 0 || c.SnapshotV1(f.scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("actual conjunction did not release once")
			}
			if pending, err = f.adapter.ReconcileCleanupV1(reconcile); err != nil || pending != 0 {
				t.Fatal("repeat reconciliation failed")
			}
		})
	}
}
func TestApplicationRequestWorkV1OwnedScopeAndCallbackRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ApplicationSessionV1, *ApplicationScopeV1, **context.Context)
	}{
		{"foreign org", func(_ *ApplicationSessionV1, s *ApplicationScopeV1, _ **context.Context) { s.OrgID = uuid.New() }},
		{"foreign document", func(_ *ApplicationSessionV1, s *ApplicationScopeV1, _ **context.Context) { s.DocumentID = uuid.New() }},
		{"ended", func(h *ApplicationSessionV1, _ *ApplicationScopeV1, _ **context.Context) { h.state.ended = true }},
		{"unknown", func(h *ApplicationSessionV1, _ *ApplicationScopeV1, _ **context.Context) { h.state.unknown = true }},
		{"missing owned admission", func(h *ApplicationSessionV1, _ *ApplicationScopeV1, _ **context.Context) { h.state.admission = nil }},
		{"foreign fence", func(h *ApplicationSessionV1, _ *ApplicationScopeV1, _ **context.Context) {
			h.state.admission.fence = &applicationSessionFenceV1{}
		}},
		{"outside active callback", func(h *ApplicationSessionV1, _ *ApplicationScopeV1, _ **context.Context) {
			h.state.callbackActive = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, h, c := applicationRequestLoanFixtureV1(t)
			scope := f.scope
			ctx := applicationTestContextV1(t)
			ptr := &ctx
			tc.mutate(h, &scope, &ptr)
			r, err := h.AcquireRequestPayloadV1(*ptr, scope, uuid.New(), ApplicationRequestPayloadCostV1{OriginBytes: 100, IntentBytes: 200})
			if r != nil || err == nil {
				if r != nil {
					r()
				}
				t.Fatal("foreign/unowned request got a consumer loan")
			}
			if c.SnapshotV1(f.scope.OrgID) != (workguard.SnapshotV1{}) || f.adapter.PendingV1().Loans != 0 {
				t.Fatal("scope refusal consumed resources")
			}
		})
	}
	f, h, c := applicationRequestLoanFixtureV1(t)
	h.state.callbackActive = true
	ctx := context.WithValue(applicationTestContextV1(t), applicationSessionCallbackKeyV1{}, h.state)
	r, err := h.AcquireRequestHeaderV1(ctx, f.scope.OrgID, f.scope.DocumentID, uuid.New())
	if err != nil {
		t.Fatal("actual matching callback should permit nonwaiting header loan", err)
	}
	r()
	close(f.done)
	if _, err = f.adapter.ReconcileCleanupV1(applicationTestContextV1(t)); err != nil || c.SnapshotV1(f.scope.OrgID) != (workguard.SnapshotV1{}) {
		t.Fatal("matching callback loan failed cleanup")
	}
}
func TestApplicationRequestWorkV1HeaderCaptureReadLoansShareOwner(t *testing.T) {
	f, h, c := applicationRequestLoanFixtureV1(t)
	ctx := applicationTestContextV1(t)
	recipient := uuid.New()
	header, err := h.AcquireRequestHeaderV1(ctx, f.scope.OrgID, f.scope.DocumentID, recipient)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := h.AcquireRequestPayloadV1(ctx, f.scope, recipient, ApplicationRequestPayloadCostV1{OriginBytes: 2000, IntentBytes: 7000, RawContextBytes: 10000})
	if err != nil {
		t.Fatal(err)
	}
	var journal []func()
	for _, kind := range []ApplicationRequestJournalKindV1{ApplicationRequestJournalCaptureV1, ApplicationRequestJournalReadV1} {
		r, err := h.AcquireRequestJournalV1(ctx, f.scope, recipient, ApplicationRequestJournalCostV1{Kind: kind, OriginBytes: 2000, IntentBytes: 7000, AuthorityBytes: manualfit.MaxAuthorityBytesV1, SpanBytes: manualfit.MaxSpanBytesV1, CurrentContextBytes: 20000})
		if err != nil {
			t.Fatal(err)
		}
		journal = append(journal, r)
	}
	before := c.SnapshotV1(f.scope.OrgID)
	if before.GlobalGrants != 4 || f.adapter.PendingV1().Loans != 4 || before.Global.SQLSessions != 0 {
		t.Fatal("different owner or implicit physical grant introduced")
	}
	header()
	payload()
	for _, r := range journal {
		r()
	}
	if c.SnapshotV1(f.scope.OrgID) != before {
		t.Fatal("logical journal finish returned capacity")
	}
	close(f.done)
	pending, err := f.adapter.ReconcileCleanupV1(ctx)
	if err != nil || pending != 0 || c.SnapshotV1(f.scope.OrgID) != (workguard.SnapshotV1{}) {
		t.Fatal("shared owned loans did not physically reconcile")
	}
}
func TestApplicationRequestWorkV1NewAdmissionReusesOwnedRegistry(t *testing.T) {
	f, h, c := applicationRequestLoanFixtureV1(t)
	ctx := applicationTestContextV1(t)
	consumer, err := h.AcquireRequestHeaderV1(ctx, f.scope.OrgID, f.scope.DocumentID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	copyHandle := *h
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := copyHandle.NewAdmissionV1(ctx)
			if err == nil && a != f.adapter {
				errs <- errors.New("new call replaced owned registry")
				return
			}
			if err != nil && !errors.Is(err, ErrApplicationSessionV1) {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if h.state.admission != f.adapter || f.adapter.PendingV1().Loans != 1 || c.SnapshotV1(f.scope.OrgID).GlobalGrants != 1 {
		t.Fatal("copied calls discarded retained loan")
	}
	consumer()
	close(f.done)
	if pending, err := f.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 0 {
		t.Fatal("cached admission could not finish")
	}
}
func TestApplicationRequestWorkV1CancelledCapacityRefusalKeepsPrivateCause(t *testing.T) {
	f, h, c := applicationRequestLoanFixtureV1(t)
	ctx, cancel := context.WithCancelCause(applicationTestContextV1(t))
	cause := errors.New("private request capacity cancellation")
	cancel(cause)
	r, err := h.AcquireRequestHeaderV1(ctx, f.scope.OrgID, f.scope.DocumentID, uuid.New())
	if r != nil || !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || err.Error() != ErrApplicationAdmissionV1.Error() {
		t.Fatal("private cancellation identity/public text failed")
	}
	if c.SnapshotV1(f.scope.OrgID) != (workguard.SnapshotV1{}) {
		t.Fatal("cancelled request consumed quota")
	}
}
