// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Private SQL/source/worker fixtures below are explicitly synthetic. They test
// dispatch/binding/physical-loan accounting, NOT actual PDF/producer/storage,
// PostgreSQL retirement, global capacity, credentials, ready COMMIT or Sign.
type applicationColdResourcesForTestV1 struct {
	mu                            sync.Mutex
	cold, parent, workers, source int
}

func (r *applicationColdResourcesForTestV1) counts() (int, int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cold, r.parent, r.workers, r.source
}
func (r *applicationColdResourcesForTestV1) acquire(_ context.Context, b ApplicationBudgetV1) (func(), error) {
	r.mu.Lock()
	r.cold++
	r.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { r.mu.Lock(); r.cold--; r.mu.Unlock() }) }, nil
}
func (r *applicationColdResourcesForTestV1) inspect(_ context.Context, b OrdinaryInspectionBudgetV1) (func(), error) {
	if b.Phase != "cold-fragment" || b.PackageBytes != 0 || b.SourceBytes < 1 || b.PlanBytes < 1 || b.MemoryBytes != 4*(b.SourceBytes+b.PlanBytes)+(8<<20) {
		return nil, errors.New("synthetic cold budget mismatch")
	}
	r.mu.Lock()
	r.parent++
	r.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { r.mu.Lock(); r.parent--; r.mu.Unlock() }) }, nil
}
func (r *applicationColdResourcesForTestV1) worker(_ context.Context, b OrdinaryInspectionWorkerBudgetV1) (func(), error) {
	if b.Phase != "fragment" || b.OrgID == uuid.Nil || b.DocumentID == uuid.Nil {
		return nil, errors.New("synthetic worker scope mismatch")
	}
	r.mu.Lock()
	r.workers++
	r.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { r.mu.Lock(); r.workers--; r.mu.Unlock() }) }, nil
}

type applicationColdFixtureForTestV1 struct {
	sql            *applicationFixtureV1
	candidate      *ApplicationCandidateV1
	original       *ApplicationOriginalV1
	cold           *ApplicationColdV1
	source         *ApplicationColdSourceV1
	resources      *applicationColdResourcesForTestV1
	fragmentCalls  atomic.Int32
	authorityCalls atomic.Int32
}

func applicationColdNewFixtureForTestV1(t *testing.T) *applicationColdFixtureForTestV1 {
	t.Helper()
	f := &applicationColdFixtureForTestV1{sql: applicationFixtureForTestV1(t, true), resources: &applicationColdResourcesForTestV1{source: 1}}
	// A new current owner may recover an immutable original captured by an older
	// owner. Never rewrite the historical captured_owner_id or captured_at.
	f.sql.metadata[0].CapturedOwnerID = uuid.New()
	var err error
	f.candidate, err = f.sql.adapter.LoadCurrentV1(applicationTestContextV1(t), f.sql.scope)
	if err != nil {
		t.Fatal(err)
	}
	f.original, err = f.sql.adapter.LoadOriginalV1(applicationTestContextV1(t), f.candidate, 2)
	if err != nil {
		t.Fatal(err)
	}
	close(f.sql.done)
	applicationReconcileForTestV1(t, f.sql.adapter)
	inspector, err := NewOrdinaryInspectorV1(f.resources.inspect, f.resources.worker)
	if err != nil {
		t.Fatal(err)
	}
	inspector.worker.fragment = func(_ context.Context, pdf []byte, w, h float64) (sanitize.PDFManualFragmentAdmission, error) {
		_, _, active, _ := f.resources.counts()
		if active != 1 {
			return sanitize.PDFManualFragmentAdmission{}, errors.New("missing joined worker grant")
		}
		f.fragmentCalls.Add(1)
		return ordinaryInspectionTestFragmentV1(pdf, w, h), nil
	}
	f.cold, err = NewApplicationColdV1(&storage.Client{}, inspector, f.resources.acquire, func(_ context.Context, d ApplicationDispatchV1) error {
		f.authorityCalls.Add(1)
		if d.Scope != f.sql.scope {
			return errors.New("foreign original credential")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// This is a private fake source-worker receipt. No public constructor is being
	// claimed to have fetched or semantically inspected the synthetic source.
	proof := &OrdinarySourceInspectionV1{state: &ordinarySourceInspectionStateV1{issuer: inspector.issuer, basis: f.sql.basis, geometry: f.sql.basis.Geometry(), release: func() {}}}
	f.source = &ApplicationColdSourceV1{issuer: f.cold.issuer, readerIssuer: f.sql.adapter.issuer, scope: f.sql.scope, basis: f.sql.basis, proof: proof, release: func() { f.resources.mu.Lock(); f.resources.source--; f.resources.mu.Unlock() }, readerFence: f.sql.adapter.fence, pages: make(map[*ApplicationColdPageV1]struct{}), inspecting: make(map[int]bool)}
	t.Cleanup(func() {
		f.original.Close()
		f.candidate.Close()
		f.sql.adapter.fence.mu.Lock()
		f.sql.adapter.fence.observe = func(context.Context, applicationBackendIdentityV1) (bool, error) { return true, nil }
		f.sql.adapter.fence.mu.Unlock()
		applicationReconcileForTestV1(t, f.sql.adapter)
		f.source.Close()
		_, _ = f.source.ReconcileCleanupV1(applicationTestContextV1(t))
	})
	return f
}
func applicationColdFreshReaderForTestV1(t *testing.T, f *applicationColdFixtureForTestV1) (*ApplicationAdmissionV1, *ApplicationCandidateV1, chan struct{}, *bool, *int) {
	t.Helper()
	done := make(chan struct{})
	gone := false
	calls := 0
	q := f.sql.adapter.queries
	q.ready = func(_ context.Context, p generated.MarkPDFSigningAdmissionReadyV1Params) (*generated.MarkPDFSigningAdmissionReadyV1Row, error) {
		calls++
		if p.OwnerID != f.sql.scope.OwnerID || p.AdmissionID != f.sql.scope.AdmissionID || len(p.SourceInspectionSha256) != 32 {
			return nil, errors.New("wrong ready authority")
		}
		return &generated.MarkPDFSigningAdmissionReadyV1Row{ID: p.AdmissionID, OrgID: p.OrgID, DocumentID: p.DocumentID, StaticBasisSha256: applicationDigestV1(f.sql.basis.SHA256()), Status: "ready", ReadyAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}, nil
	}
	a := &ApplicationAdmissionV1{issuer: &applicationIssuerV1{1}, cleanupDone: done, fence: &applicationSessionFenceV1{clientDone: done, observe: func(context.Context, applicationBackendIdentityV1) (bool, error) { return gone, nil }}, loans: make(map[*applicationLoanV1]struct{}), retainedPages: make(map[*ApplicationGeneratedPageV1]struct{}), changed: make(chan struct{}, 1), queries: q, acquire: f.sql.adapter.acquire}
	c, err := a.LoadCurrentV1(applicationTestContextV1(t), f.sql.scope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		if !applicationDoneV1(done) {
			close(done)
		}
		gone = true
		applicationReconcileForTestV1(t, a)
		f.source.Close()
		_, _ = f.source.ReconcileCleanupV1(applicationTestContextV1(t))
	})
	return a, c, done, &gone, &calls
}
func applicationColdPageForTestV1(t *testing.T, f *applicationColdFixtureForTestV1) *ApplicationColdPageV1 {
	t.Helper()
	p, err := f.cold.InspectPageV1(applicationTestContextV1(t), f.source, f.original)
	if err != nil || p == nil {
		t.Fatal("synthetic cold fragment flow", err)
	}
	return p
}

func TestApplicationColdV1OpaqueOriginalLineageAndPhysicalWorkerGrant(t *testing.T) {
	f := applicationColdNewFixtureForTestV1(t)
	p := applicationColdPageForTestV1(t, f)
	if p.metadata.CapturedOwnerID == f.sql.scope.OwnerID || !applicationColdMetadataEqualV1(p.metadata, *f.sql.metadata[0]) || !bytes.Equal(p.pdf, f.sql.originalPDF) || !bytes.Equal(p.plan, f.sql.originalPlan) || f.fragmentCalls.Load() != 1 {
		t.Fatal("cold recovery changed original/capture lineage")
	}
	cold, parent, workers, _ := f.resources.counts()
	if cold != 1 || parent != 1 || workers != 0 {
		t.Fatal("worker grant failed to retire independently of parent receipt")
	}
	if p.fragment.PDFSHA256 != plainSHA256V1(f.sql.originalPDF) || p.canonicalSHA != f.sql.basis.CanonicalSHA256() {
		t.Fatal("fresh fragment failed original/basis binding")
	}
	p.Close()
	cold, parent, workers, _ = f.resources.counts()
	if cold != 0 || parent != 0 || workers != 0 {
		t.Fatal("closed cold fragment kept its parent loans")
	}
	if !bytes.Equal(f.original.pdf, f.sql.originalPDF) {
		t.Fatal("cold receipt erased caller-owned SQL original")
	}
}

func TestApplicationColdV1RefusesForeignUnretiredDeniedAndUnpaintedOriginals(t *testing.T) {
	for _, kind := range []string{"foreign-issuer", "foreign-scope", "foreign-fence", "unretired-server", "closed-original", "unpainted", "denied-authority", "denied-capacity"} {
		t.Run(kind, func(t *testing.T) {
			f := applicationColdNewFixtureForTestV1(t)
			switch kind {
			case "foreign-issuer":
				f.original.issuer = &applicationIssuerV1{9}
			case "foreign-scope":
				f.original.scope.DocumentID = uuid.New()
			case "foreign-fence":
				f.original.fence = &applicationSessionFenceV1{}
			case "unretired-server":
				f.original.fence.mu.Lock()
				f.original.fence.retired = false
				f.original.fence.observe = func(context.Context, applicationBackendIdentityV1) (bool, error) { return false, nil }
				f.original.fence.mu.Unlock()
			case "closed-original":
				f.original.Close()
			case "unpainted":
				f.original.metadata.Page = 1
			case "denied-authority":
				f.cold.authorize = func(context.Context, ApplicationDispatchV1) error { return errors.New("private revoked original") }
			case "denied-capacity":
				f.cold.acquire = func(context.Context, ApplicationBudgetV1) (func(), error) {
					return nil, errors.New("private full resource account")
				}
			}
			p, err := f.cold.InspectPageV1(applicationTestContextV1(t), f.source, f.original)
			if p != nil || !errors.Is(err, ErrApplicationAdmissionV1) || f.fragmentCalls.Load() != 0 || err.Error() != ErrApplicationAdmissionV1.Error() {
				t.Fatal("cold refusal reached worker or leaked private input")
			}
			cold, parent, workers, _ := f.resources.counts()
			if cold != 0 || parent != 0 || workers != 0 {
				t.Fatal("refused cold page leaked a grant")
			}
		})
	}
}

func TestApplicationColdV1CurrentExactReadyAndServerFencedConsumerCleanup(t *testing.T) {
	f := applicationColdNewFixtureForTestV1(t)
	p := applicationColdPageForTestV1(t, f)
	a, c, done, gone, calls := applicationColdFreshReaderForTestV1(t, f)
	if err := f.cold.MarkReadyTxV1(applicationTestContextV1(t), a, c, f.source, []*ApplicationColdPageV1{p}); err != nil || *calls != 1 || c.header.Status != "ready" {
		t.Fatal("exact cold readiness failed", err)
	}
	ownedPDF, ownedPlan := p.pdf, p.plan
	f.source.Close()
	if len(ownedPDF) == 0 || ownedPDF[0] == 0 || len(ownedPlan) == 0 || ownedPlan[0] == 0 {
		t.Fatal("Close erased cold originals before ready session retirement")
	}
	close(done)
	if n, err := f.source.ReconcileCleanupV1(applicationTestContextV1(t)); err != nil || n < 1 {
		t.Fatal("client cleanup inferred server retirement")
	}
	cold, parent, _, source := f.resources.counts()
	if cold != 1 || parent != 1 || source != 1 {
		t.Fatal("unretired SQL lost cold consumer resources")
	}
	*gone = true
	c.Close()
	applicationReconcileForTestV1(t, a)
	if n, err := f.source.ReconcileCleanupV1(applicationTestContextV1(t)); err != nil || n != 0 {
		t.Fatal("actual retirement did not clean cold consumers")
	}
	for _, v := range append(ownedPDF, ownedPlan...) {
		if v != 0 {
			t.Fatal("retired cold original bytes not erased")
		}
	}
	cold, parent, workers, source := f.resources.counts()
	if cold != 0 || parent != 0 || workers != 0 || source != 0 {
		t.Fatal("retired cold resources remained")
	}
}

func TestApplicationColdV1ReadyRefusesIncompleteForeignAlteredAndExpiredState(t *testing.T) {
	for _, kind := range []string{"missing", "duplicate", "foreign-receipt", "changed-lineage", "changed-pdf", "changed-plan", "expired-lease", "denied-authority", "closed-source"} {
		t.Run(kind, func(t *testing.T) {
			f := applicationColdNewFixtureForTestV1(t)
			p := applicationColdPageForTestV1(t, f)
			a, c, _, _, calls := applicationColdFreshReaderForTestV1(t, f)
			pages := []*ApplicationColdPageV1{p}
			switch kind {
			case "missing":
				pages = nil
			case "duplicate":
				pages = append(pages, p)
			case "foreign-receipt":
				p.issuer = &applicationIssuerV1{99}
			case "changed-lineage":
				m := c.originals[2]
				m.CapturedOwnerID = uuid.New()
				c.originals[2] = m
			case "changed-pdf":
				a.queries.body = func(context.Context, generated.ReadPDFSigningAdmissionBodyV1Params) ([]byte, error) {
					return []byte("tampered actual SQL bytes"), nil
				}
			case "changed-plan":
				a.queries.plan = func(context.Context, generated.ReadPDFSigningAdmissionPlanV1Params) ([]byte, error) {
					return []byte("{}"), nil
				}
			case "expired-lease":
				c.header.LeaseCurrent = false
			case "denied-authority":
				f.cold.authorize = func(context.Context, ApplicationDispatchV1) error {
					return errors.New("private credential revoked after worker")
				}
			case "closed-source":
				f.source.Close()
			}
			err := f.cold.MarkReadyTxV1(applicationTestContextV1(t), a, c, f.source, pages)
			if !errors.Is(err, ErrApplicationAdmissionV1) || *calls != 0 || c.header.Status != "staging" {
				t.Fatal("invalid cold readiness reached mutation or moved state")
			}
		})
	}
}

func TestApplicationColdV1UnknownReadyNeverReplaysBeforeActualRetirement(t *testing.T) {
	f := applicationColdNewFixtureForTestV1(t)
	p := applicationColdPageForTestV1(t, f)
	a, c, done, gone, calls := applicationColdFreshReaderForTestV1(t, f)
	a.queries.ready = func(context.Context, generated.MarkPDFSigningAdmissionReadyV1Params) (*generated.MarkPDFSigningAdmissionReadyV1Row, error) {
		*calls++
		return nil, errors.New("private unknown ready transaction")
	}
	if err := f.cold.MarkReadyTxV1(applicationTestContextV1(t), a, c, f.source, []*ApplicationColdPageV1{p}); !errors.Is(err, ErrApplicationCaptureUncertainV1) {
		t.Fatal("unknown ready lost reconciliation requirement")
	}
	fresh, next, _, _, nextCalls := applicationColdFreshReaderForTestV1(t, f)
	if err := f.cold.MarkReadyTxV1(applicationTestContextV1(t), fresh, next, f.source, []*ApplicationColdPageV1{p}); !errors.Is(err, ErrApplicationAdmissionV1) || *nextCalls != 0 {
		t.Fatal("unknown old session permitted blind ready replay")
	}
	close(done)
	*gone = true
	c.Close()
	applicationReconcileForTestV1(t, a)
	// This private fixture explicitly models old rollback + a fresh guarded staging
	// row. Real callers must independently prove that scoped state, not assume it.
	if err := f.cold.MarkReadyTxV1(applicationTestContextV1(t), fresh, next, f.source, []*ApplicationColdPageV1{p}); err != nil || *nextCalls != 1 {
		t.Fatal("retired exact fresh staging could not recover", err)
	}
}

func TestApplicationColdV1CancellationKeepsOwnedPDFAndBothGrantsThroughJoin(t *testing.T) {
	f := applicationColdNewFixtureForTestV1(t)
	started := make(chan struct{})
	physical := make(chan struct{})
	var joinOnce sync.Once
	join := func() { joinOnce.Do(func() { close(physical) }) }
	defer join()
	var owned []byte
	f.cold.inspector.worker.fragment = func(ctx context.Context, pdf []byte, w, h float64) (sanitize.PDFManualFragmentAdmission, error) {
		owned = pdf
		close(started)
		<-ctx.Done()
		<-physical
		return sanitize.PDFManualFragmentAdmission{}, errors.New("private cancelled physical worker")
	}
	ctx, cancel := context.WithCancelCause(applicationTestContextV1(t))
	defer cancel(nil)
	private := errors.New("private original credential cancel")
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		p, err := f.cold.InspectPageV1(ctx, f.source, f.original)
		if p != nil {
			p.Close()
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		join()
		<-finished
		t.Fatal("cold fixed worker did not start")
	}
	cancel(private)
	cold, parent, workers, _ := f.resources.counts()
	if cold != 1 || parent != 1 || workers != 1 || len(owned) == 0 || owned[0] == 0 {
		join()
		<-finished
		t.Fatal("logical cancellation released live worker buffers/grants")
	}
	select {
	case <-finished:
		t.Fatal("cancelled worker returned before physical join")
	default:
	}
	join()
	var err error
	select {
	case err = <-result:
	case <-time.After(time.Second):
		t.Fatal("joined cold worker did not return")
	}
	<-finished
	if !errors.Is(err, context.Canceled) || !errors.Is(err, private) || err.Error() != ErrApplicationAdmissionV1.Error() {
		t.Fatal("cancelled cold failure lost identity or leaked private cause")
	}
	for _, v := range owned {
		if v != 0 {
			t.Fatal("failed cold worker owned PDF not erased")
		}
	}
	cold, parent, workers, _ = f.resources.counts()
	if cold != 0 || parent != 0 || workers != 0 {
		t.Fatal("joined cancelled worker leaked a grant")
	}
}

func TestApplicationColdV1SourceAuthorityAndConstructorRefuseBeforeProvider(t *testing.T) {
	f := applicationColdNewFixtureForTestV1(t)
	if k, err := NewApplicationColdV1(&storage.Client{}, f.cold.inspector, f.resources.acquire, nil); k != nil || !errors.Is(err, ErrApplicationAdmissionV1) {
		t.Fatal("missing mandatory original authority accepted")
	}
	f.cold.authorize = func(context.Context, ApplicationDispatchV1) error {
		return errors.New("private denied source credential")
	}
	s, err := f.cold.InspectSourceV1(applicationTestContextV1(t), f.candidate)
	cold, parent, workers, _ := f.resources.counts()
	if s != nil || !errors.Is(err, ErrApplicationAdmissionV1) || cold != 0 || parent != 0 || workers != 0 {
		t.Fatal("denied cold source reached capacity/provider")
	}
}
