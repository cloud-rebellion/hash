// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
)

// ApplicationColdV1 re-inspects SQL-retained ordinary PDF/plan originals. It has
// no renderer, package builder or metadata-to-hot-producer receipt constructor.
// Stored package/report/inspection SHAs remain historical capture lineage;
// they never stand for report/snapshot/package bodies that88 did not preserve.
type ApplicationColdV1 struct {
	store     *storage.Client
	inspector *OrdinaryInspectorV1
	acquire   ApplicationTryAcquireV1
	authorize ApplicationDispatchAuthorizationV1
	issuer    *applicationIssuerV1
}

func NewApplicationColdV1(store *storage.Client, inspector *OrdinaryInspectorV1, acquire ApplicationTryAcquireV1, authorize ApplicationDispatchAuthorizationV1) (*ApplicationColdV1, error) {
	if store == nil || !inspector.ready() || acquire == nil || authorize == nil {
		return nil, ErrApplicationAdmissionV1
	}
	return &ApplicationColdV1{store: store, inspector: inspector, acquire: acquire, authorize: authorize, issuer: &applicationIssuerV1{1}}, nil
}
func (k *ApplicationColdV1) valid() bool {
	return k != nil && k.store != nil && k.inspector.ready() && k.acquire != nil && k.authorize != nil && k.issuer != nil
}

func applicationColdMetadataCloneV1(m generated.ListPDFSigningAdmissionBodyMetadataV1Row) generated.ListPDFSigningAdmissionBodyMetadataV1Row {
	m.Sha256 = bytes.Clone(m.Sha256)
	m.StaticBasisSha256 = bytes.Clone(m.StaticBasisSha256)
	m.PlanSha256 = bytes.Clone(m.PlanSha256)
	m.PackageSha256 = bytes.Clone(m.PackageSha256)
	m.ReportSha256 = bytes.Clone(m.ReportSha256)
	m.InspectionSha256 = bytes.Clone(m.InspectionSha256)
	return m
}
func applicationColdMetadataEqualV1(a, b generated.ListPDFSigningAdmissionBodyMetadataV1Row) bool {
	return a.AdmissionID == b.AdmissionID && a.OrgID == b.OrgID && a.DocumentID == b.DocumentID && a.Kind == b.Kind && a.Page == b.Page && a.Bytes == b.Bytes && a.PlanBytes == b.PlanBytes && a.ContentType == b.ContentType && a.CapturedOwnerID == b.CapturedOwnerID && applicationStampEqualV1(a.CapturedAt, b.CapturedAt) &&
		bytes.Equal(a.Sha256, b.Sha256) && bytes.Equal(a.StaticBasisSha256, b.StaticBasisSha256) && bytes.Equal(a.PlanSha256, b.PlanSha256) && bytes.Equal(a.PackageSha256, b.PackageSha256) && bytes.Equal(a.ReportSha256, b.ReportSha256) && bytes.Equal(a.InspectionSha256, b.InspectionSha256)
}

type ApplicationColdSourceV1 struct {
	mu                                     sync.Mutex
	issuer, readerIssuer                   *applicationIssuerV1
	scope                                  ApplicationScopeV1
	basis                                  *BasisV1
	proof                                  *OrdinarySourceInspectionV1
	release                                func()
	readerFence                            *applicationSessionFenceV1
	pages                                  map[*ApplicationColdPageV1]struct{}
	inspecting                             map[int]bool
	borrowers                              int
	closed, readyActive, cleaning, cleaned bool
	readyFence                             *applicationSessionFenceV1
}

func (s *ApplicationColdSourceV1) detachLocked() func() {
	if !s.closed || s.borrowers != 0 || s.release == nil || s.cleaning || s.cleaned || (s.readyFence != nil && (!applicationDoneV1(s.readyFence.clientDone) || !s.readyFence.retiredV1())) {
		return nil
	}
	s.cleaning = true
	proof, release := s.proof, s.release
	s.proof = nil
	s.release = nil
	s.basis = nil
	s.inspecting = nil
	return func() {
		if proof != nil {
			proof.Close()
		}
		release()
		s.mu.Lock()
		s.cleaning = false
		s.cleaned = true
		s.mu.Unlock()
	}
}
func (s *ApplicationColdSourceV1) done() {
	s.mu.Lock()
	s.borrowers--
	cleanup := s.detachLocked()
	s.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
}
func (s *ApplicationColdSourceV1) borrow(k *ApplicationColdV1) (*BasisV1, *OrdinarySourceInspectionV1, func(), error) {
	if s == nil || !k.valid() {
		return nil, nil, nil, ErrApplicationAdmissionV1
	}
	s.mu.Lock()
	if s.closed || s.release == nil || s.issuer != k.issuer || s.basis == nil || s.proof == nil || !s.proof.MatchesBasisV1(s.basis) {
		s.mu.Unlock()
		return nil, nil, nil, ErrApplicationAdmissionV1
	}
	s.borrowers++
	b, p := s.basis, s.proof
	s.mu.Unlock()
	var once sync.Once
	return b, p, func() { once.Do(s.done) }, nil
}

// Close is notify/consumer-only: it issues no SQL and never treats client cleanup
// as server retirement. Keep this source in the caller's manager after timeout.
func (s *ApplicationColdSourceV1) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	pages := make([]*ApplicationColdPageV1, 0, len(s.pages))
	for p := range s.pages {
		pages = append(pages, p)
	}
	cleanup := s.detachLocked()
	s.mu.Unlock()
	for _, p := range pages {
		p.Close()
	}
	if cleanup != nil {
		cleanup()
	}
}

// ReconcileCleanupV1 must run OUTSIDE entity/SQL locks; it performs bounded fixed
// server observation for an attempted ready transaction before retiring buffers.
// It retires transient work only, never durable debt or COMMIT disposition.
func (s *ApplicationColdSourceV1) ReconcileCleanupV1(ctx context.Context) (int, error) {
	if s == nil {
		return 0, nil
	}
	if !applicationContextV1(ctx) {
		return 1, applicationErrorV1(ctx, nil)
	}
	s.mu.Lock()
	fence := s.readyFence
	s.mu.Unlock()
	if fence != nil {
		if _, err := fence.proveV1(ctx); err != nil {
			return 1, err
		}
	}
	s.mu.Lock()
	pages := make([]*ApplicationColdPageV1, 0, len(s.pages))
	for p := range s.pages {
		pages = append(pages, p)
	}
	s.mu.Unlock()
	for _, p := range pages {
		p.reconcileV1()
	}
	s.mu.Lock()
	cleanup := s.detachLocked()
	pending := len(s.pages)
	if s.release != nil || s.cleaning {
		pending++
	}
	s.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
	return pending, nil
}
func (s *ApplicationColdSourceV1) CloseV1(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if !applicationContextV1(ctx) {
		return applicationErrorV1(ctx, nil)
	}
	s.Close()
	timer := time.NewTicker(50 * time.Millisecond)
	defer timer.Stop()
	for {
		n, err := s.ReconcileCleanupV1(ctx)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		select {
		case <-timer.C:
		case <-ctx.Done():
			return applicationErrorV1(ctx, ctx.Err())
		}
	}
}

// InspectSourceV1 requires the previous actual SQL reader session to have BOTH
// client cleanup and fixed observed server retirement. The mandatory authority
// callback must recheck original credentials, all targets and current server
// lease for the current takeover owner before capacity, provider or worker I/O.
func (k *ApplicationColdV1) InspectSourceV1(ctx context.Context, c *ApplicationCandidateV1) (*ApplicationColdSourceV1, error) {
	if !k.valid() || !applicationContextV1(ctx) || c == nil {
		return nil, applicationErrorV1(ctx, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.release == nil || c.basis == nil || c.header == nil || c.fence == nil || !applicationDoneV1(c.cleanupDone) || !c.fence.retiredV1() || c.header.Status != "staging" || !c.header.LeaseCurrent || !c.header.OwnerMatches {
		return nil, applicationErrorV1(ctx, nil)
	}
	if err := k.authorize(ctx, ApplicationDispatchV1{Phase: "cold-source", Scope: c.scope}); err != nil || ctx.Err() != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	pin := c.basis.Source()
	release, err := applicationAcquireGenerationV1(ctx, k.acquire, ApplicationBudgetV1{Phase: "cold-source", OrgID: c.scope.OrgID, DocumentID: c.scope.DocumentID, AdmissionID: c.scope.AdmissionID, SourceBytes: pin.Bytes, StoredBasisBytes: int64(c.basis.CanonicalByteCount()), WorkingBytes: 4*pin.Bytes + 16*int64(c.basis.CanonicalByteCount()) + (8 << 20)})
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	raw, err := k.store.GetVerifiedVersionBounded(ctx, pin.Key, pin.VersionID, applicationDigestV1(pin.SHA256), pin.Bytes)
	defer clear(raw)
	if err != nil || ctx.Err() != nil || int64(len(raw)) != pin.Bytes {
		return nil, applicationErrorV1(ctx, err)
	}
	b, err := DecodeV1(c.basis.CanonicalJSON())
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	proof, err := k.inspector.InspectSourceV1(ctx, b, raw)
	if err != nil || ctx.Err() != nil {
		if proof != nil {
			proof.Close()
		}
		return nil, applicationErrorV1(ctx, err)
	}
	transferred = true
	return &ApplicationColdSourceV1{issuer: k.issuer, readerIssuer: c.issuer, scope: c.scope, basis: b, proof: proof, release: release, readerFence: c.fence, pages: make(map[*ApplicationColdPageV1]struct{}), inspecting: make(map[int]bool)}, nil
}

// ApplicationColdPageV1 is a distinct opaque actual fresh fragment inspection
// plus exact immutable SQL capture lineage. It is NOT a hot producer receipt,
// actual layout report, reconstructed package, reviewed UI or Sign permission.
type ApplicationColdPageV1 struct {
	mu                                                sync.Mutex
	issuer                                            *applicationIssuerV1
	source                                            *ApplicationColdSourceV1
	scope                                             ApplicationScopeV1
	page                                              int
	canonicalSHA                                      string
	metadata                                          generated.ListPDFSigningAdmissionBodyMetadataV1Row
	fragment                                          sanitize.PDFManualFragmentAdmission
	pdf, plan                                         []byte
	release, inspectionRelease, sourceDone, proofDone func()
	closed, cleaning, cleaned                         bool
}

func (p *ApplicationColdPageV1) detachLocked() func() {
	if !p.closed || p.cleaning || p.cleaned {
		return nil
	}
	s := p.source
	if s == nil {
		p.cleaned = true
		return nil
	}
	s.mu.Lock()
	fence := s.readyFence
	s.mu.Unlock()
	if fence != nil && (!applicationDoneV1(fence.clientDone) || !fence.retiredV1()) {
		return nil
	}
	p.cleaning = true
	clear(p.pdf)
	clear(p.plan)
	p.pdf = nil
	p.plan = nil
	p.metadata = generated.ListPDFSigningAdmissionBodyMetadataV1Row{}
	release, inspectionRelease, sourceDone, proofDone := p.release, p.inspectionRelease, p.sourceDone, p.proofDone
	p.release = nil
	p.inspectionRelease = nil
	p.sourceDone = nil
	p.proofDone = nil
	return func() {
		if inspectionRelease != nil {
			inspectionRelease()
		}
		if release != nil {
			release()
		}
		if proofDone != nil {
			proofDone()
		}
		if sourceDone != nil {
			sourceDone()
		}
		p.mu.Lock()
		p.cleaning = false
		p.cleaned = true
		p.mu.Unlock()
		s.mu.Lock()
		delete(s.pages, p)
		s.mu.Unlock()
	}
}
func (p *ApplicationColdPageV1) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	cleanup := p.detachLocked()
	p.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
}
func (p *ApplicationColdPageV1) reconcileV1() {
	p.mu.Lock()
	cleanup := p.detachLocked()
	p.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
}

// InspectPageV1 uses only an opaque LoadOriginalV1 result from the same actual
// retired SQL reader as the source. No caller metadata or synthetic envelope can
// mint this receipt. Admission precedes plans/clones; only the fixed isolated
// worker parses the PDF, and its physical grant stays held through worker join.
func (k *ApplicationColdV1) InspectPageV1(ctx context.Context, s *ApplicationColdSourceV1, o *ApplicationOriginalV1) (*ApplicationColdPageV1, error) {
	if !k.valid() || !applicationContextV1(ctx) || o == nil {
		return nil, applicationErrorV1(ctx, nil)
	}
	b, sourceProof, sourceDone, err := s.borrow(k)
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	transferred := false
	defer func() {
		if !transferred {
			sourceDone()
		}
	}()
	o.mu.Lock()
	if o.closed || o.release == nil || o.issuer != s.readerIssuer || o.scope != s.scope || o.fence != s.readerFence || o.fence == nil || !applicationDoneV1(o.fence.clientDone) || !o.fence.retiredV1() {
		o.mu.Unlock()
		return nil, applicationErrorV1(ctx, nil)
	}
	m := o.metadata
	o.mu.Unlock()
	page := int(m.Page)
	if !applicationExpectedPageV1(b, page) || m.Bytes < 1 || m.Bytes > 8<<20 || m.PlanBytes < 1 || m.PlanBytes > 1<<20 {
		return nil, applicationErrorV1(ctx, nil)
	}
	if err := k.authorize(ctx, ApplicationDispatchV1{Phase: "cold-page", Scope: s.scope, Page: page}); err != nil || ctx.Err() != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	release, err := applicationAcquireGenerationV1(ctx, k.acquire, ApplicationBudgetV1{Phase: "cold-fragment", OrgID: s.scope.OrgID, DocumentID: s.scope.DocumentID, AdmissionID: s.scope.AdmissionID, OriginalPDFBytes: m.Bytes, OriginalPlanBytes: m.PlanBytes, WorkingBytes: 4*(m.Bytes+m.PlanBytes) + (8 << 20)})
	if err != nil {
		return nil, err
	}
	var pdf, plan []byte
	var inspectionRelease, proofDone func()
	defer func() {
		if !transferred {
			clear(pdf)
			clear(plan)
			if inspectionRelease != nil {
				inspectionRelease()
			}
			release()
			if proofDone != nil {
				proofDone()
			}
		}
	}()
	inspectionRelease, err = k.inspector.admit(ctx, OrdinaryInspectionBudgetV1{Phase: "cold-fragment", OrgID: s.scope.OrgID, DocumentID: s.scope.DocumentID, SourceBytes: m.Bytes, PlanBytes: m.PlanBytes, MemoryBytes: 4*(m.Bytes+m.PlanBytes) + (8 << 20)})
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	s.mu.Lock()
	if s.closed || s.inspecting[page] {
		s.mu.Unlock()
		return nil, applicationErrorV1(ctx, nil)
	}
	s.inspecting[page] = true
	s.mu.Unlock()
	defer func() {
		if !transferred {
			s.mu.Lock()
			delete(s.inspecting, page)
			s.mu.Unlock()
		}
	}()
	o.mu.Lock()
	if o.closed || o.release == nil || !applicationColdMetadataEqualV1(m, o.metadata) {
		o.mu.Unlock()
		return nil, applicationErrorV1(ctx, nil)
	}
	pdf = bytes.Clone(o.pdf)
	plan = bytes.Clone(o.plan)
	o.mu.Unlock()
	if int64(len(pdf)) != m.Bytes || int64(len(plan)) != m.PlanBytes || !bytes.Equal(applicationHashV1(pdf), m.Sha256) || !bytes.Equal(applicationHashV1(plan), m.PlanSha256) {
		return nil, applicationErrorV1(ctx, nil)
	}
	plans, err := OrdinaryPlansV1(b)
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	var expected []byte
	for _, p := range plans {
		if p.Page == page {
			expected, err = json.Marshal(p)
			break
		}
	}
	if err != nil || !bytes.Equal(plan, expected) {
		return nil, applicationErrorV1(ctx, err)
	}
	_, geometry, done, err := sourceProof.borrow(k.inspector.issuer)
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	proofDone = done
	if page > len(geometry.Pages) {
		return nil, applicationErrorV1(ctx, nil)
	}
	width, height, err := geometry.Pages[page-1].ViewportPoints()
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	workerRelease, err := k.inspector.admitWorker(ctx, OrdinaryInspectionWorkerBudgetV1{OrgID: s.scope.OrgID, DocumentID: s.scope.DocumentID, Phase: "fragment"})
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	fragment, workerErr := func() (sanitize.PDFManualFragmentAdmission, error) {
		defer workerRelease()
		return k.inspector.worker.fragment(ctx, pdf, width, height)
	}()
	if workerErr != nil || ctx.Err() != nil || ordinaryInspectionFragmentV1(fragment, pdf, width, height) != nil {
		return nil, applicationErrorV1(ctx, workerErr)
	}
	p := &ApplicationColdPageV1{issuer: k.issuer, source: s, scope: s.scope, page: page, canonicalSHA: b.CanonicalSHA256(), metadata: applicationColdMetadataCloneV1(m), fragment: fragment, pdf: pdf, plan: plan, release: release, inspectionRelease: inspectionRelease, sourceDone: sourceDone, proofDone: proofDone}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, applicationErrorV1(ctx, nil)
	}
	s.pages[p] = struct{}{}
	s.mu.Unlock()
	transferred = true
	return p, nil
}

// MarkReadyTxV1 revalidates the full current locked candidate and exact required
// original set. The authority callback's locked-cold-ready phase must use this
// same caller-owned current transaction for credential/all-target/server-lease
// reads; it must never block on a separate pooled writer under these locks.
// Fresh SQL PDF/plan bytes are compared literally to inspected originals.
// Unknown query/COMMIT outcomes require fixed server retirement plus fresh
// scoped state reconciliation; no hot capture receipt or retry is fabricated.
func (k *ApplicationColdV1) MarkReadyTxV1(ctx context.Context, a *ApplicationAdmissionV1, c *ApplicationCandidateV1, s *ApplicationColdSourceV1, pages []*ApplicationColdPageV1) error {
	if !k.valid() || !a.valid() || !applicationContextV1(ctx) || c == nil || s == nil || len(pages) > 500 {
		return applicationErrorV1(ctx, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.release == nil || c.issuer != a.issuer || c.basis == nil || c.header == nil || c.header.Status != "staging" || !c.header.LeaseCurrent || !c.header.OwnerMatches || len(pages) != len(c.header.ExpectedOrdinaryPages) || len(c.originals) != len(pages) {
		return applicationErrorV1(ctx, nil)
	}
	b, sourceProof, sourceDone, err := s.borrow(k)
	if err != nil {
		return applicationErrorV1(ctx, err)
	}
	defer sourceDone()
	s.mu.Lock()
	if s.readyActive || s.scope != c.scope || (s.readyFence != nil && (!applicationDoneV1(s.readyFence.clientDone) || !s.readyFence.retiredV1())) {
		s.mu.Unlock()
		return applicationErrorV1(ctx, nil)
	}
	s.readyActive = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.readyActive = false; s.mu.Unlock() }()
	if b.SHA256() != c.basis.SHA256() || b.CanonicalSHA256() != c.basis.CanonicalSHA256() || !sourceProof.MatchesBasisV1(c.basis) {
		return applicationErrorV1(ctx, nil)
	}
	if err := k.authorize(ctx, ApplicationDispatchV1{Phase: "locked-cold-ready", Scope: c.scope}); err != nil || ctx.Err() != nil {
		return applicationErrorV1(ctx, err)
	}
	var pdfBytes, planBytes int64
	for _, m := range c.originals {
		if m.Bytes < 1 || m.Bytes > 8<<20 || m.PlanBytes < 1 || m.PlanBytes > 1<<20 {
			return applicationErrorV1(ctx, nil)
		}
		pdfBytes += m.Bytes
		planBytes += m.PlanBytes
	}
	if pdfBytes > 50<<20 || pdfBytes > c.header.BaseBytesLimit || planBytes > 8<<20 {
		return applicationErrorV1(ctx, nil)
	}
	components := c.header.GeometryBytes + c.header.GeometryPagesBytes + c.header.FieldsBytes + c.header.PartiesBytes + c.header.RenderRecipeBytes + c.header.OrdinaryRecipeBytes
	release, err := a.admit(ctx, ApplicationBudgetV1{Phase: "locked-cold-ready", OrgID: c.scope.OrgID, DocumentID: c.scope.DocumentID, AdmissionID: c.scope.AdmissionID, StoredBasisBytes: c.header.StaticBasisBytes, ComponentBytes: components, OriginalPDFBytes: pdfBytes, OriginalPlanBytes: planBytes, WorkingBytes: 16*(c.header.StaticBasisBytes+components) + 4*(pdfBytes+planBytes) + (8 << 20), DBStagingBytes: 16 * (c.header.StaticBasisBytes + components)})
	if err != nil {
		return err
	}
	defer release()
	ordered := append([]*ApplicationColdPageV1(nil), pages...)
	for _, p := range ordered {
		if p == nil {
			return applicationErrorV1(ctx, nil)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].page < ordered[j].page })
	for i, p := range ordered {
		if i > 0 && p.page == ordered[i-1].page {
			return applicationErrorV1(ctx, nil)
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		m, ok := c.originals[p.page]
		if !ok || p.closed || p.cleaned || p.release == nil || p.inspectionRelease == nil || p.sourceDone == nil || p.proofDone == nil || p.issuer != k.issuer || p.source != s || p.scope != c.scope || p.canonicalSHA != c.basis.CanonicalSHA256() || !applicationColdMetadataEqualV1(m, p.metadata) || int32(p.page) != c.header.ExpectedOrdinaryPages[i] {
			return applicationErrorV1(ctx, nil)
		}
		pdf, readErr := a.queries.body(ctx, generated.ReadPDFSigningAdmissionBodyV1Params{AdmissionID: c.scope.AdmissionID, OrgID: c.scope.OrgID, DocumentID: c.scope.DocumentID, Page: int32(p.page), ExpectedSha256: m.Sha256, ExpectedBytes: m.Bytes})
		same := int64(len(pdf)) == m.Bytes && bytes.Equal(pdf, p.pdf)
		clear(pdf)
		if readErr != nil || ctx.Err() != nil || !same {
			return applicationErrorV1(ctx, readErr)
		}
		plan, readErr := a.queries.plan(ctx, generated.ReadPDFSigningAdmissionPlanV1Params{AdmissionID: c.scope.AdmissionID, OrgID: c.scope.OrgID, DocumentID: c.scope.DocumentID, Page: int32(p.page), ExpectedSha256: m.PlanSha256, ExpectedBytes: m.PlanBytes})
		same = int64(len(plan)) == m.PlanBytes && bytes.Equal(plan, p.plan)
		clear(plan)
		if readErr != nil || ctx.Err() != nil || !same {
			return applicationErrorV1(ctx, readErr)
		}
	}
	_, geometry, proofDone, err := sourceProof.borrow(k.inspector.issuer)
	if err != nil {
		return applicationErrorV1(ctx, err)
	}
	defer proofDone()
	raw, err := json.Marshal(geometry)
	if err != nil {
		return applicationErrorV1(ctx, err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return applicationErrorV1(ctx, nil)
	}
	s.readyFence = a.fence
	s.mu.Unlock()
	row, err := a.queries.ready(ctx, generated.MarkPDFSigningAdmissionReadyV1Params{SourceInspectionSha256: applicationHashV1(raw), AdmissionID: c.scope.AdmissionID, OwnerID: c.scope.OwnerID, DocumentID: c.scope.DocumentID, OrgID: c.scope.OrgID})
	if err != nil || ctx.Err() != nil || row == nil || row.ID != c.scope.AdmissionID || row.OrgID != c.scope.OrgID || row.DocumentID != c.scope.DocumentID || row.Status != "ready" || !applicationStampV1(row.ReadyAt) || !bytes.Equal(row.StaticBasisSha256, c.header.StaticBasisSha256) {
		return applicationErrorV1(ctx, ErrApplicationCaptureUncertainV1)
	}
	c.header.Status = "ready"
	c.header.ReadyAt = row.ReadyAt
	return nil
}
