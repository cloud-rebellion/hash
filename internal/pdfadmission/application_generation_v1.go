// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ordinarypage"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
)

// ApplicationGenerationV1 has no exported renderer/worker replacement or
// metadata-to-receipt constructor. Its origin is the configured fixed private
// Gotenberg client and isolated OrdinaryInspector. The trusted deployment must
// establish that endpoint/credential/image, encryption and genuine renderer
// acceptance. This unit does not prove those operational properties by itself.
// Generate outside SQL locks: caller must finish/reconcile the load transaction,
// then open/relock/revalidate a new transaction for each capture. An unknown
// older capture/session is not permission to generate or overwrite an original.
// ApplicationDispatchAuthorizationV1 MUST perform the real current original
// credential, all-target/basis, current original-capture inventory, unresolved
// attempt disposition and server-lease gate on each hot dispatch. A nil
// callback refuses construction. Supplying a callback is not proof that the live
// application has implemented that authority; activation must qualify it.
type ApplicationDispatchV1 struct {
	Phase string
	Scope ApplicationScopeV1
	Page  int
}
type ApplicationDispatchAuthorizationV1 func(context.Context, ApplicationDispatchV1) error

type ApplicationGenerationV1 struct {
	store     *storage.Client
	renderer  *render.Gotenberg
	inspector *OrdinaryInspectorV1
	acquire   ApplicationTryAcquireV1
	authorize ApplicationDispatchAuthorizationV1
	issuer    *applicationIssuerV1
}

func NewApplicationGenerationV1(store *storage.Client, renderer *render.Gotenberg, inspector *OrdinaryInspectorV1, acquire ApplicationTryAcquireV1, authorize ApplicationDispatchAuthorizationV1) (*ApplicationGenerationV1, error) {
	if store == nil || renderer == nil || !inspector.ready() || acquire == nil || authorize == nil {
		return nil, ErrApplicationAdmissionV1
	}
	return &ApplicationGenerationV1{store: store, renderer: renderer, inspector: inspector, acquire: acquire, authorize: authorize, issuer: &applicationIssuerV1{1}}, nil
}
func (g *ApplicationGenerationV1) valid() bool {
	return g != nil && g.store != nil && g.renderer != nil && g.inspector.ready() && g.acquire != nil && g.authorize != nil && g.issuer != nil
}
func applicationAcquireGenerationV1(ctx context.Context, acquire ApplicationTryAcquireV1, budget ApplicationBudgetV1) (func(), error) {
	release, err := acquire(ctx, budget)
	if err != nil || release == nil || ctx.Err() != nil {
		if release != nil {
			release()
		}
		return nil, applicationErrorV1(ctx, err)
	}
	var once sync.Once
	return func() { once.Do(release) }, nil
}

type ApplicationSourceV1 struct {
	mu        sync.Mutex
	issuer    *applicationIssuerV1
	scope     ApplicationScopeV1
	basis     *BasisV1
	proof     *OrdinarySourceInspectionV1
	existing  map[int]bool
	release   func()
	closed    bool
	borrowers int
}

func (s *ApplicationSourceV1) detachLocked() func() {
	if !s.closed || s.borrowers != 0 {
		return nil
	}
	proof := s.proof
	r := s.release
	s.proof = nil
	s.release = nil
	s.basis = nil
	s.existing = nil
	return func() {
		if proof != nil {
			proof.Close()
		}
		if r != nil {
			r()
		}
	}
}
func (s *ApplicationSourceV1) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	cleanup := s.detachLocked()
	s.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
}
func (s *ApplicationSourceV1) pageDone() {
	s.mu.Lock()
	s.borrowers--
	cleanup := s.detachLocked()
	s.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
}

// InspectSourceV1 reads the exact original opaque version with its committed
// digest and length, then asks the fixed worker to inspect all source pages.
// The candidate is an immutable SQL snapshot, not current Sign permission. The
// caller must have physically reconciled the prior transaction before dispatch;
// this API cannot infer that from metadata or an expired lease.
func (g *ApplicationGenerationV1) InspectSourceV1(ctx context.Context, c *ApplicationCandidateV1) (*ApplicationSourceV1, error) {
	if !g.valid() || !applicationContextV1(ctx) || c == nil {
		return nil, applicationErrorV1(ctx, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.release == nil || c.basis == nil || (!applicationDoneV1(c.cleanupDone) || !c.fence.retiredV1()) || c.header.Status != "staging" || !c.header.LeaseCurrent || !c.header.OwnerMatches {
		return nil, applicationErrorV1(ctx, nil)
	}
	if err := g.authorize(ctx, ApplicationDispatchV1{Phase: "source", Scope: c.scope}); err != nil || ctx.Err() != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	pin := c.basis.Source()
	budget := ApplicationBudgetV1{Phase: "generation-source", OrgID: c.scope.OrgID, DocumentID: c.scope.DocumentID, AdmissionID: c.scope.AdmissionID, StoredBasisBytes: int64(c.basis.CanonicalByteCount()), SourceBytes: pin.Bytes, WorkingBytes: 4*pin.Bytes + 16*int64(c.basis.CanonicalByteCount()) + (8 << 20)}
	release, err := applicationAcquireGenerationV1(ctx, g.acquire, budget)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	raw, err := g.store.GetVerifiedVersionBounded(ctx, pin.Key, pin.VersionID, applicationDigestV1(pin.SHA256), pin.Bytes)
	defer clear(raw)
	if err != nil || ctx.Err() != nil || int64(len(raw)) != pin.Bytes {
		return nil, applicationErrorV1(ctx, err)
	}
	b, err := DecodeV1(c.basis.CanonicalJSON())
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	proof, err := g.inspector.InspectSourceV1(ctx, b, raw)
	if err != nil || ctx.Err() != nil {
		if proof != nil {
			proof.Close()
		}
		return nil, applicationErrorV1(ctx, err)
	}
	existing := make(map[int]bool, len(c.originals))
	for page := range c.originals {
		existing[page] = true
	}
	transferred = true
	return &ApplicationSourceV1{issuer: g.issuer, scope: c.scope, basis: b, proof: proof, existing: existing, release: release}, nil
}

type ApplicationGeneratedPageV1 struct {
	mu                                   sync.Mutex
	issuer                               *applicationIssuerV1
	scope                                ApplicationScopeV1
	basis                                *BasisV1
	proof                                *OrdinaryPageInspectionV1
	original, pdf, plan, report          []byte
	page                                 int
	release                              func()
	sourceDone                           func()
	captureDone                          <-chan struct{}
	captureFence                         *applicationSessionFenceV1
	captureOwner                         *ApplicationAdmissionV1
	closed, attempted, cleaning, cleaned bool
}

func (p *ApplicationGeneratedPageV1) detachLocked() func() {
	if !p.closed || p.cleaning || p.cleaned || (p.captureDone != nil && (!applicationDoneV1(p.captureDone) || !p.captureFence.retiredV1())) {
		return nil
	}
	p.cleaning = true
	proof := p.proof
	r := p.release
	sourceDone := p.sourceDone
	p.proof = nil
	p.release = nil
	p.sourceDone = nil
	clear(p.original)
	clear(p.pdf)
	clear(p.plan)
	clear(p.report)
	p.original = nil
	p.pdf = nil
	p.plan = nil
	p.report = nil
	p.basis = nil
	return func() {
		if proof != nil {
			proof.Close()
		}
		if r != nil {
			r()
		}
		if sourceDone != nil {
			sourceDone()
		}
		p.mu.Lock()
		p.cleaning = false
		p.cleaned = true
		owner := p.captureOwner
		p.mu.Unlock()
		if owner != nil {
			owner.notify()
		}
	}
}
func (p *ApplicationGeneratedPageV1) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	cleanup := p.detachLocked()
	owner := p.captureOwner
	p.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
	if owner != nil {
		owner.notify()
	}
}
func (p *ApplicationGeneratedPageV1) reconcileCaptureV1() bool {
	p.mu.Lock()
	cleanup := p.detachLocked()
	p.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
	p.mu.Lock()
	finished := p.closed && p.cleaned
	p.mu.Unlock()
	return finished
}

// ProducePageV1 produces only an uncaptured expected painted page. No renderer is
// dispatched for an existing original; use LoadOriginalV1 instead. The full hot
// package and genuine worker receipt stay owned through consumer Close AND the
// actual capture-session CLIENT cleanup and observed SERVER retirement. Logical query return cannot retire them. SQL88 retains PDF+plan and their immutable capture lineage, not the
// full report/snapshot/package. Cold readers must re-inspect exact PDF originals;
// stored SHAs do not recreate this producer/inspection receipt.
func applicationExpectedPageV1(b *BasisV1, page int) bool {
	if b == nil {
		return false
	}
	for _, expected := range b.ordinaryPages {
		if expected == page {
			return true
		}
	}
	return false
}
func (g *ApplicationGenerationV1) ProducePageV1(ctx context.Context, s *ApplicationSourceV1, page int) (*ApplicationGeneratedPageV1, error) {
	if !g.valid() || !applicationContextV1(ctx) || s == nil {
		return nil, applicationErrorV1(ctx, nil)
	}
	s.mu.Lock()
	if s.closed || s.release == nil || s.issuer != g.issuer || s.proof == nil || s.basis == nil || !applicationExpectedPageV1(s.basis, page) || !s.proof.MatchesBasisV1(s.basis) || s.existing[page] {
		s.mu.Unlock()
		return nil, applicationErrorV1(ctx, nil)
	}
	scope, b, sourceProof := s.scope, s.basis, s.proof
	s.borrowers++
	s.mu.Unlock()
	sourceTransferred := false
	defer func() {
		if !sourceTransferred {
			s.pageDone()
		}
	}()
	if err := g.authorize(ctx, ApplicationDispatchV1{Phase: "page", Scope: scope, Page: page}); err != nil || ctx.Err() != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	budget := ApplicationBudgetV1{Phase: "generation-page", OrgID: scope.OrgID, DocumentID: scope.DocumentID, AdmissionID: scope.AdmissionID, OriginalPDFBytes: ordinarypage.MaxPDFBytesV1, OriginalPlanBytes: ordinarypage.MaxPlanBytesV1, DBStagingBytes: ordinarypage.MaxPDFBytesV1 + ordinarypage.MaxPlanBytesV1, WorkingBytes: 8*ordinarypage.MaxPackageBytesV1 + 8*ordinarypage.MaxPlanBytesV1 + (32 << 20)}
	release, err := applicationAcquireGenerationV1(ctx, g.acquire, budget)
	if err != nil {
		return nil, err
	}
	transferred := false
	var original, pdf, plan, report []byte
	var proof *OrdinaryPageInspectionV1
	defer func() {
		if !transferred {
			if proof != nil {
				proof.Close()
			}
			clear(original)
			clear(pdf)
			clear(plan)
			clear(report)
			release()
		}
	}()
	s.mu.Lock()
	if s.closed || s.existing[page] {
		s.mu.Unlock()
		return nil, applicationErrorV1(ctx, nil)
	}
	s.existing[page] = true
	s.mu.Unlock()
	plans, err := OrdinaryPlansV1(b)
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	var expected ordinarypage.PlanV1
	found := false
	for _, p := range plans {
		if p.Page == page {
			expected = p
			found = true
			break
		}
	}
	if !found {
		return nil, applicationErrorV1(ctx, nil)
	}
	pack, err := g.renderer.PrepareOrdinaryPageV1(ctx, expected)
	if err != nil || ctx.Err() != nil || pack == nil {
		return nil, applicationErrorV1(ctx, err)
	}
	original = pack.Bytes()
	if len(original) < ordinarypage.PackageHeaderBytesV1 || len(original) > ordinarypage.MaxPackageBytesV1 {
		return nil, applicationErrorV1(ctx, nil)
	}
	proof, err = g.inspector.InspectPageV1(ctx, sourceProof, page, original)
	if err != nil || ctx.Err() != nil || !proof.MatchesOriginalV1(b, page, original) {
		return nil, applicationErrorV1(ctx, err)
	}
	pdf = pack.PDF()
	report = pack.ReportBytes()
	plan, err = json.Marshal(expected)
	if err != nil || ctx.Err() != nil || len(plan) > ordinarypage.MaxPlanBytesV1 || len(pdf) != pack.PDFByteCount() {
		return nil, applicationErrorV1(ctx, err)
	}
	// In-process duplicate production is refused even before SQL acknowledgment.
	// A fresh generation source still requires actual prior-session reconciliation.
	sourceTransferred = true
	transferred = true
	return &ApplicationGeneratedPageV1{issuer: g.issuer, scope: scope, basis: b, proof: proof, original: original, pdf: pdf, plan: plan, report: report, page: page, release: release, sourceDone: s.pageDone}, nil
}

// ApplicationCapturedPageV1 is an opaque acknowledgment of one synchronous SQL
// insert, not acknowledgment of caller COMMIT. A fresh locked candidate must
// contain the same exact body before this acknowledgment is used for readiness.
// Bodies are not retained in this small receipt; durable accounting belongs to
// the caller's commit-aware coordinator and the immutable88 counters.
type ApplicationCapturedPageV1 struct {
	issuer                                                *applicationIssuerV1
	scope                                                 ApplicationScopeV1
	page                                                  int
	pdfSHA, planSHA, packageSHA, reportSHA, inspectionSHA [32]byte
}

func applicationCapturedMatchesV1(p ApplicationCapturedPageV1, c *ApplicationCandidateV1) bool {
	m, ok := c.originals[p.page]
	return ok && p.scope == c.scope && bytes.Equal(m.Sha256, p.pdfSHA[:]) && bytes.Equal(m.PlanSha256, p.planSHA[:]) && bytes.Equal(m.PackageSha256, p.packageSHA[:]) && bytes.Equal(m.ReportSha256, p.reportSHA[:]) && bytes.Equal(m.InspectionSha256, p.inspectionSHA[:])
}
func (g *ApplicationGenerationV1) CapturePageTxV1(ctx context.Context, a *ApplicationAdmissionV1, c *ApplicationCandidateV1, p *ApplicationGeneratedPageV1) (ApplicationCapturedPageV1, error) {
	if !g.valid() || !a.valid() || !applicationContextV1(ctx) || c == nil || p == nil {
		return ApplicationCapturedPageV1{}, applicationErrorV1(ctx, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if c.closed || c.release == nil || c.issuer != a.issuer || c.header.Status != "staging" || !c.header.LeaseCurrent || !c.header.OwnerMatches || p.closed || p.attempted || p.release == nil || p.issuer != g.issuer || p.scope != c.scope || p.proof == nil || !p.proof.MatchesOriginalV1(c.basis, p.page, p.original) {
		return ApplicationCapturedPageV1{}, applicationErrorV1(ctx, nil)
	}
	if _, exists := c.originals[p.page]; exists {
		return ApplicationCapturedPageV1{}, applicationErrorV1(ctx, nil)
	}
	metadata, err := p.proof.MetadataV1()
	if err != nil || metadata.StaticBasisSHA256 != c.scope.StaticBasisSHA256 || metadata.StaticCanonicalSHA256 != c.basis.CanonicalSHA256() || metadata.Page != p.page || metadata.PackageSHA256 != plainSHA256V1(p.original) || metadata.PlanSHA256 != plainSHA256V1(p.plan) || metadata.Fragment.PDFSHA256 != plainSHA256V1(p.pdf) || metadata.Fragment.PDFBytes != int64(len(p.pdf)) {
		return ApplicationCapturedPageV1{}, applicationErrorV1(ctx, err)
	}
	inspection, err := json.Marshal(metadata)
	if err != nil {
		return ApplicationCapturedPageV1{}, applicationErrorV1(ctx, err)
	}
	release, err := a.admit(ctx, ApplicationBudgetV1{Phase: "locked-original-capture", OrgID: c.scope.OrgID, DocumentID: c.scope.DocumentID, AdmissionID: c.scope.AdmissionID, OriginalPDFBytes: int64(len(p.pdf)), OriginalPlanBytes: int64(len(p.plan)), WorkingBytes: 4*int64(len(p.pdf)+len(p.plan)) + (8 << 20), DBStagingBytes: int64(len(p.pdf) + len(p.plan))})
	if err != nil {
		return ApplicationCapturedPageV1{}, err
	}
	defer release()
	// Once SQL dispatch starts, no second capture is authorized by this receipt.
	// An error needs physical transaction reconciliation and exact scoped reads.
	a.mu.Lock()
	if a.closed || len(a.retainedPages) >= applicationMaxLoansV1 {
		a.mu.Unlock()
		return ApplicationCapturedPageV1{}, applicationErrorV1(ctx, nil)
	}
	a.retainedPages[p] = struct{}{}
	a.mu.Unlock()
	p.captureDone = a.cleanupDone
	p.captureFence = a.fence
	p.captureOwner = a
	p.attempted = true
	row, err := a.queries.capture(ctx, generated.CapturePDFSigningAdmissionBodyV1Params{Page: int32(p.page), Payload: p.pdf, Sha256: applicationHashV1(p.pdf), Bytes: int64(len(p.pdf)), StaticBasisSha256: applicationDigestV1(c.scope.StaticBasisSHA256), PlanPayload: p.plan, PlanSha256: applicationHashV1(p.plan), PackageSha256: applicationHashV1(p.original), ReportSha256: applicationHashV1(p.report), InspectionSha256: applicationHashV1(inspection), OwnerID: c.scope.OwnerID, DocumentID: c.scope.DocumentID, OrgID: c.scope.OrgID, AdmissionID: c.scope.AdmissionID})
	if err != nil || ctx.Err() != nil || row == nil {
		return ApplicationCapturedPageV1{}, applicationErrorV1(ctx, ErrApplicationCaptureUncertainV1)
	}
	m := generated.ListPDFSigningAdmissionBodyMetadataV1Row(*row)
	if !applicationBodyMetadataV1(&m, c) || m.Page != int32(p.page) || m.Bytes != int64(len(p.pdf)) || m.PlanBytes != int64(len(p.plan)) || m.CapturedOwnerID != c.scope.OwnerID || !bytes.Equal(m.Sha256, applicationHashV1(p.pdf)) || !bytes.Equal(m.PlanSha256, applicationHashV1(p.plan)) || !bytes.Equal(m.PackageSha256, applicationHashV1(p.original)) || !bytes.Equal(m.ReportSha256, applicationHashV1(p.report)) || !bytes.Equal(m.InspectionSha256, applicationHashV1(inspection)) {
		return ApplicationCapturedPageV1{}, applicationErrorV1(ctx, ErrApplicationCaptureUncertainV1)
	}
	c.originals[p.page] = m
	receipt := ApplicationCapturedPageV1{issuer: g.issuer, scope: c.scope, page: p.page}
	copy(receipt.pdfSHA[:], m.Sha256)
	copy(receipt.planSHA[:], m.PlanSha256)
	copy(receipt.packageSHA[:], m.PackageSha256)
	copy(receipt.reportSHA[:], m.ReportSha256)
	copy(receipt.inspectionSHA[:], m.InspectionSha256)
	return receipt, nil
}

// MarkReadyTxV1 requires the live genuine source proof and exactly one hot
// acknowledged capture receipt for EVERY expected painted page. Signature-only
// candidates need no party name/draft or page receipt. A restart after captured
// bodies but before ready cannot resume readiness through this hot-only method;
// a separate guarded original-lineage/PDF reinspection bridge remains required.
// Cold admitted SQL originals
// are readable but cannot be turned into hot origin receipts by this method.
func (g *ApplicationGenerationV1) MarkReadyTxV1(ctx context.Context, a *ApplicationAdmissionV1, c *ApplicationCandidateV1, s *ApplicationSourceV1, pages []ApplicationCapturedPageV1) error {
	if !g.valid() || !a.valid() || !applicationContextV1(ctx) || c == nil || s == nil {
		return applicationErrorV1(ctx, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s.mu.Lock()
	if c.closed || c.release == nil || c.issuer != a.issuer || c.header.Status != "staging" || !c.header.LeaseCurrent || !c.header.OwnerMatches || s.closed || s.release == nil || s.issuer != g.issuer || s.scope != c.scope || s.proof == nil || !s.proof.MatchesBasisV1(c.basis) || len(pages) != len(c.header.ExpectedOrdinaryPages) || len(pages) > 500 || len(c.originals) != len(pages) {
		s.mu.Unlock()
		return applicationErrorV1(ctx, nil)
	}
	s.borrowers++
	geometry, err := s.proof.GeometryV1()
	s.mu.Unlock()
	defer s.pageDone()
	if err != nil {
		return applicationErrorV1(ctx, err)
	}
	seen := make(map[int]bool, len(pages))
	for _, p := range pages {
		if p.issuer != g.issuer || seen[p.page] || !applicationCapturedMatchesV1(p, c) {
			return applicationErrorV1(ctx, nil)
		}
		seen[p.page] = true
	}
	raw, err := json.Marshal(geometry)
	if err != nil {
		return applicationErrorV1(ctx, err)
	}
	components := c.header.GeometryBytes + c.header.GeometryPagesBytes + c.header.FieldsBytes + c.header.PartiesBytes + c.header.RenderRecipeBytes + c.header.OrdinaryRecipeBytes
	release, err := a.admit(ctx, ApplicationBudgetV1{Phase: "locked-ready", OrgID: c.scope.OrgID, DocumentID: c.scope.DocumentID, AdmissionID: c.scope.AdmissionID, StoredBasisBytes: c.header.StaticBasisBytes, ComponentBytes: components, WorkingBytes: 16*(c.header.StaticBasisBytes+components) + (8 << 20)})
	if err != nil {
		return err
	}
	defer release()
	row, err := a.queries.ready(ctx, generated.MarkPDFSigningAdmissionReadyV1Params{SourceInspectionSha256: applicationHashV1(raw), AdmissionID: c.scope.AdmissionID, OwnerID: c.scope.OwnerID, DocumentID: c.scope.DocumentID, OrgID: c.scope.OrgID})
	if err != nil || ctx.Err() != nil || row == nil || row.ID != c.scope.AdmissionID || row.OrgID != c.scope.OrgID || row.DocumentID != c.scope.DocumentID || row.Status != "ready" || !applicationStampV1(row.ReadyAt) || !bytes.Equal(row.StaticBasisSha256, c.header.StaticBasisSha256) {
		return applicationErrorV1(ctx, ErrApplicationCaptureUncertainV1)
	}
	c.header.Status = "ready"
	c.header.ReadyAt = row.ReadyAt
	return nil
}
