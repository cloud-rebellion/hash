// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/ordinarypage"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
)

var ErrOrdinaryInspectionV1 = errors.New("pdfadmission: ordinary PDF inspection unavailable")

// MemoryBytes is a conservative dispatch reservation for this parent's owned
// copies, decoding and the existing worker transport. The worker has a 384MiB
// Go GC target, Linux 2GiB hard virtual-address bound, CPU/syscall policy and
// bounded slots; 384MiB is not an RSS guarantee. Aggregate parent/child RSS still
// needs caller-coordinated container/global permits. This is not a whole-service
// or global disk quota claim. Admission must use the shared live coordinator.
// A successful release belongs to the returned consumer and is held until all
// physical worker calls and receipt consumers have completed. Admission must
// not return a nil release, even for a zero-cost test/accounting implementation.
type OrdinaryInspectionBudgetV1 struct {
	Phase                     string
	OrgID, DocumentID         uuid.UUID
	SourceBytes               int64
	PackageBytes              int64
	CanonicalBytes, PlanBytes int64
	MemoryBytes               int64
}
type OrdinaryInspectionAdmissionV1 func(context.Context, OrdinaryInspectionBudgetV1) (func(), error)

// Physical workers have a shorter lifetime than retained source/page receipts.
// This mandatory second gate grants only the actual fixed worker invocation;
// its release is held through that child's physical return/join on every path.
type OrdinaryInspectionWorkerBudgetV1 struct {
	Phase             string
	OrgID, DocumentID uuid.UUID
}
type OrdinaryInspectionWorkerAdmissionV1 func(context.Context, OrdinaryInspectionWorkerBudgetV1) (func(), error)

type ordinaryInspectionWorkerV1 struct {
	source   func(context.Context, []byte) (sanitize.PDFManualGeometry, error)
	fragment func(context.Context, []byte, float64, float64) (sanitize.PDFManualFragmentAdmission, error)
}
type ordinaryInspectionIssuerV1 struct{ marker byte }

// NewOrdinaryInspectorV1 fixes the only production backend to the currently
// configured isolated sanitize worker. There is no public worker injection or
// metadata-to-semantic-proof constructor. The caller separately verifies the
// exact provider/version read, genuine private-producer origin, application
// permission/review/readiness and eventual SQL/storage/retention lifecycle.
type OrdinaryInspectorV1 struct {
	admission       OrdinaryInspectionAdmissionV1
	workerAdmission OrdinaryInspectionWorkerAdmissionV1
	worker          ordinaryInspectionWorkerV1
	issuer          *ordinaryInspectionIssuerV1
}

func NewOrdinaryInspectorV1(admission OrdinaryInspectionAdmissionV1, workerAdmission OrdinaryInspectionWorkerAdmissionV1) (*OrdinaryInspectorV1, error) {
	if admission == nil || workerAdmission == nil {
		return nil, ErrOrdinaryInspectionV1
	}
	return &OrdinaryInspectorV1{admission: admission, workerAdmission: workerAdmission, issuer: &ordinaryInspectionIssuerV1{marker: 1}, worker: ordinaryInspectionWorkerV1{
		source: sanitize.InspectManualPDFWithContext, fragment: sanitize.InspectManualPDFFragmentWithContext}}, nil
}
func (i *OrdinaryInspectorV1) ready() bool {
	return i != nil && i.admission != nil && i.workerAdmission != nil && i.issuer != nil && i.worker.source != nil && i.worker.fragment != nil
}
func ordinaryInspectionContextV1(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	_, ok := ctx.Deadline()
	return ok
}

type ordinaryInspectionFailureV1 struct{ causes []error }

func (*ordinaryInspectionFailureV1) Error() string {
	return "pdfadmission: ordinary PDF inspection unavailable"
}
func (e *ordinaryInspectionFailureV1) Unwrap() []error { return e.causes }
func ordinaryInspectionErrorV1(ctx context.Context, err error) error {
	causes := []error{ErrOrdinaryInspectionV1}
	if err != nil {
		causes = append(causes, err)
	}
	if ctx != nil && ctx.Err() != nil {
		causes = append(causes, ctx.Err())
		if cause := context.Cause(ctx); cause != nil && cause != ctx.Err() {
			causes = append(causes, cause)
		}
	}
	return &ordinaryInspectionFailureV1{causes: causes}
}
func (i *OrdinaryInspectorV1) admit(ctx context.Context, budget OrdinaryInspectionBudgetV1) (func(), error) {
	release, err := i.admission(ctx, budget)
	if err != nil || release == nil || ctx.Err() != nil {
		if release != nil {
			release()
		}
		return nil, ordinaryInspectionErrorV1(ctx, err)
	}
	var once sync.Once
	return func() { once.Do(release) }, nil
}

func (i *OrdinaryInspectorV1) admitWorker(ctx context.Context, b OrdinaryInspectionWorkerBudgetV1) (func(), error) {
	if !i.ready() || !ordinaryInspectionContextV1(ctx) || b.OrgID == uuid.Nil || b.DocumentID == uuid.Nil || (b.Phase != "source" && b.Phase != "fragment") {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	release, err := i.workerAdmission(ctx, b)
	if err != nil || release == nil || ctx.Err() != nil {
		if release != nil {
			release()
		}
		return nil, ordinaryInspectionErrorV1(ctx, err)
	}
	var once sync.Once
	return func() { once.Do(release) }, nil
}

type ordinarySourceInspectionStateV1 struct {
	mu        sync.Mutex
	issuer    *ordinaryInspectionIssuerV1
	basis     *BasisV1
	source    []byte
	geometry  sanitize.PDFManualGeometry
	release   func()
	closed    bool
	borrowers int
}

// OrdinarySourceInspectionV1 is an opaque actual-worker receipt. Source and
// basis clones are immutable private storage. Close prevents new borrowers;
// already admitted pages keep its source/body resource loan until their Close.
// Metadata does not authorize an external caller to manufacture another receipt.
type OrdinarySourceInspectionV1 struct {
	state *ordinarySourceInspectionStateV1
}

// InspectSourceV1 borrows caller-owned source only until this call returns.
// Caller must keep that slice immutable while admission/copy is pending. All
// asynchronous malware/worker I/O receives our admitted exact clone; no caller
// buffer is hashed after an asynchronous loan. No PDF parser runs in the parent.
func (i *OrdinaryInspectorV1) InspectSourceV1(ctx context.Context, b *BasisV1, source []byte) (result *OrdinarySourceInspectionV1, err error) {
	if !i.ready() || !ordinaryInspectionContextV1(ctx) || b == nil || len(source) < 1 || len(source) > sanitize.MaxPDFBytes || b.CanonicalByteCount() < 1 || b.CanonicalByteCount() > MaxCanonicalBytesV1 {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	pin := b.Source()
	if pin.Bytes != int64(len(source)) {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	budget := OrdinaryInspectionBudgetV1{Phase: "source", OrgID: b.input.OrgID, DocumentID: b.input.DocumentID, SourceBytes: int64(len(source)), CanonicalBytes: int64(b.CanonicalByteCount()), MemoryBytes: 4*int64(len(source)) + 16*int64(b.CanonicalByteCount()) + (8 << 20)}
	release, err := i.admit(ctx, budget)
	if err != nil {
		return nil, err
	}
	transferred := false
	var ownSource []byte
	defer func() {
		if !transferred {
			// Any worker call has physically joined before this defer runs.
			clear(ownSource)
			release()
		}
	}()
	ownSource = bytes.Clone(source)
	if plainSHA256V1(ownSource) != pin.SHA256 || ctx.Err() != nil {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	ownBasis, err := DecodeV1(b.CanonicalJSON())
	if err != nil || ownBasis.SHA256() != b.SHA256() || ownBasis.CanonicalSHA256() != b.CanonicalSHA256() {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	expected := ownBasis.Geometry()
	observed, err := func() (sanitize.PDFManualGeometry, error) {
		r, err := i.admitWorker(ctx, OrdinaryInspectionWorkerBudgetV1{Phase: "source", OrgID: b.input.OrgID, DocumentID: b.input.DocumentID})
		if err != nil {
			return sanitize.PDFManualGeometry{}, err
		}
		defer r()
		return i.worker.source(ctx, ownSource)
	}()
	// The fixed worker joins its one-shot child before returning. Error and
	// cancellation paths keep the owned bodies and admission through that return.
	if err != nil || ctx.Err() != nil {
		return nil, ordinaryInspectionErrorV1(ctx, err)
	}
	observed.Pages = append([]sanitize.PDFManualPage(nil), observed.Pages...)
	if !validGeometryV1(observed, ownBasis.Source()) || !ordinaryInspectionGeometryEqualV1(expected, observed) {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	result = &OrdinarySourceInspectionV1{state: &ordinarySourceInspectionStateV1{issuer: i.issuer, basis: ownBasis, source: ownSource, geometry: observed, release: release}}
	if ctx.Err() != nil {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	transferred = true
	return result, nil
}
func ordinaryInspectionGeometryEqualV1(a, b sanitize.PDFManualGeometry) bool {
	if a.SchemaVersion != b.SchemaVersion || a.SourceSHA256 != b.SourceSHA256 || a.SourceBytes != b.SourceBytes || a.GeometrySHA256 != b.GeometrySHA256 || len(a.Pages) != len(b.Pages) {
		return false
	}
	for j := range a.Pages {
		if a.Pages[j] != b.Pages[j] {
			return false
		}
	}
	return true
}
func (s *ordinarySourceInspectionStateV1) detachLocked() (func(), bool) {
	if !s.closed || s.borrowers != 0 || s.release == nil {
		return nil, false
	}
	release := s.release
	s.release = nil
	// Last borrower/consumer has joined; erase only our private byte buffer
	// before its resource permit becomes available to another consumer.
	clear(s.source)
	s.source = nil
	s.basis = nil
	s.geometry.Pages = nil
	return release, true
}
func (s *OrdinarySourceInspectionV1) Close() {
	if s == nil || s.state == nil {
		return
	}
	state := s.state
	state.mu.Lock()
	state.closed = true
	release, _ := state.detachLocked()
	state.mu.Unlock()
	if release != nil {
		release()
	}
}
func (s *OrdinarySourceInspectionV1) borrow(issuer *ordinaryInspectionIssuerV1) (*BasisV1, sanitize.PDFManualGeometry, func(), error) {
	if s == nil || s.state == nil || issuer == nil {
		return nil, sanitize.PDFManualGeometry{}, nil, ErrOrdinaryInspectionV1
	}
	state := s.state
	state.mu.Lock()
	if state.closed || state.issuer != issuer || state.basis == nil || state.release == nil {
		state.mu.Unlock()
		return nil, sanitize.PDFManualGeometry{}, nil, ErrOrdinaryInspectionV1
	}
	state.borrowers++
	b, g := state.basis, state.geometry
	state.mu.Unlock()
	var once sync.Once
	done := func() {
		once.Do(func() {
			state.mu.Lock()
			state.borrowers--
			release, _ := state.detachLocked()
			state.mu.Unlock()
			if release != nil {
				release()
			}
		})
	}
	return b, g, done, nil
}
func (s *OrdinarySourceInspectionV1) MatchesBasisV1(b *BasisV1) bool {
	if s == nil || s.state == nil || b == nil {
		return false
	}
	state := s.state
	state.mu.Lock()
	defer state.mu.Unlock()
	return !state.closed && state.release != nil && state.basis != nil && state.basis.SHA256() == b.SHA256() && state.basis.CanonicalSHA256() == b.CanonicalSHA256()
}
func (s *OrdinarySourceInspectionV1) GeometryV1() (sanitize.PDFManualGeometry, error) {
	if s == nil || s.state == nil {
		return sanitize.PDFManualGeometry{}, ErrOrdinaryInspectionV1
	}
	state := s.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.release == nil {
		return sanitize.PDFManualGeometry{}, ErrOrdinaryInspectionV1
	}
	g := state.geometry
	g.Pages = append([]sanitize.PDFManualPage(nil), g.Pages...)
	return g, nil
}

// OrdinaryInspectionMetadataV1 is an archival descriptor, NOT reconstructible
// authority. Semantic receipts cannot be created by decoding this value. A cold
// consumer must re-inspect retained exact originals using the fixed worker.
type OrdinaryInspectionMetadataV1 struct {
	OrgID                 string
	DocumentID            string
	CeremonyEpoch         string
	StaticBasisSHA256     string
	StaticCanonicalSHA256 string
	Source                manualfit.SourceTupleV1
	SourceGeometrySHA256  string
	SourcePages           int
	Page                  int
	PlanSHA256            string
	PackageSHA256         string
	PackageBytes          int64
	Fragment              sanitize.PDFManualFragmentAdmission
}
type ordinaryPageInspectionStateV1 struct {
	mu         sync.Mutex
	issuer     *ordinaryInspectionIssuerV1
	metadata   OrdinaryInspectionMetadataV1
	plan       ordinarypage.PlanV1
	original   []byte
	pdf        []byte
	release    func()
	sourceDone func()
	closed     bool
}

// OrdinaryPageInspectionV1 binds exact ORIGINAL package/PDF bytes, immutable
// basis and inspected full source geometry to an actual isolated fragment
// admission. It proves structural PDF semantics, not producer origin, glyph
// readability, reviewed values, signature authority, or publication/retention.
// Close releases all borrowed bodies/permits only after the actual worker call
// has joined. Keep the receipt open through its synchronous journal consumer.
type OrdinaryPageInspectionV1 struct {
	state *ordinaryPageInspectionStateV1
}

func (i *OrdinaryInspectorV1) InspectPageV1(ctx context.Context, source *OrdinarySourceInspectionV1, page int, original []byte) (result *OrdinaryPageInspectionV1, err error) {
	if !i.ready() || !ordinaryInspectionContextV1(ctx) || len(original) < ordinarypage.PackageHeaderBytesV1 || len(original) > ordinarypage.MaxPackageBytesV1 || page < 1 || page > sanitize.MaxPDFPages {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	b, geometry, sourceDone, err := source.borrow(i.issuer)
	if err != nil {
		return nil, ordinaryInspectionErrorV1(ctx, err)
	}
	transferred := false
	defer func() {
		if !transferred {
			sourceDone()
		}
	}()
	if page > len(geometry.Pages) {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	budget := OrdinaryInspectionBudgetV1{Phase: "fragment", OrgID: b.input.OrgID, DocumentID: b.input.DocumentID, PackageBytes: int64(len(original)), MemoryBytes: 4*int64(len(original)) + 4*ordinarypage.MaxPDFBytesV1 + 4*ordinarypage.MaxPlanBytesV1 + (8 << 20)}
	release, err := i.admit(ctx, budget)
	if err != nil {
		return nil, err
	}
	var ownOriginal, pdf []byte
	defer func() {
		if !transferred {
			// Keep private aliases intact through physical worker completion,
			// then erase them before releasing page or source resource loans.
			clear(pdf)
			clear(ownOriginal)
			release()
		}
	}()
	// Source state remains borrowed until the page receipt closes. Only after
	// shared admission may plan arrays/package/PDF bytes be cloned or decoded.
	plans, err := OrdinaryPlansV1(b)
	if err != nil {
		return nil, ordinaryInspectionErrorV1(ctx, err)
	}
	var expected ordinarypage.PlanV1
	found := false
	for _, plan := range plans {
		if plan.Page == page {
			expected = plan
			found = true
			break
		}
	}
	if !found {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	ownOriginal = bytes.Clone(original)
	pack, err := ordinarypage.DecodeWithContextV1(ctx, ownOriginal, expected)
	if err != nil {
		return nil, ordinaryInspectionErrorV1(ctx, err)
	}
	pdf = pack.PDF()
	width, height, err := geometry.Pages[page-1].ViewportPoints()
	if err != nil {
		return nil, ordinaryInspectionErrorV1(ctx, err)
	}
	fragment, err := func() (sanitize.PDFManualFragmentAdmission, error) {
		r, err := i.admitWorker(ctx, OrdinaryInspectionWorkerBudgetV1{Phase: "fragment", OrgID: b.input.OrgID, DocumentID: b.input.DocumentID})
		if err != nil {
			return sanitize.PDFManualFragmentAdmission{}, err
		}
		defer r()
		return i.worker.fragment(ctx, pdf, width, height)
	}()
	if err != nil || ctx.Err() != nil {
		return nil, ordinaryInspectionErrorV1(ctx, err)
	}
	if ordinaryInspectionFragmentV1(fragment, pdf, width, height) != nil {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	planSHA, err := ordinarypage.PlanSHA256V1(expected)
	if err != nil {
		return nil, ordinaryInspectionErrorV1(ctx, err)
	}
	metadata := OrdinaryInspectionMetadataV1{OrgID: expected.OrgID, DocumentID: expected.DocumentID, CeremonyEpoch: expected.CeremonyEpoch,
		StaticBasisSHA256: b.SHA256(), StaticCanonicalSHA256: b.CanonicalSHA256(), Source: b.Source(), SourceGeometrySHA256: geometry.GeometrySHA256, SourcePages: len(geometry.Pages), Page: page,
		PlanSHA256: planSHA, PackageSHA256: plainSHA256V1(ownOriginal), PackageBytes: int64(len(ownOriginal)), Fragment: fragment}
	result = &OrdinaryPageInspectionV1{state: &ordinaryPageInspectionStateV1{issuer: i.issuer, metadata: metadata, plan: expected, original: ownOriginal, pdf: pdf, release: release, sourceDone: sourceDone}}
	if ctx.Err() != nil {
		return nil, ordinaryInspectionErrorV1(ctx, nil)
	}
	transferred = true
	return result, nil
}
func ordinaryInspectionFragmentV1(a sanitize.PDFManualFragmentAdmission, pdf []byte, width, height float64) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return ErrOrdinaryInspectionV1
	}
	valid, err := sanitize.DecodePDFManualFragmentAdmission(raw)
	if err != nil || valid != a || a.PDFSHA256 != plainSHA256V1(pdf) || a.PDFBytes != int64(len(pdf)) || a.WidthPoints != width || a.HeightPoints != height {
		return ErrOrdinaryInspectionV1
	}
	// Recompute the fragment geometry commitment from the worker's observed
	// zero-origin all-five-box paper size. Only the worker parses these PDF boxes.
	p := sanitize.PDFManualPage{UserUnit: 1}
	for j := range p.Boxes {
		p.Boxes[j] = [4]float64{0, 0, a.ObservedWidthPoints, a.ObservedHeightPoints}
	}
	pages, err := json.Marshal([]sanitize.PDFManualPage{p})
	if err != nil || plainSHA256V1(pages) != a.GeometrySHA256 {
		return ErrOrdinaryInspectionV1
	}
	return nil
}
func (p *OrdinaryPageInspectionV1) Close() {
	if p == nil || p.state == nil {
		return
	}
	state := p.state
	state.mu.Lock()
	if state.closed {
		state.mu.Unlock()
		return
	}
	state.closed = true
	release, sourceDone := state.release, state.sourceDone
	state.release = nil
	state.sourceDone = nil
	clear(state.original)
	clear(state.pdf)
	state.original = nil
	state.pdf = nil
	state.plan.Fields = nil
	state.mu.Unlock()
	if release != nil {
		release()
	}
	if sourceDone != nil {
		sourceDone()
	}
}
func (p *OrdinaryPageInspectionV1) MetadataV1() (OrdinaryInspectionMetadataV1, error) {
	if p == nil || p.state == nil {
		return OrdinaryInspectionMetadataV1{}, ErrOrdinaryInspectionV1
	}
	state := p.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.release == nil || state.sourceDone == nil {
		return OrdinaryInspectionMetadataV1{}, ErrOrdinaryInspectionV1
	}
	return state.metadata, nil
}
func (p *OrdinaryPageInspectionV1) PlanV1() (ordinarypage.PlanV1, error) {
	if p == nil || p.state == nil {
		return ordinarypage.PlanV1{}, ErrOrdinaryInspectionV1
	}
	state := p.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.release == nil || state.sourceDone == nil {
		return ordinarypage.PlanV1{}, ErrOrdinaryInspectionV1
	}
	return ordinarypage.ClonePlanV1(state.plan)
}

// MatchesOriginalV1 is a synchronous immutable borrow, never an asynchronous
// provider/body loan. The caller keeps original unchanged until this returns.
// Exact literal bytes are compared in addition to their archived commitment.
func (p *OrdinaryPageInspectionV1) MatchesOriginalV1(b *BasisV1, page int, original []byte) bool {
	if p == nil || p.state == nil || b == nil || len(original) > ordinarypage.MaxPackageBytesV1 {
		return false
	}
	state := p.state
	state.mu.Lock()
	defer state.mu.Unlock()
	return !state.closed && state.release != nil && state.sourceDone != nil && state.metadata.Page == page && state.metadata.StaticBasisSHA256 == b.SHA256() &&
		state.metadata.StaticCanonicalSHA256 == b.CanonicalSHA256() && int64(len(original)) == state.metadata.PackageBytes && bytes.Equal(original, state.original)
}
