// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/jackc/pgx/v5/pgtype"
)

// Private fake receipts below test journal dispatch/lifetime boundaries only.
// Their synthetic bodies are not genuine PDF/package/renderer/worker proof.
// The public API has no constructor accepting these metadata or test backends.
func applicationGenerationFixtureV1(t *testing.T, f *applicationFixtureV1) (*ApplicationGenerationV1, *ApplicationSourceV1, *ApplicationGeneratedPageV1) {
	t.Helper()
	inspector, err := NewOrdinaryInspectorV1(func(context.Context, OrdinaryInspectionBudgetV1) (func(), error) { return func() {}, nil }, ordinaryInspectionTestWorkerAdmissionV1)
	if err != nil {
		t.Fatal(err)
	}
	g := &ApplicationGenerationV1{store: &storage.Client{}, renderer: &render.Gotenberg{}, inspector: inspector, acquire: f.adapter.acquire, authorize: func(context.Context, ApplicationDispatchV1) error { return nil }, issuer: &applicationIssuerV1{7}}
	sourceProof := &OrdinarySourceInspectionV1{state: &ordinarySourceInspectionStateV1{issuer: inspector.issuer, basis: f.basis, geometry: f.basis.Geometry(), release: func() {}}}
	s := &ApplicationSourceV1{issuer: g.issuer, scope: f.scope, basis: f.basis, proof: sourceProof, existing: make(map[int]bool), release: func() {}}
	plans, err := OrdinaryPlansV1(f.basis)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(plans[0])
	if err != nil {
		t.Fatal(err)
	}
	pdf := []byte("synthetic PDF body")
	original := []byte("synthetic package bytes")
	report := []byte("synthetic report bytes")
	metadata := OrdinaryInspectionMetadataV1{OrgID: f.scope.OrgID.String(), DocumentID: f.scope.DocumentID.String(), CeremonyEpoch: f.basis.input.CeremonyEpoch.Format(time.RFC3339Nano), StaticBasisSHA256: f.basis.SHA256(), StaticCanonicalSHA256: f.basis.CanonicalSHA256(), Source: f.basis.Source(), SourceGeometrySHA256: f.basis.input.Geometry.GeometrySHA256, SourcePages: len(f.basis.input.Geometry.Pages), Page: 2, PlanSHA256: plainSHA256V1(plan), PackageSHA256: plainSHA256V1(original), PackageBytes: int64(len(original)), Fragment: sanitize.PDFManualFragmentAdmission{PDFSHA256: plainSHA256V1(pdf), PDFBytes: int64(len(pdf))}}
	pageProof := &OrdinaryPageInspectionV1{state: &ordinaryPageInspectionStateV1{issuer: inspector.issuer, metadata: metadata, plan: plans[0], original: bytes.Clone(original), pdf: bytes.Clone(pdf), release: func() {}, sourceDone: func() {}}}
	p := &ApplicationGeneratedPageV1{issuer: g.issuer, scope: f.scope, basis: f.basis, proof: pageProof, original: original, pdf: pdf, plan: plan, report: report, page: 2, release: func() {}}
	return g, s, p
}
func TestApplicationGenerationV1PhysicalRetirementBeforeSourceDispatch(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	g, s, p := applicationGenerationFixtureV1(t, f)
	before := f.admitted
	if source, err := g.InspectSourceV1(applicationTestContextV1(t), c); source != nil || !errors.Is(err, ErrApplicationAdmissionV1) || f.admitted != before {
		t.Fatal("live SQL session reached provider/generation admission")
	}
	s.existing[2] = true
	if page, err := g.ProducePageV1(applicationTestContextV1(t), s, 2); page != nil || !errors.Is(err, ErrApplicationAdmissionV1) || f.admitted != before {
		t.Fatal("captured original reached renderer")
	}
	s.Close()
	p.Close()
	c.Close()
	close(f.done)
	applicationReconcileForTestV1(t, f.adapter)
}
func TestApplicationGenerationV1HotCaptureExactOriginalAndReadyPermit(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	g, s, p := applicationGenerationFixtureV1(t, f)
	captures, readyCalls := 0, 0
	f.adapter.queries.capture = func(_ context.Context, arg generated.CapturePDFSigningAdmissionBodyV1Params) (*generated.CapturePDFSigningAdmissionBodyV1Row, error) {
		captures++
		if !bytes.Equal(arg.Payload, p.pdf) || !bytes.Equal(arg.PlanPayload, p.plan) || arg.OwnerID != f.scope.OwnerID || arg.AdmissionID != f.scope.AdmissionID || arg.OrgID != f.scope.OrgID || arg.DocumentID != f.scope.DocumentID || !bytes.Equal(arg.Sha256, applicationHashV1(p.pdf)) || !bytes.Equal(arg.PackageSha256, applicationHashV1(p.original)) || !bytes.Equal(arg.ReportSha256, applicationHashV1(p.report)) {
			t.Fatal("journal changed original bytes/scope")
		}
		return &generated.CapturePDFSigningAdmissionBodyV1Row{AdmissionID: arg.AdmissionID, OrgID: arg.OrgID, DocumentID: arg.DocumentID, Kind: "ordinary_page", Page: arg.Page, Sha256: arg.Sha256, Bytes: arg.Bytes, ContentType: "application/pdf", StaticBasisSha256: arg.StaticBasisSha256, PlanSha256: arg.PlanSha256, PlanBytes: int64(len(arg.PlanPayload)), PackageSha256: arg.PackageSha256, ReportSha256: arg.ReportSha256, InspectionSha256: arg.InspectionSha256, CapturedOwnerID: arg.OwnerID, CapturedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}, nil
	}
	f.adapter.queries.ready = func(_ context.Context, arg generated.MarkPDFSigningAdmissionReadyV1Params) (*generated.MarkPDFSigningAdmissionReadyV1Row, error) {
		readyCalls++
		if len(arg.SourceInspectionSha256) != 32 {
			t.Fatal("source not committed")
		}
		return &generated.MarkPDFSigningAdmissionReadyV1Row{ID: f.scope.AdmissionID, OrgID: f.scope.OrgID, DocumentID: f.scope.DocumentID, StaticBasisSha256: applicationDigestV1(f.scope.StaticBasisSHA256), Status: "ready", ReadyAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}, nil
	}
	ack, err := g.CapturePageTxV1(applicationTestContextV1(t), f.adapter, c, p)
	if err != nil || captures != 1 {
		t.Fatal(err, captures)
	}
	if _, err := g.CapturePageTxV1(applicationTestContextV1(t), f.adapter, c, p); !errors.Is(err, ErrApplicationAdmissionV1) || captures != 1 {
		t.Fatal("original capture replayed")
	}
	f.deny = true
	if err := g.MarkReadyTxV1(applicationTestContextV1(t), f.adapter, c, s, []ApplicationCapturedPageV1{ack}); !errors.Is(err, ErrApplicationAdmissionV1) || readyCalls != 0 {
		t.Fatal("ready trigger crossed denied DB permit")
	}
	f.deny = false
	if err := g.MarkReadyTxV1(applicationTestContextV1(t), f.adapter, c, s, []ApplicationCapturedPageV1{ack}); err != nil || readyCalls != 1 {
		t.Fatal(err, readyCalls)
	}
	if f.released != 0 || f.adapter.PendingV1().Loans != 3 {
		t.Fatal("SQL capture/readiness permit released before physical session retirement")
	}
	p.Close()
	s.Close()
	c.Close()
	close(f.done)
	if applicationReconcileForTestV1(t, f.adapter) != 0 || f.released != 3 {
		t.Fatal("SQL loan not reconciled after cleanup")
	}
}
func TestApplicationGenerationV1CaptureFailuresNeverReplayOrLeakCause(t *testing.T) {
	for _, kind := range []string{"owner", "issuer", "plan", "sql-cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := applicationFixtureForTestV1(t, false)
			c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
			if err != nil {
				t.Fatal(err)
			}
			g, s, p := applicationGenerationFixtureV1(t, f)
			calls := 0
			ctx, cancel := context.WithCancelCause(applicationTestContextV1(t))
			defer cancel(nil)
			private := errors.New("private capture body path")
			f.adapter.queries.capture = func(context.Context, generated.CapturePDFSigningAdmissionBodyV1Params) (*generated.CapturePDFSigningAdmissionBodyV1Row, error) {
				calls++
				cancel(private)
				return nil, errors.New("private driver credentials")
			}
			switch kind {
			case "owner":
				p.scope.OwnerID[0] ^= 1
			case "issuer":
				p.issuer = &applicationIssuerV1{9}
			case "plan":
				p.plan = append(p.plan, ' ')
			}
			_, err = g.CapturePageTxV1(ctx, f.adapter, c, p)
			if !errors.Is(err, ErrApplicationAdmissionV1) || err.Error() != ErrApplicationAdmissionV1.Error() {
				t.Fatal("capture did not refuse privately")
			}
			if kind == "sql-cancel" {
				if calls != 1 || !errors.Is(err, ErrApplicationCaptureUncertainV1) || !errors.Is(err, context.Canceled) || !errors.Is(err, private) {
					t.Fatal("unknown capture lost cause/uncertainty")
				}
				if _, retryErr := g.CapturePageTxV1(applicationTestContextV1(t), f.adapter, c, p); !errors.Is(retryErr, ErrApplicationAdmissionV1) || calls != 1 {
					t.Fatal("unknown original capture replayed")
				}
			} else if calls != 0 {
				t.Fatal("invalid receipt reached SQL")
			}
			p.Close()
			s.Close()
			c.Close()
			if f.released != 0 {
				t.Fatal("failure released physical loan early")
			}
			close(f.done)
			applicationReconcileForTestV1(t, f.adapter)
		})
	}
}
func TestApplicationGenerationV1SourceCloseRetainsPageBasisLoan(t *testing.T) {
	released := 0
	source := &ApplicationSourceV1{basis: &BasisV1{}, release: func() { released++ }, borrowers: 1}
	pdf := []byte("owned original")
	original := []byte("owned package")
	page := &ApplicationGeneratedPageV1{basis: source.basis, pdf: pdf, original: original, release: func() {
		for _, b := range pdf {
			if b != 0 {
				t.Fatal("original released before erase")
			}
		}
	}, sourceDone: source.pageDone}
	source.Close()
	if released != 0 || source.basis == nil {
		t.Fatal("source Close released active page basis")
	}
	page.Close()
	if released != 1 || source.basis != nil {
		t.Fatal("last page consumer did not retire source loan")
	}
	source.Close()
	page.Close()
	if released != 1 {
		t.Fatal("double source release")
	}
}
func TestApplicationGenerationV1FullLeaseExpiryRefusesHotDispatch(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	fullQuery := f.adapter.queries.current
	f.adapter.queries.current = func(ctx context.Context, arg generated.GetPDFSigningAdmissionMetadataForUpdateV1Params) (*generated.GetPDFSigningAdmissionMetadataForUpdateV1Row, error) {
		row, err := fullQuery(ctx, arg)
		row.LeaseCurrent = false
		return row, err
	}
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal("expired current row should allow exact reads", err)
	}
	if c.header.LeaseCurrent {
		t.Fatal("cheap header lease flag survived later authoritative expiry")
	}
	close(f.done)
	applicationReconcileForTestV1(t, f.adapter)
	g, s, p := applicationGenerationFixtureV1(t, f)
	before := f.admitted
	if result, err := g.InspectSourceV1(applicationTestContextV1(t), c); result != nil || !errors.Is(err, ErrApplicationAdmissionV1) || before != f.admitted {
		t.Fatal("expired full validation authorized hot source IO")
	}
	c.Close()
	p.Close()
	s.Close()
	applicationReconcileForTestV1(t, f.adapter)
}

func TestApplicationGenerationV1DeniedDispatchBeforeAdmissionAndIO(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	close(f.done)
	applicationReconcileForTestV1(t, f.adapter)
	g, s, p := applicationGenerationFixtureV1(t, f)
	calls := 0
	g.authorize = func(context.Context, ApplicationDispatchV1) error {
		calls++
		return errors.New("private original credential")
	}
	before := f.admitted
	if result, err := g.InspectSourceV1(applicationTestContextV1(t), c); result != nil || !errors.Is(err, ErrApplicationAdmissionV1) || err.Error() != ErrApplicationAdmissionV1.Error() {
		t.Fatal("source gate did not refuse safely")
	}
	if result, err := g.ProducePageV1(applicationTestContextV1(t), s, 2); result != nil || !errors.Is(err, ErrApplicationAdmissionV1) || err.Error() != ErrApplicationAdmissionV1.Error() {
		t.Fatal("page gate did not refuse safely")
	}
	if calls != 2 || f.admitted != before || s.borrowers != 0 {
		t.Fatal("denied gate reached resource/provider/producer or leaked source loan")
	}
	p.Close()
	s.Close()
	c.Close()
	applicationReconcileForTestV1(t, f.adapter)
}
func TestApplicationGenerationV1CaptureFailureKeepsOriginalsUntilActualCleanup(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	g, s, p := applicationGenerationFixtureV1(t, f)
	ownedPDF := p.pdf
	ownedOriginal := p.original
	generationReleased := 0
	p.release = func() { generationReleased++ }
	f.adapter.queries.capture = func(context.Context, generated.CapturePDFSigningAdmissionBodyV1Params) (*generated.CapturePDFSigningAdmissionBodyV1Row, error) {
		return nil, errors.New("synthetic unknown SQL session")
	}
	if _, err := g.CapturePageTxV1(applicationTestContextV1(t), f.adapter, c, p); !errors.Is(err, ErrApplicationCaptureUncertainV1) {
		t.Fatal("unknown original capture not marked")
	}
	p.Close()
	s.Close()
	c.Close()
	if generationReleased != 0 || f.released != 0 || len(ownedPDF) == 0 || ownedPDF[0] == 0 || ownedOriginal[0] == 0 || f.adapter.PendingV1().RetainedPages != 1 {
		t.Fatal("consumer Close erased/released body before physical cleanup")
	}
	close(f.done)
	if applicationReconcileForTestV1(t, f.adapter) != 0 || generationReleased != 1 || f.released != 2 {
		t.Fatal("physical originals/SQL loans not reconciled")
	}
	for _, b := range append(ownedPDF, ownedOriginal...) {
		if b != 0 {
			t.Fatal("owned captured originals not cleared after cleanup")
		}
	}
}
func TestApplicationGenerationV1NotifyOnlySQLReleaseAvoidsEntityLockCycle(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	g, s, p := applicationGenerationFixtureV1(t, f)
	old := &ApplicationGeneratedPageV1{pdf: []byte("older pending original"), release: func() {}, captureDone: f.done, captureFence: f.adapter.fence, captureOwner: f.adapter, sourceDone: func() { s.mu.Lock(); s.mu.Unlock() }}
	f.adapter.retainedPages[old] = struct{}{}
	old.Close()
	ctx, cancel := context.WithCancel(applicationTestContextV1(t))
	defer cancel()
	f.adapter.queries.capture = func(context.Context, generated.CapturePDFSigningAdmissionBodyV1Params) (*generated.CapturePDFSigningAdmissionBodyV1Row, error) {
		close(f.done)
		cancel()
		return nil, errors.New("synthetic cancellation")
	}
	returned := make(chan error, 1)
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); _, err := g.CapturePageTxV1(ctx, f.adapter, c, p); returned <- err }()
	defer func() { cancel(); <-workerDone }()
	select {
	case err := <-returned:
		if !errors.Is(err, ErrApplicationCaptureUncertainV1) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SQL consumer release reconciled entity callbacks while locked")
	}
	p.Close()
	s.Close()
	c.Close()
	if applicationReconcileForTestV1(t, f.adapter) != 0 {
		t.Fatal("explicit external reconciliation retained closed page")
	}
}

func TestApplicationGenerationV1ClosedSourceKeepsAdmittedInspectionProof(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	_, source, page := applicationGenerationFixtureV1(t, f)
	proof := source.proof
	source.borrowers = 1
	source.Close()
	if source.proof != proof || !proof.MatchesBasisV1(f.basis) {
		t.Fatal("Close revoked already admitted source proof")
	}
	source.pageDone()
	if source.proof != nil || proof.MatchesBasisV1(f.basis) {
		t.Fatal("last borrower did not close source proof")
	}
	page.Close()
	source.Close()
}

func TestApplicationGenerationV1InvalidPagesCannotGrowRetainedMap(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	g, source, page := applicationGenerationFixtureV1(t, f)
	calls := 0
	g.authorize = func(context.Context, ApplicationDispatchV1) error { calls++; return nil }
	before := f.admitted
	for i := -200; i < 800; i++ {
		if i == 2 {
			continue
		}
		if result, err := g.ProducePageV1(applicationTestContextV1(t), source, i); result != nil || !errors.Is(err, ErrApplicationAdmissionV1) {
			t.Fatal("invalid page admitted", i)
		}
	}
	if calls != 0 || f.admitted != before || len(source.existing) != 0 || source.borrowers != 0 {
		t.Fatal("invalid page grew map or reached authorization/resource/producer")
	}
	page.Close()
	source.Close()
}
