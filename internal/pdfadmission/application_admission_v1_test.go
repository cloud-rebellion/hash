// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ordinarypage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These fixtures exercise adapter boundaries with synthetic private SQL seams.
// They do not establish real driver/session cleanup, SQL88, actual source/PDF,
// renderer/worker origin, global quota, credentials, Sign or publication proof.
type applicationFixtureV1 struct {
	adapter                   *ApplicationAdmissionV1
	basis                     *BasisV1
	header                    *generated.GetPDFSigningAdmissionHeaderMetadataForUpdateV1Row
	scope                     ApplicationScopeV1
	done                      chan struct{}
	events                    []string
	admitted, released        int
	originalPDF, originalPlan []byte
	metadata                  []*generated.ListPDFSigningAdmissionBodyMetadataV1Row
	bodyReads                 int
	deny                      bool
}

func applicationFixtureForTestV1(t *testing.T, withOriginal bool) *applicationFixtureV1 {
	t.Helper()
	in := basisInputV1(t, true)
	in.Fields[1].Value = "  原稿 Åsa & <text>\r\nline  "
	r := ordinarypage.KnownRecipeV1()
	in.RenderRecipe = RenderRecipeV1{Schema: r.Schema, RecipeID: r.RecipeID, HTMLTemplateSHA256: r.HTMLTemplateSHA256, CoreCSSSHA256: r.CoreCSSSHA256, MeasurementSHA256: r.MeasurementSHA256, SnapshotSHA256: r.SnapshotSHA256, PrintRecipeSHA256: r.PrintRecipeSHA256, BrandingCSS: "/* original source context */", Fonts: []FontAssetV1{{File: OrdinaryFontFileV1, Family: OrdinaryFontFamilyV1, SHA256: OrdinaryFontSHA256V1, Bytes: OrdinaryFontBytesV1}}}
	b, err := BuildV1(in)
	if err != nil {
		t.Fatal(err)
	}
	owner := uuid.New()
	scope := ApplicationScopeV1{OrgID: in.OrgID, DocumentID: in.DocumentID, AdmissionID: uuid.New(), OwnerID: owner, StaticBasisSHA256: b.SHA256()}
	h := &generated.GetPDFSigningAdmissionHeaderMetadataForUpdateV1Row{ID: scope.AdmissionID, OrgID: scope.OrgID, DocumentID: scope.DocumentID, CeremonyEpoch: pgtype.Timestamptz{Time: in.CeremonyEpoch, Valid: true}, SourceStorageKey: in.Source.Key, SourceVersionID: in.Source.VersionID, SourceSha256: applicationDigestV1(in.Source.SHA256), SourceBytes: in.Source.Bytes, SourcePages: int32(len(in.Geometry.Pages)), StaticBasisSha256: applicationDigestV1(b.SHA256()), StaticBasisBodySha256: applicationDigestV1(b.CanonicalSHA256()), StaticBasisBytes: int64(b.CanonicalByteCount()), GeometryPayloadSha256: applicationHashV1(b.geometry), GeometryBytes: int64(len(b.geometry)), GeometrySha256: applicationHashV1(b.geometryPages), GeometryPagesBytes: int64(len(b.geometryPages)), FieldsSha256: applicationHashV1(b.fields), FieldsBytes: int64(len(b.fields)), PartiesSha256: applicationHashV1(b.parties), PartiesBytes: int64(len(b.parties)), RenderRecipeSha256: applicationHashV1(b.recipe), RenderRecipeBytes: int64(len(b.recipe)), OrdinaryRecipeSha256: applicationHashV1(b.ordinaryRecipe), OrdinaryRecipeBytes: int64(len(b.ordinaryRecipe)), BrandingContextSha256: applicationDigestV1(b.BrandingCSSSHA256()), ExpectedOrdinaryPages: []int32{2}, RequiredParties: 1, FieldCount: int32(len(in.Fields)), BaseBytesLimit: 8 << 20, DescriptorBytesLimit: 1 << 20, FinalPdfBytesLimit: 8 << 20, FitsIndexBytesLimit: 8 << 20, CertificatePdfBytesLimit: 8 << 20, CertificatePayloadBytesLimit: 4 << 20, CertificateSignatureBytesLimit: 256, EventsBytesLimit: 4 << 20, VersionsBytesLimit: 4 << 20, ArchiveManifestBytesLimit: 1 << 20, ArchiveBudgetBytes: 160 << 20, ProcessingBudgetBytes: 50 << 20, OwnerID: owner, LeaseUntil: pgtype.Timestamptz{Time: time.Now().Add(time.Minute), Valid: true}, Attempts: 1, Status: "staging", DocumentStatus: "sent", SigningAdmissionCount: 1, SigningAdmissionStaticBytes: 1 << 20, CurrentDocumentIdentity: true, LeaseCurrent: true, OwnerMatches: true}
	f := &applicationFixtureV1{basis: b, header: h, scope: scope, done: make(chan struct{})}
	f.adapter = &ApplicationAdmissionV1{issuer: &applicationIssuerV1{1}, cleanupDone: f.done, fence: &applicationSessionFenceV1{clientDone: f.done, observe: func(context.Context, applicationBackendIdentityV1) (bool, error) { return true, nil }}, loans: make(map[*applicationLoanV1]struct{}), retainedPages: make(map[*ApplicationGeneratedPageV1]struct{}), changed: make(chan struct{}, 1)}
	f.adapter.acquire = func(ctx context.Context, b ApplicationBudgetV1) (func(), error) {
		f.events = append(f.events, "permit:"+b.Phase)
		if f.deny {
			return nil, errors.New("private coordinator detail")
		}
		f.admitted++
		return func() { f.released++ }, nil
	}
	f.adapter.queries = applicationQueriesV1{
		header: func(_ context.Context, p generated.GetPDFSigningAdmissionHeaderMetadataForUpdateV1Params) (*generated.GetPDFSigningAdmissionHeaderMetadataForUpdateV1Row, error) {
			f.events = append(f.events, "header")
			if p.AdmissionID != scope.AdmissionID || p.OrgID != scope.OrgID || p.DocumentID != scope.DocumentID || p.OwnerID != scope.OwnerID {
				return nil, errors.New("foreign")
			}
			return h, nil
		},
		current: func(_ context.Context, _ generated.GetPDFSigningAdmissionMetadataForUpdateV1Params) (*generated.GetPDFSigningAdmissionMetadataForUpdateV1Row, error) {
			f.events = append(f.events, "current-json")
			raw, _ := json.Marshal(h)
			var v generated.GetPDFSigningAdmissionMetadataForUpdateV1Row
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			v.CurrentBasis = true
			return &v, nil
		},
		basis: func(_ context.Context, p generated.ReadPDFSigningAdmissionBasisV1Params) ([]byte, error) {
			f.events = append(f.events, "basis-body")
			if p.ExpectedBytes != int64(len(b.canonical)) || !bytes.Equal(p.ExpectedSha256, applicationHashV1(b.canonical)) {
				t.Fatal("body unbounded")
			}
			return bytes.Clone(b.canonical), nil
		},
		component: func(_ context.Context, p generated.ReadPDFSigningAdmissionComponentV1Params) ([]byte, error) {
			f.events = append(f.events, "component:"+p.Kind)
			m := map[string][]byte{"geometry": b.geometry, "geometry_pages": b.geometryPages, "fields": b.fields, "parties": b.parties, "render_recipe": b.recipe, "ordinary_recipe": b.ordinaryRecipe}
			raw := m[p.Kind]
			if p.ExpectedBytes != int64(len(raw)) || !bytes.Equal(p.ExpectedSha256, applicationHashV1(raw)) {
				t.Fatal("component not exact")
			}
			return bytes.Clone(raw), nil
		},
		originals: func(_ context.Context, _ generated.ListPDFSigningAdmissionBodyMetadataV1Params) ([]*generated.ListPDFSigningAdmissionBodyMetadataV1Row, error) {
			f.events = append(f.events, "original-metadata")
			return f.metadata, nil
		},
		body: func(_ context.Context, p generated.ReadPDFSigningAdmissionBodyV1Params) ([]byte, error) {
			f.events = append(f.events, "original-body")
			f.bodyReads++
			if p.ExpectedBytes != int64(len(f.originalPDF)) || !bytes.Equal(p.ExpectedSha256, applicationHashV1(f.originalPDF)) {
				t.Fatal("original read not bounded")
			}
			return bytes.Clone(f.originalPDF), nil
		},
		plan: func(_ context.Context, p generated.ReadPDFSigningAdmissionPlanV1Params) ([]byte, error) {
			f.events = append(f.events, "original-plan")
			if p.ExpectedBytes != int64(len(f.originalPlan)) || !bytes.Equal(p.ExpectedSha256, applicationHashV1(f.originalPlan)) {
				t.Fatal("plan read not bounded")
			}
			return bytes.Clone(f.originalPlan), nil
		},
		capture: func(context.Context, generated.CapturePDFSigningAdmissionBodyV1Params) (*generated.CapturePDFSigningAdmissionBodyV1Row, error) {
			t.Fatal("unexpected capture")
			return nil, nil
		},
		ready: func(context.Context, generated.MarkPDFSigningAdmissionReadyV1Params) (*generated.MarkPDFSigningAdmissionReadyV1Row, error) {
			t.Fatal("unexpected ready")
			return nil, nil
		},
	}
	if withOriginal {
		plans, err := OrdinaryPlansV1(b)
		if err != nil {
			t.Fatal(err)
		}
		f.originalPlan, err = json.Marshal(plans[0])
		if err != nil {
			t.Fatal(err)
		}
		f.originalPDF = []byte("synthetic original PDF bytes, not actual PDF proof")
		f.metadata = []*generated.ListPDFSigningAdmissionBodyMetadataV1Row{{AdmissionID: scope.AdmissionID, OrgID: scope.OrgID, DocumentID: scope.DocumentID, Kind: "ordinary_page", Page: 2, Sha256: applicationHashV1(f.originalPDF), Bytes: int64(len(f.originalPDF)), ContentType: "application/pdf", StaticBasisSha256: applicationDigestV1(b.SHA256()), PlanSha256: applicationHashV1(f.originalPlan), PlanBytes: int64(len(f.originalPlan)), PackageSha256: bytes.Repeat([]byte{1}, 32), ReportSha256: bytes.Repeat([]byte{2}, 32), InspectionSha256: bytes.Repeat([]byte{3}, 32), CapturedOwnerID: owner, CapturedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}}
	}
	return f
}
func applicationTestContextV1(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestApplicationAdmissionV1MetadataBeforePermitBeforeBodies(t *testing.T) {
	f := applicationFixtureForTestV1(t, true)
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.events) < 4 || f.events[0] != "header" || f.events[1] != "permit:locked-basis" || f.events[2] != "current-json" || f.events[3] != "basis-body" || f.bodyReads != 0 {
		t.Fatal(f.events)
	}
	f.deny = true
	if o, err := f.adapter.LoadOriginalV1(applicationTestContextV1(t), c, 2); o != nil || !errors.Is(err, ErrApplicationAdmissionV1) || f.bodyReads != 0 {
		t.Fatal("read crossed denied permit")
	}
	f.deny = false
	o, err := f.adapter.LoadOriginalV1(applicationTestContextV1(t), c, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.WithOriginalV1(func(pdf, plan []byte) error {
		if !bytes.Equal(pdf, f.originalPDF) || !bytes.Equal(plan, f.originalPlan) {
			t.Fatal("original changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c.Close()
	o.Close()
	if f.released != 0 || f.adapter.PendingV1().Loans != 2 {
		t.Fatal("logical consumer Close released physical loans")
	}
	close(f.done)
	if applicationReconcileForTestV1(t, f.adapter) != 0 || f.released != 2 {
		t.Fatal("physical cleanup did not release exactly once")
	}
	applicationReconcileForTestV1(t, f.adapter)
	c.Close()
	o.Close()
	applicationReconcileForTestV1(t, f.adapter)
	if f.released != 2 {
		t.Fatal("double release")
	}
}
func TestApplicationAdmissionV1HeaderAndCurrentFailClosed(t *testing.T) {
	for _, kind := range []string{"foreign", "stale", "oversize", "version", "owner", "component"} {
		t.Run(kind, func(t *testing.T) {
			f := applicationFixtureForTestV1(t, false)
			switch kind {
			case "foreign":
				f.header.OrgID = uuid.New()
			case "stale":
				f.header.CurrentDocumentIdentity = false
			case "oversize":
				f.header.FieldsBytes = MaxComponentBytesV1 + 1
			case "version":
				f.header.SourceVersionID = "null"
			case "owner":
				f.header.OwnerMatches = false
			case "component":
				f.header.FieldsSha256 = bytes.Repeat([]byte{9}, 32)
			}
			c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
			if c != nil || !errors.Is(err, ErrApplicationAdmissionV1) {
				t.Fatal("invalid candidate accepted")
			}
			if kind != "component" && f.admitted != 0 {
				t.Fatal("invalid cheap header reached admission")
			}
			if f.bodyReads != 0 {
				t.Fatal("invalid currentness reached original")
			}
			close(f.done)
			applicationReconcileForTestV1(t, f.adapter)
		})
	}
	f := applicationFixtureForTestV1(t, false)
	f.deny = true
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if c != nil || !errors.Is(err, ErrApplicationAdmissionV1) || len(f.events) != 2 {
		t.Fatal("denied permit reached JSON/body")
	}
	f = applicationFixtureForTestV1(t, false)
	f.adapter.queries.current = func(context.Context, generated.GetPDFSigningAdmissionMetadataForUpdateV1Params) (*generated.GetPDFSigningAdmissionMetadataForUpdateV1Row, error) {
		return &generated.GetPDFSigningAdmissionMetadataForUpdateV1Row{CurrentBasis: false}, nil
	}
	c, err = f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if c != nil || !errors.Is(err, ErrApplicationAdmissionV1) {
		t.Fatal("cheap header treated as authority")
	}
	close(f.done)
	applicationReconcileForTestV1(t, f.adapter)
}
func TestApplicationAdmissionV1OriginalInventoryBeforeBodyAndNoRegeneration(t *testing.T) {
	for _, kind := range []string{"extra", "nil", "duplicate", "foreign", "page", "digest", "count"} {
		t.Run(kind, func(t *testing.T) {
			f := applicationFixtureForTestV1(t, true)
			switch kind {
			case "extra":
				f.metadata = append(f.metadata, f.metadata[0])
			case "nil":
				f.metadata[0] = nil
			case "duplicate":
				f.header.ExpectedOrdinaryPages = []int32{1, 2}
				f.metadata = append(f.metadata, f.metadata[0])
			case "foreign":
				f.metadata[0].DocumentID = uuid.New()
			case "page":
				f.metadata[0].Page = 1
			case "digest":
				f.metadata[0].PlanSha256 = nil
			case "count":
				f.metadata = make([]*generated.ListPDFSigningAdmissionBodyMetadataV1Row, 501)
			}
			c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
			if c != nil || !errors.Is(err, ErrApplicationAdmissionV1) || f.bodyReads != 0 {
				t.Fatal("invalid inventory reached original bytes")
			}
			close(f.done)
			applicationReconcileForTestV1(t, f.adapter)
		})
	}
	f := applicationFixtureForTestV1(t, true)
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	f.adapter.queries.plan = func(context.Context, generated.ReadPDFSigningAdmissionPlanV1Params) ([]byte, error) {
		return []byte("wrong plan"), nil
	}
	if o, err := f.adapter.LoadOriginalV1(applicationTestContextV1(t), c, 2); o != nil || !errors.Is(err, ErrApplicationAdmissionV1) {
		t.Fatal("wrong original plan accepted")
	}
	c.Close()
	close(f.done)
	if applicationReconcileForTestV1(t, f.adapter) != 0 || f.released != 2 {
		t.Fatal("failed original loan lost")
	}
}
func TestApplicationAdmissionV1FailedSQLQuarantineAndPrivateCancellation(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	ctx, cancel := context.WithCancelCause(applicationTestContextV1(t))
	private := errors.New("private account document name")
	f.adapter.queries.basis = func(context.Context, generated.ReadPDFSigningAdmissionBasisV1Params) ([]byte, error) {
		cancel(private)
		return nil, errors.New("private provider password")
	}
	c, err := f.adapter.LoadCurrentV1(ctx, f.scope)
	if c != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, private) || strings.Contains(err.Error(), "private") || f.released != 0 || f.adapter.PendingV1().Loans != 1 {
		t.Fatal("SQL cancellation lost ownership/cause or leaked details")
	}
	short, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	if err := f.adapter.CloseV1(short); !errors.Is(err, context.DeadlineExceeded) || f.released != 0 {
		t.Fatal("shutdown inferred physical retirement")
	}
	close(f.done)
	if applicationReconcileForTestV1(t, f.adapter) != 0 || f.released != 1 {
		t.Fatal("actual cleanup not reconciled")
	}
}
func TestApplicationAdmissionV1CleanupBeforeConsumerKeepsOriginalLoan(t *testing.T) {
	f := applicationFixtureForTestV1(t, true)
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	o, err := f.adapter.LoadOriginalV1(applicationTestContextV1(t), c, 2)
	if err != nil {
		t.Fatal(err)
	}
	close(f.done)
	if applicationReconcileForTestV1(t, f.adapter) != 2 || f.released != 0 {
		t.Fatal("cleanup stole live consumer loans")
	}
	c.Close()
	applicationReconcileForTestV1(t, f.adapter)
	if f.released != 1 {
		t.Fatal("basis consumer not released")
	}
	if err := o.WithOriginalV1(func(pdf, plan []byte) error {
		if !bytes.Equal(pdf, f.originalPDF) {
			t.Fatal("consumer original lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	o.Close()
	applicationReconcileForTestV1(t, f.adapter)
	if f.released != 2 {
		t.Fatal("last consumer not released")
	}
	if err := f.adapter.CloseV1(applicationTestContextV1(t)); err != nil {
		t.Fatal(err)
	}
}
func TestApplicationAdmissionV1ReadOnlyReadyExpiredAndOpaqueIssuers(t *testing.T) {
	f := applicationFixtureForTestV1(t, true)
	f.header.Status = "ready"
	f.header.LeaseCurrent = false
	f.header.LeaseUntil = pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal("expired staging lease incorrectly prevented immutable original read", err)
	}
	other := applicationFixtureForTestV1(t, true).adapter
	if o, err := other.LoadOriginalV1(applicationTestContextV1(t), c, 2); o != nil || !errors.Is(err, ErrApplicationAdmissionV1) {
		t.Fatal("foreign opaque reader issuer accepted")
	}
	c.Close()
	close(f.done)
	applicationReconcileForTestV1(t, f.adapter)
	if a, err := NewApplicationAdmissionV1(applicationTestContextV1(t), nil, nil, func(context.Context, ApplicationBudgetV1) (func(), error) { return func() {}, nil }); a != nil || !errors.Is(err, ErrApplicationAdmissionV1) {
		t.Fatal("nil physical transaction accepted")
	}
	if g, err := NewApplicationGenerationV1(nil, nil, nil, nil, nil); g != nil || !errors.Is(err, ErrApplicationAdmissionV1) {
		t.Fatal("missing fixed producer accepted")
	}
}

func TestApplicationAdmissionV1ReconcileAccountsUntilReleaseCompletes(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	started, finish, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.adapter.acquire = func(context.Context, ApplicationBudgetV1) (func(), error) {
		return func() { close(started); <-finish }, nil
	}
	consumer, err := f.adapter.admit(applicationTestContextV1(t), ApplicationBudgetV1{Phase: "locked-test", WorkingBytes: 123})
	if err != nil {
		t.Fatal(err)
	}
	consumer()
	close(f.done)
	// A deliberately blocked test callback violates the production nonblocking
	// release contract; inventory must still not report completion prematurely.
	workerError := make(chan error, 1)
	go func() {
		defer close(returned)
		_, err := f.adapter.ReconcileCleanupV1(applicationTestContextV1(t))
		workerError <- err
	}()
	var finishOnce sync.Once
	finishRelease := func() { finishOnce.Do(func() { close(finish) }) }
	defer func() { finishRelease(); <-returned }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("release not started")
	}
	if f.adapter.PendingV1().Loans != 1 || applicationReconcileForTestV1(t, f.adapter) != 1 {
		finishRelease()
		<-returned
		t.Fatal("release in progress disappeared from ownership inventory")
	}
	finishRelease()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("reconciliation did not finish")
	}
	if err := <-workerError; err != nil {
		t.Fatal(err)
	}
	if f.adapter.PendingV1().Loans != 0 {
		t.Fatal("completed release remained pending")
	}
}

func applicationReconcileForTestV1(t *testing.T, a *ApplicationAdmissionV1) int {
	t.Helper()
	n, err := a.ReconcileCleanupV1(applicationTestContextV1(t))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestApplicationAdmissionV1ClientCleanupDoesNotRetireServerDebt(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	c, err := f.adapter.LoadCurrentV1(applicationTestContextV1(t), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	serverGone := false
	observations := 0
	f.adapter.fence.observe = func(context.Context, applicationBackendIdentityV1) (bool, error) {
		observations++
		return serverGone, nil
	}
	c.Close()
	close(f.done)
	if applicationReconcileForTestV1(t, f.adapter) != 1 || f.released != 0 || f.adapter.PendingV1().ServerRetired || observations != 1 {
		t.Fatal("client cleanup released live-server work")
	}
	short, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := f.adapter.CloseV1(short); !errors.Is(err, context.DeadlineExceeded) || f.released != 0 {
		t.Fatal("shutdown inferred server retirement")
	}
	serverGone = true
	if applicationReconcileForTestV1(t, f.adapter) != 0 || f.released != 1 || !f.adapter.PendingV1().ServerRetired {
		t.Fatal("proved server retirement failed to release transient ownership")
	}
}
func TestApplicationAdmissionV1UnknownObserverRetainsOwnedBodiesAndPrivateCause(t *testing.T) {
	f := applicationFixtureForTestV1(t, false)
	consumer, err := f.adapter.admit(applicationTestContextV1(t), ApplicationBudgetV1{Phase: "locked-observer-test", DBStagingBytes: 100, WorkingBytes: 123})
	if err != nil {
		t.Fatal(err)
	}
	consumer()
	close(f.done)
	f.adapter.fence.observe = func(context.Context, applicationBackendIdentityV1) (bool, error) {
		return false, errors.New("private server address")
	}
	n, err := f.adapter.ReconcileCleanupV1(applicationTestContextV1(t))
	if n != 1 || !errors.Is(err, ErrApplicationAdmissionV1) || err.Error() != ErrApplicationAdmissionV1.Error() || f.released != 0 || f.adapter.PendingV1().DBStagingBytes != 100 {
		t.Fatal("unknown observer released or exposed private debt")
	}
	f.adapter.fence.observe = func(context.Context, applicationBackendIdentityV1) (bool, error) { return true, nil }
	applicationReconcileForTestV1(t, f.adapter)
}
func TestApplicationRetirementV1OriginIdentityAndTLSMismatchRefuse(t *testing.T) {
	stamp := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	old := applicationBackendIdentityV1{pid: 123, backendStart: stamp, databaseOID: 42, userOID: 7, address: "127.0.0.1", port: 5432, postmasterStart: stamp.Add(-time.Hour)}
	if !applicationIdentityValidV1(old) || !applicationServerSameV1(old, old) {
		t.Fatal("valid scoped origin refused")
	}
	for _, kind := range []string{"database", "user", "address", "port", "postmaster"} {
		changed := old
		switch kind {
		case "database":
			changed.databaseOID++
		case "user":
			changed.userOID++
		case "address":
			changed.address = "127.0.0.2"
		case "port":
			changed.port++
		case "postmaster":
			changed.postmasterStart = changed.postmasterStart.Add(time.Second)
		}
		if applicationServerSameV1(old, changed) {
			t.Fatal("drifted observer accepted", kind)
		}
	}
	if applicationTLSVerifySameV1(&tls.Config{ServerName: "server-a"}, &tls.Config{ServerName: "server-b"}) || applicationTLSVerifySameV1(nil, &tls.Config{}) {
		t.Fatal("unrelated TLS verification identity accepted")
	}
}

func TestApplicationRetirementV1AtomicOriginAndPIDVisibility(t *testing.T) {
	stamp := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	old := applicationBackendIdentityV1{pid: 123, backendStart: stamp, databaseOID: 42, userOID: 7, address: "127.0.0.1", port: 5432, postmasterStart: stamp.Add(-time.Hour)}
	current := old
	current.pid = 456
	current.backendStart = stamp.Add(time.Second)
	pid := old.pid
	db, user := old.databaseOID, old.userOID
	if gone, err := applicationObservedRetiredV1(applicationTestContextV1(t), old, current, nil, nil, nil, nil); !gone || err != nil {
		t.Fatal("same-server absent PID refused", err)
	}
	otherServer := current
	otherServer.address = "127.0.0.2"
	if gone, err := applicationObservedRetiredV1(applicationTestContextV1(t), old, otherServer, nil, nil, nil, nil); gone || !errors.Is(err, ErrApplicationAdmissionV1) {
		t.Fatal("other-server absence authorized retirement")
	}
	if gone, err := applicationObservedRetiredV1(applicationTestContextV1(t), old, current, &pid, nil, &db, &user); gone || !errors.Is(err, ErrApplicationAdmissionV1) {
		t.Fatal("masked PID row looked absent")
	}
	if gone, err := applicationObservedRetiredV1(applicationTestContextV1(t), old, current, &pid, &stamp, &db, &user); gone || err != nil {
		t.Fatal("live old backend retired")
	}
	restarted := stamp.Add(time.Minute)
	if gone, err := applicationObservedRetiredV1(applicationTestContextV1(t), old, current, &pid, &restarted, &db, &user); !gone || err != nil {
		t.Fatal("visible new PID incarnation failed to retire old backend")
	}
}
