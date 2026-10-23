// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/ordinarypage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

var ErrApplicationAdmissionV1 = errors.New("pdfadmission: application admission unavailable")
var ErrApplicationCaptureUncertainV1 = errors.New("pdfadmission: original capture requires reconciliation")

// ApplicationBudgetV1 describes this unit's bounded SQL/parent working set. The
// DBStagingBytes describes transient DB validation/write demand, NOT retained
// disk credit. Durable unknown/committed bodies need a separate durable ledger.
// WorkingBytes are conservative dispatch estimates, not measured RSS guarantees.
// The shared live coordinator must also charge physical workers, transport, tenant
// retained debt and the all-party processing/archive ledger. These values do not
// implement a quota. TryAcquire MUST be nonblocking when Phase begins locked-;
// refusal requires rollback/release of locks before waiting for capacity and a
// new READ COMMITTED transaction/header check. Never wait for quota under a lock.
// Every returned release MUST be nonblocking, synchronous and perform no I/O.
// Bounded Close relies on that real-coordinator contract; no simulated callback
// establishes it for the deployed application.
type ApplicationBudgetV1 struct {
	packageSendAuditGrant                                                 *applicationPackageSendAuditBatchV1
	PackageSendAuditEventCount                                            int64
	packageSendOutboxGrant                                                *applicationPackageSendOutboxBatchV1
	automationAuditGrant                                                  *applicationAutomationAuditBatchV1
	AutomationAuditEventCount                                             int64
	pdfLayoutAuditGrant                                                   *applicationPDFLayoutAuditBatchV1
	PDFLayoutAuditEventCount                                              int64
	htmlSendCollectionGrant                                               *applicationHTMLSendCollectionGrantV1
	htmlSendEIDASGrant                                                    *applicationHTMLSendEIDASGrantV1
	htmlSendPlanPolicyGrant                                               *applicationHTMLSendPlanPolicyGrantV1
	htmlRevisionSourceGrant                                               *applicationHTMLRevisionSourceGrantV1
	Phase                                                                 string
	OrgID, DocumentID, AdmissionID                                        uuid.UUID
	StoredBasisBytes, ComponentBytes, OriginalPDFBytes, OriginalPlanBytes int64
	SourceBytes, WorkingBytes, DBStagingBytes                             int64
	RecipientID                                                           uuid.UUID
	RequestOriginBytes, RequestIntentBytes, RequestRawContextBytes        int64
	RequestAuthorityBytes, RequestSpanBytes, RequestCurrentContextBytes   int64
	RequestOriginalRawContextBytes, RequestPolicyBytes                    int64
	HTMLInputRawBytes, HTMLInputWireBytes, HTMLSourceWireBytes            int64
	HTMLAuthoringRawBytes, HTMLAuthoringWireBytes                         int64
	HTMLAuditRawBytes, HTMLAuditWireBytes, HTMLAuditNodes                 int64
	htmlAuthoringBodyGrant                                                *applicationHTMLAuthoringBodyGrantV1
}
type ApplicationTryAcquireV1 func(context.Context, ApplicationBudgetV1) (func(), error)

type ApplicationScopeV1 struct {
	OrgID, DocumentID, AdmissionID, OwnerID uuid.UUID
	StaticBasisSHA256                       string
}

func (s ApplicationScopeV1) valid() bool {
	return s.OrgID != uuid.Nil && s.DocumentID != uuid.Nil && s.AdmissionID != uuid.Nil && s.OwnerID != uuid.Nil && digestV1(s.StaticBasisSHA256)
}

type applicationFailureV1 struct{ causes []error }

func (*applicationFailureV1) Error() string     { return ErrApplicationAdmissionV1.Error() }
func (e *applicationFailureV1) Unwrap() []error { return append([]error(nil), e.causes...) }
func applicationErrorV1(ctx context.Context, err error) error {
	causes := []error{ErrApplicationAdmissionV1}
	for _, known := range []error{ErrApplicationCaptureUncertainV1, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			causes = append(causes, known)
		}
	}
	if ctx != nil && ctx.Err() != nil {
		causes = append(causes, ctx.Err())
		if cause := context.Cause(ctx); cause != nil && cause != ctx.Err() {
			causes = append(causes, cause)
		}
	}
	return &applicationFailureV1{causes: causes}
}
func applicationContextV1(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	_, ok := ctx.Deadline()
	return ok
}
func applicationHashV1(raw []byte) []byte {
	h := sha256.Sum256(raw)
	return append([]byte(nil), h[:]...)
}
func applicationDigestV1(s string) []byte {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != sha256.Size {
		return nil
	}
	return raw
}
func applicationStampEqualV1(a, b pgtype.Timestamptz) bool {
	return a.Valid == b.Valid && a.InfinityModifier == b.InfinityModifier && a.Time.Equal(b.Time)
}
func applicationStampV1(v pgtype.Timestamptz) bool {
	return v.Valid && v.InfinityModifier == pgtype.Finite && !v.Time.IsZero() && v.Time.Year() >= 1 && v.Time.Year() <= 9999
}

// Queries are private test seams. The public constructor always binds generated
// queries to the caller's actual pgx transaction, never a pool-backed reader.
type applicationQueriesV1 struct {
	header    func(context.Context, generated.GetPDFSigningAdmissionHeaderMetadataForUpdateV1Params) (*generated.GetPDFSigningAdmissionHeaderMetadataForUpdateV1Row, error)
	current   func(context.Context, generated.GetPDFSigningAdmissionMetadataForUpdateV1Params) (*generated.GetPDFSigningAdmissionMetadataForUpdateV1Row, error)
	basis     func(context.Context, generated.ReadPDFSigningAdmissionBasisV1Params) ([]byte, error)
	component func(context.Context, generated.ReadPDFSigningAdmissionComponentV1Params) ([]byte, error)
	originals func(context.Context, generated.ListPDFSigningAdmissionBodyMetadataV1Params) ([]*generated.ListPDFSigningAdmissionBodyMetadataV1Row, error)
	body      func(context.Context, generated.ReadPDFSigningAdmissionBodyV1Params) ([]byte, error)
	plan      func(context.Context, generated.ReadPDFSigningAdmissionPlanV1Params) ([]byte, error)
	capture   func(context.Context, generated.CapturePDFSigningAdmissionBodyV1Params) (*generated.CapturePDFSigningAdmissionBodyV1Row, error)
	ready     func(context.Context, generated.MarkPDFSigningAdmissionReadyV1Params) (*generated.MarkPDFSigningAdmissionReadyV1Row, error)
}
type applicationIssuerV1 struct{ marker byte }

// ApplicationAdmissionV1 borrows a real READ COMMITTED transaction. Use a dedicated physical session closed after caller COMMIT/rollback. Caller owns
// document->ordered recipients->88->85 lock order, original credential/review
// policy, resource coordinator, physical session/commit uncertainty and rollback.
// This unit neither opens/commits transactions nor turns a ready row into Sign
// permission. Hold locks through each journal mutation; never publish success
// from these uncommitted receipts. A cold caller must query original metadata
// before producing: absence after an unknown older session is not replay proof.
type ApplicationAdmissionV1 struct {
	mu            sync.Mutex
	cleanupDone   <-chan struct{}
	fence         *applicationSessionFenceV1
	loans         map[*applicationLoanV1]struct{}
	retainedPages map[*ApplicationGeneratedPageV1]struct{}
	changed       chan struct{}
	closed        bool
	queries       applicationQueriesV1
	acquire       ApplicationTryAcquireV1
	issuer        *applicationIssuerV1
}

func NewApplicationAdmissionV1(ctx context.Context, tx pgx.Tx, observer *pgxpool.Pool, acquire ApplicationTryAcquireV1) (*ApplicationAdmissionV1, error) {
	if tx == nil || tx.Conn() == nil || tx.Conn().IsClosed() || acquire == nil {
		return nil, ErrApplicationAdmissionV1
	}
	fence, err := applicationCaptureSessionFenceV1(ctx, tx, observer)
	if err != nil {
		return nil, err
	}
	return newApplicationAdmissionWithFenceV1(tx, acquire, fence)
}

func newApplicationAdmissionWithFenceV1(tx pgx.Tx, acquire ApplicationTryAcquireV1, fence *applicationSessionFenceV1) (*ApplicationAdmissionV1, error) {
	if tx == nil || tx.Conn() == nil || tx.Conn().IsClosed() || acquire == nil || fence == nil || fence.observe == nil || fence.clientDone != tx.Conn().PgConn().CleanupDone() || uint32(fence.identity.pid) != tx.Conn().PgConn().PID() {
		return nil, ErrApplicationAdmissionV1
	}
	return newApplicationAdmissionQueriesWithFenceV1(tx, acquire, fence)
}

func newApplicationAdmissionQueriesWithFenceV1(db generated.DBTX, acquire ApplicationTryAcquireV1, fence *applicationSessionFenceV1) (*ApplicationAdmissionV1, error) {
	if db == nil || acquire == nil || fence == nil || fence.observe == nil || !applicationIdentityValidV1(fence.identity) {
		return nil, ErrApplicationAdmissionV1
	}
	q := generated.New(db)
	return &ApplicationAdmissionV1{cleanupDone: fence.clientDone, fence: fence, loans: make(map[*applicationLoanV1]struct{}), retainedPages: make(map[*ApplicationGeneratedPageV1]struct{}), changed: make(chan struct{}, 1), queries: applicationQueriesV1{q.GetPDFSigningAdmissionHeaderMetadataForUpdateV1, q.GetPDFSigningAdmissionMetadataForUpdateV1, q.ReadPDFSigningAdmissionBasisV1, q.ReadPDFSigningAdmissionComponentV1, q.ListPDFSigningAdmissionBodyMetadataV1, q.ReadPDFSigningAdmissionBodyV1, q.ReadPDFSigningAdmissionPlanV1, q.CapturePDFSigningAdmissionBodyV1, q.MarkPDFSigningAdmissionReadyV1}, acquire: acquire, issuer: &applicationIssuerV1{1}}, nil
}
func (a *ApplicationAdmissionV1) valid() bool {
	return a != nil && a.cleanupDone != nil && a.fence != nil && a.fence.observe != nil && a.loans != nil && a.retainedPages != nil && a.issuer != nil && a.acquire != nil && a.queries.header != nil && a.queries.current != nil && a.queries.basis != nil && a.queries.component != nil && a.queries.originals != nil && a.queries.body != nil && a.queries.plan != nil && a.queries.capture != nil && a.queries.ready != nil
}

type applicationLoanV1 struct {
	release                   func()
	consumerClosed, releasing bool
	budget                    ApplicationBudgetV1
}

const applicationMaxLoansV1 = 512

func applicationDoneV1(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}
func (a *ApplicationAdmissionV1) notify() {
	select {
	case a.changed <- struct{}{}:
	default:
	}
}
func (a *ApplicationAdmissionV1) admit(ctx context.Context, b ApplicationBudgetV1) (func(), error) {
	return a.admitCoreV1(ctx, b, nil, nil)
}

// The native reader bridge supplies only its actual factory work adapter and
// already-owned fixed observation. All callers share the original loan core.
func (a *ApplicationAdmissionV1) admitCoreV1(ctx context.Context, b ApplicationBudgetV1, work *WorkAdmissionV1, denial *workguard.AdmissionDenialV1) (func(), error) {
	return a.admitCoreObservedV1(ctx, b, work, denial, nil)
}
func (a *ApplicationAdmissionV1) admitCoreObservedV1(ctx context.Context, b ApplicationBudgetV1, work *WorkAdmissionV1, denial *workguard.AdmissionDenialV1, audit *htmlAuditLoanObservationV1) (func(), error) {
	a.mu.Lock()
	if a.closed || len(a.loans) >= applicationMaxLoansV1 {
		if audit != nil {
			if a.closed {
				audit.branch = htmlAuditLoanClosedV1
			} else {
				audit.branch = htmlAuditLoanRegistryLimitV1
			}
		}
		a.mu.Unlock()
		return nil, applicationErrorV1(ctx, nil)
	}
	loan := &applicationLoanV1{budget: b}
	a.loans[loan] = struct{}{}
	a.mu.Unlock()
	var release func()
	var err error
	if audit != nil {
		audit.branch = htmlAuditLoanDecisionV1
	}
	if denial != nil {
		if audit != nil {
			release, err = work.applicationAuditWithDenialV1(ctx, b, denial)
		} else {
			release, err = work.applicationSignerReadWithDenialV1(ctx, b, denial)
		}
	} else {
		release, err = a.acquire(ctx, b)
	}
	if release == nil {
		a.mu.Lock()
		delete(a.loans, loan)
		a.mu.Unlock()
		a.notify()
		return nil, applicationErrorV1(ctx, err)
	}
	a.mu.Lock()
	loan.release = release
	a.mu.Unlock()
	var once sync.Once
	closeConsumer := func() { once.Do(func() { a.mu.Lock(); loan.consumerClosed = true; a.mu.Unlock(); a.notify() }) }
	if err != nil || ctx.Err() != nil {
		if audit != nil {
			audit.branch = htmlAuditLoanConsumerV1
		}
		closeConsumer()
		return nil, applicationErrorV1(ctx, err)
	}
	return closeConsumer, nil
}

// ApplicationPendingV1 counts this adapter's live/quarantined loans only. It is
// not tenant/global debt; a durable staging disposition still belongs to the
// commit-aware coordinator. No loan is released on ambiguous SQL cancellation.
type ApplicationPendingV1 struct {
	Loans, RetainedPages         int
	ClientCleaned, ServerRetired bool
	WorkingBytes, DBStagingBytes int64
}

func (a *ApplicationAdmissionV1) PendingV1() ApplicationPendingV1 {
	if a == nil {
		return ApplicationPendingV1{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := ApplicationPendingV1{Loans: len(a.loans), RetainedPages: len(a.retainedPages), ClientCleaned: applicationDoneV1(a.cleanupDone), ServerRetired: a.fence.retiredV1()}
	for loan := range a.loans {
		out.WorkingBytes += loan.budget.WorkingBytes
		out.DBStagingBytes += loan.budget.DBStagingBytes
	}
	return out
}

// ReconcileCleanupV1 must run outside entity locks. It performs bounded, fixed
// read-only observation of the original backend only after client cleanup. An
// unknown/live/masked/drifted server retains all ownership. Proved retirement
// permits TRANSIENT process/DB validation resources to retire; it never releases
// durable retained disk credit or proves COMMIT/rollback/scoped row disposition.
func (a *ApplicationAdmissionV1) ReconcileCleanupV1(ctx context.Context) (int, error) {
	if a == nil {
		return 0, nil
	}
	if !applicationContextV1(ctx) {
		return a.PendingV1().Loans + a.PendingV1().RetainedPages, applicationErrorV1(ctx, nil)
	}
	retired, err := a.fence.proveV1(ctx)
	if err != nil {
		return a.PendingV1().Loans + a.PendingV1().RetainedPages, err
	}
	if !retired {
		return a.PendingV1().Loans + a.PendingV1().RetainedPages, nil
	}
	a.mu.Lock()
	var releases []*applicationLoanV1
	var pages []*ApplicationGeneratedPageV1
	for loan := range a.loans {
		if loan.consumerClosed && loan.release != nil && !loan.releasing {
			loan.releasing = true
			releases = append(releases, loan)
		}
	}
	for p := range a.retainedPages {
		pages = append(pages, p)
	}
	a.mu.Unlock()
	for _, loan := range releases {
		loan.release()
		a.mu.Lock()
		delete(a.loans, loan)
		a.mu.Unlock()
		a.notify()
	}
	for _, p := range pages {
		if p.reconcileCaptureV1() {
			a.mu.Lock()
			delete(a.retainedPages, p)
			a.mu.Unlock()
			a.notify()
		}
	}
	a.mu.Lock()
	pending := len(a.loans) + len(a.retainedPages)
	a.mu.Unlock()
	return pending, nil
}

// CloseV1 boundedly polls server retirement and joins all consumer ownership.
// Caller must COMMIT/rollback then CLOSE its dedicated session. Unknown observer
// results leave quarantined resources owned. Never wait only on an already closed
// client channel while a still-running server backend may later retire.
func (a *ApplicationAdmissionV1) CloseV1(ctx context.Context) error {
	if a == nil {
		return nil
	}
	if !applicationContextV1(ctx) {
		return applicationErrorV1(ctx, nil)
	}
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	timer := time.NewTicker(50 * time.Millisecond)
	defer timer.Stop()
	for {
		pending, err := a.ReconcileCleanupV1(ctx)
		if err != nil {
			return err
		}
		if pending == 0 {
			return nil
		}
		select {
		case <-a.changed:
		case <-timer.C:
		case <-ctx.Done():
			return applicationErrorV1(ctx, ctx.Err())
		}
	}
}

type ApplicationCandidateV1 struct {
	mu          sync.Mutex
	issuer      *applicationIssuerV1
	cleanupDone <-chan struct{}
	fence       *applicationSessionFenceV1
	scope       ApplicationScopeV1
	basis       *BasisV1
	header      *generated.GetPDFSigningAdmissionHeaderMetadataForUpdateV1Row
	originals   map[int]generated.ListPDFSigningAdmissionBodyMetadataV1Row
	release     func()
	closed      bool
}

// Close ends only this reader's consumer loan; call adapter reconciliation after
// physical retirement to release its permit. It does not commit/rollback/close the
// caller transaction, remove durable originals, or relax unknown-session debt.
func (c *ApplicationCandidateV1) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	release := c.release
	c.release = nil
	c.basis = nil
	c.header = nil
	c.originals = nil
	c.mu.Unlock()
	if release != nil {
		release()
	}
}
func (c *ApplicationCandidateV1) ScopeV1() (ApplicationScopeV1, error) {
	if c == nil {
		return ApplicationScopeV1{}, ErrApplicationAdmissionV1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.release == nil {
		return ApplicationScopeV1{}, ErrApplicationAdmissionV1
	}
	return c.scope, nil
}

// WithBasisV1 is a synchronous immutable borrow for the future ledger/authority
// and88->86 handoff. Keep all clones under additional caller resource admission.
// The callback must not retain the pointer, mutate private state, dispatch I/O or
// wait for capacity under these locks. A basis remains data, never Sign authority.
func (c *ApplicationCandidateV1) WithBasisV1(ctx context.Context, consume func(*BasisV1) error) error {
	if c == nil || consume == nil || !applicationContextV1(ctx) {
		return applicationErrorV1(ctx, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.release == nil || c.basis == nil {
		return applicationErrorV1(ctx, nil)
	}
	if err := consume(c.basis); err != nil || ctx.Err() != nil {
		return applicationErrorV1(ctx, err)
	}
	return nil
}

func applicationHeaderV1(h *generated.GetPDFSigningAdmissionHeaderMetadataForUpdateV1Row, s ApplicationScopeV1) (ApplicationBudgetV1, error) {
	if h == nil || h.ID != s.AdmissionID || h.OrgID != s.OrgID || h.DocumentID != s.DocumentID || h.DocumentDeleted || !h.CurrentDocumentIdentity ||
		(h.DocumentStatus != "sent" && h.DocumentStatus != "in_progress") || !applicationStampV1(h.CeremonyEpoch) || !applicationStampV1(h.LeaseUntil) ||
		(h.Status != "staging" && h.Status != "ready" && h.Status != "sealed") || (h.Status != "sealed" && (!h.OwnerMatches || h.OwnerID != s.OwnerID)) ||
		!bytes.Equal(h.StaticBasisSha256, applicationDigestV1(s.StaticBasisSHA256)) || h.SourceBytes < 1 || h.SourceBytes > 50<<20 || h.SourcePages < 1 || h.SourcePages > 500 ||
		!objectKeyV1(h.SourceStorageKey) || !manualfit.ValidObjectVersionV1(h.SourceVersionID) || h.RequiredParties < 1 || h.RequiredParties > 100 || h.FieldCount < 1 || h.FieldCount > 1000 ||
		len(h.ExpectedOrdinaryPages) > int(h.SourcePages) || h.Attempts < 1 || h.Attempts > 8 || h.SigningAdmissionCount < 1 || h.SigningAdmissionCount > 8 ||
		h.SigningAdmissionStaticBytes < 1 || h.SigningAdmissionStaticBytes > 80<<20 || h.SigningAdmissionOrdinaryBytes < 0 || h.SigningAdmissionOrdinaryBytes > 50<<20 || h.SigningAdmissionPlanBytes < 0 || h.SigningAdmissionPlanBytes > 8<<20 || h.SignatureFitReservedBytes < 0 || h.SignatureFitReservedBytes > 160<<20 || h.BaseBytesLimit < 0 || h.BaseBytesLimit > 50<<20 || h.DescriptorBytesLimit < 1 || h.DescriptorBytesLimit > 1<<20 || h.FinalPdfBytesLimit < 1 || h.FinalPdfBytesLimit > 50<<20 || h.FitsIndexBytesLimit < 1 || h.FitsIndexBytesLimit > 8<<20 || h.CertificatePdfBytesLimit < 1 || h.CertificatePdfBytesLimit > 8<<20 || h.CertificatePayloadBytesLimit < 1 || h.CertificatePayloadBytesLimit > 4<<20 || h.CertificateSignatureBytesLimit < 1 || h.CertificateSignatureBytesLimit > 256 || h.EventsBytesLimit < 1 || h.EventsBytesLimit > 4<<20 || h.VersionsBytesLimit < 1 || h.VersionsBytesLimit > 4<<20 || h.ArchiveManifestBytesLimit < 1 || h.ArchiveManifestBytesLimit > 1<<20 || h.ArchiveBudgetBytes < 1 || h.ArchiveBudgetBytes > 160<<20 || h.ProcessingBudgetBytes < 1 || h.ProcessingBudgetBytes > 50<<20 {
		return ApplicationBudgetV1{}, ErrApplicationAdmissionV1
	}
	for _, raw := range [][]byte{h.SourceSha256, h.StaticBasisSha256, h.StaticBasisBodySha256, h.GeometryPayloadSha256, h.GeometrySha256, h.FieldsSha256, h.PartiesSha256, h.RenderRecipeSha256, h.OrdinaryRecipeSha256, h.BrandingContextSha256} {
		if len(raw) != sha256.Size {
			return ApplicationBudgetV1{}, ErrApplicationAdmissionV1
		}
	}
	for _, pair := range [][2]int64{{h.StaticBasisBytes, MaxCanonicalBytesV1}, {h.GeometryBytes, MaxComponentBytesV1}, {h.GeometryPagesBytes, MaxComponentBytesV1}, {h.FieldsBytes, MaxComponentBytesV1}, {h.PartiesBytes, MaxComponentBytesV1}, {h.RenderRecipeBytes, MaxRenderRecipeBytesV1}, {h.OrdinaryRecipeBytes, 16 << 10}} {
		if pair[0] < 1 || pair[0] > pair[1] {
			return ApplicationBudgetV1{}, ErrApplicationAdmissionV1
		}
	}
	last := int32(0)
	for _, page := range h.ExpectedOrdinaryPages {
		if page <= last || page > h.SourcePages {
			return ApplicationBudgetV1{}, ErrApplicationAdmissionV1
		}
		last = page
	}
	components := h.GeometryBytes + h.GeometryPagesBytes + h.FieldsBytes + h.PartiesBytes + h.RenderRecipeBytes + h.OrdinaryRecipeBytes
	return ApplicationBudgetV1{Phase: "locked-basis", OrgID: s.OrgID, DocumentID: s.DocumentID, AdmissionID: s.AdmissionID, StoredBasisBytes: h.StaticBasisBytes, ComponentBytes: components, SourceBytes: h.SourceBytes, WorkingBytes: 16*(h.StaticBasisBytes+components) + (8 << 20)}, nil
}
func applicationCurrentV1(f *generated.GetPDFSigningAdmissionMetadataForUpdateV1Row, h *generated.GetPDFSigningAdmissionHeaderMetadataForUpdateV1Row) bool {
	return f != nil && f.CurrentBasis && !f.DocumentDeleted && f.ID == h.ID && f.OrgID == h.OrgID && f.DocumentID == h.DocumentID && f.Status == h.Status && f.DocumentStatus == h.DocumentStatus && f.OwnerID == h.OwnerID && applicationStampEqualV1(f.CeremonyEpoch, h.CeremonyEpoch) && applicationStampEqualV1(f.LeaseUntil, h.LeaseUntil) &&
		f.SourceStorageKey == h.SourceStorageKey && f.SourceVersionID == h.SourceVersionID && f.SourceBytes == h.SourceBytes && f.SourcePages == h.SourcePages && f.StaticBasisBytes == h.StaticBasisBytes &&
		bytes.Equal(f.SourceSha256, h.SourceSha256) && bytes.Equal(f.StaticBasisSha256, h.StaticBasisSha256) && bytes.Equal(f.StaticBasisBodySha256, h.StaticBasisBodySha256) && (f.Status == "sealed" || f.OwnerMatches)
}
func applicationBodyMetadataV1(m *generated.ListPDFSigningAdmissionBodyMetadataV1Row, c *ApplicationCandidateV1) bool {
	if m == nil || m.AdmissionID != c.scope.AdmissionID || m.OrgID != c.scope.OrgID || m.DocumentID != c.scope.DocumentID || m.Kind != "ordinary_page" || m.ContentType != "application/pdf" || m.Page < 1 || m.Page > c.header.SourcePages || m.Bytes < 1 || m.Bytes > ordinarypage.MaxPDFBytesV1 || m.PlanBytes < 1 || m.PlanBytes > ordinarypage.MaxPlanBytesV1 || m.CapturedOwnerID == uuid.Nil || !applicationStampV1(m.CapturedAt) || !bytes.Equal(m.StaticBasisSha256, c.header.StaticBasisSha256) {
		return false
	}
	for _, v := range [][]byte{m.Sha256, m.PlanSha256, m.PackageSha256, m.ReportSha256, m.InspectionSha256} {
		if len(v) != sha256.Size {
			return false
		}
	}
	found := false
	for _, page := range c.header.ExpectedOrdinaryPages {
		if page == m.Page {
			found = true
			break
		}
	}
	return found
}

// LoadCurrentV1 performs only the cheap bounded header query before TryAcquire.
// SQL JSON validation, canonical decoding and all original/component metadata
// retrieval follow successful admission. The returned candidate proves guarded
// immutable/current SQL consistency only; it is not reviewed UI, producer/worker
// origin, credential authority, a committed mutation or permission to sign.
func (a *ApplicationAdmissionV1) LoadCurrentV1(ctx context.Context, s ApplicationScopeV1) (result *ApplicationCandidateV1, err error) {
	if !a.valid() || !applicationContextV1(ctx) || !s.valid() {
		return nil, applicationErrorV1(ctx, nil)
	}
	h, err := a.queries.header(ctx, generated.GetPDFSigningAdmissionHeaderMetadataForUpdateV1Params{OwnerID: s.OwnerID, DocumentID: s.DocumentID, OrgID: s.OrgID, AdmissionID: s.AdmissionID})
	if err != nil || ctx.Err() != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	budget, err := applicationHeaderV1(h, s)
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	release, err := a.admit(ctx, budget)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	full, err := a.queries.current(ctx, generated.GetPDFSigningAdmissionMetadataForUpdateV1Params{OwnerID: s.OwnerID, DocumentID: s.DocumentID, OrgID: s.OrgID, AdmissionID: s.AdmissionID})
	if err != nil || ctx.Err() != nil || !applicationCurrentV1(full, h) {
		return nil, applicationErrorV1(ctx, err)
	}
	// Full validation observes the server clock after admission and all locks.
	// Preserve expired candidates for exact reads without stale hot-dispatch flags.
	latest := *h
	latest.LeaseUntil = full.LeaseUntil
	latest.LeaseCurrent = full.LeaseCurrent
	latest.OwnerMatches = full.OwnerMatches
	h = &latest
	raw, err := a.queries.basis(ctx, generated.ReadPDFSigningAdmissionBasisV1Params{AdmissionID: s.AdmissionID, OrgID: s.OrgID, DocumentID: s.DocumentID, StaticBasisSha256: h.StaticBasisSha256, ExpectedSha256: h.StaticBasisBodySha256, ExpectedBytes: h.StaticBasisBytes})
	defer clear(raw)
	if err != nil || ctx.Err() != nil || int64(len(raw)) != h.StaticBasisBytes || !bytes.Equal(applicationHashV1(raw), h.StaticBasisBodySha256) {
		return nil, applicationErrorV1(ctx, err)
	}
	b, err := DecodeV1(raw)
	if err != nil || b.SHA256() != s.StaticBasisSHA256 || b.input.OrgID != s.OrgID || b.input.DocumentID != s.DocumentID || !b.input.CeremonyEpoch.Equal(h.CeremonyEpoch.Time) || b.Source().Key != h.SourceStorageKey || b.Source().VersionID != h.SourceVersionID || b.Source().Bytes != h.SourceBytes || b.Source().SHA256 != hex.EncodeToString(h.SourceSha256) || len(b.input.Geometry.Pages) != int(h.SourcePages) || len(b.input.Fields) != int(h.FieldCount) {
		return nil, applicationErrorV1(ctx, err)
	}
	if len(b.input.Parties) != int(h.RequiredParties) || b.GeometryPagesSHA256() != hex.EncodeToString(h.GeometrySha256) || b.BrandingCSSSHA256() != hex.EncodeToString(h.BrandingContextSha256) || !bytes.Equal(b.ordinaryRecipe, ordinarypage.RecipeJSONV1()) {
		return nil, applicationErrorV1(ctx, nil)
	}
	components := []struct {
		kind string
		want []byte
		sha  []byte
		n    int64
	}{{"geometry", b.geometry, h.GeometryPayloadSha256, h.GeometryBytes}, {"geometry_pages", b.geometryPages, h.GeometrySha256, h.GeometryPagesBytes}, {"fields", b.fields, h.FieldsSha256, h.FieldsBytes}, {"parties", b.parties, h.PartiesSha256, h.PartiesBytes}, {"render_recipe", b.recipe, h.RenderRecipeSha256, h.RenderRecipeBytes}, {"ordinary_recipe", b.ordinaryRecipe, h.OrdinaryRecipeSha256, h.OrdinaryRecipeBytes}}
	for _, v := range components {
		if int64(len(v.want)) != v.n || !bytes.Equal(applicationHashV1(v.want), v.sha) {
			return nil, applicationErrorV1(ctx, nil)
		}
		original, readErr := a.queries.component(ctx, generated.ReadPDFSigningAdmissionComponentV1Params{Kind: v.kind, AdmissionID: s.AdmissionID, OrgID: s.OrgID, DocumentID: s.DocumentID, ExpectedSha256: v.sha, ExpectedBytes: v.n})
		same := int64(len(original)) == v.n && bytes.Equal(original, v.want)
		clear(original)
		if readErr != nil || ctx.Err() != nil || !same {
			return nil, applicationErrorV1(ctx, readErr)
		}
	}
	pages := b.ordinaryPages
	if len(pages) != len(h.ExpectedOrdinaryPages) {
		return nil, applicationErrorV1(ctx, nil)
	}
	for i, p := range pages {
		if int32(p) != h.ExpectedOrdinaryPages[i] {
			return nil, applicationErrorV1(ctx, nil)
		}
	}
	c := &ApplicationCandidateV1{issuer: a.issuer, cleanupDone: a.cleanupDone, fence: a.fence, scope: s, basis: b, header: h, release: release}
	rows, err := a.queries.originals(ctx, generated.ListPDFSigningAdmissionBodyMetadataV1Params{AdmissionID: s.AdmissionID, OrgID: s.OrgID, DocumentID: s.DocumentID})
	if err != nil || ctx.Err() != nil || len(rows) > len(pages) || len(rows) > 500 {
		return nil, applicationErrorV1(ctx, err)
	}
	c.originals = make(map[int]generated.ListPDFSigningAdmissionBodyMetadataV1Row, len(rows))
	var pdfTotal, planTotal int64
	for _, m := range rows {
		if !applicationBodyMetadataV1(m, c) {
			return nil, applicationErrorV1(ctx, nil)
		}
		if _, exists := c.originals[int(m.Page)]; exists {
			return nil, applicationErrorV1(ctx, nil)
		}
		c.originals[int(m.Page)] = *m
		pdfTotal += m.Bytes
		planTotal += m.PlanBytes
	}
	if pdfTotal > h.BaseBytesLimit || planTotal > 8<<20 || (h.Status != "staging" && len(rows) != len(pages)) {
		return nil, applicationErrorV1(ctx, nil)
	}
	if ctx.Err() != nil {
		return nil, applicationErrorV1(ctx, ctx.Err())
	}
	transferred = true
	return c, nil
}

type ApplicationOriginalV1 struct {
	issuer    *applicationIssuerV1
	scope     ApplicationScopeV1
	metadata  generated.ListPDFSigningAdmissionBodyMetadataV1Row
	fence     *applicationSessionFenceV1
	mu        sync.Mutex
	pdf, plan []byte
	release   func()
	closed    bool
}

func (o *ApplicationOriginalV1) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	o.closed = true
	clear(o.pdf)
	clear(o.plan)
	o.pdf = nil
	o.plan = nil
	r := o.release
	o.release = nil
	o.mu.Unlock()
	if r != nil {
		r()
	}
}

// WithOriginalV1 is a synchronous immutable borrow. Do not retain either slice,
// mutate it, send it asynchronously or copy it without separate caller admission.
func (o *ApplicationOriginalV1) WithOriginalV1(consume func(pdf, plan []byte) error) error {
	if o == nil || consume == nil {
		return ErrApplicationAdmissionV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.release == nil {
		return ErrApplicationAdmissionV1
	}
	if err := consume(o.pdf, o.plan); err != nil {
		return applicationErrorV1(nil, err)
	}
	return nil
}
func (a *ApplicationAdmissionV1) LoadOriginalV1(ctx context.Context, c *ApplicationCandidateV1, page int) (*ApplicationOriginalV1, error) {
	if !a.valid() || !applicationContextV1(ctx) || c == nil {
		return nil, applicationErrorV1(ctx, nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.release == nil || c.issuer != a.issuer {
		return nil, applicationErrorV1(ctx, nil)
	}
	m, ok := c.originals[page]
	if !ok {
		return nil, applicationErrorV1(ctx, nil)
	}
	budget := ApplicationBudgetV1{Phase: "locked-original-read", OrgID: c.scope.OrgID, DocumentID: c.scope.DocumentID, AdmissionID: c.scope.AdmissionID, OriginalPDFBytes: m.Bytes, OriginalPlanBytes: m.PlanBytes, WorkingBytes: 4*(m.Bytes+m.PlanBytes) + (8 << 20)}
	release, err := a.admit(ctx, budget)
	if err != nil {
		return nil, err
	}
	transferred := false
	var pdf, plan []byte
	defer func() {
		if !transferred {
			clear(pdf)
			clear(plan)
			release()
		}
	}()
	pdf, err = a.queries.body(ctx, generated.ReadPDFSigningAdmissionBodyV1Params{AdmissionID: c.scope.AdmissionID, OrgID: c.scope.OrgID, DocumentID: c.scope.DocumentID, Page: int32(page), ExpectedSha256: m.Sha256, ExpectedBytes: m.Bytes})
	if err != nil || ctx.Err() != nil || int64(len(pdf)) != m.Bytes || !bytes.Equal(applicationHashV1(pdf), m.Sha256) {
		return nil, applicationErrorV1(ctx, err)
	}
	plan, err = a.queries.plan(ctx, generated.ReadPDFSigningAdmissionPlanV1Params{AdmissionID: c.scope.AdmissionID, OrgID: c.scope.OrgID, DocumentID: c.scope.DocumentID, Page: int32(page), ExpectedSha256: m.PlanSha256, ExpectedBytes: m.PlanBytes})
	if err != nil || ctx.Err() != nil || int64(len(plan)) != m.PlanBytes || !bytes.Equal(applicationHashV1(plan), m.PlanSha256) {
		return nil, applicationErrorV1(ctx, err)
	}
	plans, err := OrdinaryPlansV1(c.basis)
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
	if err != nil || !bytes.Equal(plan, expected) || ctx.Err() != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	transferred = true
	return &ApplicationOriginalV1{issuer: a.issuer, scope: c.scope, metadata: applicationColdMetadataCloneV1(m), fence: a.fence, pdf: pdf, plan: plan, release: release}, nil
}
