// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrSignerPackageMemberReadV1 = errors.New("pdfadmission: owned captured package PDF unavailable")
var ErrSignerPackageMemberPreconditionV1 = errors.New("pdfadmission: captured package observation changed")
var ErrSignerPackageMemberAbsentV1 = errors.New("pdfadmission: captured package member absent")

// Observations only. Scope and every storage pin come from the original reader.
type SignerPackageMemberExpectedV1 struct {
	Position                              int32
	ManifestSHA256, LegalCommitmentSHA256 [sha256.Size]byte
}
type SignerPackageMemberPDFMetadataV1 struct {
	Observation SignerPackageReadObservationV1
	Position    int32
	PDFSHA256   string
	PDFBytes    int64
	PDFPages    int32
}

type ApplicationSignerPackageMemberReadV1 struct {
	state *applicationSignerPackageMemberReadStateV1
}
type applicationSignerPackageMemberReadStateV1 struct {
	mu                                                                               sync.Mutex
	self                                                                             *applicationSignerPackageMemberReadStateV1
	factory                                                                          *ApplicationSessionFactoryV1
	reader                                                                           *ApplicationSignerReaderV1
	ctx                                                                              context.Context
	cancel                                                                           context.CancelFunc
	scope                                                                            applicationSignerScopeSnapshotV1
	expected                                                                         SignerPackageMemberExpectedV1
	profile                                                                          applicationSignerPackageProfileV1
	completed                                                                        applicationCompletedPackagePinsV1
	originalSentAt, originalNoticeEpoch, originalDocumentExpiry, originalTokenExpiry pgtype.Timestamptz
	originalRootSHA                                                                  [sha256.Size]byte
	namespace                                                                        [sha256.Size]byte
	client                                                                           *storage.Client
	release                                                                          func()
	operation                                                                        *ApplicationHTMLSendOperationV1
	current                                                                          *ApplicationHTMLSendSQLStageV1
	provider                                                                         *storage.PackagePDFLocalReadV1
	pin                                                                              applicationSignerPackageMemberPinV1
	slot, phase, active                                                              int
	originalBorrow, attempted, loaded, delivered, closed, retired, reconciling       bool
}

// A finite constructor installs its grant before native state allocation or
// original-reader borrowing. Ordinary public-shell copies share this one owner.
func (f *ApplicationSessionFactoryV1) NewSignerPackageMemberReadV1(ctx context.Context, r *ApplicationSignerReaderV1, client *storage.Client, expected SignerPackageMemberExpectedV1) (*ApplicationSignerPackageMemberReadV1, error) {
	return f.newSignerPackageMemberReadV1(ctx, r, client, expected, signerPackageActiveProfileV1)
}
func (f *ApplicationSessionFactoryV1) NewCompletedSignerPackageMemberReadV1(ctx context.Context, r *ApplicationSignerReaderV1, client *storage.Client, expected SignerPackageMemberExpectedV1) (*ApplicationSignerPackageMemberReadV1, error) {
	return f.newSignerPackageMemberReadV1(ctx, r, client, expected, signerPackageCompletedProfileV1)
}
func (f *ApplicationSessionFactoryV1) newSignerPackageMemberReadV1(ctx context.Context, r *ApplicationSignerReaderV1, client *storage.Client, expected SignerPackageMemberExpectedV1, profile applicationSignerPackageProfileV1) (*ApplicationSignerPackageMemberReadV1, error) {
	if f == nil || f.state == nil || r == nil || r.self != r || !applicationContextV1(ctx) || expected.Position < 0 || expected.Position > documentpackage.MaxAnnexesV1 {
		return nil, ErrSignerPackageMemberReadV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, ErrSignerPackageMemberReadV1
	}
	namespace, err := client.PackageEvidenceNamespaceV1()
	if err != nil || namespace == ([32]byte{}) {
		return nil, errors.Join(ErrSignerPackageMemberReadV1, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factory != f || r.consumerClosed || r.released || r.creating || !r.read || r.mode != profile.readerModeV1() || profile.readerModeV1() == "" || r.finishScope == nil || r.models == nil || r.models.Document == nil || r.models.Recipient == nil || r.session == nil || !r.session.RetiredV1() {
		return nil, ErrSignerPackageMemberReadV1
	}
	d, recipient := r.models.Document, r.models.Recipient
	if d.ID != r.scope.document || d.OrgID != r.scope.org || recipient.ID != r.scope.recipient || recipient.DocumentID != r.scope.document || recipient.DocOrgID != r.scope.org || (profile == signerPackageActiveProfileV1 && len(d.PdfSha256) != sha256.Size) || !applicationStampV1(d.SentAt) || !applicationStampEqualV1(d.SentAt, d.Article13NoticeEpochAt) || !d.Article13NoticeEpochV61Committed || !applicationStampV1(recipient.MagicTokenExpiresAt) || !time.Now().Before(recipient.MagicTokenExpiresAt.Time) || (profile == signerPackageActiveProfileV1 && d.ExpiresAt.Valid && (!applicationStampV1(d.ExpiresAt) || !time.Now().Before(d.ExpiresAt.Time))) {
		return nil, ErrSignerReadCredentialV1
	}
	var completed applicationCompletedPackagePinsV1
	if profile == signerPackageCompletedProfileV1 {
		var err error
		completed, err = completedPackagePinsV1(d)
		if err != nil {
			return nil, err
		}
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	_, registered := p.signerReaders[r]
	slot := -1
	for i, existing := range p.signerPackageMemberReads {
		if existing == nil {
			slot = i
			break
		}
	}
	if !registered || p.closing || p.work == nil || p.work.coordinator == nil || slot < 0 {
		return nil, ErrSignerPackageMemberReadV1
	}
	// Two concrete stages/Work/header controls plus bounded selected key/version
	// and metadata copies. Variable capture and provider bodies buy separate loans.
	cost := int64(131072) + 16*int64(unsafe.Sizeof(applicationSignerPackageMemberReadStateV1{})) + 16*int64(unsafe.Sizeof(ApplicationHTMLSendOperationV1{})) + 16*int64(unsafe.Sizeof(ApplicationHTMLSendSQLStageV1{})) + 16*int64(unsafe.Sizeof(ApplicationHTMLSendWorkV1{})) + 64*int64(documentpackage.MaxObjectTextBytesV1)
	release, err := p.work.acquire(ctx, r.scope.org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		return nil, errors.Join(ErrSignerPackageMemberReadV1, err)
	}
	call, cancel := context.WithCancel(ctx)
	if profile == signerPackageCompletedProfileV1 {
		cancel()
		call, cancel = context.WithDeadline(ctx, recipient.MagicTokenExpiresAt.Time)
	}
	s := &applicationSignerPackageMemberReadStateV1{factory: f, reader: r, ctx: call, cancel: cancel, scope: r.scope, expected: expected, profile: profile, completed: completed.cloneV1(), originalSentAt: d.SentAt, originalNoticeEpoch: d.Article13NoticeEpochAt, originalDocumentExpiry: d.ExpiresAt, originalTokenExpiry: recipient.MagicTokenExpiresAt, namespace: namespace, client: client, release: release, slot: slot, originalBorrow: true}
	copy(s.originalRootSHA[:], d.PdfSha256)
	s.self = s
	r.packageMemberBorrowers++
	p.signerPackageMemberReads[slot] = s
	return &ApplicationSignerPackageMemberReadV1{state: s}, nil
}

func (h *ApplicationSignerPackageMemberReadV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.self != s {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	provider, op := s.provider, s.operation
	s.mu.Unlock()
	if provider != nil {
		provider.CloseConsumerV1()
	}
	if op != nil {
		op.EndConsumerV1()
	}
}
func (h *ApplicationSignerPackageMemberReadV1) CloseV1(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if h.state == nil || h.state.self != h.state || !applicationContextV1(ctx) {
		return ErrSignerPackageMemberReadV1
	}
	h.CloseConsumerV1()
	return h.state.reconcileV1(ctx)
}
func (h *ApplicationSignerPackageMemberReadV1) RetiredV1() bool {
	if h == nil || h.state == nil {
		return true
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.self == s && s.retired
}

// Reconciliation never waits for the original reader: this owner is its borrower.
// The native recursion guard handles operation.Close -> factory.Reconcile.
func (s *applicationSignerPackageMemberReadStateV1) reconcileV1(ctx context.Context) error {
	if s == nil || s.self != s || !applicationContextV1(ctx) {
		return ErrSignerPackageMemberReadV1
	}
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		return nil
	}
	if s.reconciling {
		s.mu.Unlock()
		return ErrApplicationSessionUnknownV1
	}
	if !s.closed {
		s.mu.Unlock()
		return nil
	}
	if s.active != 0 {
		s.mu.Unlock()
		return ErrApplicationSessionUnknownV1
	}
	s.reconciling = true
	provider, op := s.provider, s.operation
	s.mu.Unlock()
	retiredHere := false
	defer func() {
		if !retiredHere {
			s.mu.Lock()
			s.reconciling = false
			s.mu.Unlock()
		}
	}()
	var failure error
	if op != nil {
		op.EndConsumerV1()
		failure = op.CloseV1(ctx)
	}
	if provider != nil {
		provider.CloseConsumerV1()
		if !provider.RetiredV1() {
			failure = errors.Join(failure, ErrApplicationSessionUnknownV1)
		}
	}
	if failure != nil {
		return failure
	}
	p := s.factory.state
	p.mu.Lock()
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil
	}
	if s.active != 0 || !s.closed || p.signerPackageMemberReads[s.slot] != s {
		s.mu.Unlock()
		p.mu.Unlock()
		return ErrApplicationSessionUnknownV1
	}
	reader, borrowed := s.reader, s.originalBorrow
	s.originalBorrow = false
	s.mu.Unlock()
	p.mu.Unlock()
	if borrowed && reader != nil {
		reader.mu.Lock()
		reader.packageMemberBorrowers--
		consumers := reader.retireBlockSigningReadConsumersV1()
		reader.mu.Unlock()
		for _, close := range consumers {
			close()
		}
	}
	p.mu.Lock()
	s.mu.Lock()
	release := s.release
	s.release = nil
	s.reader = nil
	s.provider = nil
	s.operation = nil
	s.current = nil
	s.client = nil
	s.pin = applicationSignerPackageMemberPinV1{}
	// Publish retirement and registry absence only after the actual grant closes.
	if release != nil {
		release()
	}
	s.reconciling = false
	s.retired = true
	p.signerPackageMemberReads[s.slot] = nil
	retiredHere = true
	s.mu.Unlock()
	p.mu.Unlock()
	return nil
}
func (f *ApplicationSessionFactoryV1) reconcileSignerPackageMemberReadsV1(ctx context.Context) error {
	p := f.state
	p.mu.Lock()
	list := p.signerPackageMemberReads
	p.mu.Unlock()
	var out error
	for _, s := range list {
		if s != nil {
			out = errors.Join(out, s.reconcileV1(ctx))
		}
	}
	return out
}
