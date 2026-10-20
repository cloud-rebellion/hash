// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrHTMLRevisionReadV1 = errors.New("pdfadmission: owned HTML revision read unavailable")

type HTMLRevisionReadAccessV1 struct {
	DocumentID, OrgID, SenderID            uuid.UUID
	UpdatedAt, ExpiresAt                   pgtype.Timestamptz
	Draft, ChangesRequested, HasHTMLSource bool
}
type HTMLRevisionReadModelsV1 struct {
	Document *generated.Document
	Current  *htmlmaterialization.CurrentReadProjectionV1
}

// This source snapshot is private, captured under the actual body loan before
// exposing mutable application models. No caller can supply or replace it.
// Source expansion helpers must verify owner.self/owner.snapshot identity and
// purpose, then derive their own inputs from these actual retained bytes.
type applicationHTMLRevisionSourceSnapshotV1 struct {
	owner    *ApplicationHTMLRevisionReaderV1
	document *generated.Document
	current  *htmlmaterialization.CurrentReadProjectionV1
}

type ApplicationHTMLRevisionReaderV1 struct {
	mu                                          sync.Mutex
	self                                        *ApplicationHTMLRevisionReaderV1
	session                                     *ApplicationSessionV1
	authoring                                   *ApplicationHTMLAuthoringReaderV1
	queries                                     *generated.Queries
	packageBinding                              *applicationDocumentPackageReadBindingV1
	snapshot                                    *applicationHTMLRevisionSourceSnapshotV1
	models                                      *HTMLRevisionReadModelsV1
	closeConsumers                              []func()
	packageInventoryRead                        bool
	documentAIShared                            bool
	sourceBorrowers                             int
	read, bodyComplete, closed, resourcesClosed bool
	fieldCurrentDeferred, fieldCurrentAttempted bool
}

func (h *ApplicationSessionV1) NewHTMLRevisionReaderV1(ctx context.Context) (*ApplicationHTMLRevisionReaderV1, error) {
	actor, err := h.NewHTMLAuthoringReaderV1(ctx)
	if err != nil {
		return nil, errors.Join(ErrHTMLRevisionReadV1, err)
	}
	r := &ApplicationHTMLRevisionReaderV1{session: h, authoring: actor, queries: generated.New(&applicationOwnedDBTXV1{session: h.state})}
	r.self = r
	return r, nil
}
func (r *ApplicationHTMLRevisionReaderV1) valid(ctx context.Context) bool {
	return r != nil && r.self == r && !r.closed && r.session != nil && r.session.state != nil && r.authoring != nil && r.authoring.valid(ctx) && r.queries != nil && (r.packageBinding == nil || r.packageBinding.validV1(ctx, r))
}

// ReadDocumentV1 owns real M94 parent/cache header -> fixed actor/state/CAS
// preflight -> same-session sixJSON/current12 body loan and exact projection.
// The fixed caller still runs ALL original live actor/credential/evidence/DSR,
// source/current/parties/SigningPage checks; this method grants no mutation.
func (r *ApplicationHTMLRevisionReaderV1) ReadDocumentV1(ctx context.Context, user uuid.UUID, preflight func(HTMLRevisionReadAccessV1) error) (*HTMLRevisionReadModelsV1, error) {
	return r.readDocumentV1(ctx, user, preflight, nil)
}

// ReadDocumentWithActorV1 adds the fixed original actor/credential policy stage
// under the genuine actor loan, before document cache/body refusal. A nil gate
// is refused; the compatibility read method above grants no mutation policy.
func (r *ApplicationHTMLRevisionReaderV1) ReadDocumentWithActorV1(ctx context.Context, user uuid.UUID, preflight func(HTMLRevisionReadAccessV1) error, actorGate func(HTMLRevisionReadAccessV1, *generated.User) error) (*HTMLRevisionReadModelsV1, error) {
	if actorGate == nil {
		return nil, ErrHTMLRevisionReadV1
	}
	return r.readDocumentV1(ctx, user, preflight, actorGate)
}
func (r *ApplicationHTMLRevisionReaderV1) readDocumentV1(ctx context.Context, user uuid.UUID, preflight func(HTMLRevisionReadAccessV1) error, actorGate func(HTMLRevisionReadAccessV1, *generated.User) error) (*HTMLRevisionReadModelsV1, error) {
	return r.readDocumentBodyV1(ctx, user, preflight, actorGate, false)
}

// participant is selected only by the actual opaque signer-scope workflow below;
// it is never public caller authority or a substituted application user.
func (r *ApplicationHTMLRevisionReaderV1) readDocumentBodyV1(ctx context.Context, user uuid.UUID, preflight func(HTMLRevisionReadAccessV1) error, actorGate func(HTMLRevisionReadAccessV1, *generated.User) error, participant bool) (*HTMLRevisionReadModelsV1, error) {
	return r.readDocumentBodyModeV1(ctx, user, preflight, actorGate, participant, false)
}

func (r *ApplicationHTMLRevisionReaderV1) readDocumentBodyModeV1(ctx context.Context, user uuid.UUID, preflight func(HTMLRevisionReadAccessV1) error, actorGate func(HTMLRevisionReadAccessV1, *generated.User) error, participant, deferCurrent bool) (*HTMLRevisionReadModelsV1, error) {
	if r == nil || r.self != r || preflight == nil || (user == uuid.Nil && !participant) {
		return nil, ErrHTMLRevisionReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || r.read {
		return nil, ErrHTMLRevisionReadV1
	}
	r.read = true
	s := r.session.state
	document := s.document
	var h *generated.GetHTMLRevisionDocumentReadHeaderV1Row
	var err error
	if r.packageBinding != nil {
		document, h = r.packageBinding.document, r.packageBinding.header
	} else if r.documentAIShared {
		var shared *generated.GetDocumentAIReadHeaderV1Row
		shared, err = r.queries.GetDocumentAIReadHeaderV1(ctx, generated.GetDocumentAIReadHeaderV1Params{DocumentID: document, OrgID: s.org})
		h = (*generated.GetHTMLRevisionDocumentReadHeaderV1Row)(shared)
	} else {
		h, err = r.queries.GetHTMLRevisionDocumentReadHeaderV1(ctx, generated.GetHTMLRevisionDocumentReadHeaderV1Params{DocumentID: document, OrgID: s.org})
	}
	if err != nil {
		return nil, err
	}
	if h == nil || h.ID != document || h.OrgID != s.org || h.ServerVersionNum <= 0 || !h.UpdatedAt.Valid {
		return nil, ErrHTMLRevisionReadV1
	}
	access := HTMLRevisionReadAccessV1{DocumentID: h.ID, OrgID: h.OrgID, SenderID: h.SenderID, UpdatedAt: h.UpdatedAt, ExpiresAt: h.ExpiresAt, Draft: h.IsDraft, ChangesRequested: h.IsChangesRequested, HasHTMLSource: h.HasHtmlSource}
	if err = preflight(access); err != nil {
		return nil, err
	}
	// Parent-first actual user header/body loan preserves the original lock
	// direction. Original authoring guard reads/rechecks this same user later.
	if participant {
		// The original authenticated recipient has no organization User. Its actual
		// scope is rechecked by the workflow and full locked credential policy.
	} else if actorGate != nil {
		if err = r.readLockedActorV1(ctx, user, access, actorGate); err != nil {
			return nil, err
		}
	} else {
		if err = r.authoring.AcquireActorV1(ctx, s.org, user, false); err != nil {
			return nil, errors.Join(ErrHTMLRevisionReadV1, err)
		}
	}
	if !r.valid(ctx) || h.PolicyMeasurementServerVersionNum != h.ServerVersionNum || h.ResponseMeasurementServerVersionNum != h.ServerVersionNum || h.ReportMeasurementServerVersionNum != h.ServerVersionNum {
		return nil, ErrHTMLRevisionReadV1
	}
	wire, err := htmlAuthoringSumV1(h.HtmlOriginWireBytes, h.HtmlCurrentWireBytes, h.VariablesWireBytes, h.BlocksWireBytes, h.MetadataWireBytes, h.ReportWireBytes)
	if err != nil {
		return nil, ErrHTMLRevisionReadV1
	}
	raw := h.RawTextBytes
	var mh *generated.GetSignerCurrentMaterializationHeaderV1Row
	if h.HtmlCurrentWireBytes > 0 && !deferCurrent {
		mh, err = r.queries.GetSignerCurrentMaterializationHeaderV1(ctx, generated.GetSignerCurrentMaterializationHeaderV1Params{DocumentID: document, OrgID: s.org})
		if err != nil {
			return nil, err
		}
		if mh == nil || mh.DocumentID != document || mh.OrgID != s.org || mh.MaterializationID == uuid.Nil || mh.SourceWireBytes != h.HtmlCurrentWireBytes || mh.MeasurementServerVersionNum != h.ServerVersionNum || mh.ServerVersionNum != h.ServerVersionNum || (mh.ReportWireUpperBound != 0 && mh.ReportWireUpperBound != 65536) {
			return nil, ErrHTMLRevisionReadV1
		}
		raw, err = htmlAuthoringSumV1(raw, mh.RawTextBytes)
		if err != nil {
			return nil, ErrHTMLRevisionReadV1
		}
		wire, err = htmlAuthoringSumV1(wire, mh.SourceWireBytes, mh.ReportWireUpperBound)
		if err != nil {
			return nil, ErrHTMLRevisionReadV1
		}
	}
	closeBody, err := r.authoring.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return nil, errors.Join(ErrHTMLRevisionReadV1, err)
	}
	r.closeConsumers = append(r.closeConsumers, closeBody)
	doc, err := r.queries.ReadSignerDocumentV1(ctx, generated.ReadSignerDocumentV1Params{DocumentID: document, OrgID: s.org, ExpectedUpdatedAt: h.UpdatedAt, ExpectedHtmlOriginWireBytes: h.HtmlOriginWireBytes, ExpectedHtmlCurrentWireBytes: h.HtmlCurrentWireBytes, ExpectedVariablesWireBytes: h.VariablesWireBytes, ExpectedBlocksWireBytes: h.BlocksWireBytes, ExpectedMetadataWireBytes: h.MetadataWireBytes, ExpectedReportWireBytes: h.ReportWireBytes})
	if err != nil {
		return nil, err
	}
	if doc == nil || doc.ID != document || doc.OrgID != s.org || doc.UpdatedAt != h.UpdatedAt || signerDocumentRawBytesV1(doc) != h.RawTextBytes || int64(len(doc.HtmlSourceJson)) != h.HtmlOriginWireBytes || int64(len(doc.HtmlCurrentSourceJson)) != h.HtmlCurrentWireBytes || int64(len(doc.VariablesJson)) != h.VariablesWireBytes || int64(len(doc.BlocksJson)) != h.BlocksWireBytes || int64(len(doc.Metadata)) != h.MetadataWireBytes || int64(len(doc.MetadataRedactionReport)) != h.ReportWireBytes {
		return nil, ErrHTMLRevisionReadV1
	}
	var current *htmlmaterialization.CurrentReadProjectionV1
	if mh != nil {
		m, err := r.queries.ReadSignerCurrentMaterializationV1(ctx, generated.ReadSignerCurrentMaterializationV1Params{DocumentID: document, OrgID: s.org, ExpectedMaterializationID: mh.MaterializationID, ExpectedSourceWireBytes: mh.SourceWireBytes, ExpectedRawTextBytes: mh.RawTextBytes, ExpectedReportWireUpperBound: mh.ReportWireUpperBound})
		if err != nil {
			return nil, err
		}
		if m == nil || m.ID != mh.MaterializationID || m.DocumentID != document || m.OrgID != s.org || !doc.HtmlCurrentMaterializationID.Valid || uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) != m.ID || int64(len(m.SourceJson)) != mh.SourceWireBytes || int64(len(m.MetadataRedactionReport)) > mh.ReportWireUpperBound || signerMaterializationRawBytesV1(m) != mh.RawTextBytes {
			return nil, ErrHTMLRevisionReadV1
		}
		current = &htmlmaterialization.CurrentReadProjectionV1{ID: m.ID, DocumentID: m.DocumentID, OrgID: m.OrgID, Sequence: m.Sequence, PageCount: m.PageCount, PdfKey: m.PdfKey, PdfVersionID: m.PdfVersionID, PdfSha256: m.PdfSha256, SourceCommitment: m.SourceCommitment, OriginCommitment: m.OriginCommitment, SourceJson: m.SourceJson, MetadataRedactionReport: m.MetadataRedactionReport}
	}
	// Private and exposed copies coexist under this same actual body loan. All
	// variable fields are detached; callback mutation cannot replace source pins.
	r.snapshot = &applicationHTMLRevisionSourceSnapshotV1{owner: r, document: htmlRevisionCloneDocumentV1(doc), current: htmlRevisionCloneCurrentV1(current)}
	r.models = &HTMLRevisionReadModelsV1{Document: doc, Current: current}
	r.bodyComplete = true
	r.fieldCurrentDeferred = deferCurrent
	if ctx.Err() != nil {
		return nil, ErrHTMLRevisionReadV1
	}
	return r.models, nil
}

// Called with r.mu held, inside this same native WithTx callback. The scalar
// actor header is taken before any full User body. The trusted fixed caller's
// original role/credential refusal then precedes missing document body caches.
// This callback creates no authorization receipt or mutation permission here.
func (r *ApplicationHTMLRevisionReaderV1) readLockedActorV1(ctx context.Context, user uuid.UUID, access HTMLRevisionReadAccessV1, gate func(HTMLRevisionReadAccessV1, *generated.User) error) error {
	s := r.session.state
	header, err := r.queries.GetHTMLAuthoringActorHeaderV1(ctx, generated.GetHTMLAuthoringActorHeaderV1Params{UserID: user, OrgID: s.org})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if refusal := gate(access, nil); refusal != nil {
				return refusal
			}
		}
		return errors.Join(ErrHTMLRevisionReadV1, err)
	}
	if header == nil || header.UserID != user || header.OrgID != s.org || header.RawTextBytes < 0 {
		return ErrHTMLRevisionReadV1
	}
	closeActor, err := r.authoring.acquireOwnedRetainedBodyV1(ctx, header.RawTextBytes, 0)
	if err != nil {
		return errors.Join(ErrHTMLRevisionReadV1, err)
	}
	r.closeConsumers = append(r.closeConsumers, closeActor)
	member, err := r.queries.GetUserForShare(ctx, generated.GetUserForShareParams{ID: user, OrgID: s.org})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if refusal := gate(access, nil); refusal != nil {
				return refusal
			}
		}
		return errors.Join(ErrHTMLRevisionReadV1, err)
	}
	if member == nil || member.ID != user || member.OrgID != s.org {
		return ErrHTMLRevisionReadV1
	}
	subjectBytes := int64(0)
	if member.ZitadelSub.Valid {
		subjectBytes = int64(len(member.ZitadelSub.String))
	}
	raw, err := htmlAuthoringSumV1(int64(len(member.Email)), int64(len(member.Name)), int64(len(member.Role)), subjectBytes)
	if err != nil || raw != header.RawTextBytes {
		return ErrHTMLRevisionReadV1
	}
	// Keep the actual locked row immutable even if a callback overwrites its copy.
	copy := *member
	if err = gate(access, &copy); err != nil {
		return err
	}
	if !r.valid(ctx) {
		return ErrHTMLRevisionReadV1
	}
	return nil
}

// borrowHTMLRevisionSourceV1 mints a private original-body borrower. The source
// owner must keep it through its actual active CPU+route last use. No external
// callback/close flag or another reader can create or end this borrower.
func (r *ApplicationHTMLRevisionReaderV1) borrowHTMLRevisionSourceV1(ctx context.Context) (*applicationHTMLRevisionSourceSnapshotV1, func(), error) {
	if r == nil || r.self != r || !applicationContextV1(ctx) {
		return nil, nil, ErrHTMLRevisionReadV1
	}
	r.mu.Lock()
	if r.closed || r.resourcesClosed || r.snapshot == nil || r.snapshot.owner != r || !r.read || !r.bodyComplete || r.session == nil || r.session.state == nil || r.authoring == nil || len(r.closeConsumers) == 0 {
		r.mu.Unlock()
		return nil, nil, ErrHTMLRevisionReadV1
	}
	s := r.session.state
	a := s.admission
	if s.factory == nil || s.factory.work == nil || s.factory.work.coordinator == nil || a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone || r.snapshot.document == nil || r.snapshot.document.ID != r.logicalDocumentV1() || r.snapshot.document.OrgID != s.org {
		r.mu.Unlock()
		return nil, nil, ErrHTMLRevisionReadV1
	}
	r.sourceBorrowers++
	snapshot := r.snapshot
	r.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			r.mu.Lock()
			r.sourceBorrowers--
			closes, actor := r.retireResourcesLockedV1()
			r.mu.Unlock()
			htmlRevisionCloseConsumersV1(closes, actor)
		})
	}
	return snapshot, release, nil
}

// Caller holds r.mu. Source bytes are dropped only after original route Close
// AND every actual source consumer/call has joined. Context cancel is not join.
func (r *ApplicationHTMLRevisionReaderV1) retireResourcesLockedV1() ([]func(), *ApplicationHTMLAuthoringReaderV1) {
	if !r.closed || r.resourcesClosed || r.sourceBorrowers != 0 {
		return nil, nil
	}
	r.resourcesClosed = true
	r.snapshot = nil
	r.models = nil
	closes := r.closeConsumers
	r.closeConsumers = nil
	actor := r.authoring
	r.authoring = nil
	return closes, actor
}
func htmlRevisionCloseConsumersV1(closes []func(), actor *ApplicationHTMLAuthoringReaderV1) {
	for _, close := range closes {
		close()
	}
	if actor != nil {
		actor.CloseConsumerV1()
	}
}
func (r *ApplicationHTMLRevisionReaderV1) CloseConsumerV1() {
	if r == nil || r.self != r {
		return
	}
	r.mu.Lock()
	r.closed = true
	closes, actor := r.retireResourcesLockedV1()
	r.mu.Unlock()
	htmlRevisionCloseConsumersV1(closes, actor)
}

func htmlRevisionCloneDocumentV1(in *generated.Document) *generated.Document {
	if in == nil {
		return nil
	}
	out := *in
	out.Name = strings.Clone(in.Name)
	out.Status = strings.Clone(in.Status)
	out.RoutingMode = strings.Clone(in.RoutingMode)
	out.SourceKind = strings.Clone(in.SourceKind)
	out.BlocksJson = bytes.Clone(in.BlocksJson)
	out.VariablesJson = bytes.Clone(in.VariablesJson)
	out.RenderedPdfKey.String = strings.Clone(in.RenderedPdfKey.String)
	out.RenderedPdfSha = bytes.Clone(in.RenderedPdfSha)
	out.PdfStorageKey.String = strings.Clone(in.PdfStorageKey.String)
	out.PdfSha256 = bytes.Clone(in.PdfSha256)
	out.FinalPdfKey.String = strings.Clone(in.FinalPdfKey.String)
	out.FinalPdfSha = bytes.Clone(in.FinalPdfSha)
	out.AuditCertKey.String = strings.Clone(in.AuditCertKey.String)
	out.Metadata = bytes.Clone(in.Metadata)
	out.MetadataRedactionReport = bytes.Clone(in.MetadataRedactionReport)
	out.RoutingTier = strings.Clone(in.RoutingTier)
	out.BilingualTargetLang = strings.Clone(in.BilingualTargetLang)
	out.LawfulBasis = strings.Clone(in.LawfulBasis)
	out.DefaultLocale = strings.Clone(in.DefaultLocale)
	out.AuditPayloadKey.String = strings.Clone(in.AuditPayloadKey.String)
	out.AuditPayloadSha256 = bytes.Clone(in.AuditPayloadSha256)
	out.AuditSignatureKey.String = strings.Clone(in.AuditSignatureKey.String)
	out.AuditSignatureSha256 = bytes.Clone(in.AuditSignatureSha256)
	out.PdfStorageVersionID.String = strings.Clone(in.PdfStorageVersionID.String)
	out.RenderedPdfVersionID.String = strings.Clone(in.RenderedPdfVersionID.String)
	out.FinalPdfVersionID.String = strings.Clone(in.FinalPdfVersionID.String)
	out.AuditCertSha256 = bytes.Clone(in.AuditCertSha256)
	out.AuditCertVersionID.String = strings.Clone(in.AuditCertVersionID.String)
	out.AuditPayloadVersionID.String = strings.Clone(in.AuditPayloadVersionID.String)
	out.AuditSignatureVersionID.String = strings.Clone(in.AuditSignatureVersionID.String)
	out.Article13NoticeSchema = strings.Clone(in.Article13NoticeSchema)
	out.HtmlSourceJson = bytes.Clone(in.HtmlSourceJson)
	out.HtmlReviewedPdfSha256 = bytes.Clone(in.HtmlReviewedPdfSha256)
	out.HtmlCurrentSourceJson = bytes.Clone(in.HtmlCurrentSourceJson)
	out.HtmlEffectiveSourceCommitment.String = strings.Clone(in.HtmlEffectiveSourceCommitment.String)
	out.FitsIndexStorageKey.String = strings.Clone(in.FitsIndexStorageKey.String)
	out.FitsIndexVersionID.String = strings.Clone(in.FitsIndexVersionID.String)
	out.FitsIndexSha256 = bytes.Clone(in.FitsIndexSha256)
	out.ParticipantReportSchema = strings.Clone(in.ParticipantReportSchema)
	out.SigningAdmissionPolicy = strings.Clone(in.SigningAdmissionPolicy)
	return &out
}

func htmlRevisionCloneCurrentV1(in *htmlmaterialization.CurrentReadProjectionV1) *htmlmaterialization.CurrentReadProjectionV1 {
	if in == nil {
		return nil
	}
	out := *in
	out.PdfKey = strings.Clone(in.PdfKey)
	out.PdfVersionID = strings.Clone(in.PdfVersionID)
	out.PdfSha256 = bytes.Clone(in.PdfSha256)
	out.SourceCommitment = bytes.Clone(in.SourceCommitment)
	out.OriginCommitment = bytes.Clone(in.OriginCommitment)
	out.SourceJson = bytes.Clone(in.SourceJson)
	out.MetadataRedactionReport = bytes.Clone(in.MetadataRedactionReport)
	return &out
}

// Package readers carry only a private binding minted from their actual sorted
// locked headers. Existing readers retain the original physical document scope.
func (r *ApplicationHTMLRevisionReaderV1) logicalDocumentV1() uuid.UUID {
	if r == nil || r.session == nil || r.session.state == nil {
		return uuid.Nil
	}
	if r.packageBinding != nil {
		return r.packageBinding.document
	}
	return r.session.state.document
}
