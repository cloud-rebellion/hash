// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Each actual org-setting fetch retains the original billing evaluation time
// and full original policy. HTTP never opens SQL. A DB source stage is minted
// privately by this actual producer, at most once per admitted org binding.
func (p *applicationHTMLSendResolverV1) fetchOrgSourceV1(ctx context.Context, configured *resolver.OrgSettingSource, ref resolver.Ref) (string, error) {
	p.mu.Lock()
	if !p.liveV1() || p.active == 0 || ctx != p.source.owner.binding.ctx || ref.OrgID != p.document.OrgID || ref.DocID != p.document.ID {
		p.mu.Unlock()
		return "", ErrHTMLSendWorkV1
	}
	p.mu.Unlock()
	if configured == nil {
		return "", ErrHTMLSendWorkV1
	}
	// Preserve the original pre-query ordering and exact unknown-scope error.
	if ref.OrgID == uuid.Nil {
		return "", errors.New("org.setting: missing org context")
	}
	if configured.Q == nil {
		return "", resolver.ErrNotConfigured
	}
	if !strings.HasPrefix(ref.Path, "org.") && !strings.HasPrefix(ref.Path, "branding.") {
		return "", fmt.Errorf("org.setting: unknown path scope %q (expected org.* or branding.*)", ref.Path)
	}
	// This fixed resolver now runs in the still-active original preparation
	// callback. Reuse its real same-row lock and actual callback, rather than
	// opening another transaction that would wait on our own parent UPDATE.
	w := p.work
	w.mu.Lock()
	call := w.call
	valid := w.valid(call) && w.sourceOwner == p.source.owner
	w.mu.Unlock()
	if !valid {
		return "", p.recordCapacityFailureV1(ErrHTMLSendWorkV1)
	}
	native := &htmlSendOrgSourceReadsV1{owner: p, source: p.source, work: w, ctx: call, planSource: ref.Path == "org.plan"}
	local := *configured
	local.Q = native
	if configured.Plans != nil {
		engine, ok := configured.Plans.(*billing.Engine)
		if !ok {
			if ref.Path == "org.plan" {
				return "", ErrHTMLSendWorkV1
			}
		} else {
			local.Plans = &htmlSendPlanSourcePolicyV1{engine: engine, reads: native}
		}
	}
	return local.Fetch(call, ref)
}

type htmlSendOrgSourceReadsV1 struct {
	owner                         *applicationHTMLSendResolverV1
	quota                         *ApplicationHTMLSendWorkV1
	source                        *applicationHTMLSendSourceStateV1
	work                          *ApplicationHTMLSendWorkV1
	ctx                           context.Context
	planSource, planPolicyStarted bool
}

// A scalar selector from the SAME real preparation owner. Legacy formats use
// separate SQL; the original standalone reviewed-HTML source gates stay exact.
// The physical root owns the SQL/body admission. Only registered ordered member
// Work can select a different logical document; neither UUID is a public claim.
type htmlSendOrgReadScopeV1 struct {
	document, root                               uuid.UUID
	documentUpdated, rootUpdated                 pgtype.Timestamptz
	legacy, pdf, envelope, rootPDF, rootEnvelope bool
}

// Fixed actual scalar/query/copy scratch is priced by the original resolver
// owner before a source fetch. Dynamic source text still requires its genuine
// header-derived same-reader retained-body loan, separately below.
func htmlSendOrgReadScratchV1() int64 {
	return 4*int64(unsafe.Sizeof(htmlSendOrgReadScopeV1{})) + 4*int64(unsafe.Sizeof(htmlSendOrgSourceReadsV1{})) +
		2*int64(unsafe.Sizeof(generated.GetLegacySendOrgSourceReadHeaderV1Row{})) +
		2*int64(unsafe.Sizeof(generated.GetLegacySendOrgBrandingSourceReadHeaderV1Row{})) +
		2*int64(unsafe.Sizeof(generated.GetLegacySendOrgSourceReadHeaderV1Params{})) +
		2*int64(unsafe.Sizeof(generated.ReadLegacySendOrgSourceV1Params{})) +
		2*int64(unsafe.Sizeof(generated.GetLegacySendOrgBrandingSourceReadHeaderV1Params{})) +
		2*int64(unsafe.Sizeof(generated.ReadLegacySendOrgBrandingSourceV1Params{}))
}

func (r *htmlSendOrgSourceReadsV1) documentScopeV1(ctx context.Context, org uuid.UUID) (htmlSendOrgReadScopeV1, error) {
	var out htmlSendOrgReadScopeV1
	if !r.validV1(ctx, org) {
		return out, ErrHTMLSendWorkV1
	}
	w := r.work
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.state == nil || w.stage == nil || w.stage.operation == nil || w.session == nil || w.session.state == nil {
		return out, ErrHTMLSendWorkV1
	}
	s := w.session.state
	logical := w.logicalDocumentV1()
	h := w.state
	if logical == uuid.Nil || h.ID != logical || h.OrgID != org || s.org != org {
		return out, ErrHTMLSendWorkV1
	}
	out = htmlSendOrgReadScopeV1{document: logical, root: s.document, documentUpdated: h.UpdatedAt, rootUpdated: h.UpdatedAt, legacy: !h.HasHtmlSource, pdf: h.IsPdfSource, envelope: h.IsEnvelope, rootPDF: h.IsPdfSource, rootEnvelope: h.IsEnvelope}
	if !out.legacy {
		if !h.IsPdfSource || h.IsEnvelope || h.ParentEnvelopeID.Valid || w.familyRoot != nil || logical != s.document {
			return htmlSendOrgReadScopeV1{}, ErrHTMLSendWorkV1
		}
		return out, nil
	}
	// This additive path is only the real first-party resolver's original
	// preparation borrower. It does not extend quota, finalization, reader,
	// retained-HTML or later immutable-branding authority to legacy documents.
	if r.quota != nil || w.stage.purpose != HTMLSendPreparationV1 || r.owner == nil || r.owner != w.resolverOwner || r.owner.work != w || r.owner.source != r.source || r.source == nil || r.source != w.sourceState || r.source.work != w || r.source.owner == nil || r.source.owner != w.sourceOwner || r.source.closeRequested.Load() || r.source.owner.binding == nil || r.source.owner.binding.ctx == nil || r.source.owner.binding.ctx.Err() != nil || !time.Now().Before(r.source.owner.binding.deadline) {
		return htmlSendOrgReadScopeV1{}, ErrHTMLSendWorkV1
	}
	doc := w.sourceDocument
	if doc == nil || doc.ID != logical || doc.OrgID != org || doc.UpdatedAt != h.UpdatedAt || doc.DeletedAt.Valid || doc.Status != "draft" || h.BoundedStatus != "draft" || len(doc.HtmlSourceJson) != 0 || (doc.SourceKind != "blocks" && doc.SourceKind != "pdf") || (doc.SourceKind == "pdf") != h.IsPdfSource || doc.IsEnvelope != h.IsEnvelope || doc.ParentEnvelopeID != h.ParentEnvelopeID {
		return htmlSendOrgReadScopeV1{}, ErrHTMLSendWorkV1
	}
	if w.familyRoot == nil {
		if logical != s.document || h.ParentEnvelopeID.Valid || w.sourceActor == nil || w.sourceActor.ID == uuid.Nil || w.sourceActor.OrgID != org {
			return htmlSendOrgReadScopeV1{}, ErrHTMLSendWorkV1
		}
		return out, nil
	}
	root := w.familyRoot
	root.mu.Lock()
	defer root.mu.Unlock()
	rh, rd := root.state, root.sourceDocument
	if root.closed || root.resourcesClosed || root.stage != w.stage || root.session != w.session || root.sourceActor == nil || root.sourceActor.ID == uuid.Nil || root.sourceActor.OrgID != org || rh == nil || rd == nil || rh.ID != s.document || rd.ID != s.document || rh.OrgID != org || rd.OrgID != org || !rh.IsEnvelope || !rd.IsEnvelope || rh.ParentEnvelopeID.Valid || rd.ParentEnvelopeID.Valid || rh.HasHtmlSource || len(rd.HtmlSourceJson) != 0 || rh.BoundedStatus != "draft" || rd.Status != "draft" || rd.DeletedAt.Valid || rh.UpdatedAt != rd.UpdatedAt || (rd.SourceKind != "blocks" && rd.SourceKind != "pdf") || (rd.SourceKind == "pdf") != rh.IsPdfSource || !h.ParentEnvelopeID.Valid || uuid.UUID(h.ParentEnvelopeID.Bytes) != s.document || h.IsEnvelope {
		return htmlSendOrgReadScopeV1{}, ErrHTMLSendWorkV1
	}
	out.rootUpdated = rh.UpdatedAt
	out.rootPDF = rh.IsPdfSource
	out.rootEnvelope = true
	return out, nil
}

func (r *htmlSendOrgSourceReadsV1) validV1(ctx context.Context, id uuid.UUID) bool {
	if r == nil || r.work == nil || r.work.self != r.work || r.work.stage == nil || r.ctx != ctx {
		return false
	}
	w := r.work
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || id != w.session.state.org {
		return false
	}
	if r.quota != nil {
		return r.quota == w && w.quotaAttempted && w.stage.purpose == HTMLSendPreparationV1 && !w.sourceStarted && !w.recipientsAttempted && !w.bindingsAttempted
	}
	return r.source != nil && r.source.owner != nil && r.source.owner.self == r.source.owner && r.source.owner.purpose == htmlSendSourcePurposeV1 && r.source.work != nil && r.source.work.stage != nil && r.source.work.stage.operation == w.stage.operation && r.source.owner.binding.org == id && r.source.owner.binding.document == w.logicalDocumentV1() && r.source.owner.binding.factory == w.session.state.factory
}

func (r *htmlSendOrgSourceReadsV1) nativeFailureV1(err error) error {
	if err != nil && (errors.Is(err, ErrHTMLSendWorkV1) || errors.Is(err, ErrHTMLAuthoringReadV1)) {
		if r != nil && r.owner != nil {
			r.owner.recordCapacityFailureV1(err)
		}
	}
	return err
}
func (r *htmlSendOrgSourceReadsV1) holdV1(ctx context.Context, raw, wire int64) error {
	w := r.work
	w.mu.Lock()
	if !w.valid(ctx) {
		w.mu.Unlock()
		return r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	actor := w.actor
	w.mu.Unlock()
	close, err := actor.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return r.nativeFailureV1(errors.Join(ErrHTMLSendWorkV1, err))
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		close()
		return r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	w.closes = append(w.closes, close)
	w.mu.Unlock()
	return nil
}
func (r *htmlSendOrgSourceReadsV1) GetOrg(ctx context.Context, id uuid.UUID) (*generated.Org, error) {
	scope, err := r.documentScopeV1(ctx, id)
	if err != nil {
		return nil, r.nativeFailureV1(err)
	}
	w := r.work
	s := w.session.state
	var h *generated.GetHTMLSendOrgSourceReadHeaderV1Row
	if scope.legacy {
		var header *generated.GetLegacySendOrgSourceReadHeaderV1Row
		header, err = w.queries.GetLegacySendOrgSourceReadHeaderV1(ctx, generated.GetLegacySendOrgSourceReadHeaderV1Params{RootDocumentID: scope.root, DocumentID: scope.document, OrgID: id, ExpectedRootUpdatedAt: scope.rootUpdated, ExpectedDocumentUpdatedAt: scope.documentUpdated, ExpectedIsPdfSource: scope.pdf, ExpectedIsEnvelope: scope.envelope, ExpectedRootIsPdfSource: scope.rootPDF, ExpectedRootIsEnvelope: scope.rootEnvelope})
		if header != nil {
			copy := generated.GetHTMLSendOrgSourceReadHeaderV1Row(*header)
			h = &copy
		}
	} else {
		h, err = w.queries.GetHTMLSendOrgSourceReadHeaderV1(ctx, generated.GetHTMLSendOrgSourceReadHeaderV1Params{DocumentID: scope.document, OrgID: id})
	}
	if err != nil {
		return nil, err
	}
	if h == nil || h.OrgID != s.org || h.RawTextBytes < 0 {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	if err = r.holdV1(ctx, h.RawTextBytes, 0); err != nil {
		return nil, err
	}
	var row *generated.Org
	if scope.legacy {
		row, err = w.queries.ReadLegacySendOrgSourceV1(ctx, generated.ReadLegacySendOrgSourceV1Params{RootDocumentID: scope.root, DocumentID: scope.document, OrgID: id, ExpectedRootUpdatedAt: scope.rootUpdated, ExpectedDocumentUpdatedAt: scope.documentUpdated, ExpectedIsPdfSource: scope.pdf, ExpectedIsEnvelope: scope.envelope, ExpectedRootIsPdfSource: scope.rootPDF, ExpectedRootIsEnvelope: scope.rootEnvelope, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	} else {
		row, err = w.queries.ReadHTMLSendOrgSourceV1(ctx, generated.ReadHTMLSendOrgSourceV1Params{DocumentID: scope.document, OrgID: id, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	}
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != s.org || row.CreatedAt != h.CreatedAt || row.UpdatedAt != h.UpdatedAt || int64(len(row.Name)+len(row.Plan)+len(row.ChangeApprovalMode)) != h.RawTextBytes {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	return row, nil
}
func (r *htmlSendOrgSourceReadsV1) GetOrgBranding(ctx context.Context, id uuid.UUID) (*generated.OrgBranding, error) {
	scope, err := r.documentScopeV1(ctx, id)
	if err != nil {
		return nil, r.nativeFailureV1(err)
	}
	w := r.work
	s := w.session.state
	var h *generated.GetHTMLSendOrgBrandingSourceReadHeaderV1Row
	if scope.legacy {
		var header *generated.GetLegacySendOrgBrandingSourceReadHeaderV1Row
		header, err = w.queries.GetLegacySendOrgBrandingSourceReadHeaderV1(ctx, generated.GetLegacySendOrgBrandingSourceReadHeaderV1Params{RootDocumentID: scope.root, DocumentID: scope.document, OrgID: id, ExpectedRootUpdatedAt: scope.rootUpdated, ExpectedDocumentUpdatedAt: scope.documentUpdated, ExpectedIsPdfSource: scope.pdf, ExpectedIsEnvelope: scope.envelope, ExpectedRootIsPdfSource: scope.rootPDF, ExpectedRootIsEnvelope: scope.rootEnvelope})
		if header != nil {
			copy := generated.GetHTMLSendOrgBrandingSourceReadHeaderV1Row(*header)
			h = &copy
		}
	} else {
		h, err = w.queries.GetHTMLSendOrgBrandingSourceReadHeaderV1(ctx, generated.GetHTMLSendOrgBrandingSourceReadHeaderV1Params{DocumentID: scope.document, OrgID: id})
	}
	if err != nil {
		return nil, err
	}
	if h == nil || h.OrgID != s.org || h.RawTextBytes < 0 {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	if err = r.holdV1(ctx, h.RawTextBytes, 0); err != nil {
		return nil, err
	}
	var row *generated.OrgBranding
	if scope.legacy {
		row, err = w.queries.ReadLegacySendOrgBrandingSourceV1(ctx, generated.ReadLegacySendOrgBrandingSourceV1Params{RootDocumentID: scope.root, DocumentID: scope.document, OrgID: id, ExpectedRootUpdatedAt: scope.rootUpdated, ExpectedDocumentUpdatedAt: scope.documentUpdated, ExpectedIsPdfSource: scope.pdf, ExpectedIsEnvelope: scope.envelope, ExpectedRootIsPdfSource: scope.rootPDF, ExpectedRootIsEnvelope: scope.rootEnvelope, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedSchemaVersion: h.SchemaVersion, ExpectedRawTextBytes: h.RawTextBytes})
	} else {
		row, err = w.queries.ReadHTMLSendOrgBrandingSourceV1(ctx, generated.ReadHTMLSendOrgBrandingSourceV1Params{DocumentID: scope.document, OrgID: id, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedSchemaVersion: h.SchemaVersion, ExpectedRawTextBytes: h.RawTextBytes})
	}
	if err != nil {
		return nil, err
	}
	if row == nil || row.OrgID != s.org || row.CreatedAt != h.CreatedAt || row.UpdatedAt != h.UpdatedAt || row.SchemaVersion != h.SchemaVersion || int64(len(row.PrimaryHex)+len(row.AccentHex)+len(row.SurfaceHex)+len(row.TextHex)+len(row.MutedHex)+len(row.LogoUrl)+len(row.LogoAlt)+len(row.FontHeading)+len(row.FontBody)+len(row.SignatureColor)) != h.RawTextBytes {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	return row, nil
}

type htmlSendPlanSourcePolicyV1 struct {
	engine *billing.Engine
	reads  *htmlSendOrgSourceReadsV1
}

func (p *htmlSendPlanSourcePolicyV1) PlanForOrg(ctx context.Context, id uuid.UUID) (*generated.BillingPlan, *generated.OrgSubscription, error) {
	if p == nil || p.reads == nil || !p.reads.validV1(ctx, id) {
		return nil, nil, ErrHTMLSendWorkV1
	}
	// This executes the original body/private operator map/clock and full bool
	// features validation against genuine SAME-session measured complete models.
	return p.engine.PlanForOrgWithReadsV1(ctx, id, p.reads)
}
func (r *htmlSendOrgSourceReadsV1) GetOrgSubscription(ctx context.Context, id uuid.UUID) (*generated.OrgSubscription, error) {
	if !r.validV1(ctx, id) {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	w := r.work
	h, err := w.queries.GetPlanSourceSubscriptionHeaderV1(ctx, id)
	if err != nil {
		return nil, err
	}
	if h == nil || h.OrgID != id || h.ID == uuid.Nil || h.PlanID == uuid.Nil || h.RawTextBytes < 0 {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	if err = r.holdV1(ctx, h.RawTextBytes, 0); err != nil {
		return nil, err
	}
	row, err := w.queries.ReadPlanSourceSubscriptionV1(ctx, generated.ReadPlanSourceSubscriptionV1Params{SubscriptionID: h.ID, OrgID: id, ExpectedPlanID: h.PlanID, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != h.ID || row.OrgID != id || row.PlanID != h.PlanID || row.CreatedAt != h.CreatedAt || row.UpdatedAt != h.UpdatedAt || int64(len(row.Provider)+len(row.ProviderCustomerID.String)+len(row.ProviderSubscriptionID.String)+len(row.Status)) != h.RawTextBytes {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	return row, nil
}
func (r *htmlSendOrgSourceReadsV1) GetBillingPlanBySlug(ctx context.Context, slug string) (*generated.BillingPlan, error) {
	if r == nil || r.work == nil || !r.validV1(ctx, r.work.session.state.org) || !r.planHeaderAvailableV1(ctx) {
		return nil, ErrHTMLSendWorkV1
	}
	h, err := r.work.queries.GetPlanSourceHeaderBySlugV1(ctx, slug)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	return r.readPlanV1(ctx, h.ID, h.CreatedAt, h.RawTextBytes, h.FeaturesWireBytes, h.MeasurementServerVersionNum, h.ServerVersionNum, h.Active, h.DocumentQuotaMonthly, h.RecipientQuotaMonthly)
}
func (r *htmlSendOrgSourceReadsV1) GetBillingPlanByID(ctx context.Context, id uuid.UUID) (*generated.BillingPlan, error) {
	if r == nil || r.work == nil || !r.validV1(ctx, r.work.session.state.org) || !r.planHeaderAvailableV1(ctx) || id == uuid.Nil {
		return nil, ErrHTMLSendWorkV1
	}
	h, err := r.work.queries.GetPlanSourceHeaderByIDV1(ctx, id)
	if err != nil {
		return nil, err
	}
	if h == nil || h.ID != id {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	return r.readPlanV1(ctx, h.ID, h.CreatedAt, h.RawTextBytes, h.FeaturesWireBytes, h.MeasurementServerVersionNum, h.ServerVersionNum, h.Active, h.DocumentQuotaMonthly, h.RecipientQuotaMonthly)
}

func (r *htmlSendOrgSourceReadsV1) planHeaderAvailableV1(ctx context.Context) bool {
	if r == nil || r.work == nil || r.work.self != r.work {
		return false
	}
	w := r.work
	w.mu.Lock()
	defer w.mu.Unlock()
	return r.ctx == ctx && w.valid(ctx) && !r.planPolicyStarted
}
func (r *htmlSendOrgSourceReadsV1) readPlanV1(ctx context.Context, id uuid.UUID, created pgtype.Timestamptz, raw, wire int64, measured, server int32, active bool, docQuota, recipientQuota int32) (*generated.BillingPlan, error) {
	if r == nil || r.work == nil || !r.validV1(ctx, r.work.session.state.org) || id == uuid.Nil || raw < 0 || wire < 0 || server <= 0 || measured != server {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	// Genuine M95 header measurement precedes BOTH actual full-row read and the
	// unchanged operator bool-map validation. Missing/old cache stays refused;
	// this reader never runs a measurement or automatic on-demand repair.
	if err := r.holdV1(ctx, raw, wire); err != nil {
		return nil, err
	}
	if err := r.work.holdPlanPolicyV1(ctx, id, created, wire, server, r); err != nil {
		return nil, r.nativeFailureV1(err)
	}
	row, err := r.work.queries.ReadPlanSourceV1(ctx, generated.ReadPlanSourceV1Params{PlanID: id, ExpectedCreatedAt: created, ExpectedRawTextBytes: raw, ExpectedFeaturesWireBytes: wire})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != id || row.CreatedAt != created || row.Active != active || row.DocumentQuotaMonthly != docQuota || row.RecipientQuotaMonthly != recipientQuota || int64(len(row.Slug)+len(row.Name)+len(row.Description)+len(row.Currency)) != raw || int64(len(row.FeaturesJson)) != wire {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	return row, nil
}

func (r *htmlSendOrgSourceReadsV1) CountBillingUsageInPeriodForOrg(ctx context.Context, arg generated.CountBillingUsageInPeriodForOrgParams) (*generated.CountBillingUsageInPeriodForOrgRow, error) {
	if !r.validV1(ctx, arg.OrgID) {
		return nil, r.nativeFailureV1(ErrHTMLSendWorkV1)
	}
	if err := r.holdV1(ctx, 0, 0); err != nil {
		return nil, err
	}
	return r.work.queries.CountBillingUsageInPeriodForOrg(ctx, arg)
}
