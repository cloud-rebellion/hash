// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"unsafe"
)

// A single original PDF-template transaction can observe only its one unique
// SHARE-pinned subscription and two plans: subscribed/operator plan and free
// fallback if entitlement expires or a previously absent subscription appears.
// Every policy call still rereads genuine scalar headers and usage, including
// fresh absence. Only actual same-Tx protected full sources are reused; no
// absence, plan, scalar count, receipt or entitlement is fabricated or cached.
type pdfTemplatePlanPinV1 struct {
	row              *generated.BillingPlan
	raw, wire        int64
	measured, server int32
}
type pdfTemplateDocumentQuotaReadsV1 struct {
	state           *applicationPDFTemplateDocumentStateV1
	call            context.Context
	plans           [2]pdfTemplatePlanPinV1
	subscription    *generated.OrgSubscription
	subscriptionRaw int64
	usageFunded     bool
	usageCalls      int
}

func (w *ApplicationPDFTemplateDocumentV1) EnforceDocumentQuotaV1(ctx context.Context, engine *billing.Engine) error {
	if w == nil || w.state == nil {
		return ErrPDFTemplateDocumentV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created {
		return ErrPDFTemplateDocumentV1
	}
	if engine == nil {
		s.quotaApplied = true
		s.quotaAppliedRecipient = s.nextRecipient
		return nil
	}
	if s.quota == nil {
		s.quota = &pdfTemplateDocumentQuotaReadsV1{state: s}
	}
	reads := s.quota
	if reads.call != nil {
		return ErrPDFTemplateDocumentV1
	}
	reads.call = ctx
	defer func() { reads.call = nil }()
	local := *engine
	local.Queries = s.queries
	if err := local.EnforceDocumentQuotaWithReadsV1(ctx, s.session.state.org, reads); err != nil {
		return err
	}
	s.quotaApplied = true
	s.quotaAppliedRecipient = s.nextRecipient
	return nil
}
func (r *pdfTemplateDocumentQuotaReadsV1) validV1(ctx context.Context) bool {
	return r != nil && r.state != nil && r.call == ctx && r.state.validV1(ctx) && r.state.created
}
func (r *pdfTemplateDocumentQuotaReadsV1) GetOrgSubscription(ctx context.Context, org uuid.UUID) (*generated.OrgSubscription, error) {
	if !r.validV1(ctx) || org != r.state.session.state.org {
		return nil, ErrPDFTemplateDocumentV1
	}
	s := r.state
	h, err := s.queries.GetPlanSourceSubscriptionHeaderV1(ctx, org)
	if err != nil {
		return nil, err
	}
	if h == nil || h.OrgID != org || h.ID == uuid.Nil || h.PlanID == uuid.Nil || h.RawTextBytes < 0 {
		return nil, ErrPDFTemplateDocumentV1
	}
	if row := r.subscription; row != nil {
		if row.ID != h.ID || row.OrgID != org || row.PlanID != h.PlanID || row.CreatedAt != h.CreatedAt || row.UpdatedAt != h.UpdatedAt || r.subscriptionRaw != h.RawTextBytes {
			return nil, ErrPDFTemplateDocumentV1
		}
		return row, nil
	}
	raw, err := htmlAuthoringSumV1(h.RawTextBytes, 2*int64(unsafe.Sizeof(generated.OrgSubscription{})))
	if err != nil {
		return nil, err
	}
	if err = s.holdV1(ctx, raw, 0); err != nil {
		return nil, err
	}
	row, err := s.queries.ReadPlanSourceSubscriptionV1(ctx, generated.ReadPlanSourceSubscriptionV1Params{SubscriptionID: h.ID, OrgID: org, ExpectedPlanID: h.PlanID, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != h.ID || row.OrgID != org || row.PlanID != h.PlanID || row.CreatedAt != h.CreatedAt || row.UpdatedAt != h.UpdatedAt || int64(len(row.Provider)+len(row.ProviderCustomerID.String)+len(row.ProviderSubscriptionID.String)+len(row.Status)) != h.RawTextBytes {
		return nil, ErrPDFTemplateDocumentV1
	}
	r.subscription = row
	r.subscriptionRaw = h.RawTextBytes
	return row, nil
}
func (r *pdfTemplateDocumentQuotaReadsV1) GetBillingPlanByID(ctx context.Context, id uuid.UUID) (*generated.BillingPlan, error) {
	if !r.validV1(ctx) || id == uuid.Nil {
		return nil, ErrPDFTemplateDocumentV1
	}
	h, err := r.state.queries.GetPlanSourceHeaderByIDV1(ctx, id)
	if err != nil {
		return nil, err
	}
	if h == nil || h.ID != id {
		return nil, ErrPDFTemplateDocumentV1
	}
	return r.readV1(ctx, h.ID, h.CreatedAt, h.RawTextBytes, h.FeaturesWireBytes, h.MeasurementServerVersionNum, h.ServerVersionNum, h.Active, h.DocumentQuotaMonthly, h.RecipientQuotaMonthly)
}
func (r *pdfTemplateDocumentQuotaReadsV1) GetBillingPlanBySlug(ctx context.Context, slug string) (*generated.BillingPlan, error) {
	if !r.validV1(ctx) {
		return nil, ErrPDFTemplateDocumentV1
	}
	h, err := r.state.queries.GetPlanSourceHeaderBySlugV1(ctx, slug)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, ErrPDFTemplateDocumentV1
	}
	return r.readV1(ctx, h.ID, h.CreatedAt, h.RawTextBytes, h.FeaturesWireBytes, h.MeasurementServerVersionNum, h.ServerVersionNum, h.Active, h.DocumentQuotaMonthly, h.RecipientQuotaMonthly)
}
func (r *pdfTemplateDocumentQuotaReadsV1) readV1(ctx context.Context, id uuid.UUID, created pgtype.Timestamptz, raw, wire int64, measured, server int32, active bool, documentQuota, recipientQuota int32) (*generated.BillingPlan, error) {
	if !r.validV1(ctx) || id == uuid.Nil || raw < 0 || wire < 1 || server < 1 || measured != server {
		return nil, ErrPDFTemplateDocumentV1
	}
	free := -1
	for i := range r.plans {
		pin := &r.plans[i]
		if pin.row == nil {
			if free < 0 {
				free = i
			}
			continue
		}
		if pin.row.ID != id {
			continue
		}
		row := pin.row
		if row.CreatedAt != created || pin.raw != raw || pin.wire != wire || pin.measured != measured || pin.server != server || row.Active != active || row.DocumentQuotaMonthly != documentQuota || row.RecipientQuotaMonthly != recipientQuota {
			return nil, ErrPDFTemplateDocumentV1
		}
		return row, nil
	}
	if free < 0 {
		return nil, ErrPDFTemplateDocumentV1
	}
	s := r.state
	typed, err := htmlAuthoringSumV1(raw, 2*int64(unsafe.Sizeof(generated.BillingPlan{})))
	if err != nil {
		return nil, err
	}
	if err = s.holdV1(ctx, typed, wire); err != nil {
		return nil, err
	}
	row, err := s.queries.ReadPlanSourceV1(ctx, generated.ReadPlanSourceV1Params{PlanID: id, ExpectedCreatedAt: created, ExpectedRawTextBytes: raw, ExpectedFeaturesWireBytes: wire})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != id || row.CreatedAt != created || row.Active != active || row.DocumentQuotaMonthly != documentQuota || row.RecipientQuotaMonthly != recipientQuota || int64(len(row.Slug)+len(row.Name)+len(row.Description)+len(row.Currency)) != raw || int64(len(row.FeaturesJson)) != wire {
		return nil, ErrPDFTemplateDocumentV1
	}
	r.plans[free] = pdfTemplatePlanPinV1{row: row, raw: raw, wire: wire, measured: measured, server: server}
	return row, nil
}
func (r *pdfTemplateDocumentQuotaReadsV1) CountBillingUsageInPeriodForOrg(ctx context.Context, p generated.CountBillingUsageInPeriodForOrgParams) (*generated.CountBillingUsageInPeriodForOrgRow, error) {
	if !r.validV1(ctx) || p.OrgID != r.state.session.state.org || r.usageCalls >= len(r.state.values)+1 {
		return nil, ErrPDFTemplateDocumentV1
	}
	if !r.usageFunded {
		raw := 2*int64(unsafe.Sizeof(generated.CountBillingUsageInPeriodForOrgRow{})) + int64(unsafe.Sizeof(generated.CountBillingUsageInPeriodForOrgParams{}))
		if err := r.state.holdV1(ctx, raw, 0); err != nil {
			return nil, err
		}
		r.usageFunded = true
	}
	r.usageCalls++
	// This remains the actual prospective count query on every original iteration.
	// Two fixed scalar result headers overlap; no prior aggregate is reused.
	return r.state.queries.CountBillingUsageInPeriodForOrg(ctx, p)
}
