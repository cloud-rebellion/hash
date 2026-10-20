// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Quota remains the original billing policy. These private reads only bind
// actual complete plan/subscription models to this native producer and its
// protected M95 metadata, before body SQL and policy decoding. No cache repair.
func (w *ApplicationPlainPDFCreationWriterV1) EnforceDocumentQuotaV1(ctx context.Context, engine *billing.Engine) error {
	if w == nil || w.state == nil {
		return ErrPlainPDFWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created {
		return ErrPlainPDFWriterV1
	}
	if engine == nil {
		return nil
	}
	local := *engine
	local.Queries = s.queries
	reads := &plainPDFQuotaSourceReadsV1{state: s, call: ctx}
	return local.EnforceDocumentQuotaWithReadsV1(ctx, s.session.state.org, reads)
}

type plainPDFQuotaSourceReadsV1 struct {
	state *applicationPlainPDFCreationStateV1
	call  context.Context
}

// All methods run synchronously under the creation owner's original mutex.
func (r *plainPDFQuotaSourceReadsV1) validV1(ctx context.Context) bool {
	return r != nil && r.state != nil && r.call == ctx && r.state.validV1(ctx) && r.state.created
}
func (r *plainPDFQuotaSourceReadsV1) GetOrgSubscription(ctx context.Context, org uuid.UUID) (*generated.OrgSubscription, error) {
	if !r.validV1(ctx) || org != r.state.session.state.org {
		return nil, ErrPlainPDFWriterV1
	}
	s := r.state
	h, err := s.queries.GetPlanSourceSubscriptionHeaderV1(ctx, org)
	if err != nil {
		return nil, err
	}
	if h == nil || h.OrgID != org || h.ID == uuid.Nil || h.PlanID == uuid.Nil || h.RawTextBytes < 0 {
		return nil, ErrPlainPDFWriterV1
	}
	if err = s.holdV1(ctx, h.RawTextBytes, 0); err != nil {
		return nil, err
	}
	row, err := s.queries.ReadPlanSourceSubscriptionV1(ctx, generated.ReadPlanSourceSubscriptionV1Params{SubscriptionID: h.ID, OrgID: org, ExpectedPlanID: h.PlanID, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != h.ID || row.OrgID != org || row.PlanID != h.PlanID || row.CreatedAt != h.CreatedAt || row.UpdatedAt != h.UpdatedAt || int64(len(row.Provider)+len(row.ProviderCustomerID.String)+len(row.ProviderSubscriptionID.String)+len(row.Status)) != h.RawTextBytes {
		return nil, ErrPlainPDFWriterV1
	}
	return row, nil
}
func (r *plainPDFQuotaSourceReadsV1) GetBillingPlanByID(ctx context.Context, id uuid.UUID) (*generated.BillingPlan, error) {
	if !r.validV1(ctx) || id == uuid.Nil {
		return nil, ErrPlainPDFWriterV1
	}
	h, err := r.state.queries.GetPlanSourceHeaderByIDV1(ctx, id)
	if err != nil {
		return nil, err
	}
	if h == nil || h.ID != id {
		return nil, ErrPlainPDFWriterV1
	}
	return r.readV1(ctx, h.ID, h.CreatedAt, h.RawTextBytes, h.FeaturesWireBytes, h.MeasurementServerVersionNum, h.ServerVersionNum, h.Active, h.DocumentQuotaMonthly, h.RecipientQuotaMonthly)
}
func (r *plainPDFQuotaSourceReadsV1) GetBillingPlanBySlug(ctx context.Context, slug string) (*generated.BillingPlan, error) {
	if !r.validV1(ctx) {
		return nil, ErrPlainPDFWriterV1
	}
	h, err := r.state.queries.GetPlanSourceHeaderBySlugV1(ctx, slug)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, ErrPlainPDFWriterV1
	}
	return r.readV1(ctx, h.ID, h.CreatedAt, h.RawTextBytes, h.FeaturesWireBytes, h.MeasurementServerVersionNum, h.ServerVersionNum, h.Active, h.DocumentQuotaMonthly, h.RecipientQuotaMonthly)
}
func (r *plainPDFQuotaSourceReadsV1) readV1(ctx context.Context, id uuid.UUID, created pgtype.Timestamptz, raw, wire int64, measured, server int32, active bool, docQuota, recipientQuota int32) (*generated.BillingPlan, error) {
	if !r.validV1(ctx) || id == uuid.Nil || raw < 0 || wire < 1 || server < 1 || measured != server {
		return nil, ErrPlainPDFWriterV1
	}
	s := r.state
	if err := s.holdV1(ctx, raw, wire); err != nil {
		return nil, err
	}
	row, err := s.queries.ReadPlanSourceV1(ctx, generated.ReadPlanSourceV1Params{PlanID: id, ExpectedCreatedAt: created, ExpectedRawTextBytes: raw, ExpectedFeaturesWireBytes: wire})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != id || row.CreatedAt != created || row.Active != active || row.DocumentQuotaMonthly != docQuota || row.RecipientQuotaMonthly != recipientQuota || int64(len(row.Slug)+len(row.Name)+len(row.Description)+len(row.Currency)) != raw || int64(len(row.FeaturesJson)) != wire {
		return nil, ErrPlainPDFWriterV1
	}
	return row, nil
}
func (r *plainPDFQuotaSourceReadsV1) CountBillingUsageInPeriodForOrg(ctx context.Context, p generated.CountBillingUsageInPeriodForOrgParams) (*generated.CountBillingUsageInPeriodForOrgRow, error) {
	if !r.validV1(ctx) || p.OrgID != r.state.session.state.org {
		return nil, ErrPlainPDFWriterV1
	}
	if err := r.state.holdV1(ctx, 0, 0); err != nil {
		return nil, err
	}
	return r.state.queries.CountBillingUsageInPeriodForOrg(ctx, p)
}
