// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package billing

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"time"
)

// Fixed policy reads only. Implementations supply actual complete measured
// models and the original fixed scalar usage aggregate; this grants no native
// session, resources, mutation or entitlement authority.
type QuotaSourceReadsV1 interface {
	PlanSourceReadsV1
	CountBillingUsageInPeriodForOrg(context.Context, generated.CountBillingUsageInPeriodForOrgParams) (*generated.CountBillingUsageInPeriodForOrgRow, error)
}

func (e *Engine) EnforceDocumentQuotaWithReadsV1(ctx context.Context, orgID uuid.UUID, reads QuotaSourceReadsV1) error {
	if e == nil || e.Queries == nil || reads == nil {
		return &EntitlementUnavailableError{Stage: "quota engine unavailable"}
	}
	plan, sub, err := e.PlanForOrgWithReadsV1(ctx, orgID, reads)
	if err != nil {
		if errors.Is(err, ErrEntitlementUnavailable) {
			return err
		}
		return &EntitlementUnavailableError{Stage: "load plan", Err: err}
	}
	if plan == nil {
		return &EntitlementUnavailableError{Stage: "plan missing"}
	}
	if plan.DocumentQuotaMonthly == 0 && plan.RecipientQuotaMonthly == 0 {
		return nil
	}
	start, end := e.QuotaPeriod(sub, time.Now().UTC())
	usage, err := reads.CountBillingUsageInPeriodForOrg(ctx, generated.CountBillingUsageInPeriodForOrgParams{
		OrgID: orgID, PeriodStart: pgTime(start), PeriodEnd: pgTime(end),
	})
	if err != nil {
		return &EntitlementUnavailableError{Stage: "load usage", Err: err}
	}
	if usage == nil {
		return &EntitlementUnavailableError{Stage: "usage missing"}
	}
	if plan.DocumentQuotaMonthly > 0 && usage.DocumentsUsed > int64(plan.DocumentQuotaMonthly) {
		return fmt.Errorf("%w: plan %q allows %d documents per period; org has used %d", ErrQuotaExceeded, plan.Slug, plan.DocumentQuotaMonthly, usage.DocumentsUsed)
	}
	if plan.RecipientQuotaMonthly > 0 && usage.RecipientsUsed > int64(plan.RecipientQuotaMonthly) {
		return fmt.Errorf("%w: plan %q allows %d recipients per period; org has used %d", ErrQuotaExceeded, plan.Slug, plan.RecipientQuotaMonthly, usage.RecipientsUsed)
	}
	return nil
}
