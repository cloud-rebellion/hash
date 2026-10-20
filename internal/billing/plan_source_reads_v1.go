// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package billing

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PlanSourceReadsV1 is a pure plan-policy dependency. It grants no SQL/work or
// actor authority. Native Send supplies only its fixed same-owner scalar-before-
// body catalog/subscription reader; normal callers keep using PlanForOrg.
// The complete returned BillingPlan/OrgSubscription remain actual store models.
type PlanSourceReadsV1 interface {
	GetOrgSubscription(context.Context, uuid.UUID) (*generated.OrgSubscription, error)
	GetBillingPlanBySlug(context.Context, string) (*generated.BillingPlan, error)
	GetBillingPlanByID(context.Context, uuid.UUID) (*generated.BillingPlan, error)
}

// PlanForOrgWithReadsV1 keeps the exact original subscription/free/operator
// decisions and error ordering while allowing the native fixed catalog reader
// to acquire measured body loans before queries. Receiver configuration and
// original clock/feature/quota checks stay authoritative; no fake small plan.
func (e *Engine) PlanForOrgWithReadsV1(ctx context.Context, orgID uuid.UUID, reads PlanSourceReadsV1) (*generated.BillingPlan, *generated.OrgSubscription, error) {
	if e == nil || e.Queries == nil || reads == nil {
		return nil, nil, &EntitlementUnavailableError{Stage: "plan engine unavailable"}
	}
	if e.operatorPlans != nil {
		slug, ok := e.operatorPlans[orgID]
		if !ok {
			return nil, nil, &EntitlementUnavailableError{Stage: "internal organization not approved"}
		}
		plan, err := reads.GetBillingPlanBySlug(ctx, slug)
		if err != nil || plan == nil || !plan.Active || plan.DocumentQuotaMonthly <= 0 || plan.RecipientQuotaMonthly <= 0 {
			return nil, nil, &EntitlementUnavailableError{Stage: "internal plan unavailable or unbounded", Err: err}
		}
		var features map[string]any
		if err := json.Unmarshal(plan.FeaturesJson, &features); err != nil || features == nil {
			return nil, nil, &EntitlementUnavailableError{Stage: "invalid internal plan features", Err: err}
		}
		for _, value := range features {
			if _, ok := value.(bool); !ok {
				return nil, nil, &EntitlementUnavailableError{Stage: "invalid internal plan features"}
			}
		}
		return plan, nil, nil
	}

	sub, err := reads.GetOrgSubscription(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		free, freeErr := reads.GetBillingPlanBySlug(ctx, "free")
		if freeErr != nil {
			return nil, nil, &EntitlementUnavailableError{Stage: "load free plan", Err: freeErr}
		}
		if free == nil {
			return nil, nil, &EntitlementUnavailableError{Stage: "free plan missing"}
		}
		return free, nil, nil
	}
	if err != nil {
		return nil, nil, &EntitlementUnavailableError{Stage: "load subscription", Err: err}
	}
	if !isEntitled(sub, time.Now().UTC()) {
		free, freeErr := reads.GetBillingPlanBySlug(ctx, "free")
		if freeErr != nil {
			return nil, sub, &EntitlementUnavailableError{Stage: "load free plan", Err: freeErr}
		}
		if free == nil {
			return nil, sub, &EntitlementUnavailableError{Stage: "free plan missing"}
		}
		return free, sub, nil
	}
	plan, err := reads.GetBillingPlanByID(ctx, sub.PlanID)
	if err != nil {
		return nil, sub, &EntitlementUnavailableError{Stage: "load entitled plan", Err: err}
	}
	if plan == nil {
		return nil, sub, &EntitlementUnavailableError{Stage: "entitled plan missing"}
	}
	return plan, sub, nil
}
