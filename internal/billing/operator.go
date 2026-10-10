// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Operator mode keeps the normal transactional quota and feature checks while
// making payment methods unavailable. It never creates subscription rows.
func NewOperator(q *generated.Queries, grants []config.OperatorEntitlement) *Engine {
	plans := make(map[uuid.UUID]string, len(grants))
	for _, g := range grants {
		plans[g.OrgID] = g.PlanSlug
	}
	return &Engine{Queries: q, Provider: operatorProvider{}, operatorPlans: plans}
}
func (e *Engine) PaymentsEnabled() bool {
	return e != nil && e.Provider != nil && e.operatorPlans == nil
}
func (e *Engine) OperatorMode() bool { return e != nil && e.operatorPlans != nil }
func (e *Engine) ValidateOperatorPlans(ctx context.Context) error {
	if !e.OperatorMode() || e.Queries == nil || len(e.operatorPlans) == 0 {
		return &EntitlementUnavailableError{Stage: "internal entitlement engine unavailable"}
	}
	for orgID := range e.operatorPlans {
		if org, err := e.Queries.GetOrg(ctx, orgID); err != nil || org == nil || org.ID != orgID {
			return &EntitlementUnavailableError{Stage: "internal organization unavailable", Err: err}
		}
		if _, _, err := e.PlanForOrg(ctx, orgID); err != nil {
			return err
		}
	}
	return nil
}
func (e *Engine) QuotaPeriod(sub *generated.OrgSubscription, now time.Time) (time.Time, time.Time) {
	if e.OperatorMode() {
		now = now.UTC()
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 1, 0)
	}
	return quotaPeriod(sub, now)
}

// Only a name is exposed for status/UI. Every payment operation rejects.
type operatorProvider struct{}

func (operatorProvider) Name() string { return "operator" }
func (operatorProvider) CreateCheckout(context.Context, CheckoutInput) (*CheckoutResult, error) {
	return nil, ErrDisabled
}
func (operatorProvider) CreateSubscription(context.Context, SubscriptionInput) (*SubscriptionResult, error) {
	return nil, ErrDisabled
}
func (operatorProvider) CancelSubscription(context.Context, string, string) error { return ErrDisabled }
func (operatorProvider) ParseWebhook(context.Context, []byte, map[string]string) (*WebhookEvent, error) {
	return nil, ErrDisabled
}

func (e *Engine) OperatorOrgIDs() []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(e.operatorPlans))
	for id := range e.operatorPlans {
		ids = append(ids, id)
	}
	return ids
}
