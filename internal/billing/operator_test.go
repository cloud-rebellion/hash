// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestOperatorEntitlementsEnforceQuotaAndFeaturesWithoutSubscription(t *testing.T) {
	org := uuid.New()
	db := &quotaDB{docs: 6, recs: 10}
	e := NewOperator(generated.New(db), []config.OperatorEntitlement{{OrgID: org, PlanSlug: "free", ReviewRef: "review-1"}})
	plan, sub, err := e.PlanForOrg(context.Background(), org)
	if err != nil || plan == nil || sub != nil {
		t.Fatalf("plan=%v sub=%v err=%v", plan, sub, err)
	}
	if err := e.EnforceDocumentQuota(context.Background(), org); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("quota bypass: %v", err)
	}
	if allowed, err := e.HasFeature(context.Background(), org, "aes"); err != nil || allowed {
		t.Fatalf("feature bypass: %v %v", allowed, err)
	}
	if _, _, err := e.PlanForOrg(context.Background(), uuid.New()); !errors.Is(err, ErrEntitlementUnavailable) {
		t.Fatalf("unassigned organization accepted: %v", err)
	}
	if err := e.EnforceDocumentQuotaMutation(context.Background(), generated.New(db), org); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("transaction lost internal entitlement: %v", err)
	}
}
func TestOperatorAllPaymentEntryPointsRejectBeforeDatabase(t *testing.T) {
	e := NewOperator(nil, nil)
	ctx := context.Background()
	if e.PaymentsEnabled() {
		t.Fatal("payments enabled")
	}
	if _, err := e.StartCheckout(ctx, StartCheckoutInput{}); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if _, err := e.CompletePreparedCheckout(ctx, PreparedCheckout{}); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if err := e.CancelAtPeriodEnd(ctx, uuid.New()); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if err := e.HandleWebhook(ctx, []byte(`{"kind":"invoice.paid"}`), nil); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if _, err := e.Provider.CreateSubscription(ctx, SubscriptionInput{}); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if _, err := e.GetSubscription(ctx, uuid.New()); !errors.Is(err, ErrSubscriptionNone) {
		t.Fatal(err)
	}
}
func TestOperatorUnavailablePlanFailsClosed(t *testing.T) {
	org := uuid.New()
	e := NewOperator(generated.New(&quotaDB{planErr: errors.New("db unavailable")}), []config.OperatorEntitlement{{OrgID: org, PlanSlug: "internal", ReviewRef: "review-1"}})
	if err := e.EnforceDocumentQuota(context.Background(), org); !errors.Is(err, ErrEntitlementUnavailable) {
		t.Fatal(err)
	}
}
func TestOperatorPeriodUTCMonthAndSaaSCompatibility(t *testing.T) {
	now := time.Date(2026, 10, 1, 1, 0, 0, 0, time.FixedZone("east", 7200))
	e := NewOperator(nil, nil)
	start, end := e.QuotaPeriod(nil, now)
	if start != time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) || end != time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("%v %v", start, end)
	}
	normal := New(nil, MockProvider{}, "", "")
	if !normal.PaymentsEnabled() {
		t.Fatal("legacy payment mode disabled")
	}
	start, end = normal.QuotaPeriod(nil, now)
	wantStart, wantEnd := quotaPeriod(nil, now)
	if !start.Equal(wantStart) || !end.Equal(wantEnd) {
		t.Fatal("changed existing SaaS quota window")
	}
}

type operatorFeatureDB struct {
	quotaDB
	features string
}

func (db *operatorFeatureDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	row := db.quotaDB.QueryRow(ctx, query, args...)
	if strings.Contains(query, "GetBillingPlanBySlug") {
		r := row.(quotaRow)
		r.values[9] = json.RawMessage(db.features)
		return r
	}
	return row
}
func TestOperatorMalformedFeatureGrantsFailClosed(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"mcp":"yes"}`, `{"mcp":true,"evidence_bundle":1}`, `{"mcp":null}`, `{"mcp":true,"evidence_bundle":null}`} {
		org := uuid.New()
		db := &operatorFeatureDB{features: raw}
		e := NewOperator(generated.New(db), []config.OperatorEntitlement{{OrgID: org, PlanSlug: "free", ReviewRef: "review"}})
		if _, _, err := e.PlanForOrg(context.Background(), org); !errors.Is(err, ErrEntitlementUnavailable) {
			t.Fatalf("accepted features %s: %v", raw, err)
		}
	}
}
