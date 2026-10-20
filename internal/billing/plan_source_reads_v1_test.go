// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package billing

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Pure decision oracle only. Actual measured/native SQL ownership is qualified
// separately; these complete model fixtures grant no work or source authority.
type planSourceOracleDBV1 struct {
	quotaDB
	plan                *generated.BillingPlan
	subscription        *generated.OrgSubscription
	subErr, readPlanErr error
	calls               []string
}

func planSourceOracleRowV1(model any) quotaRow {
	value := reflect.ValueOf(model).Elem()
	fields := make([]any, value.NumField())
	for i := range fields {
		fields[i] = value.Field(i).Interface()
	}
	return quotaRow{values: fields}
}
func (db *planSourceOracleDBV1) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	switch {
	case strings.Contains(query, "GetOrgSubscription"):
		db.calls = append(db.calls, "subscription")
		if db.subErr != nil {
			return quotaRow{err: db.subErr}
		}
		if db.subscription == nil {
			return quotaRow{err: pgx.ErrNoRows}
		}
		return planSourceOracleRowV1(db.subscription)
	case strings.Contains(query, "GetBillingPlanBySlug"):
		db.calls = append(db.calls, "slug:"+args[0].(string))
	case strings.Contains(query, "GetBillingPlanByID"):
		db.calls = append(db.calls, "id:"+args[0].(uuid.UUID).String())
	default:
		return quotaRow{err: errors.New("unexpected pure oracle query")}
	}
	if db.readPlanErr != nil {
		return quotaRow{err: db.readPlanErr}
	}
	if db.plan == nil {
		return quotaRow{err: pgx.ErrNoRows}
	}
	return planSourceOracleRowV1(db.plan)
}
func TestPlanForOrgOwnedReadDependencyMatchesOriginalV1(t *testing.T) {
	org, planID := uuid.New(), uuid.New()
	now := time.Now().UTC()
	dbFailure := errors.New("synthetic source read failure")
	cases := []struct {
		name, status, features     string
		operator, assigned, active bool
		docQuota, recipientQuota   int32
		period                     time.Duration
		subErr, planErr            error
	}{
		{name: "free_no_subscription", active: true},
		{name: "free_plan_failure", planErr: dbFailure},
		{name: "subscription_failure", subErr: dbFailure},
		{name: "expired", status: "active", active: true, period: -time.Hour},
		{name: "unpaid", status: "unpaid", active: true, period: time.Hour},
		{name: "active", status: "active", active: true, period: time.Hour},
		{name: "trialing", status: "trialing", active: true, period: time.Hour},
		{name: "cancelled_still_entitled", status: "cancelled", active: true, period: time.Hour},
		{name: "entitled_plan_failure", status: "active", period: time.Hour, planErr: dbFailure},
		{name: "operator_valid", operator: true, assigned: true, active: true, docQuota: 10, recipientQuota: 20, features: `{"mcp":true,"aes":false}`},
		{name: "operator_unassigned", operator: true, active: true, docQuota: 10, recipientQuota: 20, features: `{}`},
		{name: "operator_inactive", operator: true, assigned: true, docQuota: 10, recipientQuota: 20, features: `{}`},
		{name: "operator_unbounded_docs", operator: true, assigned: true, active: true, recipientQuota: 20, features: `{}`},
		{name: "operator_unbounded_recipients", operator: true, assigned: true, active: true, docQuota: 10, features: `{}`},
		{name: "operator_features_null", operator: true, assigned: true, active: true, docQuota: 10, recipientQuota: 20, features: `null`},
		{name: "operator_feature_null", operator: true, assigned: true, active: true, docQuota: 10, recipientQuota: 20, features: `{"mcp":null}`},
		{name: "operator_feature_number", operator: true, assigned: true, active: true, docQuota: 10, recipientQuota: 20, features: `{"mcp":1}`},
		{name: "operator_feature_string", operator: true, assigned: true, active: true, docQuota: 10, recipientQuota: 20, features: `{"mcp":"true"}`},
		{name: "operator_feature_array", operator: true, assigned: true, active: true, docQuota: 10, recipientQuota: 20, features: `[]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db := &planSourceOracleDBV1{plan: &generated.BillingPlan{ID: planID, Slug: "actual-plan", Name: "Actual complete fixture", Active: c.active, DocumentQuotaMonthly: c.docQuota, RecipientQuotaMonthly: c.recipientQuota, FeaturesJson: json.RawMessage(c.features)}, subErr: c.subErr, readPlanErr: c.planErr}
			if c.status != "" {
				db.subscription = &generated.OrgSubscription{ID: uuid.New(), OrgID: org, PlanID: planID, Status: c.status, CurrentPeriodEnd: pgtype.Timestamptz{Time: now.Add(c.period), Valid: true}}
			}
			queries := generated.New(db)
			engine := New(queries, nil, "", "")
			if c.operator {
				var grants []config.OperatorEntitlement
				if c.assigned {
					grants = []config.OperatorEntitlement{{OrgID: org, PlanSlug: "actual-plan", ReviewRef: "synthetic decision oracle"}}
				}
				engine = NewOperator(queries, grants)
			}
			expectedPlan, expectedSub, expectedErr := engine.PlanForOrg(context.Background(), org)
			expectedCalls := append([]string(nil), db.calls...)
			db.calls = nil
			actualPlan, actualSub, actualErr := engine.PlanForOrgWithReadsV1(context.Background(), org, queries)
			if !reflect.DeepEqual(expectedPlan, actualPlan) || !reflect.DeepEqual(expectedSub, actualSub) || !reflect.DeepEqual(expectedCalls, db.calls) {
				t.Fatalf("complete result/query order changed: original%+v/%+v/%v owned%+v/%+v/%v", expectedPlan, expectedSub, expectedCalls, actualPlan, actualSub, db.calls)
			}
			if (expectedErr == nil) != (actualErr == nil) {
				t.Fatalf("original%v owned%v", expectedErr, actualErr)
			}
			if expectedErr != nil && (expectedErr.Error() != actualErr.Error() || errors.Is(expectedErr, dbFailure) != errors.Is(actualErr, dbFailure)) {
				t.Fatalf("error/cause changed: original%v owned%v", expectedErr, actualErr)
			}
		})
	}
	engine := New(generated.New(&quotaDB{}), nil, "", "")
	if _, _, err := engine.PlanForOrgWithReadsV1(context.Background(), org, nil); !errors.Is(err, ErrEntitlementUnavailable) {
		t.Fatal("missing native read dependency accepted", err)
	}
}
