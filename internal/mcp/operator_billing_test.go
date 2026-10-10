// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
)

type operatorObservabilityDB struct{ reads int }

func (*operatorObservabilityDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected mutation")
}
func (*operatorObservabilityDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected invoice/catalog query")
}
func (d *operatorObservabilityDB) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	d.reads++
	if !strings.Contains(query, "GetBillingPlanBySlug") {
		return operatorObservabilityRow{err: errors.New("unexpected subscription query")}
	}
	return operatorObservabilityRow{values: []any{uuid.New(), "internal-sales", "Internal Sales", "Reviewed", int32(0), int32(0), "EUR", int32(31000), int32(62000), json.RawMessage(`{"mcp":true,"evidence_bundle":true}`), true, int32(10), pgtype.Timestamptz{}}}
}

type operatorObservabilityRow struct {
	values []any
	err    error
}

func (r operatorObservabilityRow) Scan(dst ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dst) != len(r.values) {
		return errors.New("incorrect plan scan")
	}
	for i := range dst {
		reflect.ValueOf(dst[i]).Elem().Set(reflect.ValueOf(r.values[i]))
	}
	return nil
}
func TestOperatorBillingRegisteredObservabilityHandlers(t *testing.T) {
	org := uuid.New()
	db := &operatorObservabilityDB{}
	engine := billing.NewOperator(generated.New(db), []config.OperatorEntitlement{{OrgID: org, PlanSlug: "internal-sales", ReviewRef: "approved-run"}})
	s := NewServer()
	registerBillingTools(s, Deps{Billing: engine})
	ctx := context.WithValue(context.Background(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	req := httptest.NewRequest("POST", "/mcp", nil).WithContext(ctx)
	for _, name := range []string{"list_billing_plans", "get_org_subscription", "list_billing_invoices"} {
		value, err := s.tools[name].Handler(req, json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		result := value.(map[string]any)
		if result["provider"] != "operator" || result["payments_enabled"] != false {
			t.Fatalf("missing mode metadata: %#v", result)
		}
		if name == "get_org_subscription" {
			if result["subscription"] != nil || result["plan"].(map[string]any)["slug"] != "internal-sales" {
				t.Fatalf("fake subscription/free fallback: %#v", result)
			}
		} else if result["count"] != 0 {
			t.Fatalf("fake payments/catalog: %#v", result)
		}
	}
	if db.reads != 1 {
		t.Fatalf("unexpected subscription/payment reads: %d", db.reads)
	}
	otherCtx := context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	if _, err := s.tools["get_org_subscription"].Handler(req.WithContext(otherCtx), json.RawMessage(`{}`)); !errors.Is(err, billing.ErrEntitlementUnavailable) {
		t.Fatalf("unassigned org accepted: %v", err)
	}
}
