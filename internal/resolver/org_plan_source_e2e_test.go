//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOrgPlanSourceUsesReviewedOperatorEntitlementsE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("HASH_E2E_DB_URL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Effective plan resolver fixture", Plan: "free"})
	if err != nil {
		t.Fatal(err)
	}
	slug := "resolver-operator-" + uuid.NewString()
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := pool.Exec(cleanup, `DELETE FROM orgs WHERE id=$1`, org.ID); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(cleanup, `DELETE FROM billing_plans WHERE slug=$1`, slug); err != nil {
			t.Error(err)
		}
	}()
	if _, err := pool.Exec(ctx, `INSERT INTO billing_plans (slug,name,document_quota_monthly,recipient_quota_monthly,features_json) VALUES ($1,'Resolver test',25,100,'{"mcp":true}')`, slug); err != nil {
		t.Fatal(err)
	}
	engine := billing.NewOperator(q, []config.OperatorEntitlement{{OrgID: org.ID, PlanSlug: slug, ReviewRef: "synthetic reviewed resolver test"}})
	if err := engine.ValidateOperatorPlans(ctx); err != nil {
		t.Fatal(err)
	}
	source := &OrgSettingSource{Q: q, Plans: engine}
	ref := Ref{OrgID: org.ID, Path: "org.plan"}
	got, err := source.Fetch(ctx, ref)
	if err != nil || got != slug {
		t.Fatalf("effective plan=%q error=%v", got, err)
	}
	// Revoking the operator assignment must not fall back to orgs.plan=free.
	source.Plans = billing.NewOperator(q, nil)
	if got, err := source.Fetch(ctx, ref); err == nil || got != "" {
		t.Fatalf("unapproved plan=%q error=%v", got, err)
	}
	source.Plans = engine
	if _, err := pool.Exec(ctx, `UPDATE billing_plans SET document_quota_monthly=0 WHERE slug=$1`, slug); err != nil {
		t.Fatal(err)
	}
	if got, err := source.Fetch(ctx, ref); err == nil || got != "" {
		t.Fatalf("invalid operator quota plan=%q error=%v", got, err)
	}
}
