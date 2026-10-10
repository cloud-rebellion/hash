// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

type orgPlanStore struct {
	org       *generated.Org
	plan      *generated.BillingPlan
	sub       *generated.OrgSubscription
	err       error
	requested uuid.UUID
	lookups   int
}

func (s *orgPlanStore) GetOrg(context.Context, uuid.UUID) (*generated.Org, error) { return s.org, nil }
func (s *orgPlanStore) GetOrgBranding(context.Context, uuid.UUID) (*generated.OrgBranding, error) {
	return nil, errors.New("unexpected branding lookup")
}
func (s *orgPlanStore) PlanForOrg(_ context.Context, id uuid.UUID) (*generated.BillingPlan, *generated.OrgSubscription, error) {
	s.requested = id
	s.lookups++
	return s.plan, s.sub, s.err
}

func TestOrgPlanSourceUsesEffectiveAuthority(t *testing.T) {
	id := uuid.New()
	store := &orgPlanStore{org: &generated.Org{ID: id, Name: "Company", Plan: "stale-legacy-plan"}, plan: &generated.BillingPlan{Slug: "approved-operator", Active: true}}
	source := &OrgSettingSource{Q: store, Plans: store}
	got, err := source.Fetch(context.Background(), Ref{OrgID: id, Source: uuid.NewString(), Path: "org.plan"})
	if err != nil || got != "approved-operator" || store.requested != id {
		t.Fatalf("value=%q tenant=%s error=%v", got, store.requested, err)
	}
	for path, want := range map[string]string{"org.name": "Company", "org.id": id.String()} {
		got, err := source.Fetch(context.Background(), Ref{OrgID: id, Path: path})
		if err != nil || got != want {
			t.Fatalf("path=%s value=%q error=%v", path, got, err)
		}
	}
	if store.lookups != 1 {
		t.Fatalf("unnecessary entitlement lookups=%d", store.lookups)
	}
}

func TestOrgPlanSourceRefusesMissingStaleOrForeignAuthority(t *testing.T) {
	id := uuid.New()
	for _, tc := range []struct {
		name      string
		configure func(*orgPlanStore, *OrgSettingSource)
	}{
		{"missing plan authority", func(_ *orgPlanStore, s *OrgSettingSource) { s.Plans = nil }},
		{"dependency failure", func(s *orgPlanStore, _ *OrgSettingSource) { s.err = errors.New("secret upstream diagnostic") }},
		{"missing plan", func(s *orgPlanStore, _ *OrgSettingSource) { s.plan = nil }},
		{"inactive plan", func(s *orgPlanStore, _ *OrgSettingSource) { s.plan.Active = false }},
		{"empty plan", func(s *orgPlanStore, _ *OrgSettingSource) { s.plan.Slug = " " }},
		{"foreign subscription", func(s *orgPlanStore, _ *OrgSettingSource) { s.sub = &generated.OrgSubscription{OrgID: uuid.New()} }},
		{"foreign organization", func(s *orgPlanStore, _ *OrgSettingSource) { s.org.ID = uuid.New() }},
		{"missing organization", func(s *orgPlanStore, _ *OrgSettingSource) { s.org = nil }},
		{"missing store", func(_ *orgPlanStore, s *OrgSettingSource) { s.Q = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &orgPlanStore{org: &generated.Org{ID: id, Plan: "stale-legacy-plan"}, plan: &generated.BillingPlan{Slug: "approved-operator", Active: true}}
			source := &OrgSettingSource{Q: store, Plans: store}
			tc.configure(store, source)
			got, err := source.Fetch(context.Background(), Ref{OrgID: id, Path: "org.plan"})
			if err == nil || got != "" || strings.Contains(err.Error(), "secret upstream diagnostic") {
				t.Fatalf("unsafe value=%q error=%v", got, err)
			}
		})
	}
}
