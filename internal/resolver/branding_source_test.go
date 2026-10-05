// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type brandingSourceStore struct {
	org uuid.UUID
	row *generated.OrgBranding
	err error
}

func (s *brandingSourceStore) GetOrg(context.Context, uuid.UUID) (*generated.Org, error) {
	return nil, errors.New("unexpected org lookup")
}
func (s *brandingSourceStore) GetOrgBranding(_ context.Context, org uuid.UUID) (*generated.OrgBranding, error) {
	s.org = org
	return s.row, s.err
}

func TestOrgSettingBrandingReadsTenantFields(t *testing.T) {
	org := uuid.New()
	store := &brandingSourceStore{row: &generated.OrgBranding{OrgID: org, PrimaryHex: "#112233", AccentHex: "#445566", SurfaceHex: "#ffffff", TextHex: "#000000", MutedHex: "#999999", LogoUrl: "/branding/logo/example.png", LogoAlt: "Brand", FontHeading: "Inter", FontBody: "Geist", SignatureColor: "#123456"}}
	source := &OrgSettingSource{Q: store}
	for field, want := range map[string]string{"primary_hex": "#112233", "accent_hex": "#445566", "surface_hex": "#ffffff", "text_hex": "#000000", "muted_hex": "#999999", "logo_url": "/branding/logo/example.png", "logo_alt": "Brand", "font_heading": "Inter", "font_body": "Geist", "signature_color": "#123456"} {
		got, err := source.Fetch(context.Background(), Ref{OrgID: org, Source: "ignored unrelated org ID", Path: "branding." + field})
		if err != nil || got != want || store.org != org {
			t.Fatalf("field=%s value=%q tenant=%s error=%v", field, got, store.org, err)
		}
	}
	if _, err := source.Fetch(context.Background(), Ref{OrgID: org, Path: "branding.secret"}); err == nil {
		t.Fatal("unknown field accepted")
	}
	store.row.OrgID = uuid.New()
	if _, err := source.Fetch(context.Background(), Ref{OrgID: org, Path: "branding.primary_hex"}); err == nil {
		t.Fatal("different tenant row accepted")
	}
}

func TestOrgSettingBrandingMissingIsNotConfigured(t *testing.T) {
	source := &OrgSettingSource{Q: &brandingSourceStore{err: pgx.ErrNoRows}}
	if _, err := source.Fetch(context.Background(), Ref{OrgID: uuid.New(), Path: "branding.primary_hex"}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("error=%v", err)
	}
	if _, err := source.Fetch(context.Background(), Ref{Path: "branding.primary_hex"}); err == nil {
		t.Fatal("missing tenant accepted")
	}
}
