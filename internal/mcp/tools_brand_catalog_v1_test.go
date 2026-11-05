// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/branding/catalog"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/google/uuid"
)

func TestBrandCatalog783ScanFailureKeepsSafeSentinelAndAuthorization(t *testing.T) {
	private := "private-provider-object/version/path and scanner detail"
	for _, row := range []struct {
		name string
		in   error
		want error
	}{
		{"none", nil, nil},
		{"detected", malwarescan.ErrDetected, malwarescan.ErrDetected},
		{"wrapped-detected", fmt.Errorf("%s: %w", private, malwarescan.ErrDetected), malwarescan.ErrDetected},
		{"unavailable", malwarescan.ErrUnavailable, malwarescan.ErrUnavailable},
		{"wrapped-unavailable", fmt.Errorf("%s: %w", private, malwarescan.ErrUnavailable), malwarescan.ErrUnavailable},
		{"unknown", errors.New(private), catalog.ErrUnavailableV1},
		{"revoked", fmt.Errorf("%s: %w", private, auth.ErrMutationPermissionRevoked), auth.ErrMutationPermissionRevoked},
		{"expired", fmt.Errorf("%s: %w", private, auth.ErrMutationCredentialExpired), auth.ErrMutationCredentialExpired},
		{"input", fmt.Errorf("%s: %w", private, catalog.ErrInputV1), catalog.ErrInputV1},
		{"conflict", fmt.Errorf("%s: %w", private, catalog.ErrConflictV1), catalog.ErrConflictV1},
		{"not-found", fmt.Errorf("%s: %w", private, catalog.ErrNotFoundV1), catalog.ErrNotFoundV1},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := brandCatalogFailureV1(row.in)
			if got != row.want {
				t.Fatal("catalog failure lost its safe fixed classification")
			}
			if got != nil && (sanitizeToolError(got) != row.want.Error() || strings.Contains(sanitizeToolError(got), private)) {
				t.Fatal("catalog tool response exposed wrapped provider data")
			}
		})
	}
}

// Metadata service fixture only: binary resolution is deliberately absent, so
// accidental storage/base64 reads through the discovery tool fail the test.
type catalogDiscovery783 struct {
	catalog.BrandProfilesV1
	profile catalog.ProfileV1
	reads   []uuid.UUID
	bytes   int64
}

func (d *catalogDiscovery783) GetProfileV1(_ context.Context, _ authoring.Actor, id uuid.UUID, revision int64) (catalog.ProfileV1, error) {
	if id != d.profile.ProfileID || revision != d.profile.Revision {
		return catalog.ProfileV1{}, catalog.ErrNotFoundV1
	}
	return d.profile, nil
}
func (d *catalogDiscovery783) GetAssetV1(_ context.Context, _ authoring.Actor, id uuid.UUID, revision int64) (catalog.AssetV1, error) {
	d.reads = append(d.reads, id)
	return catalog.AssetV1{AssetID: id, Revision: revision, Original: catalog.ObjectV1{VersionID: "private-original-version", SHA256: strings.Repeat("a", 64), Bytes: 100, MediaType: "image/svg+xml"}, Render: catalog.ObjectV1{VersionID: "private-render-version", SHA256: strings.Repeat("b", 64), Bytes: d.bytes, MediaType: "image/png", Width: 256, Height: 256}}, nil
}
func TestBrandCatalog783MetadataDiscoveryExactSelectedSlots(t *testing.T) {
	d := &catalogDiscovery783{profile: catalog.ProfileV1{ProfileRefV1: catalog.ProfileRefV1{ProfileID: uuid.New(), Revision: 3, ContentSHA256: strings.Repeat("c", 64)}}, bytes: 100}
	for i := 0; i < 49; i++ {
		d.profile.Profile.Assets = append(d.profile.Profile.Assets, catalog.AssetRefV1{Slot: fmt.Sprintf("variant_%02d", i), AssetID: uuid.New(), Revision: 1})
	}
	p := brandCatalogArgsV1{ProfileID: d.profile.ProfileID, Revision: 3, ContentSHA256: d.profile.ContentSHA256}
	if _, err := describeBrandDesignAssetsV1(context.Background(), d, DesignActorV1{}, p); err == nil || len(d.reads) != 0 {
		t.Fatal("49-asset profile silently expanded without explicit selection")
	}
	p.AssetSlots = []string{}
	if _, err := describeBrandDesignAssetsV1(context.Background(), d, DesignActorV1{}, p); err != nil || len(d.reads) != 0 {
		t.Fatal("explicit empty selection did not remain empty", err)
	}
	p.AssetSlots = []string{"variant_02", "variant_07"}
	value, err := describeBrandDesignAssetsV1(context.Background(), d, DesignActorV1{}, p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.reads) != 2 || d.reads[0] != d.profile.Profile.Assets[2].AssetID || d.reads[1] != d.profile.Profile.Assets[7].AssetID {
		t.Fatal("discovery read unselected asset revisions")
	}
	if strings.Contains(string(raw), "base64") || strings.Contains(string(raw), "private-") || !strings.Contains(string(raw), "hash-asset:brand_variant_02") {
		t.Fatal("discovery exposed binary/storage identity or lost opaque asset name")
	}
	p.ContentSHA256 = strings.Repeat("d", 64)
	if _, err = describeBrandDesignAssetsV1(context.Background(), d, DesignActorV1{}, p); err == nil {
		t.Fatal("mismatched profile content commitment accepted")
	}
}
func TestBrandCatalog783MetadataProjectionAndTotalMasterLimit(t *testing.T) {
	d := &catalogDiscovery783{profile: catalog.ProfileV1{ProfileRefV1: catalog.ProfileRefV1{ProfileID: uuid.New(), Revision: 1, ContentSHA256: strings.Repeat("a", 64)}}, bytes: htmlmaster.MaxAssetBytes}
	for i := 0; i < 5; i++ {
		d.profile.Profile.Assets = append(d.profile.Profile.Assets, catalog.AssetRefV1{Slot: fmt.Sprintf("logo_%d", i), AssetID: uuid.New(), Revision: 1})
	}
	p := brandCatalogArgsV1{ProfileID: d.profile.ProfileID, Revision: 1, ContentSHA256: d.profile.ContentSHA256}
	if _, err := describeBrandDesignAssetsV1(context.Background(), d, DesignActorV1{}, p); err == nil {
		t.Fatal("selected total exceeded native 8MiB master cap")
	}
	asset, _ := d.GetAssetV1(context.Background(), authoring.Actor{}, uuid.New(), 1)
	raw, _ := json.Marshal(publicBrandAssetV1(asset))
	if strings.Contains(string(raw), "version_id") || strings.Contains(string(raw), "private-") {
		t.Fatal("storage version identifiers exposed")
	}
	s := New(Deps{})
	for _, name := range []string{"list_brand_profiles", "get_brand_profile", "get_default_brand_profile", "save_brand_profile", "list_brand_profile_revisions", "select_default_brand_profile", "list_brand_assets", "get_brand_asset", "list_brand_asset_revisions", "get_brand_asset_upload", "upload_brand_asset", "resolve_brand_design_assets"} {
		tool, ok := s.tools[name]
		if !ok || mcpToolRequiredScopes[name] == "" || tool.InputSchema["additionalProperties"] != false || docScopeSafeTools[name] {
			t.Fatal("catalog tool unclassified/open/document-scoped", name)
		}
		if tool.Write && (string(tool.MinRole) != "owner" || tool.MinFeature != "branding") {
			t.Fatal("catalog mutation lost owner/plan gate", name)
		}
	}
}
