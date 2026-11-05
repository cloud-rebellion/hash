// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/branding/catalog"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/google/uuid"
	"net/http"
)

type brandCatalogArgsV1 struct {
	RequestID                 uuid.UUID       `json:"request_id,omitempty"`
	ProfileID                 uuid.UUID       `json:"profile_id,omitempty"`
	AssetID                   uuid.UUID       `json:"asset_id,omitempty"`
	Revision                  int64           `json:"revision,omitempty"`
	ContentSHA256             string          `json:"content_sha256,omitempty"`
	AssetSlots                []string        `json:"asset_slots,omitempty"`
	ExpectedSelectionRevision int64           `json:"expected_selection_revision,omitempty"`
	BeforeRevision            int64           `json:"before_revision,omitempty"`
	Limit                     int             `json:"limit,omitempty"`
	AfterID                   uuid.UUID       `json:"after_id,omitempty"`
	Input                     json.RawMessage `json:"input,omitempty"`
}

func publicBrandAssetV1(a catalog.AssetV1) map[string]any {
	object := func(v catalog.ObjectV1) map[string]any {
		return map[string]any{"sha256": v.SHA256, "bytes": v.Bytes, "media_type": v.MediaType, "width": v.Width, "height": v.Height}
	}
	return map[string]any{"asset_id": a.AssetID, "revision": a.Revision, "name": a.Name, "original": object(a.Original), "render": object(a.Render), "render_method": a.RenderMethod, "created_at": a.CreatedAt, "html_usable": a.Render.MediaType == "image/png" && a.Render.Bytes > 0 && a.Render.Bytes <= htmlmaster.MaxAssetBytes, "original_is_html_asset": false}
}
func brandCatalogFailureV1(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{catalog.ErrInputV1, catalog.ErrConflictV1, catalog.ErrNotFoundV1, malwarescan.ErrUnavailable, malwarescan.ErrDetected, auth.ErrMutationPermissionRevoked, auth.ErrMutationCredentialExpired, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	return catalog.ErrUnavailableV1
}
func registerBrandCatalogToolsV1(s *Server, d Deps) {
	for _, item := range []struct {
		name, description string
		write             bool
	}{
		{"list_brand_profiles", "Discover versioned brand profiles in this organization. Returns exact profile revision/content commitments; no customer or vendor defaults are inserted.", false},
		{"get_brand_profile", "Read a complete brand profile: semantic palette, typography, spacing, voice/usage guidance, asset slots and exact asset revisions. revision=0 reads current; use exact returned pins for design creation.", false},
		{"get_default_brand_profile", "Read the exact currently selected default profile revision and selection revision. Selection is explicit; no silent profile creation or default change occurs.", false},
		{"save_brand_profile", "OWNER: create or revise a complete brand profile using expected_revision CAS. No default selection, document rewrite, logo upload or Send occurs.", true},
		{"list_brand_profile_revisions", "Read retained immutable revisions of a brand profile.", false},
		{"select_default_brand_profile", "OWNER: explicitly select an exact profile revision as the organization default using expected_selection_revision CAS. Updates future defaults; existing frozen documents/artifacts remain unchanged.", true},
		{"list_brand_assets", "Discover versioned original assets and safe PNG render variants. SVG/oversized originals are retained source assets, not automatically usable HTML. No storage URLs/keys are returned.", false},
		{"get_brand_asset", "Read exact asset original/render metadata. Use asset_id/revision opaque refs. Original SVG is never inline arbitrary SVG in an HTML master.", false},
		{"list_brand_asset_revisions", "Read retained original/render metadata for immutable asset revisions.", false},
		{"get_brand_asset_upload", "OWNER: inspect one exact request_id after an uncertain upload acknowledgement. Reports state without upload, resume, mutation or retry authorization.", false},
		{"upload_brand_asset", "OWNER: retain an exact original asset and optional safe PNG render variant at a new revision. Preserve original bytes; server validates limits. Supply request_id and expected_revision; omitted asset_id creates a new asset. No external fetch or document mutation. The MCP request-size limit still applies.", true},
		{"resolve_brand_design_assets", "Inspect selected usable asset slots from an EXACT profile revision/content hash. Returns opaque refs, brand_<slot> names and safe PNG metadata, not binary bytes. Pass the same profile/asset_slots to create/update_design_template for server-side verified asset resolution before native admission.", false},
	} {
		item := item
		props := map[string]any{"request_id": stringSchema("exact upload request UUID"), "profile_id": stringSchema("profile UUID"), "asset_id": stringSchema("asset UUID"), "revision": map[string]any{"type": "integer", "minimum": 0}, "content_sha256": stringSchema("exact lowercase profile content SHA-256"), "asset_slots": map[string]any{"type": "array", "maxItems": 16, "items": map[string]any{"type": "string"}}, "expected_selection_revision": map[string]any{"type": "integer", "minimum": 0}, "before_revision": map[string]any{"type": "integer", "minimum": 0}, "limit": intSchema("maximum rows", 1, catalog.MaxCatalogPageV1, catalog.MaxCatalogPageV1), "after_id": stringSchema("pagination UUID"), "input": map[string]any{"type": "object", "description": "Complete typed profile {name,expected_revision,profile}, or asset {request_id,asset_id,expected_revision,name,media_type,original_base64,render_png_base64}"}}
		required := []string{}
		switch item.name {
		case "get_brand_profile", "list_brand_profile_revisions":
			required = []string{"profile_id"}
		case "list_brand_asset_revisions":
			required = []string{"asset_id"}
		case "get_brand_asset_upload":
			required = []string{"request_id"}
		case "get_brand_asset":
			required = []string{"asset_id", "revision"}
		case "save_brand_profile", "upload_brand_asset":
			required = []string{"input"}
		case "select_default_brand_profile":
			required = []string{"profile_id", "revision", "content_sha256", "expected_selection_revision"}
		case "resolve_brand_design_assets":
			required = []string{"profile_id", "revision", "content_sha256"}
		}
		keys := map[string][]string{
			"list_brand_profiles": {"limit", "after_id"}, "get_brand_profile": {"profile_id", "revision"}, "get_default_brand_profile": {},
			"save_brand_profile": {"profile_id", "input"}, "list_brand_profile_revisions": {"profile_id", "before_revision", "limit"},
			"select_default_brand_profile": {"profile_id", "revision", "content_sha256", "expected_selection_revision"},
			"list_brand_assets":            {"limit", "after_id"}, "get_brand_asset": {"asset_id", "revision"}, "upload_brand_asset": {"input"},
			"list_brand_asset_revisions": {"asset_id", "before_revision", "limit"}, "get_brand_asset_upload": {"request_id"},
			"resolve_brand_design_assets": {"profile_id", "revision", "content_sha256", "asset_slots"},
		}[item.name]
		closed := map[string]any{}
		for _, key := range keys {
			closed[key] = props[key]
		}
		props = closed
		tool := ToolDef{Name: item.name, Description: item.description, Write: item.write, InputSchema: schemaObject(props, required)}
		tool.InputSchema["additionalProperties"] = false
		if item.write {
			tool.MinRole = auth.RoleOwner
			tool.MinFeature = "branding"
		}
		if item.name == "get_brand_asset_upload" {
			tool.MinRole = auth.RoleOwner
		}
		tool.Handler = func(r *http.Request, raw json.RawMessage) (result any, failure error) {
			var release func()
			defer func() {
				failure = brandCatalogFailureV1(failure)
				if release != nil {
					result = &designOwnedResultV1{state: &designOwnedStateV1{value: result, release: release}}
				}
			}()
			if d.BrandCatalog == nil {
				return nil, catalog.ErrUnavailableV1
			}
			a, err := designActorV1(r.Context(), uuid.Nil, item.write)
			if err != nil {
				return nil, err
			}
			call := r.Context()
			if item.name == "upload_brand_asset" {
				call, release, err = catalog.AcquireInputV1(call, a.OrgID)
				if err != nil {
					return nil, err
				}
			}
			var p brandCatalogArgsV1
			if err := designObjectShapeV1(raw, props, required); err != nil {
				return nil, catalog.ErrInputV1
			}
			if err := designDecodeV1(raw, &p); err != nil {
				return nil, catalog.ErrInputV1
			}
			ref := catalog.ProfileRefV1{ProfileID: p.ProfileID, Revision: p.Revision, ContentSHA256: p.ContentSHA256, AssetSlots: p.AssetSlots}
			switch item.name {
			case "list_brand_profiles":
				v, e := d.BrandCatalog.ListProfilesV1(r.Context(), a.Actor, p.Limit, p.AfterID)
				return map[string]any{"profiles": v}, e
			case "get_brand_profile":
				return d.BrandCatalog.GetProfileV1(r.Context(), a.Actor, p.ProfileID, p.Revision)
			case "get_default_brand_profile":
				return d.BrandCatalog.GetDefaultV1(r.Context(), a.Actor)
			case "save_brand_profile":
				var v catalog.ProfileInputV1
				if err = designDecodeV1(p.Input, &v); err != nil {
					return nil, catalog.ErrInputV1
				}
				return d.BrandCatalog.SaveProfileV1(r.Context(), a.Actor, p.ProfileID, v)
			case "list_brand_profile_revisions":
				v, e := d.BrandCatalog.ListProfileRevisionsV1(r.Context(), a.Actor, p.ProfileID, p.BeforeRevision, p.Limit)
				return map[string]any{"revisions": v}, e
			case "select_default_brand_profile":
				return d.BrandCatalog.SelectDefaultV1(r.Context(), a.Actor, ref, p.ExpectedSelectionRevision)
			case "list_brand_assets":
				v, e := d.BrandCatalog.ListAssetsV1(r.Context(), a.Actor, p.Limit, p.AfterID)
				out := make([]map[string]any, 0, len(v))
				for _, asset := range v {
					out = append(out, publicBrandAssetV1(asset))
				}
				return map[string]any{"assets": out}, e
			case "get_brand_asset":
				v, e := d.BrandCatalog.GetAssetV1(r.Context(), a.Actor, p.AssetID, p.Revision)
				if e != nil {
					return nil, e
				}
				return publicBrandAssetV1(v), nil
			case "list_brand_asset_revisions":
				v, e := d.BrandCatalog.ListAssetRevisionsV1(call, a.Actor, p.AssetID, p.BeforeRevision, p.Limit)
				out := make([]map[string]any, 0, len(v))
				for _, asset := range v {
					out = append(out, publicBrandAssetV1(asset))
				}
				return map[string]any{"revisions": out}, e
			case "get_brand_asset_upload":
				v, e := d.BrandCatalog.GetUploadStatusV1(call, a.Actor, p.RequestID)
				if e != nil {
					return nil, e
				}
				return map[string]any{"upload": v, "retry_authorized": false}, nil
			case "upload_brand_asset":
				var v catalog.AssetUploadV1
				if err = designDecodeV1(p.Input, &v); err != nil {
					return nil, catalog.ErrInputV1
				}
				asset, e := d.BrandCatalog.UploadAssetV1(call, a.Actor, v)
				if e != nil {
					return nil, e
				}
				return publicBrandAssetV1(asset), nil
			case "resolve_brand_design_assets":
				return describeBrandDesignAssetsV1(r.Context(), d.BrandCatalog, a, p)
			}
			return nil, catalog.ErrInputV1
		}
		s.RegisterTool(tool)
	}
}
func describeBrandDesignAssetsV1(ctx context.Context, s catalog.BrandProfilesV1, a DesignActorV1, p brandCatalogArgsV1) (any, error) {
	if p.ProfileID == uuid.Nil || p.Revision < 1 || len(p.ContentSHA256) != 64 {
		return nil, catalog.ErrInputV1
	}
	profile, err := s.GetProfileV1(ctx, a.Actor, p.ProfileID, p.Revision)
	if err != nil {
		return nil, err
	}
	if profile.ContentSHA256 != p.ContentSHA256 {
		return nil, catalog.ErrConflictV1
	}
	selected := map[string]bool{}
	selectAll := p.AssetSlots == nil
	for _, slot := range p.AssetSlots {
		if slot == "" || selected[slot] {
			return nil, catalog.ErrInputV1
		}
		selected[slot] = true
	}
	if len(selected) > 16 || (selectAll && len(profile.Profile.Assets) > 16) {
		return nil, catalog.ErrInputV1
	}
	assets := []map[string]any{}
	matched := 0
	var total int64
	for _, slot := range profile.Profile.Assets {
		if !selectAll && !selected[slot.Slot] {
			continue
		}
		matched++
		v, e := s.GetAssetV1(ctx, a.Actor, slot.AssetID, slot.Revision)
		if e != nil {
			return nil, e
		}
		if v.Render.MediaType != "image/png" || v.Render.Bytes < 1 || v.Render.Bytes > htmlmaster.MaxAssetBytes {
			return nil, catalog.ErrInputV1
		}
		if v.Render.Bytes > htmlmaster.MaxTotalAssetBytes-total {
			return nil, catalog.ErrInputV1
		}
		total += v.Render.Bytes
		assets = append(assets, map[string]any{"slot": slot.Slot, "html_asset_name": "brand_" + slot.Slot, "reference": "hash-asset:brand_" + slot.Slot, "asset_id": v.AssetID, "revision": v.Revision, "sha256": v.Render.SHA256, "bytes": v.Render.Bytes, "media_type": v.Render.MediaType, "width": v.Render.Width, "height": v.Render.Height, "alt": slot.Alt, "usage": slot.Usage})
	}
	if !selectAll && matched != len(selected) {
		return nil, catalog.ErrInputV1
	}
	return map[string]any{"profile": profile, "selected_assets": assets, "binary_included": false, "next": "Pass exact profile_id/revision/content_sha256/asset_slots as brand_profile to create_design_template or update_design_template. Reference returned asset names; server resolves bytes before admission."}, nil
}
