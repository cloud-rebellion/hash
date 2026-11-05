// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package catalog

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *ServiceV1) GetDefaultV1(ctx context.Context, actor authoring.Actor) (DefaultSelectionV1, error) {
	return catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) (DefaultSelectionV1, error) {
		r, e := q.GetBrandDefaultV1(c, actor.OrgID)
		if errors.Is(e, pgx.ErrNoRows) {
			return DefaultSelectionV1{Configured: false}, nil
		}
		if e != nil {
			return DefaultSelectionV1{}, e
		}
		return DefaultSelectionV1{Configured: true, ProfileRefV1: ProfileRefV1{ProfileID: r.ProfileID, Revision: r.ProfileRevision, ContentSHA256: hex.EncodeToString(r.ContentSha256)}, SelectionRevision: r.SelectionRevision}, nil
	})
}
func selectedSlotsV1(p ProfileDataV1, requested []string) ([]string, error) {
	available := map[string]bool{}
	for _, a := range p.Assets {
		available[a.Slot] = true
	}
	if requested == nil {
		if len(p.Assets) > htmlmaster.MaxAssets {
			return nil, ErrInputV1
		}
		requested = make([]string, 0, len(p.Assets))
		for _, a := range p.Assets {
			requested = append(requested, a.Slot)
		}
	}
	if len(requested) > htmlmaster.MaxAssets {
		return nil, ErrInputV1
	}
	out := append([]string{}, requested...)
	seen := map[string]bool{}
	for _, slot := range out {
		if !available[slot] || seen[slot] {
			return nil, ErrInputV1
		}
		seen[slot] = true
	}
	sort.Strings(out)
	return out, nil
}
func (s *ServiceV1) ResolveDesignBundleV1(ctx context.Context, actor authoring.Actor, ref ProfileRefV1, admit BundleAdmissionV1) (*DesignBundleV1, error) {
	if s == nil || s.store == nil || admit == nil || ref.ProfileID == uuid.Nil || ref.Revision < 1 || !digestV1.MatchString(ref.ContentSHA256) {
		return nil, ErrInputV1
	}
	var release func()
	success := false
	defer func() {
		if !success && release != nil {
			release()
		}
	}()
	out, e := catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) (*DesignBundleV1, error) {
		row, e := q.GetBrandProfileV1(c, generated.GetBrandProfileV1Params{OrgID: actor.OrgID, ProfileID: ref.ProfileID, Revision: ref.Revision})
		if e != nil {
			return nil, e
		}
		profile, e := profileDTOv1(row)
		if e != nil {
			return nil, e
		}
		if profile.ContentSHA256 != ref.ContentSHA256 {
			return nil, ErrConflictV1
		}
		slots, e := selectedSlotsV1(profile.Profile, ref.AssetSlots)
		if e != nil {
			return nil, e
		}
		selected := map[string]bool{}
		for _, slot := range slots {
			selected[slot] = true
		}
		type item struct {
			slot string
			row  *generated.BrandAssetRevisionsV1
		}
		items := make([]item, 0, len(slots))
		measure := BundleMeasureV1{ProfileBytes: int64(len(row.ProfileJson)), AssetCount: len(slots)}
		for _, a := range profile.Profile.Assets {
			if !selected[a.Slot] {
				continue
			}
			r, e := q.GetBrandAssetV1(c, generated.GetBrandAssetV1Params{OrgID: actor.OrgID, AssetID: a.AssetID, Revision: a.Revision})
			if e != nil {
				return nil, e
			}
			if r.RenderBytes < 1 || r.RenderBytes > htmlmaster.MaxAssetBytes || measure.RawAssetBytes+r.RenderBytes > htmlmaster.MaxTotalAssetBytes {
				return nil, ErrInputV1
			}
			measure.RawAssetBytes += r.RenderBytes
			measure.Base64Bytes += int64(base64.StdEncoding.EncodedLen(int(r.RenderBytes)))
			measure.MetadataBytes += int64(len(r.RenderKey) + len(r.RenderVersionID) + len(a.Slot) + len(a.Alt) + 256)
			items = append(items, item{a.Slot, r})
		}
		// This callback is the actual caller's native owner grant, not a new private
		// budget. No object response/base64 copy exists before it succeeds.
		release, e = admit(ctx, measure)
		if e != nil {
			return nil, e
		}
		if release == nil {
			return nil, ErrUnavailableV1
		}
		assets := make([]htmlmaster.Asset, 0, len(items))
		for _, item := range items {
			r := item.row
			body, e := s.store.GetVerifiedVersionBounded(c, r.RenderKey, r.RenderVersionID, r.RenderSha256, r.RenderBytes)
			if e != nil {
				return nil, e
			}
			if int64(len(body)) != r.RenderBytes {
				return nil, ErrUnavailableV1
			}
			assets = append(assets, htmlmaster.Asset{Name: "brand_" + item.slot, MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString(body), SHA256: hex.EncodeToString(r.RenderSha256)})
		}
		ownedRef := ProfileRefV1{ProfileID: ref.ProfileID, Revision: ref.Revision, ContentSHA256: ref.ContentSHA256, AssetSlots: append([]string{}, slots...)}
		return &DesignBundleV1{Profile: profile, Assets: assets, Provenance: ProvenanceV1{ProfileRefV1: ownedRef}, orgID: actor.OrgID, actorID: actor.UserID, ref: ownedRef, slots: append([]string{}, slots...), release: release}, nil
	})
	if e != nil {
		return nil, e
	}
	success = true
	return out, nil
}

// BindTemplateRevisionV1 runs in the native writer's EXISTING transaction.
// The ordinary canonical-master validator has already checked asset bytes/SHA.
// This scalar query compares those persisted pins, without decoding a second
// full master or allowing a post-commit provenance write.
func (s *ServiceV1) BindTemplateRevisionV1(ctx context.Context, tx pgx.Tx, actor authoring.Actor, templateID uuid.UUID, version int32, b *DesignBundleV1) error {
	if s == nil || tx == nil || b == nil || b.closed.Load() || b.orgID != actor.OrgID || b.actorID != actor.UserID || actor.Authorize == nil || templateID == uuid.Nil || version < 1 {
		return ErrInputV1
	}
	q := generated.New(tx)
	matches, e := q.BrandTemplateAssetsMatchV1(ctx, generated.BrandTemplateAssetsMatchV1Params{OrgID: actor.OrgID, TemplateID: templateID, TemplateVersion: version, ProfileID: b.ref.ProfileID, ProfileRevision: b.ref.Revision, SelectedSlots: b.slots})
	if e != nil {
		return e
	}
	if !matches {
		return ErrInputV1
	}
	sum, e := hex.DecodeString(b.ref.ContentSHA256)
	if e != nil {
		return ErrInputV1
	}
	n, e := q.InsertBrandTemplateBindingV1(ctx, generated.InsertBrandTemplateBindingV1Params{OrgID: actor.OrgID, TemplateID: templateID, TemplateVersion: version, ProfileID: b.ref.ProfileID, ProfileRevision: b.ref.Revision, ProfileSha256: sum, SelectedSlots: b.slots, CreatedBy: actor.UserID})
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrConflictV1
	}
	return nil
}
func (s *ServiceV1) TemplateProvenanceV1(ctx context.Context, actor authoring.Actor, templateID uuid.UUID, version int32) (ProvenanceV1, error) {
	if templateID == uuid.Nil || version < 1 {
		return ProvenanceV1{}, ErrInputV1
	}
	return catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) (ProvenanceV1, error) {
		r, e := q.GetBrandTemplateBindingV1(c, generated.GetBrandTemplateBindingV1Params{OrgID: actor.OrgID, TemplateID: templateID, TemplateVersion: version})
		if e != nil {
			return ProvenanceV1{}, e
		}
		return ProvenanceV1{ProfileRefV1: ProfileRefV1{ProfileID: r.ProfileID, Revision: r.ProfileRevision, ContentSHA256: hex.EncodeToString(r.ProfileSha256), AssetSlots: append([]string{}, r.SelectedSlots...)}}, nil
	})
}
