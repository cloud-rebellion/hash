// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type objectStoreV1 interface {
	PutVersioned(context.Context, string, string, []byte) (storage.StoredObject, error)
	GetVerifiedVersionBounded(context.Context, string, string, []byte, int64) ([]byte, error)
	DeleteVersion(context.Context, string, string, []byte) error
}
type ServiceV1 struct {
	Pool  *pgxpool.Pool
	Audit *audit.Logger
	store objectStoreV1
}

func NewServiceV1(pool *pgxpool.Pool, logger *audit.Logger, objects *storage.Client) *ServiceV1 {
	s := &ServiceV1{Pool: pool, Audit: logger}
	if objects != nil {
		s.store = objects
	}
	return s
}
func catalogReadV1[T any](ctx context.Context, s *ServiceV1, actor authoring.Actor, fn func(context.Context, *generated.Queries) (T, error), ownerOnly ...bool) (T, error) {
	var zero T
	if s == nil || s.Pool == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return zero, ErrUnavailableV1
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return zero, e
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	q := generated.New(tx)
	u, e := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
	if errors.Is(e, pgx.ErrNoRows) {
		return zero, auth.ErrMutationPermissionRevoked
	}
	if e != nil {
		return zero, e
	}
	if u.OrgID != actor.OrgID || (u.Role != string(auth.RoleOwner) && u.Role != string(auth.RoleSender) && u.Role != string(auth.RoleViewer)) {
		return zero, auth.ErrMutationPermissionRevoked
	}
	if len(ownerOnly) > 0 && ownerOnly[0] && u.Role != string(auth.RoleOwner) {
		return zero, auth.ErrMutationPermissionRevoked
	}
	if e = actor.Authorize(ctx, tx, u); e != nil {
		return zero, e
	}
	value, e := fn(ctx, q)
	if e != nil {
		return zero, catalogErrorV1(e)
	}
	if e = actor.Authorize(ctx, tx, u); e != nil {
		return zero, e
	}
	if e = tx.Commit(ctx); e != nil {
		return zero, e
	}
	return value, nil
}
func catalogErrorV1(e error) error {
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrNotFoundV1
	}
	return e
}
func pageV1(n int) int32 {
	if n < 1 || n > MaxCatalogPageV1 {
		return MaxCatalogPageV1
	}
	return int32(n)
}
func eventV1(actor authoring.Actor, kind string, payload map[string]any) audit.Entry {
	return audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, Kind: kind, Payload: payload}
}
func profileDTOv1(r *generated.BrandProfileRevisionsV1) (ProfileV1, error) {
	if r == nil {
		return ProfileV1{}, ErrNotFoundV1
	}
	data, e := decodeProfileV1(r.ProfileJson)
	if e != nil || validateProfileV1(&data) != nil {
		return ProfileV1{}, ErrUnavailableV1
	}
	raw, e := canonicalV1(data)
	if e != nil {
		return ProfileV1{}, e
	}
	sum := sha256.Sum256(raw)
	if len(r.ContentSha256) != 32 || hex.EncodeToString(sum[:]) != hex.EncodeToString(r.ContentSha256) {
		return ProfileV1{}, ErrUnavailableV1
	}
	return ProfileV1{ProfileRefV1: ProfileRefV1{ProfileID: r.ProfileID, Revision: r.Revision, ContentSHA256: hex.EncodeToString(sum[:])}, Name: r.Name, Profile: data, CreatedAt: r.CreatedAt.Time}, nil
}
func (s *ServiceV1) ListProfilesV1(ctx context.Context, actor authoring.Actor, limit int, after uuid.UUID) ([]ProfileSummaryV1, error) {
	return catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) ([]ProfileSummaryV1, error) {
		rows, e := q.ListBrandProfilesV1(c, generated.ListBrandProfilesV1Params{OrgID: actor.OrgID, AfterID: after, PageSize: pageV1(limit)})
		if e != nil {
			return nil, e
		}
		out := make([]ProfileSummaryV1, 0, len(rows))
		for _, r := range rows {
			out = append(out, ProfileSummaryV1{ProfileID: r.ID, Name: r.Name, Revision: r.HeadRevision, ContentSHA256: hex.EncodeToString(r.ContentSha256)})
		}
		return out, nil
	})
}
func (s *ServiceV1) GetProfileV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, revision int64) (ProfileV1, error) {
	if id == uuid.Nil || revision < 0 {
		return ProfileV1{}, ErrInputV1
	}
	return catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) (ProfileV1, error) {
		r, e := q.GetBrandProfileV1(c, generated.GetBrandProfileV1Params{OrgID: actor.OrgID, ProfileID: id, Revision: revision})
		if e != nil {
			return ProfileV1{}, e
		}
		return profileDTOv1(r)
	})
}
func saveProfileTxV1(ctx context.Context, q *generated.Queries, actor authoring.Actor, id uuid.UUID, in ProfileInputV1) (ProfileV1, error) {
	if !textV1(in.Name, 160, true) || in.ExpectedRevision < 0 || validateProfileV1(&in.Profile) != nil {
		return ProfileV1{}, ErrInputV1
	}
	if id == uuid.Nil {
		if in.ExpectedRevision != 0 {
			return ProfileV1{}, ErrInputV1
		}
		id = uuid.New()
		if e := q.InsertBrandProfileV1(ctx, generated.InsertBrandProfileV1Params{OrgID: actor.OrgID, ID: id, Name: in.Name, CreatedBy: actor.UserID}); e != nil {
			return ProfileV1{}, e
		}
	} else {
		head, e := q.GetBrandProfileHeadV1(ctx, generated.GetBrandProfileHeadV1Params{OrgID: actor.OrgID, ProfileID: id})
		if e != nil {
			return ProfileV1{}, catalogErrorV1(e)
		}
		if head.HeadRevision != in.ExpectedRevision {
			return ProfileV1{}, ErrConflictV1
		}
	}
	revision := in.ExpectedRevision + 1
	raw, e := canonicalV1(in.Profile)
	if e != nil {
		return ProfileV1{}, e
	}
	sum := sha256.Sum256(raw)
	for _, a := range in.Profile.Assets {
		if _, e := q.GetBrandAssetV1(ctx, generated.GetBrandAssetV1Params{OrgID: actor.OrgID, AssetID: a.AssetID, Revision: a.Revision}); e != nil {
			return ProfileV1{}, catalogErrorV1(e)
		}
	}
	r, e := q.InsertBrandProfileRevisionV1(ctx, generated.InsertBrandProfileRevisionV1Params{OrgID: actor.OrgID, ProfileID: id, Revision: revision, Name: in.Name, ProfileJson: raw, ContentSha256: sum[:], CreatedBy: actor.UserID})
	if e != nil {
		return ProfileV1{}, e
	}
	for _, a := range in.Profile.Assets {
		if e = q.InsertBrandProfileAssetV1(ctx, generated.InsertBrandProfileAssetV1Params{OrgID: actor.OrgID, ProfileID: id, ProfileRevision: revision, Slot: a.Slot, AssetID: a.AssetID, AssetRevision: a.Revision}); e != nil {
			return ProfileV1{}, e
		}
	}
	if in.ExpectedRevision > 0 {
		n, e := q.AdvanceBrandProfileV1(ctx, generated.AdvanceBrandProfileV1Params{OrgID: actor.OrgID, ProfileID: id, Revision: revision, ExpectedRevision: in.ExpectedRevision, Name: in.Name})
		if e != nil {
			return ProfileV1{}, e
		}
		if n != 1 {
			return ProfileV1{}, ErrConflictV1
		}
	}
	return profileDTOv1(r)
}
func (s *ServiceV1) SaveProfileV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, in ProfileInputV1) (ProfileV1, error) {
	if s == nil {
		return ProfileV1{}, ErrUnavailableV1
	}
	return authoring.CommitOwnerMutation(ctx, s.Pool, s.Audit, actor, func(c context.Context, q *generated.Queries) (ProfileV1, error) {
		return saveProfileTxV1(c, q, actor, id, in)
	}, func(r ProfileV1) audit.Entry {
		return eventV1(actor, "branding.profile_revised", map[string]any{"profile_id": r.ProfileID, "revision": r.Revision, "content_sha256": r.ContentSHA256})
	})
}
func (s *ServiceV1) ListProfileRevisionsV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, before int64, limit int) ([]ProfileSummaryV1, error) {
	if id == uuid.Nil || before < 0 {
		return nil, ErrInputV1
	}
	return catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) ([]ProfileSummaryV1, error) {
		rs, e := q.ListBrandProfileRevisionsV1(c, generated.ListBrandProfileRevisionsV1Params{OrgID: actor.OrgID, ProfileID: id, BeforeRevision: before, PageSize: pageV1(limit)})
		if e != nil {
			return nil, e
		}
		out := make([]ProfileSummaryV1, 0, len(rs))
		for _, r := range rs {
			out = append(out, ProfileSummaryV1{ProfileID: r.ProfileID, Name: r.Name, Revision: r.Revision, ContentSHA256: hex.EncodeToString(r.ContentSha256)})
		}
		return out, nil
	})
}
func profileThemeV1(p ProfileDataV1) branding.Branding {
	r := p.Palette.Roles
	c := p.Palette.Colors
	return branding.Branding{PrimaryHex: c[r.Primary], AccentHex: c[r.Accent], SurfaceHex: c[r.Surface], TextHex: c[r.Text], MutedHex: c[r.Muted], SignatureColor: c[r.Signature], FontHeading: p.Typography.Heading, FontBody: p.Typography.Body}
}
func selectDefaultTxV1(ctx context.Context, q *generated.Queries, actor authoring.Actor, ref ProfileRefV1, expected int64) (DefaultSelectionV1, error) {
	if ref.ProfileID == uuid.Nil || ref.Revision < 1 || !digestV1.MatchString(ref.ContentSHA256) || expected < 0 || len(ref.AssetSlots) > 0 {
		return DefaultSelectionV1{}, ErrInputV1
	}
	r, e := q.GetBrandProfileV1(ctx, generated.GetBrandProfileV1Params{OrgID: actor.OrgID, ProfileID: ref.ProfileID, Revision: ref.Revision})
	if e != nil {
		return DefaultSelectionV1{}, catalogErrorV1(e)
	}
	if hex.EncodeToString(r.ContentSha256) != ref.ContentSHA256 {
		return DefaultSelectionV1{}, ErrConflictV1
	}
	p, e := profileDTOv1(r)
	if e != nil {
		return DefaultSelectionV1{}, e
	}
	old, e := q.GetBrandDefaultV1(ctx, actor.OrgID)
	actual := int64(0)
	if e == nil {
		actual = old.SelectionRevision
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return DefaultSelectionV1{}, e
	}
	if actual != expected {
		return DefaultSelectionV1{}, ErrConflictV1
	}
	if e = q.DeleteBrandDefaultV1(ctx, actor.OrgID); e != nil {
		return DefaultSelectionV1{}, e
	}
	b := profileThemeV1(p.Profile)
	if _, e = q.UpsertOrgBranding(ctx, generated.UpsertOrgBrandingParams{OrgID: actor.OrgID, PrimaryHex: b.PrimaryHex, AccentHex: b.AccentHex, SurfaceHex: b.SurfaceHex, TextHex: b.TextHex, MutedHex: b.MutedHex, LogoUrl: "", LogoAlt: "", FontHeading: b.FontHeading, FontBody: b.FontBody, SignatureColor: b.SignatureColor}); e != nil {
		return DefaultSelectionV1{}, e
	}
	if e = q.InsertBrandDefaultV1(ctx, generated.InsertBrandDefaultV1Params{OrgID: actor.OrgID, ProfileID: ref.ProfileID, ProfileRevision: ref.Revision, SelectionRevision: actual + 1}); e != nil {
		return DefaultSelectionV1{}, e
	}
	return DefaultSelectionV1{Configured: true, ProfileRefV1: ref, SelectionRevision: actual + 1}, nil
}
func (s *ServiceV1) SelectDefaultV1(ctx context.Context, actor authoring.Actor, ref ProfileRefV1, expected int64) (DefaultSelectionV1, error) {
	if s == nil {
		return DefaultSelectionV1{}, ErrUnavailableV1
	}
	return authoring.CommitOwnerMutation(ctx, s.Pool, s.Audit, actor, func(c context.Context, q *generated.Queries) (DefaultSelectionV1, error) {
		return selectDefaultTxV1(c, q, actor, ref, expected)
	}, func(r DefaultSelectionV1) audit.Entry {
		return eventV1(actor, "branding.default_selected", map[string]any{"profile_id": r.ProfileID, "revision": r.Revision, "selection_revision": r.SelectionRevision})
	})
}

// SaveLegacyBrandingV1 preserves old REST/MCP behavior while a selected profile
// receives a NEW revision. Extended palette, guidance and asset slots survive.
func (s *ServiceV1) SaveLegacyBrandingV1(ctx context.Context, actor authoring.Actor, b branding.Branding) (branding.Branding, error) {
	if s == nil {
		return branding.Branding{}, ErrUnavailableV1
	}
	return authoring.CommitOwnerMutation(ctx, s.Pool, s.Audit, actor, func(c context.Context, q *generated.Queries) (branding.Branding, error) {
		return legacyProjectionTxV1(c, q, actor, b)
	}, func(branding.Branding) audit.Entry {
		return eventV1(actor, "branding.legacy_updated", map[string]any{"versioned_projection": true})
	})
}

// UpdateLegacyProjectionTxV1 is used inside the EXISTING REST/MCP live-owner
// transaction. It never starts a second transaction or moves authorization
// outside the caller's original owner/audit/credential recheck.
func UpdateLegacyProjectionTxV1(ctx context.Context, q *generated.Queries, actor authoring.Actor, b branding.Branding) (*generated.OrgBranding, error) {
	if _, e := legacyProjectionTxV1(ctx, q, actor, b); e != nil {
		return nil, e
	}
	return q.GetOrgBranding(ctx, actor.OrgID)
}
func legacyProjectionTxV1(c context.Context, q *generated.Queries, actor authoring.Actor, b branding.Branding) (branding.Branding, error) {
	d, e := q.GetBrandDefaultV1(c, actor.OrgID)
	if errors.Is(e, pgx.ErrNoRows) {
		_, e = q.UpsertOrgBranding(c, generated.UpsertOrgBrandingParams{OrgID: actor.OrgID, PrimaryHex: b.PrimaryHex, AccentHex: b.AccentHex, SurfaceHex: b.SurfaceHex, TextHex: b.TextHex, MutedHex: b.MutedHex, LogoUrl: b.LogoURL, LogoAlt: b.LogoAlt, FontHeading: b.FontHeading, FontBody: b.FontBody, SignatureColor: b.SignatureColor})
		return b, e
	}
	if e != nil {
		return branding.Branding{}, e
	}
	if b.LogoURL != "" {
		return branding.Branding{}, ErrInputV1
	}
	r, e := q.GetBrandProfileV1(c, generated.GetBrandProfileV1Params{OrgID: actor.OrgID, ProfileID: d.ProfileID, Revision: d.ProfileRevision})
	if e != nil {
		return branding.Branding{}, e
	}
	p, e := profileDTOv1(r)
	if e != nil {
		return branding.Branding{}, e
	}
	head, e := q.GetBrandProfileHeadV1(c, generated.GetBrandProfileHeadV1Params{OrgID: actor.OrgID, ProfileID: d.ProfileID})
	if e != nil {
		return branding.Branding{}, e
	}
	colors := p.Profile.Palette.Colors
	roles := &p.Profile.Palette.Roles
	for _, v := range []struct {
		role        *string
		name, color string
	}{{&roles.Primary, "legacy_primary", b.PrimaryHex}, {&roles.Accent, "legacy_accent", b.AccentHex}, {&roles.Surface, "legacy_surface", b.SurfaceHex}, {&roles.Text, "legacy_text", b.TextHex}, {&roles.Muted, "legacy_muted", b.MutedHex}, {&roles.Signature, "legacy_signature", b.SignatureColor}} {
		colors[v.name] = v.color
		*v.role = v.name
	}
	p.Profile.Typography.Heading, p.Profile.Typography.Body = b.FontHeading, b.FontBody
	updated, e := saveProfileTxV1(c, q, actor, d.ProfileID, ProfileInputV1{Name: p.Name, ExpectedRevision: head.HeadRevision, Profile: p.Profile})
	if e != nil {
		return branding.Branding{}, e
	}
	if _, e = selectDefaultTxV1(c, q, actor, updated.ProfileRefV1, d.SelectionRevision); e != nil {
		return branding.Branding{}, e
	}
	return b, nil
}
