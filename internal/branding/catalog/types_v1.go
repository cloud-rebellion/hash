// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
)

const (
	MaxProfileBytesV1  = 48 << 10
	MaxOriginalBytesV1 = 8 << 20
	MaxRenderBytesV1   = 2 << 20
	MaxCatalogPageV1   = 50
)

var (
	ErrInputV1       = errors.New("invalid brand catalog input")
	ErrNotFoundV1    = errors.New("brand catalog item not found")
	ErrConflictV1    = errors.New("brand catalog revision changed")
	ErrUnavailableV1 = errors.New("brand catalog unavailable")
)

type PaletteRolesV1 struct {
	Primary    string `json:"primary"`
	Accent     string `json:"accent"`
	AccentText string `json:"accent_text"`
	Surface    string `json:"surface"`
	Text       string `json:"text"`
	Muted      string `json:"muted"`
	Signature  string `json:"signature"`
}
type PaletteV1 struct {
	Colors map[string]string `json:"colors"`
	Roles  PaletteRolesV1    `json:"roles"`
}
type TypographyV1 struct {
	Heading    string    `json:"heading"`
	Body       string    `json:"body"`
	Mono       string    `json:"mono"`
	ScalePX    []float64 `json:"scale_px"`
	LineHeight float64   `json:"line_height"`
}
type LogoUsageV1 struct {
	ClearSpace         string   `json:"clear_space"`
	MinimumWidthPX     int      `json:"minimum_width_px"`
	AllowedBackgrounds []string `json:"allowed_backgrounds"`
}
type AssetRefV1 struct {
	Slot     string      `json:"slot"`
	AssetID  uuid.UUID   `json:"asset_id"`
	Revision int64       `json:"revision"`
	Alt      string      `json:"alt"`
	Usage    LogoUsageV1 `json:"usage"`
}
type ProfileDataV1 struct {
	SchemaVersion int          `json:"schema_version"`
	Palette       PaletteV1    `json:"palette"`
	Typography    TypographyV1 `json:"typography"`
	SpacingPX     []float64    `json:"spacing_px"`
	Guidance      string       `json:"guidance"`
	Do            []string     `json:"do"`
	Dont          []string     `json:"dont"`
	Assets        []AssetRefV1 `json:"assets"`
}
type ProfileRefV1 struct {
	ProfileID     uuid.UUID `json:"profile_id"`
	Revision      int64     `json:"revision"`
	ContentSHA256 string    `json:"content_sha256"`
	AssetSlots    []string  `json:"asset_slots,omitempty"`
}
type ProfileV1 struct {
	ProfileRefV1
	Name      string        `json:"name"`
	Profile   ProfileDataV1 `json:"profile"`
	CreatedAt time.Time     `json:"created_at"`
}
type ProfileSummaryV1 struct {
	ProfileID     uuid.UUID `json:"profile_id"`
	Name          string    `json:"name"`
	Revision      int64     `json:"revision"`
	ContentSHA256 string    `json:"content_sha256"`
}
type ProfileInputV1 struct {
	Name             string        `json:"name"`
	ExpectedRevision int64         `json:"expected_revision"`
	Profile          ProfileDataV1 `json:"profile"`
}
type DefaultSelectionV1 struct {
	Configured bool `json:"configured"`
	ProfileRefV1
	SelectionRevision int64 `json:"selection_revision"`
}
type ObjectV1 struct {
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	MediaType string `json:"media_type"`
	Width     int32  `json:"width"`
	Height    int32  `json:"height"`
}
type AssetV1 struct {
	AssetID      uuid.UUID `json:"asset_id"`
	Revision     int64     `json:"revision"`
	Name         string    `json:"name"`
	Original     ObjectV1  `json:"original"`
	Render       ObjectV1  `json:"render"`
	RenderMethod string    `json:"render_method"`
	CreatedAt    time.Time `json:"created_at"`
}
type AssetUploadV1 struct {
	RequestID        uuid.UUID `json:"request_id"`
	AssetID          uuid.UUID `json:"asset_id"`
	ExpectedRevision int64     `json:"expected_revision"`
	Name             string    `json:"name"`
	MediaType        string    `json:"media_type"`
	OriginalBase64   string    `json:"original_base64"`
	RenderPNGBase64  string    `json:"render_png_base64,omitempty"`
}
type UploadStatusV1 struct {
	RequestID uuid.UUID `json:"request_id"`
	AssetID   uuid.UUID `json:"asset_id"`
	Revision  int64     `json:"revision"`
	State     string    `json:"state"`
}
type ProvenanceV1 struct{ ProfileRefV1 }
type BundleMeasureV1 struct {
	ProfileBytes  int64
	MetadataBytes int64
	RawAssetBytes int64
	Base64Bytes   int64
	AssetCount    int
}
type BundleAdmissionV1 func(context.Context, BundleMeasureV1) (func(), error)
type DesignBundleV1 struct {
	Profile    ProfileV1          `json:"profile"`
	Assets     []htmlmaster.Asset `json:"assets"`
	Provenance ProvenanceV1       `json:"provenance"`
	orgID      uuid.UUID
	actorID    uuid.UUID
	ref        ProfileRefV1
	slots      []string
	release    func()
	once       sync.Once
	closed     atomic.Bool
}

func (b *DesignBundleV1) Close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		b.closed.Store(true)
		b.Assets = nil
		if b.release != nil {
			b.release()
		}
	})
}

// BrandProfilesV1 is the shared REST/MCP contract. Org and credential are always
// carried by the current native Actor, never by JSON arguments.
type BrandProfilesV1 interface {
	ListProfilesV1(context.Context, authoring.Actor, int, uuid.UUID) ([]ProfileSummaryV1, error)
	GetProfileV1(context.Context, authoring.Actor, uuid.UUID, int64) (ProfileV1, error)
	SaveProfileV1(context.Context, authoring.Actor, uuid.UUID, ProfileInputV1) (ProfileV1, error)
	ListProfileRevisionsV1(context.Context, authoring.Actor, uuid.UUID, int64, int) ([]ProfileSummaryV1, error)
	SelectDefaultV1(context.Context, authoring.Actor, ProfileRefV1, int64) (DefaultSelectionV1, error)
	GetDefaultV1(context.Context, authoring.Actor) (DefaultSelectionV1, error)
	ListAssetsV1(context.Context, authoring.Actor, int, uuid.UUID) ([]AssetV1, error)
	GetAssetV1(context.Context, authoring.Actor, uuid.UUID, int64) (AssetV1, error)
	ListAssetRevisionsV1(context.Context, authoring.Actor, uuid.UUID, int64, int) ([]AssetV1, error)
	GetUploadStatusV1(context.Context, authoring.Actor, uuid.UUID) (UploadStatusV1, error)
	UploadAssetV1(context.Context, authoring.Actor, AssetUploadV1) (AssetV1, error)
	ResolveDesignBundleV1(context.Context, authoring.Actor, ProfileRefV1, BundleAdmissionV1) (*DesignBundleV1, error)
}

func decodeProfileV1(raw []byte) (ProfileDataV1, error) {
	var v ProfileDataV1
	err := strictJSONV1(raw, &v, MaxProfileBytesV1)
	return v, err
}
func canonicalV1(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil || len(b) > MaxProfileBytesV1 {
		return nil, ErrInputV1
	}
	return b, nil
}
