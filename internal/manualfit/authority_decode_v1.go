// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
)

// DecodeAuthorityV1 reads the archived application authority. Its literal V1
// geometry limits and viewport rules do not call a current worker, PDF parser,
// renderer, or current font bundle. A new policy needs a separate reader.
func DecodeAuthorityV1(raw []byte) (*AuthorityV1, error) {
	var s authorityCanonicalV1
	if len(raw) == 0 || len(raw) > MaxAuthorityBytesV1 || closedCanonicalV1(raw, &s) != nil || s.Schema != AuthoritySchemaV1 {
		return nil, ErrAuthorityV1
	}
	epoch, err := time.Parse(time.RFC3339Nano, s.CeremonyEpoch)
	if err != nil || epoch.IsZero() || epoch.Year() < 1 || epoch.Year() > 9999 || epoch.UTC().Format(time.RFC3339Nano) != s.CeremonyEpoch ||
		s.OrgID == [16]byte{} || s.DocumentID == [16]byte{} || s.RecipientID == [16]byte{} ||
		!authorityObjectTextV1(s.Source.Key) || !validObjectVersionV1(s.Source.VersionID) ||
		!authorityDigestV1(s.Source.SHA256) || !authorityDigestV1(s.SpanSHA256) || s.Source.Bytes < 1 || s.Source.Bytes > 50<<20 ||
		len(s.Targets) < 1 || len(s.Targets) > 1000 || len(s.ExpectedTargetIDs) != len(s.Targets) {
		return nil, ErrAuthorityV1
	}
	font, ok := signaturefit.Font(s.Font)
	if !ok || s.FontInfo != (authorityFontV1{font.File, font.SHA256, font.Family, font.PostScript}) {
		return nil, ErrAuthorityV1
	}
	g := s.Geometry
	if g.SchemaVersion != 1 || g.SourceSHA256 != s.Source.SHA256 || g.SourceBytes != s.Source.Bytes ||
		!authorityDigestV1(g.GeometrySHA256) || len(g.Pages) < 1 || len(g.Pages) > 500 {
		return nil, ErrAuthorityV1
	}
	geometryJSON, err := json.Marshal(g.Pages)
	if err != nil || authoritySHA256V1(geometryJSON) != g.GeometrySHA256 {
		return nil, ErrAuthorityV1
	}
	for _, p := range g.Pages {
		if _, _, err := archivedViewportV1(p); err != nil {
			return nil, ErrAuthorityV1
		}
	}
	byPage := make(map[int][]signaturefit.Target)
	previous := ""
	for i, t := range s.Targets {
		if t.ID == [16]byte{} || t.ID.String() <= previous || t.ID != s.ExpectedTargetIDs[i] ||
			t.OrgID != s.OrgID || t.DocumentID != s.DocumentID || t.RecipientID != s.RecipientID || !t.Required || t.Page < 1 || t.Page > len(g.Pages) {
			return nil, ErrAuthorityV1
		}
		previous = t.ID.String()
		x, ex := PercentToFractionV1(t.X)
		y, ey := PercentToFractionV1(t.Y)
		w, ew := PercentToFractionV1(t.W)
		h, eh := PercentToFractionV1(t.H)
		if ex != nil || ey != nil || ew != nil || eh != nil {
			return nil, ErrAuthorityV1
		}
		byPage[t.Page] = append(byPage[t.Page], signaturefit.Target{ID: t.ID.String(), X: x, Y: y, W: w, H: h})
		if len(byPage[t.Page]) > 128 {
			return nil, ErrAuthorityV1
		}
	}
	if len(s.Pages) != len(byPage) || len(s.Pages) == 0 {
		return nil, ErrAuthorityV1
	}
	previousPage, totalPlanBytes := 0, 0
	for _, p := range s.Pages {
		if p.Plan.Page <= previousPage || p.Plan.Page > len(g.Pages) {
			return nil, ErrAuthorityV1
		}
		previousPage = p.Plan.Page
		targets, exists := byPage[p.Plan.Page]
		if !exists {
			return nil, ErrAuthorityV1
		}
		width, height, err := archivedViewportV1(g.Pages[p.Plan.Page-1])
		if err != nil {
			return nil, ErrAuthorityV1
		}
		want := signaturefit.Plan{Text: s.TypedName, Font: s.Font, SourceSHA256: s.Source.SHA256, GeometrySHA256: g.GeometrySHA256,
			SpanSHA256: s.SpanSHA256, Page: p.Plan.Page, WidthPoints: strconv.FormatFloat(width, 'f', -1, 64), HeightPoints: strconv.FormatFloat(height, 'f', -1, 64), Targets: targets}
		wantJSON, err := json.Marshal(want)
		gotJSON, gotErr := json.Marshal(p.Plan)
		inputSHA, shaErr := signaturefit.InputSHA(want)
		if err != nil || gotErr != nil || shaErr != nil || !bytes.Equal(wantJSON, gotJSON) || p.InputSHA256 != inputSHA || len(wantJSON) > (2<<20)-totalPlanBytes {
			return nil, ErrAuthorityV1
		}
		totalPlanBytes += len(wantJSON)
	}
	in := AuthorityInputV1{OrgID: s.OrgID, DocumentID: s.DocumentID, RecipientID: s.RecipientID, CeremonyEpoch: epoch.UTC(), Source: s.Source,
		TypedName: s.TypedName, Font: s.Font, SpanSHA256: s.SpanSHA256, ExpectedTargetIDs: s.ExpectedTargetIDs, Targets: s.Targets}
	return &AuthorityV1{input: in, geometry: g, font: font, pages: s.Pages, canonical: bytes.Clone(raw), sha256: authoritySHA256V1(raw)}, nil
}

func archivedViewportV1(p sanitize.PDFManualPage) (float64, float64, error) {
	finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
	if p.Rotation%90 != 0 || !finite(p.UserUnit) || p.UserUnit <= 0 || p.UserUnit > 75000 {
		return 0, 0, ErrAuthorityV1
	}
	for _, box := range p.Boxes {
		for _, v := range box {
			if !finite(v) || math.Abs(v) > 1e9 {
				return 0, 0, ErrAuthorityV1
			}
		}
		if box[2] <= box[0] || box[3] <= box[1] {
			return 0, 0, ErrAuthorityV1
		}
	}
	m, c := p.Boxes[0], p.Boxes[1]
	r := [4]float64{math.Max(m[0], c[0]), math.Max(m[1], c[1]), math.Min(m[2], c[2]), math.Min(m[3], c[3])}
	if r[2] <= r[0] || r[3] <= r[1] {
		r = m
	}
	w, h := (r[2]-r[0])*p.UserUnit, (r[3]-r[1])*p.UserUnit
	if ((p.Rotation%360+360)%360)%180 != 0 {
		w, h = h, w
	}
	if !finite(w) || !finite(h) || w <= 0 || h <= 0 || w > 14400 || h > 14400 {
		return 0, 0, ErrAuthorityV1
	}
	return w, h, nil
}

// Canonical equality closes aliases, number forms and omitted fields. The token
// pass also rejects duplicate keys/null values before destination decoding.
func closedCanonicalV1(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if closedTokenV1(d, 0) != nil {
		return ErrAuthorityV1
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrAuthorityV1
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrAuthorityV1
	}
	canonical, err := json.Marshal(dst)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrAuthorityV1
	}
	return nil
}
func closedTokenV1(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrAuthorityV1
	}
	t, err := d.Token()
	if err != nil || t == nil {
		return ErrAuthorityV1
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			s, ok := key.(string)
			if err != nil || !ok || seen[s] {
				return ErrAuthorityV1
			}
			seen[s] = true
			if closedTokenV1(d, depth+1) != nil {
				return ErrAuthorityV1
			}
		}
		if t, err = d.Token(); err != nil || t != json.Delim('}') {
			return ErrAuthorityV1
		}
	case json.Delim('['):
		for d.More() {
			if closedTokenV1(d, depth+1) != nil {
				return ErrAuthorityV1
			}
		}
		if t, err = d.Token(); err != nil || t != json.Delim(']') {
			return ErrAuthorityV1
		}
	}
	return nil
}

// VersionIDs are opaque exact identities. TrimSpace is used only to reject
// reserved unversioned identities and never changes the returned/stored value.
func validObjectVersionV1(version string) bool {
	if !authorityObjectTextV1(version) {
		return false
	}
	switch strings.TrimSpace(version) {
	case "null", "hash:unversioned-development":
		return false
	default:
		return true
	}
}

// ValidObjectVersionV1 exposes the frozen exact-version policy to application
// archive adapters. Accepted opaque bytes are preserved, never normalized.
func ValidObjectVersionV1(version string) bool {
	return validObjectVersionV1(version)
}
