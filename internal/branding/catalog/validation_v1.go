// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package catalog

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/branding"
	"github.com/google/uuid"
)

var tokenV1 = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
var digestV1 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func strictJSONV1(raw []byte, out any, max int) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return ErrInputV1
	}
	// Duplicate keys must not acquire different meanings between caller,
	// canonical commitment, PostgreSQL JSONB and the eventual renderer.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 24 {
			return ErrInputV1
		}
		t, e := d.Token()
		if e != nil {
			return ErrInputV1
		}
		if q, ok := t.(json.Delim); ok {
			switch q {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || seen[s] {
						return ErrInputV1
					}
					seen[s] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return ErrInputV1
				}
			case '[':
				for d.More() {
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return ErrInputV1
				}
			default:
				return ErrInputV1
			}
		}
		return nil
	}
	if walk(0) != nil {
		return ErrInputV1
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInputV1
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInputV1
	}
	return nil
}

// DecodeJSONV1 is shared by the bounded REST and MCP catalog adapters.
func DecodeJSONV1(raw []byte, out any, max int) error { return strictJSONV1(raw, out, max) }
func textV1(s string, max int, required bool) bool {
	if len(s) > max || !utf8.ValidString(s) || required && strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if r == 0 || r == 127 || r < 32 && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}
func validateProfileV1(v *ProfileDataV1) error {
	if v == nil || v.SchemaVersion != 1 || len(v.Palette.Colors) < 1 || len(v.Palette.Colors) > 32 || len(v.Assets) > 128 || len(v.Do) > 16 || len(v.Dont) > 16 || !textV1(v.Guidance, 8192, false) {
		return ErrInputV1
	}
	for name, color := range v.Palette.Colors {
		if !tokenV1.MatchString(name) {
			return ErrInputV1
		}
		n := branding.NormaliseHex(color)
		if n == "" {
			return ErrInputV1
		}
		v.Palette.Colors[name] = n
	}
	r := v.Palette.Roles
	for _, key := range []string{r.Primary, r.Accent, r.AccentText, r.Surface, r.Text, r.Muted, r.Signature} {
		if _, ok := v.Palette.Colors[key]; !ok {
			return ErrInputV1
		}
	}
	for _, foreground := range []string{r.Text, r.Muted, r.AccentText} {
		if ContrastRatioV1(v.Palette.Colors[foreground], v.Palette.Colors[r.Surface]) < 4.5 {
			return ErrInputV1
		}
	}
	for _, f := range []*string{&v.Typography.Heading, &v.Typography.Body, &v.Typography.Mono} {
		n, e := branding.NormaliseFontFamily(*f)
		if e != nil {
			return ErrInputV1
		}
		*f = n
	}
	if len(v.Typography.ScalePX) < 1 || len(v.Typography.ScalePX) > 16 || len(v.SpacingPX) < 1 || len(v.SpacingPX) > 24 || !finiteBetweenV1(v.Typography.LineHeight, 1, 2.5) {
		return ErrInputV1
	}
	for _, seq := range []struct {
		v        []float64
		min, max float64
	}{{v.Typography.ScalePX, 8, 160}, {v.SpacingPX, 0, 512}} {
		previous := -1.0
		for _, x := range seq.v {
			if !finiteBetweenV1(x, seq.min, seq.max) || x <= previous {
				return ErrInputV1
			}
			previous = x
		}
	}
	for _, lines := range [][]string{v.Do, v.Dont} {
		for _, s := range lines {
			if !textV1(s, 1024, true) {
				return ErrInputV1
			}
		}
	}
	slots := map[string]bool{}
	for _, a := range v.Assets {
		if !tokenV1.MatchString(a.Slot) || slots[a.Slot] || a.AssetID == uuid.Nil || a.Revision < 1 || !textV1(a.Alt, 512, true) || !textV1(a.Usage.ClearSpace, 512, false) || a.Usage.MinimumWidthPX < 0 || a.Usage.MinimumWidthPX > 16384 || len(a.Usage.AllowedBackgrounds) > 16 {
			return ErrInputV1
		}
		slots[a.Slot] = true
		for _, background := range a.Usage.AllowedBackgrounds {
			if _, ok := v.Palette.Colors[background]; !ok {
				return ErrInputV1
			}
		}
	}
	sort.Slice(v.Assets, func(i, j int) bool { return v.Assets[i].Slot < v.Assets[j].Slot })
	if _, e := canonicalV1(v); e != nil {
		return e
	}
	return nil
}
func finiteBetweenV1(x, lo, hi float64) bool {
	return !math.IsNaN(x) && !math.IsInf(x, 0) && x >= lo && x <= hi
}

// ContrastRatioV1 uses the sRGB transfer function, independently of the old
// foreground-choice heuristic. Preserved logo colors are never recolored.
func ContrastRatioV1(a, b string) float64 {
	luminance := func(s string) (float64, bool) {
		n := branding.NormaliseHex(s)
		if n == "" {
			return 0, false
		}
		v, e := strconv.ParseUint(n[1:], 16, 32)
		if e != nil {
			return 0, false
		}
		rgb := []float64{float64(v>>16&255) / 255, float64(v>>8&255) / 255, float64(v&255) / 255}
		for i, c := range rgb {
			if c <= 0.04045 {
				rgb[i] = c / 12.92
			} else {
				rgb[i] = math.Pow((c+0.055)/1.055, 2.4)
			}
		}
		return .2126*rgb[0] + .7152*rgb[1] + .0722*rgb[2], true
	}
	x, ok := luminance(a)
	y, ok2 := luminance(b)
	if !ok || !ok2 {
		return 0
	}
	if y > x {
		x, y = y, x
	}
	return (x + .05) / (y + .05)
}

func DefaultProfileDataV1() ProfileDataV1 {
	b := branding.DefaultBranding()
	return ProfileDataV1{SchemaVersion: 1, Palette: PaletteV1{Colors: map[string]string{"primary": b.PrimaryHex, "accent": b.AccentHex, "accent_text": b.TextHex, "surface": b.SurfaceHex, "text": b.TextHex, "muted": b.MutedHex, "signature": b.SignatureColor}, Roles: PaletteRolesV1{"primary", "accent", "accent_text", "surface", "text", "muted", "signature"}}, Typography: TypographyV1{Heading: b.FontHeading, Body: b.FontBody, Mono: "monospace", ScalePX: []float64{12, 16, 24, 32, 48}, LineHeight: 1.5}, SpacingPX: []float64{0, 4, 8, 16, 24, 32, 48}, Do: []string{}, Dont: []string{}, Assets: []AssetRefV1{}}
}
