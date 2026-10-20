// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package signaturefit validates the frozen HSHFIT01 archive format.
// Integrity and renderer observations do not prove PDF structure or glyph paint;
// isolated-worker admission is required before signing consumes a package.
package signaturefit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	Policy              = "hash-manual-signature-pdf-seal-v1"
	RoutePath           = "/hash/chromium/signature-pdf/v1"
	MediaType           = "application/vnd.hash.signature-fit.v1"
	MaxRequestBytes     = 2 << 20
	MaxPackageBytes     = packageHeader + maxReportBytes + maxPDFBytes + maxHTMLBytes + maxFontBytes + maxSnapshotBytes
	RecipeSHA256V1      = "ed5a53b65dfe42099002721a6453fe2a2b9aef26fd97a8ae0dcc7fd6cad2c6da"
	packageHeader       = 60
	maxReportBytes      = 1 << 20
	maxPDFBytes         = 8 << 20
	maxHTMLBytes        = 2 << 20
	maxFontBytes        = 1 << 20
	maxSnapshotBytes    = 4 << 20
	measurementPolicyV1 = "hash-manual-signature-measurement-v1"
)

var ErrInvalid = errors.New("signaturefit: invalid V1 signature PDF package or request")

// Plan preserves the exact V1 JSON order and decimal strings. It describes one
// source page; the application must bind the complete ordered page set and its
// own document, recipient, source object version and signing authority separately.
type Plan struct {
	Text           string   `json:"text"`
	Font           string   `json:"font"`
	SourceSHA256   string   `json:"sourceSha256"`
	GeometrySHA256 string   `json:"geometrySha256"`
	SpanSHA256     string   `json:"spanSha256"`
	Page           int      `json:"page"`
	WidthPoints    string   `json:"widthPoints"`
	HeightPoints   string   `json:"heightPoints"`
	Targets        []Target `json:"targets"`
}

type Target struct {
	ID string `json:"id"`
	X  string `json:"x"`
	Y  string `json:"y"`
	W  string `json:"w"`
	H  string `json:"h"`
}

// FontInfo is literal V1 metadata. Historical decoding never reads the current
// application font bundle and never accepts a fallback or caller-supplied pin.
type FontInfo struct{ File, SHA256, Family, PostScript string }

func Font(name string) (FontInfo, bool) {
	switch name {
	case "Caveat":
		return FontInfo{"Caveat.woff2", "d0b7b931b8980049327e8f8f9ac264617c8200b8422d62e886473d3d9527bad3", "Caveat", "Caveat-Regular"}, true
	case "Dancing Script":
		return FontInfo{"DancingScript.woff2", "570e4265bbcb453353ce2fdf63d179332d8daa92691d567547b8a383f3b46c3b", "Dancing Script", "DancingScript-Regular"}, true
	case "Great Vibes":
		return FontInfo{"GreatVibes.woff2", "c59dc73d29daf142ef2431f455d21464172374aa750d793a79d608735db2d856", "Great Vibes", "GreatVibes-Regular"}, true
	case "Sacramento":
		return FontInfo{"Sacramento.woff2", "2fcd867d2812578d001b0eca921848e24de91d01986f26e038be374ec7c5cfd2", "Sacramento", "Sacramento-Regular"}, true
	case "Homemade Apple":
		return FontInfo{"HomemadeApple.woff2", "bbaa96c741caa479d4647fc567f64e5ddc71eec58ee9849cb9e8a14bee65bc30", "Homemade Apple", "HomemadeApple-Regular"}, true
	default:
		return FontInfo{}, false
	}
}

var decimalPatternV1 = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,2})?$`)

func decimalV1(s string) (*big.Rat, float64, bool) {
	if len(s) == 0 || len(s) > 128 || !decimalPatternV1.MatchString(s) {
		return nil, 0, false
	}
	if at := strings.IndexAny(s, "eE"); at >= 0 {
		exponent, err := strconv.Atoi(s[at+1:])
		if err != nil || exponent < -32 || exponent > 32 {
			return nil, 0, false
		}
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Num().BitLen() > 1024 || r.Denom().BitLen() > 1024 {
		return nil, 0, false
	}
	n, _ := r.Float64()
	return r, n, !math.IsNaN(n) && !math.IsInf(n, 0)
}

func digestV1(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s && s != strings.Repeat("0", 64)
}

func targetIDV1(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func ValidatePlan(p Plan) error {
	if !utf8.ValidString(p.Text) || len(p.Text) > 800 || utf8.RuneCountInString(p.Text) > 200 || strings.TrimSpace(p.Text) == "" {
		return ErrInvalid
	}
	if _, ok := Font(p.Font); !ok {
		return ErrInvalid
	}
	if !digestV1(p.SourceSHA256) || !digestV1(p.GeometrySHA256) || !digestV1(p.SpanSHA256) || p.Page < 1 || p.Page > 500 || len(p.Targets) < 1 || len(p.Targets) > 128 {
		return ErrInvalid
	}
	_, width, okW := decimalV1(p.WidthPoints)
	_, height, okH := decimalV1(p.HeightPoints)
	if !okW || !okH || width <= 0 || height <= 0 || width > 14400 || height > 14400 {
		return ErrInvalid
	}
	previous := ""
	zero, one := new(big.Rat), big.NewRat(1, 1)
	for _, t := range p.Targets {
		if !targetIDV1(t.ID) || t.ID <= previous {
			return ErrInvalid
		}
		previous = t.ID
		x, _, okX := decimalV1(t.X)
		y, _, okY := decimalV1(t.Y)
		w, _, okW := decimalV1(t.W)
		h, _, okH := decimalV1(t.H)
		if !okX || !okY || !okW || !okH || x.Cmp(zero) < 0 || y.Cmp(zero) < 0 || w.Cmp(zero) <= 0 || h.Cmp(zero) <= 0 || new(big.Rat).Add(x, w).Cmp(one) > 0 || new(big.Rat).Add(y, h).Cmp(one) > 0 {
			return ErrInvalid
		}
	}
	return nil
}

func InputSHA(p Plan) (string, error) {
	if err := ValidatePlan(p); err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", ErrInvalid
	}
	return sha(b), nil
}

func sha(b []byte) string   { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func clonePlan(p Plan) Plan { p.Targets = append([]Target(nil), p.Targets...); return p }
