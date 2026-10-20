// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package ordinarypage defines the frozen ordinary-field page protocol.
// Integrity/layout observations are not signing authority or parsed PDF proof.
package ordinarypage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	PolicyV1             = "hash-ordinary-page-pdf-v1"
	RoutePathV1          = "/hash/chromium/ordinary-page/v1"
	MediaTypeV1          = "application/vnd.hash.ordinary-page.v1"
	MaxPlanBytesV1       = 1 << 20
	MaxRequestBytesV1    = 2 << 20
	MaxFieldsV1          = 1000
	MaxValueBytesV1      = 4096
	MaxPDFBytesV1        = 8 << 20
	MaxReportBytesV1     = 8 << 20
	MaxHTMLBytesV1       = 1 << 20
	MaxFontBytesV1       = 1 << 20
	MaxSnapshotBytesV1   = 8 << 20
	PackageHeaderBytesV1 = 60
	MaxPackageBytesV1    = PackageHeaderBytesV1 + MaxReportBytesV1 + MaxPDFBytesV1 + MaxHTMLBytesV1 + MaxFontBytesV1 + MaxSnapshotBytesV1
	MaxLinesV1           = 10000
	FontFileV1           = "Inter.woff2"
	FontFamilyV1         = "Inter"
	FontBytesV1          = 48256
	FontSHA256V1         = "3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62"
	FontSizePXV1         = 11
	PaddingPXV1          = 2
)

var ErrInvalidV1 = errors.New("ordinarypage: invalid frozen page")
var ErrUnavailableV1 = errors.New("ordinarypage: producer unavailable")

type PlanV1 struct {
	Schema                int            `json:"schema"`
	OrgID                 string         `json:"org_id"`
	DocumentID            string         `json:"document_id"`
	CeremonyEpoch         string         `json:"ceremony_epoch"`
	SourceKey             string         `json:"source_key"`
	SourceVersionID       string         `json:"source_version_id"`
	SourceSHA256          string         `json:"source_sha256"`
	SourceBytes           int64          `json:"source_bytes"`
	SourcePages           int            `json:"source_pages"`
	GeometrySHA256        string         `json:"geometry_sha256"`
	Page                  int            `json:"page"`
	Geometry              PageGeometryV1 `json:"geometry"`
	WidthPoints           string         `json:"width_points"`
	HeightPoints          string         `json:"height_points"`
	StaticBasisSHA256     string         `json:"static_basis_sha256"`
	FieldsSHA256          string         `json:"fields_sha256"`
	BrandingContextSHA256 string         `json:"branding_context_sha256"`
	RenderRecipeSHA256    string         `json:"render_recipe_sha256"`
	Fields                []FieldV1      `json:"fields"`
}
type PageGeometryV1 struct {
	Boxes    [5][4]float64 `json:"boxes"`
	Rotation int           `json:"rotation"`
	UserUnit float64       `json:"user_unit"`
}
type FieldV1 struct {
	ID          string `json:"id"`
	RecipientID string `json:"recipient_id"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	XPct        string `json:"x_pct"`
	YPct        string `json:"y_pct"`
	WPct        string `json:"w_pct"`
	HPct        string `json:"h_pct"`
	ValueValid  bool   `json:"value_valid"`
	Value       string `json:"value"`
}
type FontAssetV1 struct {
	File   string `json:"file"`
	Family string `json:"family"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type RecipeV1 struct {
	Schema             string        `json:"schema"`
	RecipeID           string        `json:"recipe_id"`
	HTMLTemplateSHA256 string        `json:"html_template_sha256"`
	CoreCSSSHA256      string        `json:"core_css_sha256"`
	MeasurementSHA256  string        `json:"measurement_sha256"`
	SnapshotSHA256     string        `json:"snapshot_sha256"`
	PrintRecipeSHA256  string        `json:"print_recipe_sha256"`
	Fonts              []FontAssetV1 `json:"fonts"`
}
type RequestV1 struct {
	Schema    int    `json:"schema"`
	Plan      PlanV1 `json:"plan"`
	FontBytes []byte `json:"font_bytes"`
}
type ProducerV1 interface {
	PrepareOrdinaryPageV1(context.Context, PlanV1) (*PackageV1, error)
}

// The actual caller separately checks reviewed/required values, dropdown/date/
// initial policy, complete party/field membership, source and credentials.
// No false-checkbox-to-required-true rule is invented here.
func ValidatePlanV1(p PlanV1) error {
	if p.Schema != 1 || !validIDV1(p.OrgID) || !validIDV1(p.DocumentID) || !validEpochV1(p.CeremonyEpoch) ||
		!validObjectTextV1(p.SourceKey) || p.SourceKey != strings.TrimSpace(p.SourceKey) || !validVersionV1(p.SourceVersionID) ||
		!validDigestV1(p.SourceSHA256) || p.SourceBytes < 1 || p.SourceBytes > 50<<20 || p.SourcePages < 1 || p.SourcePages > 500 ||
		!validDigestV1(p.GeometrySHA256) || p.Page < 1 || p.Page > p.SourcePages ||
		!validDigestV1(p.StaticBasisSHA256) || !validDigestV1(p.FieldsSHA256) || !validDigestV1(p.BrandingContextSHA256) ||
		p.RenderRecipeSHA256 != RecipeSHA256V1() || len(p.Fields) < 1 || len(p.Fields) > MaxFieldsV1 {
		return ErrInvalidV1
	}
	width, height, err := p.Geometry.ViewportPointsV1()
	_, pw, okW := decimalV1(p.WidthPoints)
	_, ph, okH := decimalV1(p.HeightPoints)
	if err != nil || !okW || !okH || pw != width || ph != height {
		return ErrInvalidV1
	}
	// Conservative JSON cost BEFORE clone/marshal/renderer I/O, including HTML
	// escaping expansion. It is a dispatch bound, not a whole-process memory SLA.
	cost := 8192 + escapedStringCostV1(p.SourceKey) + escapedStringCostV1(p.SourceVersionID)
	previous := ""
	zero, hundred := new(big.Rat), big.NewRat(100, 1)
	for _, f := range p.Fields {
		if !validIDV1(f.ID) || f.ID <= previous || !validIDV1(f.RecipientID) || len(f.Value) > MaxValueBytesV1 || !utf8.ValidString(f.Value) ||
			(!f.ValueValid && f.Value != "") {
			return ErrInvalidV1
		}
		previous = f.ID
		switch f.Type {
		case "text", "date", "initial", "dropdown", "checkbox":
		default:
			return ErrInvalidV1
		}
		for _, r := range f.Value {
			if unicode.IsControl(r) && r != '\r' && r != '\n' {
				return ErrInvalidV1
			}
		}
		x, _, ox := decimalV1(f.XPct)
		y, _, oy := decimalV1(f.YPct)
		w, _, ow := decimalV1(f.WPct)
		h, _, oh := decimalV1(f.HPct)
		if !ox || !oy || !ow || !oh || x.Cmp(zero) < 0 || y.Cmp(zero) < 0 || w.Cmp(zero) <= 0 || h.Cmp(zero) <= 0 ||
			new(big.Rat).Add(x, w).Cmp(hundred) > 0 || new(big.Rat).Add(y, h).Cmp(hundred) > 0 {
			return ErrInvalidV1
		}
		cost += 256 + escapedStringCostV1(f.Value) + escapedStringCostV1(f.XPct) + escapedStringCostV1(f.YPct) + escapedStringCostV1(f.WPct) + escapedStringCostV1(f.HPct)
		if cost > MaxPlanBytesV1 {
			return ErrInvalidV1
		}
	}
	return nil
}
func ClonePlanV1(p PlanV1) (PlanV1, error) {
	if ValidatePlanV1(p) != nil {
		return PlanV1{}, ErrInvalidV1
	}
	p.Fields = append([]FieldV1(nil), p.Fields...)
	return p, nil
}
func PlanSHA256V1(p PlanV1) (string, error) {
	if ValidatePlanV1(p) != nil {
		return "", ErrInvalidV1
	}
	b, err := json.Marshal(p)
	if err != nil || len(b) > MaxPlanBytesV1 {
		return "", ErrInvalidV1
	}
	return digestV1(b), nil
}
func (g PageGeometryV1) ViewportPointsV1() (float64, float64, error) {
	if g.Rotation%90 != 0 || !finiteV1(g.UserUnit) || g.UserUnit <= 0 || g.UserUnit > 75000 {
		return 0, 0, ErrInvalidV1
	}
	for _, b := range g.Boxes {
		for _, n := range b {
			if !finiteV1(n) || math.Abs(n) > 1e9 {
				return 0, 0, ErrInvalidV1
			}
		}
		if b[2] <= b[0] || b[3] <= b[1] {
			return 0, 0, ErrInvalidV1
		}
	}
	m, c := g.Boxes[0], g.Boxes[1]
	x0, y0, x1, y1 := math.Max(m[0], c[0]), math.Max(m[1], c[1]), math.Min(m[2], c[2]), math.Min(m[3], c[3])
	if x1 <= x0 || y1 <= y0 {
		x0, y0, x1, y1 = m[0], m[1], m[2], m[3]
	}
	w, h := (x1-x0)*g.UserUnit, (y1-y0)*g.UserUnit
	if ((g.Rotation%360+360)%360)%180 != 0 {
		w, h = h, w
	}
	if !finiteV1(w) || !finiteV1(h) || w <= 0 || h <= 0 || w > 14400 || h > 14400 {
		return 0, 0, ErrInvalidV1
	}
	return w, h, nil
}
func CheckedV1(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on", "checked", "x":
		return true
	}
	return false
}
func visibleValueV1(f FieldV1) string {
	if !f.ValueValid || f.Type == "checkbox" || strings.TrimSpace(f.Value) == "" {
		return ""
	}
	return f.Value
}
func EncodeRequestV1(p PlanV1, font []byte) ([]byte, error) {
	if ValidatePlanV1(p) != nil || len(font) != FontBytesV1 || digestV1(font) != FontSHA256V1 {
		return nil, ErrInvalidV1
	}
	b, err := json.Marshal(RequestV1{Schema: 1, Plan: p, FontBytes: font})
	if err != nil || len(b) > MaxRequestBytesV1 {
		return nil, ErrInvalidV1
	}
	return b, nil
}
func DecodeRequestV1(ctx context.Context, raw []byte) (RequestV1, error) {
	var r RequestV1
	if closedDecodeV1(ctx, raw, MaxRequestBytesV1, &r) != nil || r.Schema != 1 || ValidatePlanV1(r.Plan) != nil ||
		len(r.FontBytes) != FontBytesV1 || digestV1(r.FontBytes) != FontSHA256V1 {
		return RequestV1{}, ContextErrorV1(ctx)
	}
	return r, nil
}

type contextFailureV1 struct{ causes []error }

func (*contextFailureV1) Error() string     { return "ordinarypage: producer unavailable" }
func (e *contextFailureV1) Unwrap() []error { return e.causes }
func ContextErrorV1(ctx context.Context) error {
	causes := []error{ErrUnavailableV1}
	if ctx != nil && ctx.Err() != nil {
		causes = append(causes, ctx.Err())
		if cause := context.Cause(ctx); cause != nil && cause != ctx.Err() {
			causes = append(causes, cause)
		}
	}
	return &contextFailureV1{causes}
}
func finiteV1(n float64) bool  { return !math.IsNaN(n) && !math.IsInf(n, 0) }
func digestV1(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validDigestV1(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s && s != strings.Repeat("0", 64)
}
func validIDV1(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validEpochV1(s string) bool {
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && t.UTC().Format(time.RFC3339Nano) == s
}
func validObjectTextV1(s string) bool {
	if len(s) < 1 || len(s) > 1024 || !utf8.ValidString(s) || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validVersionV1(s string) bool {
	return validObjectTextV1(s) && strings.TrimSpace(s) != "null" && strings.TrimSpace(s) != "hash:unversioned-development"
}

var decimalPatternV1 = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,2})?$`)

func decimalV1(s string) (*big.Rat, float64, bool) {
	if len(s) < 1 || len(s) > 128 || !decimalPatternV1.MatchString(s) {
		return nil, 0, false
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		n, err := strconv.Atoi(s[i+1:])
		if err != nil || n < -32 || n > 32 {
			return nil, 0, false
		}
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Num().BitLen() > 1024 || r.Denom().BitLen() > 1024 {
		return nil, 0, false
	}
	f, _ := r.Float64()
	return r, f, finiteV1(f)
}
func escapedStringCostV1(s string) int {
	n := 2
	for _, r := range s {
		switch r {
		case '"', '\\', '\r', '\n', '\t':
			n += 2
		case '<', '>', '&', '\u2028', '\u2029':
			n += 6
		default:
			if r < 0x20 {
				n += 6
			} else {
				n += utf8.RuneLen(r)
			}
		}
	}
	return n
}

type jsonBudgetV1 struct{ tokens, lines int }

func closedDecodeV1(ctx context.Context, raw []byte, maxBytes int, dst any) error {
	if ctx == nil || ctx.Err() != nil {
		return ContextErrorV1(ctx)
	}
	if len(raw) < 1 || len(raw) > maxBytes || !utf8.Valid(raw) {
		return ErrInvalidV1
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	budget := &jsonBudgetV1{}
	if closedTokenV1(ctx, d, 0, "", budget) != nil {
		return ErrInvalidV1
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalidV1
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrInvalidV1
	}
	canonical, err := json.Marshal(dst)
	if ctx.Err() != nil {
		return ContextErrorV1(ctx)
	}
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrInvalidV1
	}
	return nil
}
func closedTokenV1(ctx context.Context, d *json.Decoder, depth int, key string, budget *jsonBudgetV1) error {
	budget.tokens++
	if depth > 16 || budget.tokens > 1000000 || budget.tokens%64 == 0 && ctx.Err() != nil {
		return ErrInvalidV1
	}
	t, err := d.Token()
	if err != nil || t == nil {
		return ErrInvalidV1
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			s, ok := k.(string)
			if err != nil || !ok || seen[s] || len(seen) >= 64 {
				return ErrInvalidV1
			}
			seen[s] = true
			if closedTokenV1(ctx, d, depth+1, s, budget) != nil {
				return ErrInvalidV1
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return ErrInvalidV1
		}
	case json.Delim('['):
		count := 0
		limit := 1000
		if key == "fonts" {
			limit = 1
		}
		if key == "styles" {
			limit = 64
		}
		for d.More() {
			count++
			if count > limit {
				return ErrInvalidV1
			}
			if key == "lines" {
				budget.lines++
				if budget.lines > MaxLinesV1 {
					return ErrInvalidV1
				}
			}
			if closedTokenV1(ctx, d, depth+1, key, budget) != nil {
				return ErrInvalidV1
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim(']') {
			return ErrInvalidV1
		}
	}
	return nil
}
