// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package manualfit binds manual signature fitting to application-owned source
// and placement snapshots. It does not authorize or activate a signing flow.
package manualfit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/google/uuid"
)

const (
	AuthoritySchemaV1            = "manual_pdf_fit_v1"
	MaxAuthorityTargetsV1        = 1000
	MaxAuthorityTargetsPerPageV1 = 128
	MaxAuthorityBytesV1          = 1 << 20
)

var ErrAuthorityV1 = errors.New("manualfit: invalid V1 source or all-target authority")

// SourceTupleV1 names an exact source version. VersionID remains opaque: it is
// compared and retained byte-for-byte, never normalized or resolved as latest.
type SourceTupleV1 struct {
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
}

// TargetV1 preserves the database percentage strings independently of the
// renderer's fractional coordinates. The caller supplies every assigned
// signature target from its authoritative snapshot, not arbitrary client rows.
type TargetV1 struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`
	DocumentID  uuid.UUID `json:"document_id"`
	RecipientID uuid.UUID `json:"recipient_id"`
	Page        int       `json:"page"`
	Required    bool      `json:"required"`
	X           string    `json:"x_pct"`
	Y           string    `json:"y_pct"`
	W           string    `json:"w_pct"`
	H           string    `json:"h_pct"`
}

// AuthorityInputV1 is artifact identity, not signing authorization. Notice,
// credential, status and these same source/target tuples still need a locked
// rebind at selection and signature publication. ExpectedTargetIDs must come
// from the captured ALL-target set; it makes omitted and extra rows detectable.
type AuthorityInputV1 struct {
	OrgID             uuid.UUID
	DocumentID        uuid.UUID
	RecipientID       uuid.UUID
	CeremonyEpoch     time.Time
	Source            SourceTupleV1
	TypedName         string
	Font              string
	SpanSHA256        string
	ExpectedTargetIDs []uuid.UUID
	Targets           []TargetV1
}

// PagePlanV1 covers one assigned source page. InputSHA256 commits the exact
// frozen renderer request; the surrounding authority adds object-version and
// application identity commitments absent from that request.
type PagePlanV1 struct {
	Plan        signaturefit.Plan `json:"plan"`
	InputSHA256 string            `json:"input_sha256"`
}

type authorityFontV1 struct {
	File       string `json:"file"`
	SHA256     string `json:"sha256"`
	Family     string `json:"family"`
	PostScript string `json:"postscript"`
}

type authorityCanonicalV1 struct {
	Schema            string                     `json:"schema"`
	OrgID             uuid.UUID                  `json:"org_id"`
	DocumentID        uuid.UUID                  `json:"document_id"`
	RecipientID       uuid.UUID                  `json:"recipient_id"`
	CeremonyEpoch     string                     `json:"ceremony_epoch"`
	Source            SourceTupleV1              `json:"source"`
	TypedName         string                     `json:"typed_name"`
	Font              string                     `json:"font"`
	FontInfo          authorityFontV1            `json:"font_info"`
	SpanSHA256        string                     `json:"span_sha256"`
	Geometry          sanitize.PDFManualGeometry `json:"geometry"`
	ExpectedTargetIDs []uuid.UUID                `json:"expected_target_ids"`
	Targets           []TargetV1                 `json:"targets"`
	Pages             []PagePlanV1               `json:"pages"`
}

// AuthorityV1 is immutable through its public API. Accessors copy every slice.
// It is only the input core of a future retained-package manifest: a page plan
// does not demonstrate that a PDF was rendered, admitted or durably retained.
type AuthorityV1 struct {
	input     AuthorityInputV1
	geometry  sanitize.PDFManualGeometry
	font      signaturefit.FontInfo
	pages     []PagePlanV1
	canonical []byte
	sha256    string
}

// BuildAuthorityV1 consumes already inspected worker geometry; it never parses
// PDF bytes in the application. All pages, including those without targets,
// participate in the geometry commitment. Only assigned pages produce plans.
func BuildAuthorityV1(in AuthorityInputV1, geometry sanitize.PDFManualGeometry) (*AuthorityV1, error) {
	if in.OrgID == uuid.Nil || in.DocumentID == uuid.Nil || in.RecipientID == uuid.Nil ||
		in.CeremonyEpoch.IsZero() || in.CeremonyEpoch.Year() < 1 || in.CeremonyEpoch.Year() > 9999 ||
		!authorityObjectTextV1(in.Source.Key) || !validObjectVersionV1(in.Source.VersionID) ||
		!authorityDigestV1(in.Source.SHA256) || !authorityDigestV1(in.SpanSHA256) ||
		in.Source.Bytes < 1 || in.Source.Bytes > sanitize.MaxPDFBytes ||
		len(in.Targets) < 1 || len(in.Targets) > MaxAuthorityTargetsV1 ||
		len(in.ExpectedTargetIDs) != len(in.Targets) {
		return nil, ErrAuthorityV1
	}
	font, ok := signaturefit.Font(in.Font)
	if !ok {
		return nil, ErrAuthorityV1
	}
	if geometry.SchemaVersion != 1 || geometry.SourceSHA256 != in.Source.SHA256 ||
		geometry.SourceBytes != in.Source.Bytes || !authorityDigestV1(geometry.GeometrySHA256) ||
		len(geometry.Pages) < 1 || len(geometry.Pages) > sanitize.MaxPDFPages {
		return nil, ErrAuthorityV1
	}
	geometry.Pages = append([]sanitize.PDFManualPage(nil), geometry.Pages...)
	for _, page := range geometry.Pages {
		if _, _, err := page.ViewportPoints(); err != nil {
			return nil, ErrAuthorityV1
		}
	}
	// PDFManualPage deliberately has the same V1 field order and JSON tags as
	// the worker's pdfCompositionRawPage. This is its full geometry SHA policy.
	geometryJSON, err := json.Marshal(geometry.Pages)
	if err != nil || authoritySHA256V1(geometryJSON) != geometry.GeometrySHA256 {
		return nil, ErrAuthorityV1
	}
	in.CeremonyEpoch = in.CeremonyEpoch.UTC().Round(0)
	in.ExpectedTargetIDs = append([]uuid.UUID(nil), in.ExpectedTargetIDs...)
	in.Targets = append([]TargetV1(nil), in.Targets...)
	sort.Slice(in.ExpectedTargetIDs, func(i, j int) bool { return bytes.Compare(in.ExpectedTargetIDs[i][:], in.ExpectedTargetIDs[j][:]) < 0 })
	sort.Slice(in.Targets, func(i, j int) bool { return bytes.Compare(in.Targets[i].ID[:], in.Targets[j].ID[:]) < 0 })
	byPage := make(map[int][]signaturefit.Target)
	for i, target := range in.Targets {
		if target.ID == uuid.Nil || target.ID != in.ExpectedTargetIDs[i] ||
			(i > 0 && (target.ID == in.Targets[i-1].ID || in.ExpectedTargetIDs[i] == in.ExpectedTargetIDs[i-1])) ||
			target.OrgID != in.OrgID || target.DocumentID != in.DocumentID || target.RecipientID != in.RecipientID ||
			!target.Required || target.Page < 1 || target.Page > len(geometry.Pages) {
			return nil, ErrAuthorityV1
		}
		x, errX := PercentToFractionV1(target.X)
		y, errY := PercentToFractionV1(target.Y)
		w, errW := PercentToFractionV1(target.W)
		h, errH := PercentToFractionV1(target.H)
		if errX != nil || errY != nil || errW != nil || errH != nil {
			return nil, ErrAuthorityV1
		}
		byPage[target.Page] = append(byPage[target.Page], signaturefit.Target{ID: target.ID.String(), X: x, Y: y, W: w, H: h})
		if len(byPage[target.Page]) > MaxAuthorityTargetsPerPageV1 {
			return nil, ErrAuthorityV1
		}
	}
	pageNumbers := make([]int, 0, len(byPage))
	for page := range byPage {
		pageNumbers = append(pageNumbers, page)
	}
	sort.Ints(pageNumbers)
	pages := make([]PagePlanV1, 0, len(pageNumbers))
	totalPlanBytes := 0
	for _, page := range pageNumbers {
		width, height, err := geometry.Pages[page-1].ViewportPoints()
		if err != nil {
			return nil, ErrAuthorityV1
		}
		plan := signaturefit.Plan{Text: in.TypedName, Font: in.Font, SourceSHA256: in.Source.SHA256,
			GeometrySHA256: geometry.GeometrySHA256, SpanSHA256: in.SpanSHA256, Page: page,
			WidthPoints: strconv.FormatFloat(width, 'f', -1, 64), HeightPoints: strconv.FormatFloat(height, 'f', -1, 64),
			Targets: byPage[page]}
		if err := signaturefit.ValidatePlan(plan); err != nil {
			return nil, ErrAuthorityV1
		}
		inputSHA, err := signaturefit.InputSHA(plan)
		if err != nil {
			return nil, ErrAuthorityV1
		}
		planJSON, err := json.Marshal(plan)
		if err != nil || len(planJSON) > signaturefit.MaxRequestBytes-totalPlanBytes {
			return nil, ErrAuthorityV1
		}
		totalPlanBytes += len(planJSON)
		pages = append(pages, PagePlanV1{Plan: plan, InputSHA256: inputSHA})
	}
	canonical, err := json.Marshal(authorityCanonicalV1{Schema: AuthoritySchemaV1, OrgID: in.OrgID,
		DocumentID: in.DocumentID, RecipientID: in.RecipientID, CeremonyEpoch: in.CeremonyEpoch.Format(time.RFC3339Nano),
		Source: in.Source, TypedName: in.TypedName, Font: in.Font,
		FontInfo: authorityFontV1{font.File, font.SHA256, font.Family, font.PostScript}, SpanSHA256: in.SpanSHA256,
		Geometry: geometry, ExpectedTargetIDs: in.ExpectedTargetIDs, Targets: in.Targets, Pages: pages})
	if err != nil || len(canonical) > MaxAuthorityBytesV1 {
		return nil, ErrAuthorityV1
	}
	return &AuthorityV1{input: in, geometry: geometry, font: font, pages: pages,
		canonical: canonical, sha256: authoritySHA256V1(canonical)}, nil
}

// PercentToFractionV1 converts a bounded base-10 database percentage to a
// canonical exact fraction. No float or rounded division participates. Raw
// percentage strings remain unchanged in AuthorityV1's input commitment.
func PercentToFractionV1(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 128 {
		return "", ErrAuthorityV1
	}
	s := raw
	negative := false
	if s[0] == '+' || s[0] == '-' {
		negative = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return "", ErrAuthorityV1
	}
	scale, digits, seenDot := 0, "", false
	for _, c := range s {
		if c == '.' && !seenDot {
			seenDot = true
			continue
		}
		if c < '0' || c > '9' {
			return "", ErrAuthorityV1
		}
		digits += string(c)
		if seenDot {
			scale++
		}
	}
	if digits == "" || scale > 32 {
		return "", ErrAuthorityV1
	}
	coefficient, ok := new(big.Int).SetString(digits, 10)
	if !ok || coefficient.BitLen() > 512 {
		return "", ErrAuthorityV1
	}
	if negative {
		coefficient.Neg(coefficient)
	}
	denominator := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)
	if coefficient.Sign() < 0 || coefficient.Cmp(new(big.Int).Mul(denominator, big.NewInt(100))) > 0 {
		return "", ErrAuthorityV1
	}
	if coefficient.Sign() == 0 {
		return "0", nil
	}
	decimal := coefficient.String()
	scale += 2
	if len(decimal) <= scale {
		decimal = strings.Repeat("0", scale+1-len(decimal)) + decimal
	}
	decimal = decimal[:len(decimal)-scale] + "." + decimal[len(decimal)-scale:]
	return strings.TrimRight(strings.TrimRight(decimal, "0"), "."), nil
}

func (a *AuthorityV1) Input() AuthorityInputV1 {
	if a == nil {
		return AuthorityInputV1{}
	}
	in := a.input
	in.ExpectedTargetIDs = append([]uuid.UUID(nil), in.ExpectedTargetIDs...)
	in.Targets = append([]TargetV1(nil), in.Targets...)
	return in
}

func (a *AuthorityV1) Geometry() sanitize.PDFManualGeometry {
	if a == nil {
		return sanitize.PDFManualGeometry{}
	}
	g := a.geometry
	g.Pages = append([]sanitize.PDFManualPage(nil), g.Pages...)
	return g
}

func (a *AuthorityV1) Pages() []PagePlanV1 {
	if a == nil {
		return nil
	}
	pages := append([]PagePlanV1(nil), a.pages...)
	for i := range pages {
		pages[i].Plan.Targets = append([]signaturefit.Target(nil), pages[i].Plan.Targets...)
	}
	return pages
}

func (a *AuthorityV1) FontInfo() signaturefit.FontInfo {
	if a == nil {
		return signaturefit.FontInfo{}
	}
	return a.font
}

func (a *AuthorityV1) CanonicalJSON() []byte {
	if a == nil {
		return nil
	}
	return bytes.Clone(a.canonical)
}

func (a *AuthorityV1) SHA256() string {
	if a == nil {
		return ""
	}
	return a.sha256
}

func authorityObjectTextV1(s string) bool {
	if len(s) == 0 || len(s) > 1024 || !utf8.ValidString(s) || strings.TrimSpace(s) == "" {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func authorityDigestV1(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s && s != strings.Repeat("0", 64)
}

func authoritySHA256V1(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
