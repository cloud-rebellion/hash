// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package pdfadmission freezes standalone PDF signing inputs before the first
// actual signature. Its model proves bounded canonical identity/consistency,
// not caller permission, genuine inspection/rendering, SQL sealing or retention.
package pdfadmission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
)

const (
	SchemaV1                             = "hash-pdf-signing-static-basis-v1"
	DomainV1                             = "hash:pdf-signing-static-basis:v1:"
	MaxCanonicalBytesV1                  = 4 << 20
	MaxComponentBytesV1                  = 1 << 20
	MaxRenderRecipeBytesV1               = 256 << 10
	MaxBrandingCSSBytesV1                = 64 << 10
	MaxOriginalDocumentNameBytesV1       = 65536
	OrdinaryRecipeSchemaV1               = "hash-ordinary-page-recipe-v1"
	OrdinaryRecipeIDV1                   = "hash-ordinary-page-inter-11px-v1"
	OrdinaryFontFileV1                   = "Inter.woff2"
	OrdinaryFontFamilyV1                 = "Inter"
	OrdinaryFontBytesV1            int64 = 48256
	OrdinaryFontSHA256V1                 = "3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62"
)

var ErrBasisV1 = errors.New("pdfadmission: invalid immutable PDF signing basis")
var decimalV1 = regexp.MustCompile("^-?[0-9]+(?:[.][0-9]+)?$")

// FieldV1's capitalized wire keys/order match the Fields ARRAY in the historical
// finalization basis. Scope is verified on capture and is inherited from the
// basis header on decode. No Legacy/future name/font/time is fabricated here.
type FieldV1 struct {
	OrgID          uuid.UUID `json:"-"`
	DocumentID     uuid.UUID `json:"-"`
	ID             uuid.UUID
	RecipientID    uuid.UUID
	RecipientValid bool
	Type           string
	Page           int32
	Required       bool
	X              string
	Y              string
	W              string
	H              string
	ValueValid     bool
	Value          string
}

type PartyV1 struct {
	OrgID      uuid.UUID `json:"-"`
	DocumentID uuid.UUID `json:"-"`
	ID         uuid.UUID `json:"id"`
	Role       string    `json:"role"`
	Email      string    `json:"email"`
	Name       string    `json:"name"`
	OrderIndex int32     `json:"order_index"`
	Locale     string    `json:"locale"`
}

type FontAssetV1 struct {
	File   string `json:"file"`
	Family string `json:"family"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// BrandingCSS is frozen ORIGINAL context, not permission to insert arbitrary
// CSS into the ordinary producer. Source PDF pins preserve its visual branding.
// The fixed owned ordinary recipe is committed separately from this context.
type RenderRecipeV1 struct {
	Schema             string
	RecipeID           string
	HTMLTemplateSHA256 string
	CoreCSSSHA256      string
	MeasurementSHA256  string
	SnapshotSHA256     string
	PrintRecipeSHA256  string
	BrandingCSS        string
	Fonts              []FontAssetV1
}

type InputV1 struct {
	OrgID                uuid.UUID
	DocumentID           uuid.UUID
	OriginalDocumentName string
	CeremonyEpoch        time.Time
	SourceKind           string
	RequiresSignature    bool
	IsEnvelope           bool
	ParentEnvelopeID     uuid.UUID
	Source               manualfit.SourceTupleV1
	Geometry             sanitize.PDFManualGeometry
	Fields               []FieldV1
	Parties              []PartyV1
	RequiredRoles        []string // Exact set captured by the actual locked application.
	RoutingMode          string
	RenderRecipe         RenderRecipeV1
}

type partyPlanV1 struct {
	RequiredRoles []string  `json:"required_roles"`
	RoutingMode   string    `json:"routing_mode"`
	Parties       []PartyV1 `json:"parties"`
}

type ordinaryRecipeV1 struct {
	Schema             string        `json:"schema"`
	RecipeID           string        `json:"recipe_id"`
	HTMLTemplateSHA256 string        `json:"html_template_sha256"`
	CoreCSSSHA256      string        `json:"core_css_sha256"`
	MeasurementSHA256  string        `json:"measurement_sha256"`
	SnapshotSHA256     string        `json:"snapshot_sha256"`
	PrintRecipeSHA256  string        `json:"print_recipe_sha256"`
	Fonts              []FontAssetV1 `json:"fonts"`
}

type brandingContextV1 struct {
	CSS    string `json:"css"`
	SHA256 string `json:"sha256"`
}

type renderRecipeWireV1 struct {
	Ordinary                ordinaryRecipeV1  `json:"ordinary"`
	OriginalBrandingContext brandingContextV1 `json:"original_branding_context"`
}

type basisWireV1 struct {
	Schema               string                     `json:"schema"`
	OrgID                uuid.UUID                  `json:"org_id"`
	DocumentID           uuid.UUID                  `json:"document_id"`
	OriginalDocumentName string                     `json:"original_document_name"`
	CeremonyEpoch        string                     `json:"ceremony_epoch"`
	SourceKind           string                     `json:"source_kind"`
	RequiresSignature    bool                       `json:"requires_signature"`
	IsEnvelope           bool                       `json:"is_envelope"`
	ParentEnvelopeID     uuid.UUID                  `json:"parent_envelope_id"`
	Source               manualfit.SourceTupleV1    `json:"source"`
	Geometry             sanitize.PDFManualGeometry `json:"geometry"`
	Fields               []FieldV1                  `json:"fields"`
	PartyPlan            partyPlanV1                `json:"party_plan"`
	RenderRecipe         renderRecipeWireV1         `json:"render_recipe"`
}

// BasisV1 owns immutable clones. Component SHAs are plain literal-byte hashes;
// SHA256 is domain-separated and CanonicalSHA256 is the plain object-body SHA.
// FieldsSHA256 is NOT the eventual Fields+Legacy finalization hash. Caller88
// admission must reserve that final wrapper and all actual/future legacy
// descriptors within its separate existing 1MiB final-basis and 8MiB index gates.
type BasisV1 struct {
	input          InputV1
	canonical      []byte
	geometry       []byte
	geometryPages  []byte
	fields         []byte
	parties        []byte
	recipe         []byte
	ordinaryRecipe []byte
	ordinaryPages  []int
	sha            string
}

// BuildV1 consumes an application-owned complete snapshot. Stored source SHA
// and geometry metadata do not prove a worker inspected those bytes. Actual
// Send/selection/first-Sign SQL must independently bind this exact complete row
// set, reviewed values, original credential, source/version and rendering proof.
// Empty ordinary values are valid provisional input; readiness and Sign retain
// current required-field policy. This constructor neither freezes edits nor signs.
func BuildV1(in InputV1) (*BasisV1, error) {
	if in.OrgID == uuid.Nil || in.DocumentID == uuid.Nil || in.SourceKind != "pdf" || !in.RequiresSignature || in.IsEnvelope || in.ParentEnvelopeID != uuid.Nil ||
		in.CeremonyEpoch.IsZero() || in.CeremonyEpoch.Year() < 1 || in.CeremonyEpoch.Year() > 9999 || in.CeremonyEpoch.Nanosecond()%1000 != 0 ||
		!textV1(in.OriginalDocumentName, MaxOriginalDocumentNameBytesV1, false) || strings.TrimSpace(in.OriginalDocumentName) == "" ||
		!objectKeyV1(in.Source.Key) || !manualfit.ValidObjectVersionV1(in.Source.VersionID) || !digestV1(in.Source.SHA256) || in.Source.Bytes < 1 || in.Source.Bytes > sanitize.MaxPDFBytes ||
		len(in.Fields) < 1 || len(in.Fields) > pdflayout.MaxFields || len(in.Parties) < 1 || len(in.Parties) > pdflayout.MaxParties || len(in.RequiredRoles) != len(in.Parties) ||
		(in.RoutingMode != "parallel" && in.RoutingMode != "sequential") {
		return nil, ErrBasisV1
	}
	if !validGeometryV1(in.Geometry, in.Source) || !validRecipeV1(in.RenderRecipe) {
		return nil, ErrBasisV1
	}
	in.CeremonyEpoch = in.CeremonyEpoch.UTC().Round(0)
	in.Geometry.Pages = append([]sanitize.PDFManualPage(nil), in.Geometry.Pages...)
	in.Fields = append([]FieldV1(nil), in.Fields...)
	in.Parties = append([]PartyV1(nil), in.Parties...)
	in.RequiredRoles = append([]string(nil), in.RequiredRoles...)
	in.RenderRecipe.Fonts = append([]FontAssetV1(nil), in.RenderRecipe.Fonts...)
	sort.Slice(in.Fields, func(i, j int) bool { return bytes.Compare(in.Fields[i].ID[:], in.Fields[j].ID[:]) < 0 })
	sort.Slice(in.Parties, func(i, j int) bool { return bytes.Compare(in.Parties[i].ID[:], in.Parties[j].ID[:]) < 0 })
	sort.Strings(in.RequiredRoles)
	sort.Slice(in.RenderRecipe.Fonts, func(i, j int) bool { return in.RenderRecipe.Fonts[i].File < in.RenderRecipe.Fonts[j].File })
	byParty := make(map[uuid.UUID]PartyV1, len(in.Parties))
	byRole := make(map[string]bool, len(in.Parties))
	for j, p := range in.Parties {
		if p.ID == uuid.Nil || p.OrgID != in.OrgID || p.DocumentID != in.DocumentID || (j > 0 && p.ID == in.Parties[j-1].ID) || byRole[p.Role] ||
			recipients.ValidateResponseRole(p.Role) != nil || recipients.ValidatePersisted(recipients.Values{Email: p.Email, Name: p.Name, Role: p.Role, OrderIndex: p.OrderIndex, Locale: p.Locale}) != nil {
			return nil, ErrBasisV1
		}
		byParty[p.ID] = p
		byRole[p.Role] = true
	}
	for j, role := range in.RequiredRoles {
		if !byRole[role] || (j > 0 && role == in.RequiredRoles[j-1]) {
			return nil, ErrBasisV1
		}
	}
	seenSignature := make(map[uuid.UUID]bool, len(in.Parties))
	perPage := make(map[uuid.UUID]map[int32]int, len(in.Parties))
	ordinaryPages := make(map[int]bool)
	fieldEncodedBytes := 2
	for j, f := range in.Fields {
		party, ok := byParty[f.RecipientID]
		if f.ID == uuid.Nil || f.OrgID != in.OrgID || f.DocumentID != in.DocumentID || (j > 0 && f.ID == in.Fields[j-1].ID) ||
			!f.RecipientValid || !ok || f.Page < 1 || int(f.Page) > len(in.Geometry.Pages) || !validRectangleV1(f) ||
			!textV1(f.Value, MaxComponentBytesV1, true) || (!f.ValueValid && f.Value != "") {
			return nil, ErrBasisV1
		}
		if f.Type == "signature" {
			if !f.Required || (f.ValueValid && strings.TrimSpace(f.Value) != "") {
				return nil, ErrBasisV1
			}
			seenSignature[f.RecipientID] = true
			if perPage[f.RecipientID] == nil {
				perPage[f.RecipientID] = make(map[int32]int)
			}
			perPage[f.RecipientID][f.Page]++
			if perPage[f.RecipientID][f.Page] > manualfit.MaxAuthorityTargetsPerPageV1 {
				return nil, ErrBasisV1
			}
		} else {
			if len(in.Parties) != 1 || party.Role != "signer" {
				return nil, ErrBasisV1
			}
			switch f.Type {
			case "text", "date", "checkbox", "dropdown", "initial":
			default:
				return nil, ErrBasisV1
			}
			if paintsOrdinaryV1(f) {
				ordinaryPages[int(f.Page)] = true
			}
		}
		// Marshal only a bounded empty-value header before admitting the actual JSON
		// escaping expansion. A large original value never allocates its encoded copy
		// until the full Fields ARRAY has passed its shared 1MiB component gate.
		empty := f
		empty.Value = ""
		header, err := json.Marshal(empty)
		if err != nil {
			return nil, ErrBasisV1
		}
		encoded, ok := jsonStringBytesV1(f.Value, MaxComponentBytesV1)
		if !ok {
			return nil, ErrBasisV1
		}
		addition := len(header) + encoded - 2
		if j > 0 {
			addition++
		}
		if addition > MaxComponentBytesV1-fieldEncodedBytes {
			return nil, ErrBasisV1
		}
		fieldEncodedBytes += addition
	}
	for id := range byParty {
		if !seenSignature[id] {
			return nil, ErrBasisV1
		}
	}
	geom, err := json.Marshal(in.Geometry)
	if err != nil || len(geom) > MaxComponentBytesV1 {
		return nil, ErrBasisV1
	}
	geomPages, err := json.Marshal(in.Geometry.Pages)
	if err != nil || len(geomPages) > MaxComponentBytesV1 {
		return nil, ErrBasisV1
	}
	fields, err := json.Marshal(in.Fields)
	if err != nil || len(fields) != fieldEncodedBytes || len(fields) > MaxComponentBytesV1 {
		return nil, ErrBasisV1
	}
	partyPlan := partyPlanV1{RequiredRoles: in.RequiredRoles, RoutingMode: in.RoutingMode, Parties: in.Parties}
	parties, err := json.Marshal(partyPlan)
	if err != nil || len(parties) > MaxComponentBytesV1 {
		return nil, ErrBasisV1
	}
	ordinary := ordinaryRecipeV1{Schema: in.RenderRecipe.Schema, RecipeID: in.RenderRecipe.RecipeID, HTMLTemplateSHA256: in.RenderRecipe.HTMLTemplateSHA256, CoreCSSSHA256: in.RenderRecipe.CoreCSSSHA256,
		MeasurementSHA256: in.RenderRecipe.MeasurementSHA256, SnapshotSHA256: in.RenderRecipe.SnapshotSHA256, PrintRecipeSHA256: in.RenderRecipe.PrintRecipeSHA256, Fonts: in.RenderRecipe.Fonts}
	recipeWire := renderRecipeWireV1{Ordinary: ordinary, OriginalBrandingContext: brandingContextV1{CSS: in.RenderRecipe.BrandingCSS, SHA256: plainSHA256V1([]byte(in.RenderRecipe.BrandingCSS))}}
	emptyRecipe := recipeWire
	emptyRecipe.OriginalBrandingContext.CSS = ""
	recipeHeader, err := json.Marshal(emptyRecipe)
	if err != nil {
		return nil, ErrBasisV1
	}
	cssBytes, ok := jsonStringBytesV1(in.RenderRecipe.BrandingCSS, MaxRenderRecipeBytesV1)
	if !ok || len(recipeHeader)+cssBytes-2 > MaxRenderRecipeBytesV1 {
		return nil, ErrBasisV1
	}
	recipe, err := json.Marshal(recipeWire)
	if err != nil || len(recipe) > MaxRenderRecipeBytesV1 {
		return nil, ErrBasisV1
	}
	ownedRecipe, err := json.Marshal(ordinary)
	if err != nil {
		return nil, ErrBasisV1
	}
	wire := basisWireV1{Schema: SchemaV1, OrgID: in.OrgID, DocumentID: in.DocumentID, OriginalDocumentName: in.OriginalDocumentName, CeremonyEpoch: in.CeremonyEpoch.Format(time.RFC3339Nano),
		SourceKind: in.SourceKind, RequiresSignature: in.RequiresSignature, IsEnvelope: in.IsEnvelope, ParentEnvelopeID: in.ParentEnvelopeID, Source: in.Source, Geometry: in.Geometry, Fields: in.Fields, PartyPlan: partyPlan, RenderRecipe: recipeWire}
	// Components contain bounded canonical arrays; this sum is conservative for
	// the small fixed header and escaped original document name, before Marshal.
	nameBytes, ok := jsonStringBytesV1(in.OriginalDocumentName, MaxCanonicalBytesV1)
	if !ok {
		return nil, ErrBasisV1
	}
	if len(geom)+len(fields)+len(parties)+len(recipe)+nameBytes+4096 > MaxCanonicalBytesV1 {
		return nil, ErrBasisV1
	}
	canonical, err := json.Marshal(wire)
	if err != nil || len(canonical) > MaxCanonicalBytesV1 {
		return nil, ErrBasisV1
	}
	pages := make([]int, 0, len(ordinaryPages))
	for p := range ordinaryPages {
		pages = append(pages, p)
	}
	sort.Ints(pages)
	committed := sha256.New()
	_, _ = committed.Write([]byte(DomainV1))
	_, _ = committed.Write(canonical)
	return &BasisV1{input: in, canonical: canonical, geometry: geom, geometryPages: geomPages, fields: fields, parties: parties, recipe: recipe, ordinaryRecipe: ownedRecipe, ordinaryPages: pages, sha: hex.EncodeToString(committed.Sum(nil))}, nil
}

// DecodeV1 accepts only exactly the canonical closed UTF-8 wire. Array counts
// and component lengths are checked before typed slice decoding. Duplicate keys,
// alternative ordering/whitespace/number spelling and extra trailing values all
// refuse rather than being normalized into a different stored commitment.
func DecodeV1(raw []byte) (*BasisV1, error) {
	if len(raw) < 1 || len(raw) > MaxCanonicalBytesV1 || !utf8.Valid(raw) {
		return nil, ErrBasisV1
	}
	var env struct {
		Schema               string          `json:"schema"`
		OrgID                uuid.UUID       `json:"org_id"`
		DocumentID           uuid.UUID       `json:"document_id"`
		OriginalDocumentName string          `json:"original_document_name"`
		CeremonyEpoch        string          `json:"ceremony_epoch"`
		SourceKind           string          `json:"source_kind"`
		RequiresSignature    bool            `json:"requires_signature"`
		IsEnvelope           bool            `json:"is_envelope"`
		ParentEnvelopeID     uuid.UUID       `json:"parent_envelope_id"`
		Source               json.RawMessage `json:"source"`
		Geometry             json.RawMessage `json:"geometry"`
		Fields               json.RawMessage `json:"fields"`
		PartyPlan            json.RawMessage `json:"party_plan"`
		RenderRecipe         json.RawMessage `json:"render_recipe"`
	}
	if decodeClosedV1(raw, &env) != nil || env.Schema != SchemaV1 || !componentV1(env.Source, 16<<10) || len(env.OriginalDocumentName) > MaxOriginalDocumentNameBytesV1 || len(env.CeremonyEpoch) > 40 || !componentV1(env.Geometry, MaxComponentBytesV1) || !componentV1(env.Fields, MaxComponentBytesV1) || !componentV1(env.PartyPlan, MaxComponentBytesV1) || !componentV1(env.RenderRecipe, MaxRenderRecipeBytesV1) {
		return nil, ErrBasisV1
	}
	var geometry struct {
		SchemaVersion  int             `json:"schema_version"`
		SourceSHA256   string          `json:"source_sha256"`
		SourceBytes    int64           `json:"source_bytes"`
		GeometrySHA256 string          `json:"geometry_sha256"`
		Pages          json.RawMessage `json:"pages"`
	}
	var parties struct {
		RequiredRoles json.RawMessage `json:"required_roles"`
		RoutingMode   string          `json:"routing_mode"`
		Parties       json.RawMessage `json:"parties"`
	}
	var recipe struct {
		Ordinary struct {
			Schema             string          `json:"schema"`
			RecipeID           string          `json:"recipe_id"`
			HTMLTemplateSHA256 string          `json:"html_template_sha256"`
			CoreCSSSHA256      string          `json:"core_css_sha256"`
			MeasurementSHA256  string          `json:"measurement_sha256"`
			SnapshotSHA256     string          `json:"snapshot_sha256"`
			PrintRecipeSHA256  string          `json:"print_recipe_sha256"`
			Fonts              json.RawMessage `json:"fonts"`
		} `json:"ordinary"`
		OriginalBrandingContext brandingContextV1 `json:"original_branding_context"`
	}
	if decodeClosedV1(env.Geometry, &geometry) != nil || arrayCountV1(geometry.Pages, sanitize.MaxPDFPages) < 1 || arrayCountV1(env.Fields, pdflayout.MaxFields) < 1 ||
		decodeClosedV1(env.PartyPlan, &parties) != nil || arrayCountV1(parties.Parties, pdflayout.MaxParties) < 1 || arrayCountV1(parties.RequiredRoles, pdflayout.MaxParties) < 1 ||
		decodeClosedV1(env.RenderRecipe, &recipe) != nil || arrayCountV1(recipe.Ordinary.Fonts, 1) != 1 {
		return nil, ErrBasisV1
	}
	var wire basisWireV1
	if decodeClosedV1(raw, &wire) != nil {
		return nil, ErrBasisV1
	}
	epoch, err := time.Parse(time.RFC3339Nano, wire.CeremonyEpoch)
	if err != nil {
		return nil, ErrBasisV1
	}
	for j := range wire.Fields {
		wire.Fields[j].OrgID = wire.OrgID
		wire.Fields[j].DocumentID = wire.DocumentID
	}
	for j := range wire.PartyPlan.Parties {
		wire.PartyPlan.Parties[j].OrgID = wire.OrgID
		wire.PartyPlan.Parties[j].DocumentID = wire.DocumentID
	}
	r := wire.RenderRecipe.Ordinary
	in := InputV1{OrgID: wire.OrgID, DocumentID: wire.DocumentID, OriginalDocumentName: wire.OriginalDocumentName, CeremonyEpoch: epoch, SourceKind: wire.SourceKind, RequiresSignature: wire.RequiresSignature,
		IsEnvelope: wire.IsEnvelope, ParentEnvelopeID: wire.ParentEnvelopeID, Source: wire.Source, Geometry: wire.Geometry, Fields: wire.Fields, Parties: wire.PartyPlan.Parties, RequiredRoles: wire.PartyPlan.RequiredRoles, RoutingMode: wire.PartyPlan.RoutingMode,
		RenderRecipe: RenderRecipeV1{Schema: r.Schema, RecipeID: r.RecipeID, HTMLTemplateSHA256: r.HTMLTemplateSHA256, CoreCSSSHA256: r.CoreCSSSHA256, MeasurementSHA256: r.MeasurementSHA256, SnapshotSHA256: r.SnapshotSHA256, PrintRecipeSHA256: r.PrintRecipeSHA256, BrandingCSS: wire.RenderRecipe.OriginalBrandingContext.CSS, Fonts: r.Fonts}}
	basis, err := BuildV1(in)
	if err != nil || !bytes.Equal(raw, basis.canonical) {
		return nil, ErrBasisV1
	}
	return basis, nil
}

func validGeometryV1(g sanitize.PDFManualGeometry, s manualfit.SourceTupleV1) bool {
	if g.SchemaVersion != 1 || g.SourceSHA256 != s.SHA256 || g.SourceBytes != s.Bytes || !digestV1(g.GeometrySHA256) || len(g.Pages) < 1 || len(g.Pages) > sanitize.MaxPDFPages {
		return false
	}
	for _, p := range g.Pages {
		if p.Rotation%90 != 0 || math.IsNaN(p.UserUnit) || math.IsInf(p.UserUnit, 0) || p.UserUnit <= 0 {
			return false
		}
		for _, box := range p.Boxes {
			for _, n := range box {
				if math.IsNaN(n) || math.IsInf(n, 0) {
					return false
				}
			}
			if box[2] <= box[0] || box[3] <= box[1] {
				return false
			}
		}
		if _, _, err := p.ViewportPoints(); err != nil {
			return false
		}
	}
	raw, err := json.Marshal(g.Pages)
	return err == nil && len(raw) <= MaxComponentBytesV1 && plainSHA256V1(raw) == g.GeometrySHA256
}

// Known template/measurement/print hash ownership is verified by the actual
// ordinary producer/caller. This model binds their declared exact identity.
func validRecipeV1(r RenderRecipeV1) bool {
	return r.Schema == OrdinaryRecipeSchemaV1 && r.RecipeID == OrdinaryRecipeIDV1 && digestV1(r.HTMLTemplateSHA256) && digestV1(r.CoreCSSSHA256) &&
		digestV1(r.MeasurementSHA256) && digestV1(r.SnapshotSHA256) && digestV1(r.PrintRecipeSHA256) && textV1(r.BrandingCSS, MaxBrandingCSSBytesV1, true) &&
		len(r.Fonts) == 1 && r.Fonts[0].File == OrdinaryFontFileV1 && r.Fonts[0].Family == OrdinaryFontFamilyV1 && r.Fonts[0].SHA256 == OrdinaryFontSHA256V1 && r.Fonts[0].Bytes == OrdinaryFontBytesV1
}

func validRectangleV1(f FieldV1) bool {
	values := []string{f.X, f.Y, f.W, f.H}
	numbers := make([]*big.Rat, 4)
	for i, s := range values {
		if len(s) < 1 || len(s) > 128 || !decimalV1.MatchString(s) {
			return false
		}
		n, ok := new(big.Rat).SetString(s)
		if !ok || n.Num().BitLen() > 512 || n.Denom().BitLen() > 512 {
			return false
		}
		numbers[i] = n
	}
	x, y, w, h := numbers[0], numbers[1], numbers[2], numbers[3]
	return x.Sign() >= 0 && y.Sign() >= 0 && w.Sign() > 0 && h.Sign() > 0 && new(big.Rat).Add(x, w).Cmp(big.NewRat(100, 1)) <= 0 && new(big.Rat).Add(y, h).Cmp(big.NewRat(100, 1)) <= 0
}

func paintsOrdinaryV1(f FieldV1) bool {
	return f.Type != "signature" && f.ValueValid && strings.TrimSpace(f.Value) != "" && (f.Type != "checkbox" || CheckboxTruthyV1(f.Value))
}

// CheckboxTruthyV1 preserves the existing renderer classification only. It
// neither normalizes the original value nor determines required-field policy.
func CheckboxTruthyV1(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "on", "checked", "x":
		return true
	}
	return false
}

func textV1(s string, max int, empty bool) bool {
	return len(s) <= max && (empty || len(s) > 0) && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func objectKeyV1(s string) bool {
	if !textV1(s, 1024, false) || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func digestV1(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s && s != strings.Repeat("0", 64)
}
func plainSHA256V1(raw []byte) string      { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func componentV1(raw []byte, max int) bool { return len(raw) > 0 && len(raw) <= max }
func decodeClosedV1(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return ErrBasisV1
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrBasisV1
	}
	return nil
}
func arrayCountV1(raw []byte, max int) int {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('[') {
		return -1
	}
	n := 0
	for d.More() {
		n++
		if n > max {
			return -1
		}
		var item json.RawMessage
		if d.Decode(&item) != nil {
			return -1
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim(']') || d.Decode(new(any)) != io.EOF {
		return -1
	}
	return n
}

func jsonStringBytesV1(s string, max int) (int, bool) {
	n := 2
	for _, r := range s {
		add := utf8.RuneLen(r)
		switch r {
		case '"', '\\', '\n', '\r', '\t', '\b', '\f':
			add = 2
		case '<', '>', '&', '\u2028', '\u2029':
			add = 6
		default:
			if r < 0x20 {
				add = 6
			}
		}
		if add < 0 || add > max-n {
			return 0, false
		}
		n += add
	}
	return n, true
}

func (b *BasisV1) CanonicalJSON() []byte {
	if b == nil {
		return nil
	}
	return bytes.Clone(b.canonical)
}
func (b *BasisV1) SHA256() string {
	if b == nil {
		return ""
	}
	return b.sha
}
func (b *BasisV1) CanonicalSHA256() string {
	if b == nil {
		return ""
	}
	return plainSHA256V1(b.canonical)
}
func (b *BasisV1) Source() manualfit.SourceTupleV1 {
	if b == nil {
		return manualfit.SourceTupleV1{}
	}
	return b.input.Source
}
func (b *BasisV1) Geometry() sanitize.PDFManualGeometry {
	if b == nil {
		return sanitize.PDFManualGeometry{}
	}
	g := b.input.Geometry
	g.Pages = append([]sanitize.PDFManualPage(nil), g.Pages...)
	return g
}
func (b *BasisV1) Fields() []FieldV1 {
	if b == nil {
		return nil
	}
	return append([]FieldV1(nil), b.input.Fields...)
}
func (b *BasisV1) Parties() []PartyV1 {
	if b == nil {
		return nil
	}
	return append([]PartyV1(nil), b.input.Parties...)
}
func (b *BasisV1) RenderRecipe() RenderRecipeV1 {
	if b == nil {
		return RenderRecipeV1{}
	}
	r := b.input.RenderRecipe
	r.Fonts = append([]FontAssetV1(nil), r.Fonts...)
	return r
}
func (b *BasisV1) Input() InputV1 {
	if b == nil {
		return InputV1{}
	}
	in := b.input
	in.Geometry = b.Geometry()
	in.Fields = b.Fields()
	in.Parties = b.Parties()
	in.RequiredRoles = append([]string(nil), in.RequiredRoles...)
	in.RenderRecipe = b.RenderRecipe()
	return in
}
func (b *BasisV1) GeometryJSON() []byte {
	if b == nil {
		return nil
	}
	return bytes.Clone(b.geometry)
}
func (b *BasisV1) GeometryPagesJSON() []byte {
	if b == nil {
		return nil
	}
	return bytes.Clone(b.geometryPages)
}
func (b *BasisV1) FieldsJSON() []byte {
	if b == nil {
		return nil
	}
	return bytes.Clone(b.fields)
}
func (b *BasisV1) PartiesJSON() []byte {
	if b == nil {
		return nil
	}
	return bytes.Clone(b.parties)
}
func (b *BasisV1) RenderRecipeJSON() []byte {
	if b == nil {
		return nil
	}
	return bytes.Clone(b.recipe)
}
func (b *BasisV1) OrdinaryRecipeJSON() []byte {
	if b == nil {
		return nil
	}
	return bytes.Clone(b.ordinaryRecipe)
}
func (b *BasisV1) FieldsSHA256() string {
	if b == nil {
		return ""
	}
	return plainSHA256V1(b.fields)
}
func (b *BasisV1) PartiesSHA256() string {
	if b == nil {
		return ""
	}
	return plainSHA256V1(b.parties)
}
func (b *BasisV1) RenderRecipeSHA256() string {
	if b == nil {
		return ""
	}
	return plainSHA256V1(b.recipe)
}
func (b *BasisV1) OrdinaryRecipeSHA256() string {
	if b == nil {
		return ""
	}
	return plainSHA256V1(b.ordinaryRecipe)
}
func (b *BasisV1) BrandingCSSSHA256() string {
	if b == nil {
		return ""
	}
	return plainSHA256V1([]byte(b.input.RenderRecipe.BrandingCSS))
}
func (b *BasisV1) OrdinaryPages() []int {
	if b == nil {
		return nil
	}
	return append([]int(nil), b.ordinaryPages...)
}
func (b *BasisV1) SignatureTargets(recipientID uuid.UUID) ([]manualfit.TargetV1, error) {
	if b == nil || recipientID == uuid.Nil {
		return nil, ErrBasisV1
	}
	out := make([]manualfit.TargetV1, 0)
	for _, f := range b.input.Fields {
		if f.Type == "signature" && f.RecipientID == recipientID {
			out = append(out, manualfit.TargetV1{ID: f.ID, OrgID: b.input.OrgID, DocumentID: b.input.DocumentID, RecipientID: recipientID, Page: int(f.Page), Required: f.Required, X: f.X, Y: f.Y, W: f.W, H: f.H})
		}
	}
	if len(out) == 0 {
		return nil, ErrBasisV1
	}
	return out, nil
}

func (b *BasisV1) CanonicalByteCount() int {
	if b == nil {
		return 0
	}
	return len(b.canonical)
}
func (b *BasisV1) FieldsByteCount() int {
	if b == nil {
		return 0
	}
	return len(b.fields)
}
func (b *BasisV1) GeometryJSONSHA256() string {
	if b == nil {
		return ""
	}
	return plainSHA256V1(b.geometry)
}
func (b *BasisV1) GeometryPagesSHA256() string {
	if b == nil {
		return ""
	}
	return b.input.Geometry.GeometrySHA256
}
