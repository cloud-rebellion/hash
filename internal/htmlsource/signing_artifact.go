// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlsource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/sanitize"
)

// SigningRectangle uses percentage * 10000 integer coordinates, matching the
// four decimal places stored by PostgreSQL. No floating JSON enters commitments.
type SigningRectangle struct {
	Slot string `json:"slot"`
	Page int32  `json:"page"`
	X    int64  `json:"x"`
	Y    int64  `json:"y"`
	W    int64  `json:"w"`
	H    int64  `json:"h"`
}

type SigningArtifact struct {
	Version     int                             `json:"version"`
	Policy      string                          `json:"policy"`
	PlanSHA256  string                          `json:"plan_sha256"`
	Composition sanitize.PDFCompositionManifest `json:"composition"`
	Fields      []SigningRectangle              `json:"fields"`
}

func cloneSigningArtifact(a *SigningArtifact) *SigningArtifact {
	if a == nil {
		return nil
	}
	copy := *a
	copy.Fields = slices.Clone(a.Fields)
	return &copy
}

func signingRectangles(pages int32) []SigningRectangle {
	return []SigningRectangle{{Slot: "customer", Page: pages, X: 100000, Y: 420000, W: 800000, H: 70000},
		{Slot: "provider", Page: pages, X: 100000, Y: 790000, W: 800000, H: 70000}}
}

// NewSigningArtifact binds both fresh component PDFs and the composed output
// to the reviewed policy, printed identities and stable party UUIDs.
func NewSigningArtifact(compiled *htmlmaster.Compiled, input htmlmaster.Input, bindings []PartyBinding, composition sanitize.PDFCompositionManifest) (*SigningArtifact, error) {
	if compiled == nil || compiled.SigningPagePolicy() == nil {
		return nil, invalid("signing page policy")
	}
	if err := sanitize.ValidatePDFCompositionManifest(composition, composition.OutputSHA256, composition.FinalPages); err != nil {
		return nil, invalid("signing page composition")
	}
	plan, err := signingPlanDigest(compiled, input, bindings)
	if err != nil {
		return nil, err
	}
	return &SigningArtifact{Version: 1, Policy: compiled.SigningPagePolicy().Policy, PlanSHA256: plan,
		Composition: composition, Fields: signingRectangles(int32(composition.FinalPages))}, nil
}

func signingPlanDigest(compiled *htmlmaster.Compiled, input htmlmaster.Input, bindings []PartyBinding) (string, error) {
	if _, err := compiled.SigningPageHTML(input); err != nil {
		return "", invalid("signing page printable identities")
	}
	readiness, err := compiled.ContractReadiness(input)
	if err != nil || !readiness.Complete {
		return "", invalid("signing page essentials")
	}
	bindings = slices.Clone(bindings)
	slices.SortFunc(bindings, func(a, b PartyBinding) int { return strings.Compare(a.Slot, b.Slot) })
	if len(bindings) != 2 || bindings[0].Slot != "customer" || bindings[1].Slot != "provider" ||
		bindings[0].RecipientID == uuid.Nil || bindings[1].RecipientID == uuid.Nil || bindings[0].RecipientID == bindings[1].RecipientID {
		return "", invalid("signing page bindings")
	}
	plan := struct {
		Policy   *htmlmaster.SigningPagePolicy    `json:"policy"`
		Parties  []htmlmaster.ContractPartyValues `json:"parties"`
		Bindings []PartyBinding                   `json:"bindings"`
	}{compiled.SigningPagePolicy(), readiness.Parties, bindings}
	raw, err := json.Marshal(plan)
	if err != nil {
		return "", invalid("signing plan encoding")
	}
	h := sha256.New()
	_, _ = h.Write([]byte("hash.signing-plan.v1\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validateSigningArtifact(s source) error {
	if s.SchemaVersion != SigningPageSchemaVersion {
		if s.SigningArtifact != nil {
			return invalid("legacy source cannot carry signing artifact")
		}
		return nil
	}
	a := s.SigningArtifact
	if a == nil || a.Version != 1 || a.Policy != "hash-branded-signing-page-a4-v1" || !validSHA256(a.PlanSHA256) {
		return invalid("signing artifact policy")
	}
	if err := sanitize.ValidatePDFCompositionManifest(a.Composition, s.PDFSHA256, a.Composition.FinalPages); err != nil {
		return invalid("signing artifact geometry or PDF binding")
	}
	if !slices.Equal(a.Fields, signingRectangles(int32(a.Composition.FinalPages))) {
		return invalid("signing artifact rectangles")
	}
	master, err := htmlmaster.Decode(s.MasterJSON)
	if err != nil {
		return invalid("signing artifact master")
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return invalid("signing artifact master")
	}
	plan, err := signingPlanDigest(compiled, htmlmaster.Input{Values: s.Values, Sections: s.Sections}, s.PartyBindings)
	if err != nil || plan != a.PlanSHA256 {
		return invalid("signing artifact plan commitment")
	}
	return nil
}

// SigningPage returns only a validated current policy and artifact. Explicit
// corrupt schema3 provenance never falls back to manual field authoring.
func SigningPage(doc *generated.Document) (*htmlmaster.SigningPagePolicy, *SigningArtifact, error) {
	s, err := validatedSource(doc, false)
	if err != nil {
		return nil, nil, err
	}
	if s.SchemaVersion != SigningPageSchemaVersion {
		return nil, nil, nil
	}
	master, err := htmlmaster.Decode(s.MasterJSON)
	if err != nil {
		return nil, nil, err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return nil, nil, err
	}
	return compiled.SigningPagePolicy(), cloneSigningArtifact(s.SigningArtifact), nil
}

type signingFieldOptions struct {
	Policy           string `json:"policy"`
	Slot             string `json:"slot"`
	SourceCommitment string `json:"source_commitment"`
}

func SigningFieldOptions(doc *generated.Document, slot string) (json.RawMessage, error) {
	_, a, err := SigningPage(doc)
	if err != nil || a == nil {
		return nil, invalid("automatic signature field source")
	}
	if slot != "customer" && slot != "provider" {
		return nil, invalid("automatic signature field slot")
	}
	commitment, err := Commitment(doc)
	if err != nil {
		return nil, err
	}
	return json.Marshal(signingFieldOptions{Policy: a.Policy, Slot: slot, SourceCommitment: commitment})
}

// ValidateSigningFields checks the complete pair, exact party ownership and
// fixed rectangles before send, capture, stamping and recovery effects.
func ValidateSigningFields(doc *generated.Document, rows []*generated.DocumentField, pages int) error {
	s, err := validatedSource(doc, false)
	if err != nil {
		return err
	}
	if s.SchemaVersion != SigningPageSchemaVersion {
		return nil
	}
	if len(rows) != 2 || (pages > 0 && pages != s.SigningArtifact.Composition.FinalPages) ||
		(doc.HtmlCurrentPageCount.Valid && int(doc.HtmlCurrentPageCount.Int32) != s.SigningArtifact.Composition.FinalPages) {
		return invalid("automatic signature field count or page")
	}
	seen := map[uuid.UUID]bool{}
	for i, rectangle := range s.SigningArtifact.Fields {
		var matched *generated.DocumentField
		for _, row := range rows {
			if row != nil && row.RecipientID.Valid && uuid.UUID(row.RecipientID.Bytes) == s.PartyBindings[i].RecipientID {
				if matched != nil {
					return invalid("duplicate automatic signature field")
				}
				matched = row
			}
		}
		if matched == nil || matched.ID == uuid.Nil || seen[matched.ID] || matched.DocumentID != doc.ID || matched.Type != "signature" || !matched.Required || matched.Page != rectangle.Page ||
			!matched.Label.Valid || matched.Label.String != strings.ToUpper(rectangle.Slot[:1])+rectangle.Slot[1:]+" signature" ||
			!numericEqual(matched.XPct, rectangle.X) || !numericEqual(matched.YPct, rectangle.Y) || !numericEqual(matched.WPct, rectangle.W) || !numericEqual(matched.HPct, rectangle.H) {
			return invalid("automatic signature field placement or ownership")
		}
		seen[matched.ID] = true
		var options signingFieldOptions
		if err := strictDecode(matched.OptionsJson, &options, 2048); err != nil {
			return invalid("automatic signature field binding")
		}
		canonical, _ := json.Marshal(options)
		var original, typed any
		if json.Unmarshal(matched.OptionsJson, &original) != nil || json.Unmarshal(canonical, &typed) != nil || !reflect.DeepEqual(original, typed) ||
			options.Policy != s.SigningArtifact.Policy || options.Slot != rectangle.Slot || options.SourceCommitment != s.Commitment {
			return invalid("automatic signature field source binding")
		}
	}
	return nil
}

func numericEqual(value pgtype.Numeric, expected int64) bool {
	if !value.Valid || value.NaN || value.InfinityModifier != pgtype.Finite || value.Int == nil {
		return false
	}
	n, err := value.Float64Value()
	return err == nil && n.Valid && n.Float64 == float64(expected)/10000
}

func ValidateSigningBranding(doc *generated.Document, row *generated.DocumentBrandingOverride) error {
	policy, artifact, err := SigningPage(doc)
	if err != nil || artifact == nil {
		return err
	}
	if row == nil || row.DocumentID != doc.ID {
		return invalid("reviewed signing page branding missing")
	}
	b := policy.Branding
	for _, field := range []struct {
		actual   pgtype.Text
		expected string
	}{
		{row.PrimaryHex, b.PrimaryHex}, {row.AccentHex, b.AccentHex}, {row.SurfaceHex, b.SurfaceHex}, {row.TextHex, b.TextHex}, {row.MutedHex, b.MutedHex},
		{row.LogoUrl, b.LogoURL}, {row.LogoAlt, b.LogoAlt}, {row.FontHeading, b.FontHeading}, {row.FontBody, b.FontBody}, {row.SignatureColor, b.SignatureColor},
	} {
		if !field.actual.Valid || field.actual.String != field.expected {
			return invalid("reviewed signing page branding drifted")
		}
	}
	return nil
}

type signingStateQueries interface {
	ListRecipientsByDocument(context.Context, uuid.UUID) ([]*generated.Recipient, error)
	ListFieldsByDocument(context.Context, uuid.UUID) ([]*generated.DocumentField, error)
	GetDocumentBrandingOverride(context.Context, uuid.UUID) (*generated.DocumentBrandingOverride, error)
}

// ValidateSigningPageState is called before external writes on fresh locked
// lifecycle/recovery snapshots. Schema1/2 do not acquire new database reads.
func ValidateSigningPageState(ctx context.Context, q signingStateQueries, doc *generated.Document, pages int) error {
	_, artifact, err := SigningPage(doc)
	if err != nil || artifact == nil {
		return err
	}
	if q == nil {
		return invalid("signing page state store unavailable")
	}
	parties, err := q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return err
	}
	if err := ValidateContractParties(doc, parties); err != nil {
		return err
	}
	fields, err := q.ListFieldsByDocument(ctx, doc.ID)
	if err != nil {
		return err
	}
	if err := ValidateSigningFields(doc, fields, pages); err != nil {
		return err
	}
	brand, err := q.GetDocumentBrandingOverride(ctx, doc.ID)
	if err != nil {
		return invalid("signing page branding unavailable")
	}
	return ValidateSigningBranding(doc, brand)
}

func exactSigningArtifactJSON(raw []byte, artifact *SigningArtifact) error {
	if artifact == nil {
		return invalid("missing signing artifact")
	}
	canonical, err := json.Marshal(artifact)
	if err != nil {
		return invalid("signing artifact encoding")
	}
	var original, typed any
	if json.Unmarshal(raw, &original) != nil || json.Unmarshal(canonical, &typed) != nil || !reflect.DeepEqual(original, typed) {
		return invalid("signing artifact exact schema keys")
	}
	return nil
}
