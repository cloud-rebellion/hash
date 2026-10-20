// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/bright-interaction/hash/internal/malwarescan"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const PDFProviderOverlayPolicy = "hash-provider-confined-overlay-v1"
const pdfProviderOverlayOperation = "provider-overlay-v1"

// This is an immutable supported profile, not the hash of whatever embedded
// font a future build contains. Historical recovery uses its archived assets;
// a new Inter asset must retain this profile or add a separately pinned one.
const providerInterFontSHA256 = "3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62"
const providerType3StreamLimit = 64 << 10
const providerType3DecodedLimit = 2 << 20

var ErrPDFProviderOverlay = errors.New("sanitize: invalid provider overlay")

// Refusal stages are a fixed internal vocabulary. Neither parser errors nor
// names, operands, resource keys or document text cross the worker boundary.
type providerOverlayStageError struct {
	stage string
	cause error
}

func (e providerOverlayStageError) Error() string {
	return ErrPDFProviderOverlay.Error() + ": " + e.stage
}
func (e providerOverlayStageError) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrPDFProviderOverlay}
	}
	return []error{ErrPDFProviderOverlay, e.cause}
}

func validProviderOverlayStage(stage string) bool {
	switch stage {
	case "base-content", "base-operators", "fragment-input", "fragment-pages",
		"fragment-properties", "fragment-geometry", "fragment-rotation", "fragment-boxes",
		"fragment-resources", "fragment-content", "fragment-operators", "fragment-resource-copy",
		"fragment-form-stream", "fragment-form-encode", "fragment-form-object",
		"resource-key", "font-count", "font-dictionary", "font-identity", "font-name",
		"font-descendant", "font-embedded", "font-subtype", "extgstate-count",
		"extgstate-dictionary", "extgstate-type", "extgstate-alpha", "extgstate-blend", "extgstate-key",
		"type3-scope", "type3-dictionary", "type3-identity", "type3-matrix", "type3-box",
		"type3-widths", "type3-encoding", "type3-resources", "type3-glyphs", "type3-stream",
		"type3-expansion", "type3-operators", "type3-metrics",
		"processing-forms", "cleaned-geometry", "cleaned-content", "cleaned-forms", "result-proof":
		return true
	}
	return false
}

func providerOverlayStage(stage string, cause error) error {
	if !validProviderOverlayStage(stage) {
		return ErrPDFProviderOverlay
	}
	return providerOverlayStageError{stage: stage, cause: cause}
}

func providerOverlayErrorCode(err error) string {
	var staged providerOverlayStageError
	if errors.As(err, &staged) && validProviderOverlayStage(staged.stage) {
		return "invalid-provider-overlay:" + staged.stage
	}
	return "invalid-provider-overlay"
}

func providerOverlayErrorFromCode(code string) error {
	stage, found := strings.CutPrefix(code, "invalid-provider-overlay:")
	if !found || !validProviderOverlayStage(stage) {
		return ErrPDFWorkerUnavailable
	}
	return providerOverlayStage(stage, nil)
}

// These bindings are byte commitments, not an authorization or a renderer
// attestation. The private preparation adapter derives them from actual source,
// grant and controlled renderer input; the child binds them to inspected output.
type PDFProviderOverlayBindings struct {
	SourceCommitment    string `json:"source_commitment"`
	SigningPlanSHA256   string `json:"signing_plan_sha256"`
	BrandingSHA256      string `json:"branding_sha256"`
	PolicySHA256        string `json:"policy_sha256"`
	GrantSHA256         string `json:"grant_sha256"`
	Font                string `json:"font"`
	SpanSHA256          string `json:"span_sha256"`
	SignatureFontSHA256 string `json:"signature_font_sha256"`
	InterFontSHA256     string `json:"inter_font_sha256"`
	DisclosureSHA256    string `json:"disclosure_sha256"`
	RecipeSHA256        string `json:"recipe_sha256"`
}

// Form proof records constructed painting containers, not just page geometry.
// The implicit Form BBox and explicit clip cannot be removed by imported PDF
// operands; unbalanced graphics/text operators and indirect paint are refused.
type PDFProviderFormProof struct {
	Slot                   string   `json:"slot"`
	RectangleMicroPoints   [4]int64 `json:"rectangle_micro_points"`
	ContentSHA256          string   `json:"content_sha256"`
	ResourcesSHA256        string   `json:"resources_sha256"`
	FragmentGeometrySHA256 string   `json:"fragment_geometry_sha256"`
}

type PDFProviderOverlayManifest struct {
	SchemaVersion         int                     `json:"schema_version"`
	Policy                string                  `json:"policy"`
	BindingsSHA256        string                  `json:"bindings_sha256"`
	BaseSHA256            string                  `json:"base_sha256"`
	BaseBytes             int64                   `json:"base_bytes"`
	SignatureSHA256       string                  `json:"signature_sha256"`
	DisclosureSHA256      string                  `json:"disclosure_sha256"`
	ProcessingSHA256      string                  `json:"processing_sha256"`
	ProcessingBytes       int64                   `json:"processing_bytes"`
	OutputSHA256          string                  `json:"output_sha256"`
	OutputBytes           int64                   `json:"output_bytes"`
	Pages                 int                     `json:"pages"`
	GeometrySHA256        string                  `json:"geometry_sha256"`
	OriginalContentSHA256 string                  `json:"original_content_sha256"`
	Forms                 [2]PDFProviderFormProof `json:"forms"`
}

type PDFProviderOverlayResult struct {
	Result
	Overlay PDFProviderOverlayManifest
}

func PDFProviderOverlayBindingsSHA256(b PDFProviderOverlayBindings) string {
	if !validProviderBindings(b) {
		return ""
	}
	raw, _ := json.Marshal(b)
	return pdfSHA(append([]byte("hash:presign-provider-worker-bindings:v1\x00"), raw...))
}

func validProviderBindings(b PDFProviderOverlayBindings) bool {
	if providerPostScriptName(b.Font) == "" {
		return false
	}
	for _, s := range []string{b.SourceCommitment, b.SigningPlanSHA256, b.BrandingSHA256, b.PolicySHA256, b.GrantSHA256, b.SpanSHA256, b.SignatureFontSHA256, b.InterFontSHA256, b.DisclosureSHA256, b.RecipeSHA256} {
		if !validPDFSHA(s) {
			return false
		}
	}
	return true
}

// Fixed lower-left point rectangles, derived from the exact source3 Chromium
// A4 geometry. The signature has a two-point inset preserving its border.
func providerRectangles() [2][4]float64 {
	return [2][4]float64{{61.495996, 119.8687972, 471.967968, 54.9343986}, {59.495996, 71.5631983, 475.967968, 25.2575994}}
}
func providerRectangleMicros(i int) [4]int64 {
	var r [4]int64
	for j, v := range providerRectangles()[i] {
		r[j] = int64(math.Round(v * 1e6))
	}
	return r
}

func ValidatePDFProviderOverlayManifest(m PDFProviderOverlayManifest) error {
	if m.SchemaVersion != 1 || m.Policy != PDFProviderOverlayPolicy || !validPDFSHA(m.BindingsSHA256) || m.Pages < 1 || m.Pages > MaxPDFPages {
		return ErrPDFProviderOverlay
	}
	for _, s := range []string{m.BaseSHA256, m.SignatureSHA256, m.DisclosureSHA256, m.ProcessingSHA256, m.OutputSHA256, m.GeometrySHA256, m.OriginalContentSHA256} {
		if !validPDFSHA(s) {
			return ErrPDFProviderOverlay
		}
	}
	for _, n := range []int64{m.BaseBytes, m.ProcessingBytes, m.OutputBytes} {
		if n < 1 || n > MaxPDFBytes {
			return ErrPDFProviderOverlay
		}
	}
	if m.BaseSHA256 == m.OutputSHA256 {
		return ErrPDFProviderOverlay
	}
	for i, f := range m.Forms {
		slot := []string{"provider_signature", "provider_disclosure"}[i]
		if f.Slot != slot || f.RectangleMicroPoints != providerRectangleMicros(i) || !validPDFSHA(f.ContentSHA256) || !validPDFSHA(f.ResourcesSHA256) || !validPDFSHA(f.FragmentGeometrySHA256) {
			return ErrPDFProviderOverlay
		}
	}
	return nil
}

func ValidatePDFProviderOverlayResult(r PDFProviderOverlayResult) error {
	m := r.Overlay
	if ValidatePDFProviderOverlayManifest(m) != nil || m.OutputSHA256 != pdfSHA(r.Bytes) || m.OutputBytes != int64(len(r.Bytes)) || ValidatePDFResult(r.Report, m.ProcessingSHA256, m.OutputSHA256, m.ProcessingBytes, m.OutputBytes) != nil || r.Report.PDF.PagesAfter != m.Pages || r.Report.PDF.GeometrySHA256After != m.GeometrySHA256 {
		return ErrPDFProviderOverlay
	}
	return nil
}

func DecodePDFProviderOverlayManifest(raw []byte) (PDFProviderOverlayManifest, error) {
	var m PDFProviderOverlayManifest
	if len(raw) < 1 || len(raw) > pdfWorkerHeaderLimit || strictPDFWorkerJSON(raw) != nil {
		return m, ErrPDFProviderOverlay
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return PDFProviderOverlayManifest{}, ErrPDFProviderOverlay
	}
	// Exact canonical equality rejects omitted members, short/extra arrays,
	// aliases and null scalars while permitting protocol JSON key ordering.
	if !providerExactJSONShape(raw, reflect.TypeOf(m)) || ValidatePDFProviderOverlayManifest(m) != nil {
		return PDFProviderOverlayManifest{}, ErrPDFProviderOverlay
	}
	return m, nil
}

func providerExactJSONShape(raw []byte, t reflect.Type) bool {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != t.NumField() {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			v, ok := fields[f.Tag.Get("json")]
			if !ok || !providerExactJSONShape(v, f.Type) {
				return false
			}
		}
	case reflect.Array:
		var a []json.RawMessage
		if json.Unmarshal(raw, &a) != nil || len(a) != t.Len() {
			return false
		}
		for _, v := range a {
			if !providerExactJSONShape(v, t.Elem()) {
				return false
			}
		}
	}
	return true
}

func ApplyProviderOverlayWithContext(ctx context.Context, asset string, base, signature, disclosure []byte, bindings PDFProviderOverlayBindings) (PDFProviderOverlayResult, error) {
	if len(asset) > 128 || !validProviderBindings(bindings) || len(base) < 1 || len(signature) < 1 || len(disclosure) < 1 {
		return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
	}
	if len(base) > MaxPDFBytes || len(signature) > MaxPDFBytes-len(base) || len(disclosure) > MaxPDFBytes-len(base)-len(signature) {
		return PDFProviderOverlayResult{}, ErrPDFTooLarge
	}
	for _, raw := range [][]byte{base, signature, disclosure} {
		if err := malwarescan.ScanActive(ctx, raw); err != nil {
			return PDFProviderOverlayResult{}, err
		}
	}
	w := activePDFWorker.Load()
	if w == nil {
		return PDFProviderOverlayResult{}, ErrPDFWorkerUnavailable
	}
	raw := make([]byte, 0, len(base)+len(signature)+len(disclosure))
	raw = append(raw, base...)
	raw = append(raw, signature...)
	raw = append(raw, disclosure...)
	response, out, err := w.run(ctx, pdfWorkerRequest{Operation: pdfProviderOverlayOperation, Asset: asset, Length: len(raw), BodyLength: len(base), SignatureLength: len(signature), DisclosureLength: len(disclosure), ProviderBindings: &bindings}, raw)
	if err != nil {
		return PDFProviderOverlayResult{}, err
	}
	if response.Report == nil || response.ProviderOverlay == nil {
		return PDFProviderOverlayResult{}, ErrPDFWorkerUnavailable
	}
	result := PDFProviderOverlayResult{Result: Result{Bytes: out, Report: *response.Report}, Overlay: *response.ProviderOverlay}
	if ValidatePDFProviderOverlayResult(result) != nil {
		return PDFProviderOverlayResult{}, ErrPDFWorkerUnavailable
	}
	return result, nil
}

func providerPostScriptName(font string) string {
	switch font {
	case "Caveat":
		return "Caveat-Regular"
	case "Dancing Script":
		return "DancingScript-Regular"
	case "Great Vibes":
		return "GreatVibes-Regular"
	case "Sacramento":
		return "Sacramento-Regular"
	case "Homemade Apple":
		return "HomemadeApple-Regular"
	}
	return ""
}

func providerContentDigests(ctx *model.Context) ([][]byte, error) {
	out := make([][]byte, ctx.PageCount)
	for i := range out {
		d, _, _, err := ctx.PageDict(i+1, false)
		if err != nil {
			return nil, ErrPDFProviderOverlay
		}
		b, err := ctx.PageContent(d, i+1)
		if err != nil && !errors.Is(err, model.ErrNoContent) {
			return nil, ErrPDFProviderOverlay
		}
		out[i] = bytes.Clone(b)
	}
	return out, nil
}

func providerContentSHA(pages [][]byte) string { h, _ := json.Marshal(pages); return pdfSHA(h) }

// Only the isolated child and tests call this parser implementation.
func providerOverlayInProcess(asset string, base, signature, disclosure []byte, bindings PDFProviderOverlayBindings) (PDFProviderOverlayResult, error) {
	if !validProviderBindings(bindings) || len(base) < 1 || len(signature) < 1 || len(disclosure) < 1 || len(base)+len(signature)+len(disclosure) > MaxPDFBytes {
		return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
	}
	ctx, geometry, err := observePDFCompositionInput(base)
	if err != nil {
		return PDFProviderOverlayResult{}, err
	}
	if ctx.PageCount < 1 || ctx.PageCount > MaxPDFPages {
		return PDFProviderOverlayResult{}, ErrTooManyPages
	}
	pages, err := pdfCompositionGeometry(ctx)
	if err != nil || !isCanonicalSigningPage(pages[len(pages)-1]) {
		return PDFProviderOverlayResult{}, ErrPDFSigningPageInvalid
	}
	originals, err := providerContentDigests(ctx)
	if err != nil {
		return PDFProviderOverlayResult{}, providerOverlayStage("base-content", err)
	}
	// The original page is wrapped in q/Q below. Balance alone would not reset
	// a top-level original cm or clip before the new call stream.
	if err := validateProviderOperators(originals[len(originals)-1], false); err != nil {
		return PDFProviderOverlayResult{}, providerOverlayStage("base-operators", err)
	}
	page, _, attrs, err := ctx.PageDict(ctx.PageCount, false)
	if err != nil {
		return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
	}
	resources := types.NewDict()
	if attrs.Resources != nil {
		for k, v := range attrs.Resources {
			resources[k] = v
		}
	}
	xobjects := types.NewDict()
	if o, ok := resources["XObject"]; ok {
		d, err := ctx.DereferenceDict(o)
		if err != nil {
			return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
		}
		for k, v := range d {
			xobjects[k] = v
		}
	}
	names := [2]string{"HashProviderSignatureV1", "HashProviderDisclosureV1"}
	for _, n := range names {
		if _, exists := xobjects[n]; exists {
			return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
		}
	}
	proof := PDFProviderOverlayManifest{SchemaVersion: 1, Policy: PDFProviderOverlayPolicy, BindingsSHA256: PDFProviderOverlayBindingsSHA256(bindings), BaseSHA256: pdfSHA(base), BaseBytes: int64(len(base)), SignatureSHA256: pdfSHA(signature), DisclosureSHA256: pdfSHA(disclosure), Pages: ctx.PageCount, GeometrySHA256: geometry, OriginalContentSHA256: providerContentSHA(originals)}
	var calls bytes.Buffer
	for i, raw := range [][]byte{signature, disclosure} {
		font := providerPostScriptName(bindings.Font)
		if i == 1 {
			font = "Inter-Regular"
		}
		ir, p, err := constructProviderForm(ctx, raw, i, font, i == 1 && bindings.InterFontSHA256 == providerInterFontSHA256)
		if err != nil {
			return PDFProviderOverlayResult{}, err
		}
		proof.Forms[i] = p
		xobjects[names[i]] = *ir
		rect := providerRectangles()[i]
		fmt.Fprintf(&calls, "q 1 0 0 1 %.9f %.9f cm /%s Do Q\n", rect[0], rect[1], names[i])
	}
	resources["XObject"] = xobjects
	page["Resources"] = resources
	// Save the original page's initial graphics state before any old operands,
	// then restore it before placing the fixed Forms. This preserves original
	// painting and prevents its CTM/clip from moving or hiding our new material.
	prefixBytes := []byte("q\n")
	callBytes := append([]byte("\nQ\n"), calls.Bytes()...)
	prefixStream, err := ctx.NewStreamDictForBuf(prefixBytes)
	if err != nil || prefixStream.Encode() != nil {
		return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
	}
	prefixIR, err := ctx.IndRefForNewObject(*prefixStream)
	if err != nil {
		return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
	}
	stream, err := ctx.NewStreamDictForBuf(callBytes)
	if err != nil || stream.Encode() != nil {
		return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
	}
	ir, err := ctx.IndRefForNewObject(*stream)
	if err != nil {
		return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
	}
	existing := page["Contents"]
	if existing == nil {
		page["Contents"] = types.Array{*prefixIR, *ir}
	} else {
		o, err := ctx.Dereference(existing)
		if err != nil {
			return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
		}
		if a, ok := o.(types.Array); ok {
			page["Contents"] = append(append(types.Array{*prefixIR}, a...), *ir)
		} else {
			page["Contents"] = types.Array{*prefixIR, existing, *ir}
		}
	}
	var processing boundedPDFBuffer
	if err := pdfapi.WriteContext(ctx, &processing); err != nil {
		return PDFProviderOverlayResult{}, ErrPDFProviderOverlay
	}
	if err := verifyProviderForms(ctx, proof.Forms); err != nil {
		return PDFProviderOverlayResult{}, providerOverlayStage("processing-forms", err)
	}
	cleaned, err := cleanPDF(asset, "application/pdf", processing.Bytes())
	if err != nil {
		return PDFProviderOverlayResult{}, err
	}
	final, _, finalGeometry, err := observePDF(cleaned.Bytes)
	if err != nil || final.PageCount != proof.Pages || finalGeometry != geometry {
		return PDFProviderOverlayResult{}, providerOverlayStage("cleaned-geometry", err)
	}
	contents, err := providerContentDigests(final)
	if err != nil {
		return PDFProviderOverlayResult{}, err
	}
	for i, b := range originals {
		wanted := b
		if i == len(originals)-1 {
			wanted = append(append(bytes.Clone(prefixBytes), b...), callBytes...)
		}
		if !bytes.Equal(contents[i], wanted) {
			return PDFProviderOverlayResult{}, providerOverlayStage("cleaned-content", nil)
		}
	}
	if err := verifyProviderForms(final, proof.Forms); err != nil {
		return PDFProviderOverlayResult{}, providerOverlayStage("cleaned-forms", err)
	}
	proof.ProcessingSHA256 = pdfSHA(processing.Bytes())
	proof.ProcessingBytes = int64(processing.Len())
	proof.OutputSHA256 = pdfSHA(cleaned.Bytes)
	proof.OutputBytes = int64(len(cleaned.Bytes))
	result := PDFProviderOverlayResult{Result: cleaned, Overlay: proof}
	if ValidatePDFProviderOverlayResult(result) != nil {
		return PDFProviderOverlayResult{}, providerOverlayStage("result-proof", nil)
	}
	return result, nil
}

func constructProviderForm(dest *model.Context, raw []byte, index int, fontName string, allowInterType3 bool) (*types.IndirectRef, PDFProviderFormProof, error) {
	var p PDFProviderFormProof
	source, geometry, err := observePDFCompositionInput(raw)
	if err != nil {
		return nil, p, providerOverlayStage("fragment-input", err)
	}
	if source.PageCount != 1 {
		return nil, p, providerOverlayStage("fragment-pages", nil)
	}
	props, err := observedPDFProperties(source)
	if err != nil || props.Annotations || props.AcroForm || props.EmbeddedFiles {
		return nil, p, providerOverlayStage("fragment-properties", err)
	}
	pg, err := pdfCompositionGeometry(source)
	if err != nil {
		return nil, p, providerOverlayStage("fragment-geometry", err)
	}
	g := pg[0]
	rect := providerRectangles()[index]
	if g.Rotation != 0 || g.UserUnit != 1 {
		return nil, p, providerOverlayStage("fragment-rotation", nil)
	}
	for _, b := range g.Boxes {
		if b[0] != 0 || b[1] != 0 || math.Abs(b[2]-rect[2]) > 0.5 || math.Abs(b[3]-rect[3]) > 0.5 || b[2] <= 0 || b[3] <= 0 {
			return nil, p, providerOverlayStage("fragment-boxes", nil)
		}
	}
	page, _, attrs, err := source.PageDict(1, false)
	if err != nil || attrs.Resources == nil {
		return nil, p, providerOverlayStage("fragment-resources", err)
	}
	contents, err := source.PageContent(page, 1)
	if err != nil {
		return nil, p, providerOverlayStage("fragment-content", err)
	}
	if err := validateProviderOperators(contents, true); err != nil {
		return nil, p, providerOverlayStage("fragment-operators", err)
	}
	if err := validateProviderResources(source, attrs.Resources, fontName, index == 1 && allowInterType3); err != nil {
		return nil, p, err
	}
	copied, semantic, err := copyProviderObject(source, dest, attrs.Resources, 0, new(providerCopyBudget))
	if err != nil {
		return nil, p, providerOverlayStage("fragment-resource-copy", err)
	}
	// Force a fixed implicit clip and an independent explicit clip before any
	// admitted source operand. Imported fragments cannot reset this container.
	var b bytes.Buffer
	fmt.Fprintf(&b, "q 0 0 %.9f %.9f re W n %.12f 0 0 %.12f 0 0 cm\n", rect[2], rect[3], rect[2]/g.Boxes[0][2], rect[3]/g.Boxes[0][3])
	b.Write(contents)
	b.WriteString("\nQ\n")
	sd, err := dest.NewStreamDictForBuf(b.Bytes())
	if err != nil {
		return nil, p, providerOverlayStage("fragment-form-stream", err)
	}
	sd.Dict["Type"] = types.Name("XObject")
	sd.Dict["Subtype"] = types.Name("Form")
	sd.Dict["BBox"] = types.NewNumberArray(0, 0, rect[2], rect[3])
	sd.Dict["Matrix"] = types.NewNumberArray(1, 0, 0, 1, 0, 0)
	sd.Dict["Resources"] = copied
	if sd.Encode() != nil {
		return nil, p, providerOverlayStage("fragment-form-encode", err)
	}
	ir, err := dest.IndRefForNewObject(*sd)
	if err != nil {
		return nil, p, providerOverlayStage("fragment-form-object", err)
	}
	resourceBytes, _ := json.Marshal(semantic)
	p = PDFProviderFormProof{Slot: []string{"provider_signature", "provider_disclosure"}[index], RectangleMicroPoints: providerRectangleMicros(index), ContentSHA256: pdfSHA(b.Bytes()), ResourcesSHA256: pdfSHA(resourceBytes), FragmentGeometrySHA256: geometry}
	return ir, p, nil
}

func verifyProviderForms(ctx *model.Context, proof [2]PDFProviderFormProof) error {
	_, _, attrs, err := ctx.PageDict(ctx.PageCount, false)
	if err != nil || attrs.Resources == nil {
		return ErrPDFProviderOverlay
	}
	xobjects, err := ctx.DereferenceDict(attrs.Resources["XObject"])
	if err != nil {
		return ErrPDFProviderOverlay
	}
	for i, name := range []string{"HashProviderSignatureV1", "HashProviderDisclosureV1"} {
		sd, _, err := ctx.DereferenceStreamDict(xobjects[name])
		if err != nil || sd == nil || sd.Decode() != nil {
			return ErrPDFProviderOverlay
		}
		r := providerRectangles()[i]
		if sd.Dict.NameEntry("Type") == nil || *sd.Dict.NameEntry("Type") != "XObject" || sd.Dict.NameEntry("Subtype") == nil || *sd.Dict.NameEntry("Subtype") != "Form" || !providerNumbers(ctx, sd.Dict["BBox"], []float64{0, 0, r[2], r[3]}) || !providerNumbers(ctx, sd.Dict["Matrix"], []float64{1, 0, 0, 1, 0, 0}) || pdfSHA(sd.Content) != proof[i].ContentSHA256 {
			return ErrPDFProviderOverlay
		}
		for k := range sd.Dict {
			switch k {
			case "Type", "Subtype", "BBox", "Matrix", "Resources", "Filter", "Length", "DecodeParms":
			default:
				return ErrPDFProviderOverlay
			}
		}
		_, semantic, err := copyProviderObject(ctx, nil, sd.Dict["Resources"], 0, new(providerCopyBudget))
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(semantic)
		if pdfSHA(raw) != proof[i].ResourcesSHA256 {
			return ErrPDFProviderOverlay
		}
	}
	return nil
}

func providerNumbers(ctx *model.Context, o types.Object, expected []float64) bool {
	a, err := ctx.DereferenceArray(o)
	if err != nil || len(a) != len(expected) {
		return false
	}
	for i, v := range a {
		n, err := ctx.DereferenceNumber(v)
		if err != nil || n != expected[i] {
			return false
		}
	}
	return true
}

func validateProviderResources(ctx *model.Context, d types.Dict, fontName string, allowInterType3 bool) error {
	for k := range d {
		switch k {
		case "Font", "ExtGState", "ProcSet":
		default:
			return providerOverlayStage("resource-key", nil)
		}
	}
	fonts, err := ctx.DereferenceDict(d["Font"])
	if err != nil || len(fonts) < 1 || len(fonts) > 8 {
		return providerOverlayStage("font-count", nil)
	}
	// Shared across every Type3 face in this one disclosure fragment, including
	// the bounded ToUnicode streams. It must not reset for each font or glyph.
	type3Budget := new(providerType3Budget)
	for _, o := range fonts {
		f, err := ctx.DereferenceDict(o)
		if err != nil {
			return providerOverlayStage("font-dictionary", nil)
		}
		sub := f.NameEntry("Subtype")
		if sub == nil {
			return providerOverlayStage("font-identity", nil)
		}
		if *sub == "Type3" {
			if !allowInterType3 || fontName != "Inter-Regular" {
				return providerOverlayStage("type3-scope", nil)
			}
			if err := validateProviderInterType3(ctx, f, type3Budget); err != nil {
				return err
			}
			continue
		}
		base := f.NameEntry("BaseFont")
		if base == nil {
			return providerOverlayStage("font-identity", nil)
		}
		n := *base
		if len(n) > 7 && n[6] == '+' {
			n = n[7:]
		}
		if n != fontName {
			return providerOverlayStage("font-name", nil)
		}
		switch *sub {
		case "Type0":
			a, err := ctx.DereferenceArray(f["DescendantFonts"])
			if err != nil || len(a) != 1 {
				return providerOverlayStage("font-descendant", nil)
			}
			fd, err := ctx.DereferenceDict(a[0])
			if err != nil || fd.NameEntry("Subtype") == nil || *fd.NameEntry("Subtype") != "CIDFontType2" || !providerEmbeddedFont(ctx, fd) {
				return providerOverlayStage("font-embedded", nil)
			}
		case "TrueType":
			if !providerEmbeddedFont(ctx, f) {
				return providerOverlayStage("font-embedded", nil)
			}
		default:
			return providerOverlayStage("font-subtype", nil)
		}
	}
	if o, ok := d["ExtGState"]; ok {
		gs, err := ctx.DereferenceDict(o)
		if err != nil || len(gs) > 8 {
			return providerOverlayStage("extgstate-count", nil)
		}
		for _, o := range gs {
			g, err := ctx.DereferenceDict(o)
			if err != nil {
				return providerOverlayStage("extgstate-dictionary", nil)
			}
			for k, v := range g {
				switch k {
				case "Type":
					if n, ok := v.(types.Name); !ok || n != "ExtGState" {
						return providerOverlayStage("extgstate-type", nil)
					}
				case "CA", "ca":
					n, err := ctx.DereferenceNumber(v)
					if err != nil || n != 1 {
						return providerOverlayStage("extgstate-alpha", nil)
					}
				case "BM":
					if n, ok := v.(types.Name); !ok || n != "Normal" {
						return providerOverlayStage("extgstate-blend", nil)
					}
				default:
					return providerOverlayStage("extgstate-key", nil)
				}
			}
		}
	}
	return nil
}

type providerType3Budget struct{ decoded int }

// Type3 is admitted only for the observed, pinned Inter disclosure profile.
// Its embedded glyph programs replace a font file; the descriptor alone does
// not attest glyph bytes. Every program is inspected and included in the
// existing semantic Resources hash inside the worker-owned clipped Form.
func validateProviderInterType3(ctx *model.Context, f types.Dict, budget *providerType3Budget) error {
	if budget == nil || len(f) < 12 || !providerType3Keys(f, "Type Subtype FontMatrix FirstChar LastChar FontBBox CIDToGIDMap ToUnicode FontDescriptor Widths Encoding CharProcs Resources") || f.NameEntry("Type") == nil || *f.NameEntry("Type") != "Font" || f.NameEntry("Subtype") == nil || *f.NameEntry("Subtype") != "Type3" {
		return providerOverlayStage("type3-dictionary", nil)
	}
	descriptor, err := ctx.DereferenceDict(f["FontDescriptor"])
	if err != nil || len(descriptor) != 10 || !providerType3Keys(descriptor, "Type FontName FontFamily FontStretch FontWeight ItalicAngle CapHeight StemV XHeight Flags") {
		return providerOverlayStage("type3-identity", nil)
	}
	name := descriptor.NameEntry("FontName")
	family := descriptor.StringEntry("FontFamily")
	if descriptor.NameEntry("Type") == nil || *descriptor.NameEntry("Type") != "FontDescriptor" || name == nil || !providerInterSubsetName(*name) || family == nil || *family != "Inter" || descriptor.NameEntry("FontStretch") == nil || *descriptor.NameEntry("FontStretch") != "Normal" {
		return providerOverlayStage("type3-identity", nil)
	}
	for key, expected := range map[string]float64{"FontWeight": 400, "ItalicAngle": 0, "CapHeight": -1490, "StemV": 109, "XHeight": 1118, "Flags": 4} {
		n, err := ctx.DereferenceNumber(descriptor[key])
		if err != nil || n != expected {
			return providerOverlayStage("type3-identity", nil)
		}
	}
	if !providerNumbers(ctx, f["FontMatrix"], []float64{1.0 / 2048, 0, 0, -1.0 / 2048, 0, 0}) {
		return providerOverlayStage("type3-matrix", nil)
	}
	box, err := providerType3Numbers(ctx, f["FontBBox"], 4)
	if err != nil || box[0] >= box[2] || box[1] <= box[3] {
		return providerOverlayStage("type3-box", nil)
	}
	// This Skia profile uses a negative-Y font matrix and a reversed-Y FontBBox.
	// Normalize only the comparison bounds; retain the actual dictionary bytes.
	fontBox := [4]float64{box[0], box[3], box[2], box[1]}
	first, err := ctx.DereferenceInteger(f["FirstChar"])
	last, lastErr := ctx.DereferenceInteger(f["LastChar"])
	if err != nil || lastErr != nil || first == nil || last == nil || first.Value() != 0 || last.Value() < 0 || last.Value() > 255 || f.NameEntry("CIDToGIDMap") == nil || *f.NameEntry("CIDToGIDMap") != "Identity" {
		return providerOverlayStage("type3-widths", nil)
	}
	widths, err := providerType3Numbers(ctx, f["Widths"], last.Value()+1)
	if err != nil {
		return providerOverlayStage("type3-widths", nil)
	}
	for _, width := range widths {
		if width < 0 {
			return providerOverlayStage("type3-widths", nil)
		}
	}
	if o, exists := f["Resources"]; exists {
		resources, err := ctx.DereferenceDict(o)
		if err != nil || resources == nil || len(resources) != 0 {
			return providerOverlayStage("type3-resources", nil)
		}
	}
	encoding, err := ctx.DereferenceDict(f["Encoding"])
	if err != nil || len(encoding) != 2 || !providerType3Keys(encoding, "Type Differences") || encoding.NameEntry("Type") == nil || *encoding.NameEntry("Type") != "Encoding" {
		return providerOverlayStage("type3-encoding", nil)
	}
	differences, err := ctx.DereferenceArray(encoding["Differences"])
	if err != nil || len(differences) != len(widths)+1 {
		return providerOverlayStage("type3-encoding", nil)
	}
	start, err := ctx.DereferenceInteger(differences[0])
	if err != nil || start == nil || start.Value() != 0 {
		return providerOverlayStage("type3-encoding", nil)
	}
	glyphs, err := ctx.DereferenceDict(f["CharProcs"])
	if err != nil || len(glyphs) < 1 || len(glyphs) > 256 {
		return providerOverlayStage("type3-glyphs", nil)
	}
	encodedWidths := make(map[string][]float64, len(glyphs))
	for i, o := range differences[1:] {
		value, err := ctx.Dereference(o)
		glyph, ok := value.(types.Name)
		if err != nil || !ok || !providerType3GlyphName(string(glyph)) {
			return providerOverlayStage("type3-encoding", nil)
		}
		if _, exists := glyphs[string(glyph)]; !exists {
			return providerOverlayStage("type3-encoding", nil)
		}
		encodedWidths[string(glyph)] = append(encodedWidths[string(glyph)], widths[i])
	}
	for name, o := range glyphs {
		if !providerType3GlyphName(name) || len(encodedWidths[name]) == 0 {
			return providerOverlayStage("type3-encoding", nil)
		}
		stream, err := providerType3Stream(ctx, o, budget)
		if err != nil {
			return err
		}
		metrics, err := validateProviderType3Glyph(stream.Content)
		if err != nil {
			return err
		}
		matchedWidth := false
		for _, width := range encodedWidths[name] {
			matchedWidth = matchedWidth || width == metrics.width
		}
		// Skia fills unused codes with g0 and zero width. Require each actual
		// glyph to have a matching encoded width; do not invent used codes.
		if !matchedWidth || (metrics.box != [4]float64{} && (metrics.box[0] < fontBox[0] || metrics.box[1] < fontBox[1] || metrics.box[2] > fontBox[2] || metrics.box[3] > fontBox[3])) {
			return providerOverlayStage("type3-metrics", nil)
		}
		// DereferenceStreamDict returns a value copy. Retain bounded decoded
		// bytes in this private fragment graph before semantic resource copying;
		// copying must not invoke an unbounded decoder on these streams again.
		glyphs[name] = *stream
	}
	cmap, err := providerType3Stream(ctx, f["ToUnicode"], budget)
	if err != nil {
		return err
	}
	f["ToUnicode"] = *cmap
	return nil
}

func providerType3Keys(d types.Dict, allowed string) bool {
	keys := strings.Fields(allowed)
	if d == nil || len(d) > len(keys) {
		return false
	}
	for key := range d {
		found := false
		for _, known := range keys {
			found = found || key == known
		}
		if !found {
			return false
		}
	}
	return true
}

func providerInterSubsetName(name string) bool {
	if name == "Inter-Regular" {
		return true
	}
	if len(name) != 7+len("Inter-Regular") || name[6:] != "+Inter-Regular" {
		return false
	}
	for _, c := range name[:6] {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

func providerType3GlyphName(name string) bool {
	if len(name) < 2 || len(name) > 5 || name[0] != 'g' {
		return false
	}
	n, err := strconv.ParseUint(name[1:], 16, 16)
	return err == nil && fmt.Sprintf("g%X", n) == name
}

func providerType3Numbers(ctx *model.Context, o types.Object, count int) ([]float64, error) {
	array, err := ctx.DereferenceArray(o)
	if err != nil || count < 1 || count > 256 || len(array) != count {
		return nil, ErrPDFProviderOverlay
	}
	out := make([]float64, count)
	for i, value := range array {
		n, err := ctx.DereferenceNumber(value)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || math.Abs(n) > 8192 {
			return nil, ErrPDFProviderOverlay
		}
		out[i] = n
	}
	return out, nil
}

func providerType3Stream(ctx *model.Context, o types.Object, budget *providerType3Budget) (*types.StreamDict, error) {
	if budget == nil || budget.decoded < 0 || budget.decoded >= providerType3DecodedLimit {
		return nil, providerOverlayStage("type3-expansion", nil)
	}
	stream, _, err := ctx.DereferenceStreamDict(o)
	if err != nil || stream == nil || !providerType3Keys(stream.Dict, "Length Filter") || len(stream.Raw) > 1<<20 {
		return nil, providerOverlayStage("type3-stream", nil)
	}
	length, err := ctx.DereferenceInteger(stream.Dict["Length"])
	if err != nil || length == nil || length.Value() != len(stream.Raw) {
		return nil, providerOverlayStage("type3-stream", nil)
	}
	compressed := false
	if filter, exists := stream.Dict["Filter"]; exists {
		value, err := ctx.Dereference(filter)
		name, ok := value.(types.Name)
		if err != nil || !ok || name != "FlateDecode" || len(stream.FilterPipeline) != 1 || stream.FilterPipeline[0].Name != "FlateDecode" || stream.FilterPipeline[0].DecodeParms != nil {
			return nil, providerOverlayStage("type3-stream", nil)
		}
		compressed = true
	} else if len(stream.FilterPipeline) != 0 {
		return nil, providerOverlayStage("type3-stream", nil)
	}
	remaining := providerType3DecodedLimit - budget.decoded
	if remaining > providerType3StreamLimit {
		remaining = providerType3StreamLimit
	}
	if remaining < 1 {
		return nil, providerOverlayStage("type3-expansion", nil)
	}
	// Always validate actual encoded bytes, including a strict zlib checksum.
	// An earlier parser cache is never authority for this admission.
	content := stream.Raw
	if compressed {
		encoded := bytes.NewReader(stream.Raw)
		reader, err := zlib.NewReader(encoded)
		if err != nil {
			return nil, providerOverlayStage("type3-stream", nil)
		}
		content, err = io.ReadAll(io.LimitReader(reader, int64(remaining)+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil || encoded.Len() != 0 {
			return nil, providerOverlayStage("type3-stream", nil)
		}
	}
	if len(content) < 1 || len(content) > remaining {
		return nil, providerOverlayStage("type3-expansion", nil)
	}
	if stream.Content != nil && !bytes.Equal(stream.Content, content) {
		return nil, providerOverlayStage("type3-stream", nil)
	}
	budget.decoded += len(content)
	stream.Content = content
	return stream, nil
}

type providerType3Metrics struct {
	width float64
	box   [4]float64
}

// A Type3 CharProc may contain arbitrary page operators in PDF. This profile
// permits only the seven observed operators, with exact numeric arities. No
// names, strings, arrays, resource lookup, text, images, color or transforms can
// execute here, even when an omitted Resources dictionary inherits page fonts.
func validateProviderType3Glyph(raw []byte) (providerType3Metrics, error) {
	var metrics providerType3Metrics
	if len(raw) < 1 || len(raw) > providerType3StreamLimit {
		return metrics, providerOverlayStage("type3-expansion", nil)
	}
	var operands [6]float64
	count, tokens := 0, 0
	initialized, path, painted := false, false, false
	for i := 0; i < len(raw); {
		if pdfWhite(raw[i]) {
			i++
			continue
		}
		if raw[i] == '%' {
			for i < len(raw) && raw[i] != '\n' && raw[i] != '\r' {
				i++
			}
			continue
		}
		start := i
		for i < len(raw) && !pdfDelimiter(raw[i]) {
			i++
		}
		tokens++
		if i == start || tokens > 20000 {
			return metrics, providerOverlayStage("type3-operators", nil)
		}
		word := string(raw[start:i])
		if providerNumberToken(word) {
			n, _ := strconv.ParseFloat(word, 64)
			if count == len(operands) || math.Abs(n) > 8192 {
				return metrics, providerOverlayStage("type3-operators", nil)
			}
			operands[count] = n
			count++
			continue
		}
		if !initialized && word != "d1" {
			return metrics, providerOverlayStage("type3-operators", nil)
		}
		switch word {
		case "d1":
			if initialized || count != 6 || operands[0] <= 0 || operands[1] != 0 || operands[2] > operands[4] || operands[3] > operands[5] {
				return metrics, providerOverlayStage("type3-metrics", nil)
			}
			metrics = providerType3Metrics{width: operands[0], box: [4]float64{operands[2], operands[3], operands[4], operands[5]}}
			initialized = true
		case "m":
			if count != 2 {
				return metrics, providerOverlayStage("type3-operators", nil)
			}
			path = true
		case "l":
			if count != 2 || !path {
				return metrics, providerOverlayStage("type3-operators", nil)
			}
		case "c":
			if count != 6 || !path {
				return metrics, providerOverlayStage("type3-operators", nil)
			}
		case "h":
			if count != 0 || !path {
				return metrics, providerOverlayStage("type3-operators", nil)
			}
		case "re":
			if count != 4 || operands[2] <= 0 || operands[3] <= 0 || math.Abs(operands[0]+operands[2]) > 8192 || math.Abs(operands[1]+operands[3]) > 8192 {
				return metrics, providerOverlayStage("type3-operators", nil)
			}
			path = true
		case "f":
			if count != 0 || !path {
				return metrics, providerOverlayStage("type3-operators", nil)
			}
			path, painted = false, true
		default:
			return metrics, providerOverlayStage("type3-operators", nil)
		}
		count = 0
	}
	if !initialized || count != 0 || path || (painted && (metrics.box[0] >= metrics.box[2] || metrics.box[1] >= metrics.box[3])) {
		return metrics, providerOverlayStage("type3-metrics", nil)
	}
	return metrics, nil
}

func providerEmbeddedFont(ctx *model.Context, f types.Dict) bool {
	d, err := ctx.DereferenceDict(f["FontDescriptor"])
	if err != nil {
		return false
	}
	s, _, err := ctx.DereferenceStreamDict(d["FontFile2"])
	return err == nil && s != nil
}

// Copy only the already admitted resource graph; never migrate catalogs,
// pages or arbitrary XObjects. Semantic hashes ignore reference numbering and
// compression, which optimizers may safely change. Cycles exceed bounded depth.
type providerCopyBudget struct{ nodes, decodedBytes int }

func copyProviderObject(src, dst *model.Context, o types.Object, depth int, budget *providerCopyBudget) (types.Object, any, error) {
	budget.nodes++
	if depth > 64 || budget.nodes > 4096 {
		return nil, nil, ErrPDFProviderOverlay
	}
	if _, indirect := o.(types.IndirectRef); indirect {
		value, err := src.Dereference(o)
		if err != nil || value == nil {
			return nil, nil, ErrPDFProviderOverlay
		}
		copied, semantic, err := copyProviderObject(src, dst, value, depth+1, budget)
		if err != nil {
			return nil, nil, err
		}
		if dst == nil {
			return nil, semantic, nil
		}
		if _, already := copied.(types.IndirectRef); already {
			return copied, semantic, nil
		}
		ir, err := dst.IndRefForNewObject(copied)
		if err != nil {
			return nil, nil, ErrPDFProviderOverlay
		}
		return *ir, semantic, nil
	}
	o, err := src.Dereference(o)
	if err != nil || o == nil {
		return nil, nil, ErrPDFProviderOverlay
	}
	switch v := o.(type) {
	case types.Dict:
		out := types.NewDict()
		semantic := map[string]any{}
		for k, val := range v {
			switch k {
			case "AA", "A", "JS", "JavaScript", "OC", "Group", "SMask", "Pattern", "Shading", "XObject", "Metadata", "EmbeddedFiles":
				return nil, nil, ErrPDFProviderOverlay
			}
			c, s, err := copyProviderObject(src, dst, val, depth+1, budget)
			if err != nil {
				return nil, nil, err
			}
			out[k] = c
			semantic[k] = s
		}
		return out, semantic, nil
	case types.Array:
		out := types.Array{}
		semantic := []any{}
		for _, val := range v {
			c, s, err := copyProviderObject(src, dst, val, depth+1, budget)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, c)
			semantic = append(semantic, s)
		}
		return out, semantic, nil
	case types.StreamDict:
		if _, ok := v.Dict["F"]; ok {
			return nil, nil, ErrPDFProviderOverlay
		}
		if v.Decode() != nil || len(v.Content) > 8<<20 {
			return nil, nil, ErrPDFProviderOverlay
		}
		budget.decodedBytes += len(v.Content)
		if budget.decodedBytes > 16<<20 {
			return nil, nil, ErrPDFProviderOverlay
		}
		d := types.NewDict()
		for k, val := range v.Dict {
			if k != "Length" && k != "Filter" && k != "DecodeParms" {
				d[k] = val
			}
		}
		c, s, err := copyProviderObject(src, dst, d, depth+1, budget)
		if err != nil {
			return nil, nil, err
		}
		semantic := map[string]any{"dict": s, "content": bytes.Clone(v.Content)}
		if dst == nil {
			return nil, semantic, nil
		}
		sd, err := dst.NewStreamDictForBuf(bytes.Clone(v.Content))
		if err != nil {
			return nil, nil, ErrPDFProviderOverlay
		}
		for k, val := range c.(types.Dict) {
			sd.Dict[k] = val
		}
		if sd.Encode() != nil {
			return nil, nil, ErrPDFProviderOverlay
		}
		ir, err := dst.IndRefForNewObject(*sd)
		if err != nil {
			return nil, nil, ErrPDFProviderOverlay
		}
		return *ir, semantic, nil
	case types.Integer, types.Float, types.Name, types.StringLiteral, types.HexLiteral, types.Boolean:
		return v, struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}{fmt.Sprintf("%T", v), v.PDFString()}, nil
	default:
		return nil, nil, ErrPDFProviderOverlay
	}
}

// Lexical operator admission skips complete strings/arrays/dictionaries, so
// text containing "Q" is never treated as a graphics restore. No inline image,
// XObject, shading, compatibility section or unknown operator is admitted.
func validateProviderOperators(raw []byte, fragment bool) error {
	if len(raw) > 8<<20 {
		return ErrPDFProviderOverlay
	}
	q, bt, marked := 0, 0, 0
	budget := 0
	for i := 0; i < len(raw); {
		if pdfWhite(raw[i]) {
			i++
			continue
		}
		if raw[i] == '%' {
			for i < len(raw) && raw[i] != '\n' && raw[i] != '\r' {
				i++
			}
			continue
		}
		budget++
		if budget > 100000 {
			return ErrPDFProviderOverlay
		}
		start := i
		if raw[i] == '/' {
			i++
			for i < len(raw) && !pdfDelimiter(raw[i]) {
				i++
			}
			continue
		}
		if raw[i] == '(' || raw[i] == '[' || raw[i] == '<' {
			var err error
			i, err = providerSkipOperand(raw, i, 0)
			if err != nil {
				return err
			}
			continue
		}
		for i < len(raw) && !pdfDelimiter(raw[i]) {
			i++
		}
		if i == start {
			return ErrPDFProviderOverlay
		}
		word := string(raw[start:i])
		if providerNumberToken(word) {
			continue
		}
		if word == "true" || word == "false" || word == "null" {
			continue
		}
		switch word {
		case "q":
			q++
		case "Q":
			q--
		case "BT":
			if bt != 0 {
				return ErrPDFProviderOverlay
			}
			bt = 1
		case "ET":
			bt--
		case "BMC", "BDC":
			marked++
		case "EMC":
			marked--
		case "cm", "w", "J", "j", "M", "d", "ri", "i", "gs", "m", "l", "c", "v", "y", "h", "re", "S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n", "W", "W*", "Tc", "Tw", "Tz", "TL", "Tf", "Tr", "Ts", "Td", "TD", "Tm", "T*", "Tj", "TJ", "'", "\"", "CS", "cs", "SC", "SCN", "sc", "scn", "G", "g", "RG", "rg", "K", "k", "MP", "DP":
		case "Do":
			if fragment {
				return ErrPDFProviderOverlay
			}
		default:
			return ErrPDFProviderOverlay
		}
		if q < 0 || q > 128 || bt < 0 || bt > 1 || marked < 0 || marked > 64 {
			return ErrPDFProviderOverlay
		}
	}
	if q != 0 || bt != 0 || marked != 0 {
		return ErrPDFProviderOverlay
	}
	return nil
}

func pdfWhite(c byte) bool     { return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32 }
func pdfDelimiter(c byte) bool { return pdfWhite(c) || strings.ContainsRune("()<>[]{}/%", rune(c)) }
func providerSkipOperand(raw []byte, i, depth int) (int, error) {
	if depth >= 64 || i >= len(raw) {
		return i, ErrPDFProviderOverlay
	}
	start := raw[i]
	i++
	if start == '(' {
		level := 1
		for i < len(raw) {
			c := raw[i]
			i++
			if c == '\\' {
				if i < len(raw) {
					i++
				}
				continue
			}
			if c == '(' {
				level++
				if level > 64 {
					return i, ErrPDFProviderOverlay
				}
			}
			if c == ')' {
				level--
				if level == 0 {
					return i, nil
				}
			}
		}
		return i, ErrPDFProviderOverlay
	}
	if start == '<' && (i >= len(raw) || raw[i] != '<') {
		for i < len(raw) && raw[i] != '>' {
			c := raw[i]
			if !pdfWhite(c) && !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return i, ErrPDFProviderOverlay
			}
			i++
		}
		if i == len(raw) {
			return i, ErrPDFProviderOverlay
		}
		return i + 1, nil
	}
	close := byte(']')
	dict := start == '<'
	if dict {
		i++
		close = '>'
	}
	for i < len(raw) {
		if pdfWhite(raw[i]) {
			i++
			continue
		}
		if raw[i] == '%' {
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			continue
		}
		if raw[i] == close {
			if dict {
				if i+1 >= len(raw) || raw[i+1] != '>' {
					return i, ErrPDFProviderOverlay
				}
				return i + 2, nil
			}
			return i + 1, nil
		}
		if raw[i] == '(' || raw[i] == '[' || raw[i] == '<' {
			var err error
			i, err = providerSkipOperand(raw, i, depth+1)
			if err != nil {
				return i, err
			}
			continue
		}
		named := raw[i] == '/'
		if named {
			i++
		}
		j := i
		for i < len(raw) && !pdfDelimiter(raw[i]) {
			i++
		}
		if i == j {
			return i, ErrPDFProviderOverlay
		}
		if !named {
			word := string(raw[j:i])
			if !providerNumberToken(word) && word != "true" && word != "false" && word != "null" {
				return i, ErrPDFProviderOverlay
			}
		}
	}
	return i, ErrPDFProviderOverlay
}

func providerNumberToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	n, err := strconv.ParseFloat(s, 64)
	return err == nil && !math.IsNaN(n) && !math.IsInf(n, 0)
}
