// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"

	"github.com/bright-interaction/hash/internal/malwarescan"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const (
	pdfManualLayersOperation           = "manual-layers-v1"
	pdfManualFragmentOperation         = "manual-fragment-inspect-v1"
	pdfManualOperationsCapabilityV1    = "manual-fragment-inspect-v1+manual-layers-v1"
	PDFManualLayersPolicy              = "hash-pdf-manual-ordered-layers-v1"
	PDFManualFragmentPolicy            = "hash-pdf-manual-full-viewport-fragment-v1"
	PDFManualLayerBaseV1               = "base_text_v1"
	PDFManualLayerSignatureV1          = "retained_signature_v1"
	MaxPDFManualSignatureFragmentBytes = 8 << 20
	// Explicit descriptor bound; byte and shared resource quotas also apply.
	MaxPDFManualLayersV1 = 1500
)

var (
	ErrPDFManualLayers   = errors.New("sanitize: invalid ordered manual PDF layers")
	ErrPDFManualFragment = errors.New("sanitize: invalid full-viewport PDF fragment")
)

// PDFManualLayerV1 is one full-viewport PDF. Page/order are explicit, ascending
// and contiguous within each page. A page may have one base_text_v1 first,
// followed by any admitted retained_signature_v1 fragments. Identity is an
// opaque bounded application identifier, not a path or a storage capability.
// The caller must already have frozen-decoded the retained signature package.
// This layer proves structural import, not the authenticity of that package.
type PDFManualLayerV1 struct {
	Page     int
	Order    int
	Kind     string
	Identity string
	PDF      []byte
}

type manualLayerDescriptorV1 struct {
	Page     int    `json:"page"`
	Order    int    `json:"order"`
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
}

type manualLayersBatchV1 struct {
	SchemaVersion  int                       `json:"schema_version"`
	SourceSHA256   string                    `json:"source_sha256"`
	SourceBytes    int64                     `json:"source_bytes"`
	GeometrySHA256 string                    `json:"geometry_sha256"`
	Pages          int                       `json:"pages"`
	Layers         []manualLayerDescriptorV1 `json:"layers"`
}

// PDFManualLayersManifest commits the exact ordered descriptors, all original
// page painting, and the independently verified import witnesses. The witness
// SHA includes every page, each fragment's identity/content/resources/Group,
// its effective viewport matrix, and the exact ordered page invocation stream.
// It does not assert glyph readability or legal effect.
type PDFManualLayersManifest struct {
	SchemaVersion         int    `json:"schema_version"`
	Policy                string `json:"policy"`
	SourceSHA256          string `json:"source_sha256"`
	SourceBytes           int64  `json:"source_bytes"`
	DescriptorSHA256      string `json:"descriptor_sha256"`
	GeometrySHA256        string `json:"geometry_sha256"`
	Pages                 int    `json:"pages"`
	Layers                int    `json:"layers"`
	OriginalContentSHA256 string `json:"original_content_sha256"`
	OrderedPaintingSHA256 string `json:"ordered_painting_sha256"`
	ProcessingSHA256      string `json:"processing_sha256"`
	ProcessingBytes       int64  `json:"processing_bytes"`
	OutputSHA256          string `json:"output_sha256"`
	OutputBytes           int64  `json:"output_bytes"`
}

type PDFManualLayersResult struct {
	Result
	Layers PDFManualLayersManifest
}

// PDFManualFragmentAdmission binds a single zero-origin, upright viewport
// fragment to its exact PDF bytes and structural/resource commitments. Expected
// and observed paper sizes remain distinct: only <=0.75pt Chromium quantization
// is admitted, consistently with the existing manual-placement policy.
type PDFManualFragmentAdmission struct {
	SchemaVersion        int     `json:"schema_version"`
	Policy               string  `json:"policy"`
	PDFSHA256            string  `json:"pdf_sha256"`
	PDFBytes             int64   `json:"pdf_bytes"`
	WidthPoints          float64 `json:"width_points"`
	HeightPoints         float64 `json:"height_points"`
	ObservedWidthPoints  float64 `json:"observed_width_points"`
	ObservedHeightPoints float64 `json:"observed_height_points"`
	GeometrySHA256       string  `json:"geometry_sha256"`
	ContentSHA256        string  `json:"content_sha256"`
	ResourcesSHA256      string  `json:"resources_sha256"`
	GroupSHA256          string  `json:"group_sha256"`
}

type manualFragmentRequestV1 struct {
	SchemaVersion int     `json:"schema_version"`
	PDFSHA256     string  `json:"pdf_sha256"`
	PDFBytes      int64   `json:"pdf_bytes"`
	WidthPoints   float64 `json:"width_points"`
	HeightPoints  float64 `json:"height_points"`
}

func manualLayerIdentityV1(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == ':') {
			return false
		}
	}
	return true
}

func validateManualLayerDescriptorsV1(ds []manualLayerDescriptorV1, pages int) error {
	if pages < 1 || pages > MaxPDFPages || len(ds) < 1 || len(ds) > MaxPDFManualLayersV1 {
		return ErrPDFManualLayers
	}
	previousPage, previousOrder := 0, 0
	seen := map[string]struct{}{}
	for _, d := range ds {
		if d.Page < 1 || d.Page > pages || d.Page < previousPage || d.Order < 1 || !manualLayerIdentityV1(d.Identity) || !validPDFSHA(d.SHA256) || d.Bytes < 1 || d.Bytes > MaxPDFBytes {
			return ErrPDFManualLayers
		}
		if d.Page != previousPage {
			previousOrder = 0
			seen = map[string]struct{}{}
		}
		if d.Order != previousOrder+1 {
			return ErrPDFManualLayers
		}
		switch d.Kind {
		case PDFManualLayerBaseV1:
			if d.Order != 1 {
				return ErrPDFManualLayers
			}
		case PDFManualLayerSignatureV1:
			if d.Bytes > MaxPDFManualSignatureFragmentBytes {
				return ErrPDFTooLarge
			}
		default:
			return ErrPDFManualLayers
		}
		if _, duplicate := seen[d.Kind+":"+d.Identity]; duplicate {
			return ErrPDFManualLayers
		}
		seen[d.Kind+":"+d.Identity] = struct{}{}
		previousPage, previousOrder = d.Page, d.Order
	}
	return nil
}

func validateManualLayersManifest(m PDFManualLayersManifest) error {
	if m.SchemaVersion != 1 || m.Policy != PDFManualLayersPolicy || m.Pages < 1 || m.Pages > MaxPDFPages || m.Layers < 1 || m.Layers > MaxPDFManualLayersV1 {
		return ErrPDFManualLayers
	}
	for _, s := range []string{m.SourceSHA256, m.DescriptorSHA256, m.GeometrySHA256, m.OriginalContentSHA256, m.OrderedPaintingSHA256, m.ProcessingSHA256, m.OutputSHA256} {
		if !validPDFSHA(s) {
			return ErrPDFManualLayers
		}
	}
	for _, n := range []int64{m.SourceBytes, m.ProcessingBytes, m.OutputBytes} {
		if n < 1 || n > MaxPDFBytes {
			return ErrPDFManualLayers
		}
	}
	if m.SourceSHA256 == m.OutputSHA256 {
		return ErrPDFManualLayers
	}
	return nil
}

func DecodePDFManualLayersManifest(raw []byte) (PDFManualLayersManifest, error) {
	var m PDFManualLayersManifest
	if decodeManualLayersJSON(raw, &m) != nil || validateManualLayersManifest(m) != nil {
		return PDFManualLayersManifest{}, ErrPDFManualLayers
	}
	return m, nil
}

func ValidatePDFManualLayersResult(r PDFManualLayersResult) error {
	m := r.Layers
	if validateManualLayersManifest(m) != nil || m.OutputSHA256 != pdfSHA(r.Bytes) || m.OutputBytes != int64(len(r.Bytes)) || ValidatePDFResult(r.Report, m.ProcessingSHA256, m.OutputSHA256, m.ProcessingBytes, m.OutputBytes) != nil || r.Report.Asset != "manual-layered-pdf" || r.Report.PDF.PagesAfter != m.Pages || r.Report.PDF.GeometrySHA256After != m.GeometrySHA256 {
		return ErrPDFManualLayers
	}
	return nil
}

func validateManualFragmentAdmission(a PDFManualFragmentAdmission) error {
	if a.SchemaVersion != 1 || a.Policy != PDFManualFragmentPolicy || a.PDFBytes < 1 || a.PDFBytes > MaxPDFManualSignatureFragmentBytes {
		return ErrPDFManualFragment
	}
	for _, s := range []string{a.PDFSHA256, a.GeometrySHA256, a.ContentSHA256, a.ResourcesSHA256, a.GroupSHA256} {
		if !validPDFSHA(s) {
			return ErrPDFManualFragment
		}
	}
	for _, n := range []float64{a.WidthPoints, a.HeightPoints, a.ObservedWidthPoints, a.ObservedHeightPoints} {
		if !manualFinite(n) || n <= 0 || n > maxManualViewportPoints {
			return ErrPDFManualFragment
		}
	}
	if math.Abs(a.WidthPoints-a.ObservedWidthPoints) > .75 || math.Abs(a.HeightPoints-a.ObservedHeightPoints) > .75 {
		return ErrPDFManualFragment
	}
	return nil
}

func DecodePDFManualFragmentAdmission(raw []byte) (PDFManualFragmentAdmission, error) {
	var a PDFManualFragmentAdmission
	if decodeManualLayersJSON(raw, &a) != nil || validateManualFragmentAdmission(a) != nil {
		return PDFManualFragmentAdmission{}, ErrPDFManualFragment
	}
	return a, nil
}

func validateManualFragmentRequestV1(d manualFragmentRequestV1, pdf []byte) error {
	if d.SchemaVersion != 1 || !validPDFSHA(d.PDFSHA256) || d.PDFBytes < 1 || d.PDFBytes > MaxPDFManualSignatureFragmentBytes || !manualFinite(d.WidthPoints) || !manualFinite(d.HeightPoints) || d.WidthPoints <= 0 || d.HeightPoints <= 0 || d.WidthPoints > maxManualViewportPoints || d.HeightPoints > maxManualViewportPoints {
		return ErrPDFManualFragment
	}
	if pdf != nil && (d.PDFBytes != int64(len(pdf)) || d.PDFSHA256 != pdfSHA(pdf)) {
		return ErrPDFManualFragment
	}
	return nil
}

// InspectManualPDFFragmentWithContext admits the exact PDF section of a frozen
// signature package in the mandatory isolated child. It never parses a PDF in
// the application, admits other package sections, or rewrites the fragment.
func InspectManualPDFFragmentWithContext(ctx context.Context, pdf []byte, widthPoints, heightPoints float64) (PDFManualFragmentAdmission, error) {
	if ctx == nil {
		return PDFManualFragmentAdmission{}, ErrPDFManualFragment
	}
	if err := ctx.Err(); err != nil {
		return PDFManualFragmentAdmission{}, err
	}
	if len(pdf) > MaxPDFManualSignatureFragmentBytes {
		return PDFManualFragmentAdmission{}, ErrPDFTooLarge
	}
	pdf = bytes.Clone(pdf)
	d := manualFragmentRequestV1{1, pdfSHA(pdf), int64(len(pdf)), widthPoints, heightPoints}
	if err := validateManualFragmentRequestV1(d, pdf); err != nil {
		return PDFManualFragmentAdmission{}, err
	}
	metadata, err := json.Marshal(d)
	if err != nil {
		return PDFManualFragmentAdmission{}, ErrPDFManualFragment
	}
	if err := malwarescan.ScanActive(ctx, pdf); err != nil {
		return PDFManualFragmentAdmission{}, err
	}
	w := activePDFWorker.Load()
	if w == nil {
		return PDFManualFragmentAdmission{}, ErrPDFWorkerUnavailable
	}
	raw := make([]byte, 0, len(metadata)+len(pdf))
	raw = append(raw, metadata...)
	raw = append(raw, pdf...)
	_, out, err := w.run(ctx, pdfWorkerRequest{Operation: pdfManualFragmentOperation, Length: len(raw), ManualMetadataLength: len(metadata)}, raw)
	if err != nil {
		return PDFManualFragmentAdmission{}, err
	}
	if err := ctx.Err(); err != nil {
		return PDFManualFragmentAdmission{}, err
	}
	a, err := DecodePDFManualFragmentAdmission(out)
	if err != nil || a.PDFSHA256 != d.PDFSHA256 || a.PDFBytes != d.PDFBytes || a.WidthPoints != d.WidthPoints || a.HeightPoints != d.HeightPoints {
		return PDFManualFragmentAdmission{}, ErrPDFWorkerUnavailable
	}
	return a, nil
}

// ApplyManualPDFLayersWithContext makes exactly one ordered composition pass.
// Byte/metadata/part admission precedes malware scanning and child execution;
// source plus all PDFs plus metadata must fit the existing 50 MiB processing
// budget. Signature package authenticity and the distinct 160 MiB evidence
// export budget are the calling retained-signature orchestrator's obligations.
func ApplyManualPDFLayersWithContext(ctx context.Context, source []byte, g PDFManualGeometry, layers []PDFManualLayerV1) (PDFManualLayersResult, error) {
	if ctx == nil {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	if err := ctx.Err(); err != nil {
		return PDFManualLayersResult{}, err
	}
	if len(source) > MaxPDFBytes {
		return PDFManualLayersResult{}, ErrPDFTooLarge
	}
	g.Pages = append([]PDFManualPage(nil), g.Pages...)
	if validateManualGeometry(g, source) != nil || len(layers) < 1 || len(layers) > MaxPDFManualLayersV1 {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	batch := manualLayersBatchV1{1, g.SourceSHA256, g.SourceBytes, g.GeometrySHA256, len(g.Pages), make([]manualLayerDescriptorV1, len(layers))}
	total := len(source)
	for i, l := range layers {
		if len(l.PDF) < 1 || len(l.PDF) > MaxPDFBytes-total {
			return PDFManualLayersResult{}, ErrPDFTooLarge
		}
		total += len(l.PDF)
		batch.Layers[i] = manualLayerDescriptorV1{l.Page, l.Order, l.Kind, l.Identity, len(l.PDF), pdfSHA(l.PDF)}
	}
	if err := validateManualLayerDescriptorsV1(batch.Layers, batch.Pages); err != nil {
		return PDFManualLayersResult{}, err
	}
	metadata, err := json.Marshal(batch)
	if err != nil || len(metadata) > manualMetadataLimit || len(metadata) > MaxPDFBytes-total {
		return PDFManualLayersResult{}, ErrPDFTooLarge
	}
	raw := make([]byte, 0, total+len(metadata))
	raw = append(raw, metadata...)
	raw = append(raw, source...)
	for _, l := range layers {
		raw = append(raw, l.PDF...)
	}
	// Scan the immutable framed copies, not caller-owned slices that may change
	// while an external scanner is awaited.
	rest := raw[len(metadata):]
	if err := malwarescan.ScanActive(ctx, rest[:len(source)]); err != nil {
		return PDFManualLayersResult{}, err
	}
	rest = rest[len(source):]
	for _, d := range batch.Layers {
		if err := malwarescan.ScanActive(ctx, rest[:d.Bytes]); err != nil {
			return PDFManualLayersResult{}, err
		}
		rest = rest[d.Bytes:]
	}
	w := activePDFWorker.Load()
	if w == nil {
		return PDFManualLayersResult{}, ErrPDFWorkerUnavailable
	}
	response, out, err := w.run(ctx, pdfWorkerRequest{Operation: pdfManualLayersOperation, Length: len(raw), ManualMetadataLength: len(metadata)}, raw)
	if err != nil {
		return PDFManualLayersResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return PDFManualLayersResult{}, err
	}
	if response.ManualLayers == nil || response.Report == nil {
		return PDFManualLayersResult{}, ErrPDFWorkerUnavailable
	}
	r := PDFManualLayersResult{Result{out, *response.Report}, *response.ManualLayers}
	if ValidatePDFManualLayersResult(r) != nil || r.Layers.DescriptorSHA256 != pdfSHA(metadata) || r.Layers.SourceSHA256 != g.SourceSHA256 || r.Layers.SourceBytes != g.SourceBytes || r.Layers.GeometrySHA256 != g.GeometrySHA256 || r.Layers.Pages != len(g.Pages) || r.Layers.Layers != len(layers) {
		return PDFManualLayersResult{}, ErrPDFWorkerUnavailable
	}
	return r, nil
}

// Closed shape including nested arrays: this operation has a larger explicit
// layer-count budget than the historical one-overlay-per-page operation.
func decodeManualLayersJSON(raw []byte, out any) error {
	if len(raw) < 1 || len(raw) > manualMetadataLimit || strictPDFWorkerJSON(raw) != nil {
		return ErrPDFManualLayers
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF || !manualLayersExactJSON(raw, reflect.TypeOf(out).Elem()) {
		return ErrPDFManualLayers
	}
	return nil
}

func manualLayersExactJSON(raw []byte, t reflect.Type) bool {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || len(m) != t.NumField() {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			v, ok := m[f.Tag.Get("json")]
			if !ok || !manualLayersExactJSON(v, f.Type) {
				return false
			}
		}
	case reflect.Array, reflect.Slice:
		var a []json.RawMessage
		if json.Unmarshal(raw, &a) != nil || len(a) > MaxPDFManualLayersV1 || t.Kind() == reflect.Array && len(a) != t.Len() {
			return false
		}
		for _, v := range a {
			if !manualLayersExactJSON(v, t.Elem()) {
				return false
			}
		}
	}
	return true
}

type admittedManualFragmentV1 struct {
	ctx       *model.Context
	content   []byte
	resources types.Object
	group     types.Object
	box       [4]float64
	admission PDFManualFragmentAdmission
}

// All fragments are fully admitted before the processing source is mutated.
// Admission and import use separate bounded phases, each sharing aggregate
// content/resource quotas. Image/font resource streams remain encoded; drawing
// streams decode only under the content quota for visibility-policy admission.
func admitManualFragmentV1(pdf []byte, width, height float64, usage *manualResourceUsage) (*admittedManualFragmentV1, error) {
	ctx, geometry, err := observePDFCompositionInput(pdf)
	if err != nil {
		return nil, err
	}
	props, err := observedPDFProperties(ctx)
	if err != nil || ctx.PageCount != 1 || props.Annotations || props.AcroForm || props.EmbeddedFiles {
		return nil, ErrPDFManualFragment
	}
	pages, err := pdfCompositionGeometry(ctx)
	if err != nil || len(pages) != 1 {
		return nil, ErrPDFManualFragment
	}
	p := pages[0]
	ow, oh := p.Boxes[0][2], p.Boxes[0][3]
	if p.Rotation != 0 || p.UserUnit != 1 || !manualFinite(width) || !manualFinite(height) || width <= 0 || height <= 0 || width > maxManualViewportPoints || height > maxManualViewportPoints || math.Abs(width-ow) > .75 || math.Abs(height-oh) > .75 {
		return nil, ErrPDFManualFragment
	}
	for _, b := range p.Boxes {
		if b != [4]float64{0, 0, ow, oh} {
			return nil, ErrPDFManualFragment
		}
	}
	page, _, attrs, err := ctx.PageDict(1, false)
	if err != nil || attrs.Resources == nil {
		return nil, ErrPDFManualFragment
	}
	content, err := manualPageContent(ctx, page, usage)
	if err != nil {
		return nil, err
	}
	if err := manualFragmentVisibilityV1(ctx, content, usage); err != nil {
		return nil, err
	}
	budget := newManualCopyBudget(usage)
	rh, err := manualResourceHashWithBudget(ctx, attrs.Resources, budget)
	if err != nil {
		return nil, err
	}
	group, err := manualOverlayGroup(ctx, page["Group"])
	if err != nil {
		return nil, err
	}
	gh, err := manualResourceHashWithBudget(ctx, group, budget)
	if err != nil {
		return nil, err
	}
	a := PDFManualFragmentAdmission{1, PDFManualFragmentPolicy, pdfSHA(pdf), int64(len(pdf)), width, height, ow, oh, geometry, pdfSHA(content), rh, gh}
	// Base-text overlays may exceed the frozen signature PDF-section bound. The
	// caller's layer kind applies that bound, while structural checks are shared.
	return &admittedManualFragmentV1{ctx, content, attrs.Resources, group, [4]float64{0, 0, ow, oh}, a}, nil
}

func manualFragmentInProcess(raw []byte, n int) (PDFManualFragmentAdmission, error) {
	if n < 1 || n > manualMetadataLimit || n >= len(raw) || len(raw) > MaxPDFBytes {
		return PDFManualFragmentAdmission{}, ErrPDFManualFragment
	}
	var d manualFragmentRequestV1
	if decodeManualLayersJSON(raw[:n], &d) != nil || validateManualFragmentRequestV1(d, raw[n:]) != nil {
		return PDFManualFragmentAdmission{}, ErrPDFManualFragment
	}
	f, err := admitManualFragmentV1(raw[n:], d.WidthPoints, d.HeightPoints, &manualResourceUsage{})
	if err != nil {
		return PDFManualFragmentAdmission{}, err
	}
	if validateManualFragmentAdmission(f.admission) != nil {
		return PDFManualFragmentAdmission{}, ErrPDFManualFragment
	}
	return f.admission, nil
}

type manualLayerFormWitnessV1 struct {
	Descriptor      manualLayerDescriptorV1 `json:"descriptor"`
	Name            string                  `json:"name"`
	ContentSHA256   string                  `json:"content_sha256"`
	ResourcesSHA256 string                  `json:"resources_sha256"`
	GroupSHA256     string                  `json:"group_sha256"`
	Box             [4]float64              `json:"box"`
	Matrix          [6]float64              `json:"matrix"`
}

type manualLayerPageWitnessV1 struct {
	Page                int                        `json:"page"`
	BaseName            string                     `json:"base_name"`
	ContentSHA256       string                     `json:"content_sha256"`
	ResourcesSHA256     string                     `json:"resources_sha256"`
	PageResourcesSHA256 string                     `json:"page_resources_sha256"`
	GroupSHA256         string                     `json:"group_sha256"`
	BaseBox             [4]float64                 `json:"base_box"`
	Layers              []manualLayerFormWitnessV1 `json:"layers"`
	InvocationSHA256    string                     `json:"invocation_sha256"`
	Calls               []byte                     `json:"-"`
}

func manualLayersInProcess(raw []byte, n int) (PDFManualLayersResult, error) {
	if n < 1 || n > manualMetadataLimit || n >= len(raw) || len(raw) > MaxPDFBytes {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	metadata := raw[:n]
	var b manualLayersBatchV1
	if decodeManualLayersJSON(metadata, &b) != nil || b.SchemaVersion != 1 || b.SourceBytes < 1 || b.SourceBytes > int64(len(raw)-n) || !validPDFSHA(b.SourceSHA256) || !validPDFSHA(b.GeometrySHA256) {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	if err := validateManualLayerDescriptorsV1(b.Layers, b.Pages); err != nil {
		return PDFManualLayersResult{}, err
	}
	source := raw[n : n+int(b.SourceBytes)]
	rest := raw[n+int(b.SourceBytes):]
	if pdfSHA(source) != b.SourceSHA256 {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	g, err := manualGeometryInProcess(source)
	if err != nil {
		return PDFManualLayersResult{}, err
	}
	if g.GeometrySHA256 != b.GeometrySHA256 || len(g.Pages) != b.Pages {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	parts := make([][]byte, len(b.Layers))
	for i, d := range b.Layers {
		if d.Bytes > len(rest) {
			return PDFManualLayersResult{}, ErrPDFManualLayers
		}
		parts[i], rest = rest[:d.Bytes], rest[d.Bytes:]
		if pdfSHA(parts[i]) != d.SHA256 {
			return PDFManualLayersResult{}, ErrPDFManualLayers
		}
	}
	if len(rest) != 0 {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	dest, _, err := observePDFCompositionInput(source)
	if err != nil {
		return PDFManualLayersResult{}, err
	}
	admissionUsage := &manualResourceUsage{}
	originals, err := manualPageContents(dest, admissionUsage)
	if err != nil {
		return PDFManualLayersResult{}, err
	}
	fragments := make([]*admittedManualFragmentV1, len(parts))
	for i, part := range parts {
		width, height, err := g.Pages[b.Layers[i].Page-1].ViewportPoints()
		if err != nil {
			return PDFManualLayersResult{}, err
		}
		fragments[i], err = admitManualFragmentV1(part, width, height, admissionUsage)
		if err != nil {
			return PDFManualLayersResult{}, err
		}
	}
	usage := &manualResourceUsage{}
	budget := newManualCopyBudget(usage)
	witnesses := make([]manualLayerPageWitnessV1, b.Pages)
	next := 0
	for page := 1; page <= b.Pages; page++ {
		p, _, attrs, err := dest.PageDict(page, false)
		if err != nil {
			return PDFManualLayersResult{}, ErrPDFManualLayers
		}
		rh, err := manualResourceHashWithBudget(dest, attrs.Resources, budget)
		if err != nil {
			return PDFManualLayersResult{}, err
		}
		gh, err := manualResourceHashWithBudget(dest, p["Group"], budget)
		if err != nil {
			return PDFManualLayersResult{}, err
		}
		w := manualLayerPageWitnessV1{page, "", pdfSHA(originals[page-1]), rh, rh, gh, g.Pages[page-1].Boxes[0], []manualLayerFormWitnessV1{}, pdfSHA(originals[page-1]), bytes.Clone(originals[page-1])}
		end := next
		for end < len(b.Layers) && b.Layers[end].Page == page {
			end++
		}
		if end > next {
			w, err = composeManualLayersPageV1(dest, g.Pages[page-1], originals[page-1], w, b.Layers[next:end], fragments[next:end], usage)
			if err != nil {
				return PDFManualLayersResult{}, err
			}
		}
		witnesses[page-1] = w
		next = end
	}
	if next != len(b.Layers) {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	// Independently inspect the constructed source and every imported Form before
	// rewriting; the same witness is checked again on the cleaned serialization.
	prewriteBudget := newManualCopyBudget(&manualResourceUsage{})
	for _, w := range witnesses {
		if err := verifyManualLayersPageV1(dest, w, prewriteBudget); err != nil {
			return PDFManualLayersResult{}, err
		}
	}
	var processing boundedPDFBuffer
	if pdfapi.WriteContext(dest, &processing) != nil {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	cleaned, err := cleanPDFWithResourcePreservation("manual-layered-pdf", "application/pdf", processing.Bytes(), true)
	if err != nil {
		return PDFManualLayersResult{}, err
	}
	final, _, geometry, err := observePDF(cleaned.Bytes)
	if err != nil || geometry != g.GeometrySHA256 || final.PageCount != b.Pages {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	verificationBudget := newManualCopyBudget(&manualResourceUsage{})
	for _, w := range witnesses {
		if err := verifyManualLayersPageV1(final, w, verificationBudget); err != nil {
			return PDFManualLayersResult{}, err
		}
	}
	witnessJSON, err := json.Marshal(witnesses)
	if err != nil {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	m := PDFManualLayersManifest{1, PDFManualLayersPolicy, g.SourceSHA256, g.SourceBytes, pdfSHA(metadata), g.GeometrySHA256, b.Pages, len(b.Layers), providerContentSHA(originals), pdfSHA(witnessJSON), pdfSHA(processing.Bytes()), int64(processing.Len()), pdfSHA(cleaned.Bytes), int64(len(cleaned.Bytes))}
	r := PDFManualLayersResult{cleaned, m}
	if ValidatePDFManualLayersResult(r) != nil {
		return PDFManualLayersResult{}, ErrPDFManualLayers
	}
	return r, nil
}

// Reuse the bounded original importer/Form builder; never wrap an already
// composed page again. There is one source Form and one independently imported
// Form for each ordered fragment, with the page's original Group kept in place.
func composeManualLayersPageV1(dest *model.Context, target PDFManualPage, original []byte, w manualLayerPageWitnessV1, ds []manualLayerDescriptorV1, fragments []*admittedManualFragmentV1, usage *manualResourceUsage) (manualLayerPageWitnessV1, error) {
	page, _, attrs, err := dest.PageDict(w.Page, false)
	if err != nil {
		return manualLayerPageWitnessV1{}, ErrPDFManualLayers
	}
	resources := types.NewDict()
	for k, v := range attrs.Resources {
		resources[k] = v
	}
	// Only the generated source/fragment Forms are callable at page level; all
	// original source resources remain inside its Form unchanged.
	xobjects := types.NewDict()
	w.BaseName = "HashManualLayersSourceV1"
	base, err := manualForm(dest, original, attrs.Resources, target.Boxes[0], nil)
	if err != nil {
		return manualLayerPageWitnessV1{}, err
	}
	xobjects[w.BaseName] = *base
	var calls bytes.Buffer
	fmt.Fprintf(&calls, "q /%s Do Q\n", w.BaseName)
	for i, f := range fragments {
		copyBudget := newManualCopyBudget(usage)
		copied, semantic, err := manualResourceObject(f.ctx, dest, f.resources, 0, copyBudget)
		if err != nil {
			return manualLayerPageWitnessV1{}, err
		}
		rh, err := manualSemanticHash(semantic)
		if err != nil || rh != f.admission.ResourcesSHA256 {
			return manualLayerPageWitnessV1{}, ErrPDFManualLayers
		}
		group, groupSemantic, err := manualResourceObject(f.ctx, dest, f.group, 0, copyBudget)
		if err != nil {
			return manualLayerPageWitnessV1{}, err
		}
		gh, err := manualSemanticHash(groupSemantic)
		if err != nil || gh != f.admission.GroupSHA256 {
			return manualLayerPageWitnessV1{}, ErrPDFManualLayers
		}
		matrix, err := manualPlacementMatrix(target, f.box[2], f.box[3])
		if err != nil {
			return manualLayerPageWitnessV1{}, err
		}
		form, err := manualForm(dest, f.content, copied, f.box, group)
		if err != nil {
			return manualLayerPageWitnessV1{}, err
		}
		name := fmt.Sprintf("HashManualLayersFragmentV1_%d", ds[i].Order)
		xobjects[name] = *form
		fmt.Fprintf(&calls, "q %.12f %.12f %.12f %.12f %.12f %.12f cm /%s Do Q\n", matrix[0], matrix[1], matrix[2], matrix[3], matrix[4], matrix[5], name)
		w.Layers = append(w.Layers, manualLayerFormWitnessV1{ds[i], name, f.admission.ContentSHA256, rh, gh, f.box, matrix})
	}
	resources["XObject"] = xobjects
	page["Resources"] = resources
	w.Calls = bytes.Clone(calls.Bytes())
	w.InvocationSHA256 = pdfSHA(w.Calls)
	sd, err := dest.NewStreamDictForBuf(w.Calls)
	if err != nil || sd.Encode() != nil {
		return manualLayerPageWitnessV1{}, ErrPDFManualLayers
	}
	ir, err := dest.IndRefForNewObject(*sd)
	if err != nil {
		return manualLayerPageWitnessV1{}, ErrPDFManualLayers
	}
	page["Contents"] = *ir
	// The page Group may name a ColorSpace in these top-level resources. Binding
	// only source/fragment Form resources would miss a changed blending space.
	w.PageResourcesSHA256, err = manualResourceHash(dest, resources)
	if err != nil {
		return manualLayerPageWitnessV1{}, err
	}
	return w, nil
}

func verifyManualLayersPageV1(ctx *model.Context, w manualLayerPageWitnessV1, budget *manualCopyBudget) error {
	page, _, attrs, err := ctx.PageDict(w.Page, false)
	if err != nil {
		return ErrPDFManualLayers
	}
	calls, err := manualPageContent(ctx, page, budget.usage)
	if err != nil || !bytes.Equal(calls, w.Calls) || pdfSHA(calls) != w.InvocationSHA256 {
		return ErrPDFManualLayers
	}
	if len(w.Layers) > 0 {
		if w.BaseName != "HashManualLayersSourceV1" {
			return ErrPDFManualLayers
		}
		var expected bytes.Buffer
		fmt.Fprintf(&expected, "q /%s Do Q\n", w.BaseName)
		for i, f := range w.Layers {
			if f.Descriptor.Page != w.Page || f.Descriptor.Order != i+1 || f.Name != fmt.Sprintf("HashManualLayersFragmentV1_%d", f.Descriptor.Order) {
				return ErrPDFManualLayers
			}
			m := f.Matrix
			fmt.Fprintf(&expected, "q %.12f %.12f %.12f %.12f %.12f %.12f cm /%s Do Q\n", m[0], m[1], m[2], m[3], m[4], m[5], f.Name)
		}
		if !bytes.Equal(expected.Bytes(), w.Calls) {
			return ErrPDFManualLayers
		}
	}
	gh, err := manualResourceHashWithBudget(ctx, page["Group"], budget)
	if err != nil || gh != w.GroupSHA256 {
		return ErrPDFManualLayers
	}
	pageRH, err := manualResourceHashWithBudget(ctx, attrs.Resources, budget)
	if err != nil || pageRH != w.PageResourcesSHA256 {
		return ErrPDFManualLayers
	}
	if len(w.Layers) == 0 {
		if pageRH != w.ResourcesSHA256 {
			return ErrPDFManualLayers
		}
		return nil
	}
	xobjects, err := ctx.DereferenceDict(attrs.Resources["XObject"])
	if err != nil || len(xobjects) != len(w.Layers)+1 {
		return ErrPDFManualLayers
	}
	if err := verifyManualLayerFormV1(ctx, xobjects[w.BaseName], w.ContentSHA256, w.ResourcesSHA256, "", w.BaseBox, true, budget); err != nil {
		return err
	}
	for _, f := range w.Layers {
		if err := verifyManualLayerFormV1(ctx, xobjects[f.Name], f.ContentSHA256, f.ResourcesSHA256, f.GroupSHA256, f.Box, false, budget); err != nil {
			return err
		}
	}
	return nil
}

func verifyManualLayerFormV1(ctx *model.Context, o types.Object, contentSHA, resourcesSHA, groupSHA string, box [4]float64, source bool, budget *manualCopyBudget) error {
	sd, _, err := ctx.DereferenceStreamDict(o)
	if err != nil || sd == nil || sd.Dict.NameEntry("Type") == nil || *sd.Dict.NameEntry("Type") != "XObject" || sd.Dict.NameEntry("Subtype") == nil || *sd.Dict.NameEntry("Subtype") != "Form" {
		return ErrPDFManualLayers
	}
	for k := range sd.Dict {
		switch k {
		case "Type", "Subtype", "BBox", "Matrix", "Resources", "Group", "Length", "Filter", "DecodeParms":
		default:
			return ErrPDFManualLayers
		}
	}
	content, err := manualContentStream(ctx, sd, min(16<<20, (32<<20)-budget.usage.content))
	if err != nil {
		return err
	}
	budget.usage.content += len(content)
	if !manualNumberArray(ctx, sd.Dict["BBox"], box[:]) || !manualNumberArray(ctx, sd.Dict["Matrix"], []float64{1, 0, 0, 1, 0, 0}) || pdfSHA(content) != contentSHA {
		return ErrPDFManualLayers
	}
	rh, err := manualResourceHashWithBudget(ctx, sd.Dict["Resources"], budget)
	if err != nil || rh != resourcesSHA {
		return ErrPDFManualLayers
	}
	if source {
		if _, ok := sd.Dict["Group"]; ok {
			return ErrPDFManualLayers
		}
	} else {
		gh, err := manualResourceHashWithBudget(ctx, sd.Dict["Group"], budget)
		if err != nil || gh != groupSHA {
			return ErrPDFManualLayers
		}
	}
	return nil
}

// probeManualOperationsV1 executes both new operations inside the same isolated
// executable. A version-3 worker without this exact capability cannot satisfy
// application startup/readiness, even though historical framing remains v3.
func probeManualOperationsV1(source []byte) error {
	g, err := manualGeometryInProcess(source)
	if err != nil || len(g.Pages) != 1 {
		return ErrPDFWorkerUnavailable
	}
	width, height, err := g.Pages[0].ViewportPoints()
	if err != nil {
		return ErrPDFWorkerUnavailable
	}
	d := manualFragmentRequestV1{1, pdfSHA(source), int64(len(source)), width, height}
	metadata, err := json.Marshal(d)
	if err != nil {
		return ErrPDFWorkerUnavailable
	}
	a, err := manualFragmentInProcess(append(bytes.Clone(metadata), source...), len(metadata))
	if err != nil || a.PDFSHA256 != pdfSHA(source) || a.WidthPoints != width || a.HeightPoints != height {
		return ErrPDFWorkerUnavailable
	}
	b := manualLayersBatchV1{1, g.SourceSHA256, g.SourceBytes, g.GeometrySHA256, 1, []manualLayerDescriptorV1{
		{1, 1, PDFManualLayerBaseV1, "probe-base", len(source), pdfSHA(source)},
		{1, 2, PDFManualLayerSignatureV1, "probe-party-a", len(source), pdfSHA(source)},
		{1, 3, PDFManualLayerSignatureV1, "probe-party-b", len(source), pdfSHA(source)},
	}}
	metadata, err = json.Marshal(b)
	if err != nil {
		return ErrPDFWorkerUnavailable
	}
	raw := append(bytes.Clone(metadata), source...)
	for range b.Layers {
		raw = append(raw, source...)
	}
	r, err := manualLayersInProcess(raw, len(metadata))
	if err != nil || ValidatePDFManualLayersResult(r) != nil || r.Layers.SourceSHA256 != g.SourceSHA256 || r.Layers.GeometrySHA256 != g.GeometrySHA256 || r.Layers.Layers != 3 || r.Layers.DescriptorSHA256 != pdfSHA(metadata) {
		return ErrPDFWorkerUnavailable
	}
	return nil
}

// Fragment catalogs are not imported into the destination. Optional-content
// default visibility therefore cannot be carried safely by a page/resource
// import. Reject it only on fragments; source-document catalog policy is kept.
func manualFragmentVisibilityV1(ctx *model.Context, pageContent []byte, usage *manualResourceUsage) error {
	if err := manualFragmentDrawingVisibilityV1(pageContent); err != nil {
		return err
	}
	drawingRefs := map[types.IndirectRef]struct{}{}
	directGlyphStreams := []types.Object{}
	if err := eachPDFObject(ctx, func(o types.Object, key string) error {
		if key == "OC" || key == "OCProperties" {
			return ErrPDFManualFragment
		}
		d := pdfObjectDict(o)
		if d == nil {
			return nil
		}
		typ, err := manualDrawingResolvedNameV1(ctx, d["Type"])
		if err != nil {
			return err
		}
		if typ == "OCG" || typ == "OCMD" {
			return ErrPDFManualFragment
		}
		subtype, err := manualDrawingResolvedNameV1(ctx, d["Subtype"])
		if err != nil {
			return err
		}
		if subtype != "Type3" {
			return nil
		}
		glyphs, err := ctx.DereferenceDict(d["CharProcs"])
		if err != nil || len(glyphs) > 65536 {
			return ErrPDFManualFragment
		}
		for _, proc := range glyphs {
			if ref, ok := proc.(types.IndirectRef); ok {
				drawingRefs[ref] = struct{}{}
			} else {
				directGlyphStreams = append(directGlyphStreams, proc)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	// eachPDFObject above already enforces table/work bounds. Xref identities
	// deduplicate drawing streams shared between Form, Pattern and CharProcs
	// facilities, without conflating equal bytes with a different filter policy.
	for number, entry := range ctx.Table {
		if entry == nil || entry.Free || entry.Object == nil {
			continue
		}
		d := pdfObjectDict(entry.Object)
		if d == nil {
			continue
		}
		subtype, err := manualDrawingResolvedNameV1(ctx, d["Subtype"])
		if err != nil {
			return err
		}
		patternType, err := manualDrawingResolvedObjectV1(ctx, d["PatternType"])
		if err != nil {
			return err
		}
		pattern, ok := patternType.(types.Integer)
		if subtype != "Form" && (!ok || pattern != 1) {
			continue
		}
		generation := 0
		if entry.Generation != nil {
			generation = *entry.Generation
		}
		drawingRefs[*types.NewIndirectRef(number, generation)] = struct{}{}
	}
	scan := func(o types.Object) error {
		sd, _, err := ctx.DereferenceStreamDict(o)
		if err != nil || sd == nil {
			return ErrPDFManualFragment
		}
		content, err := manualContentStream(ctx, sd, min(16<<20, (32<<20)-usage.content))
		if err != nil {
			return err
		}
		usage.content += len(content)
		return manualFragmentDrawingVisibilityV1(content)
	}
	for ref := range drawingRefs {
		if err := scan(ref); err != nil {
			return err
		}
	}
	for _, o := range directGlyphStreams {
		if err := scan(o); err != nil {
			return err
		}
	}
	return nil
}

func manualDrawingResolvedObjectV1(ctx *model.Context, o types.Object) (types.Object, error) {
	seen := map[types.IndirectRef]struct{}{}
	for depth := 0; depth <= 64; depth++ {
		ref, ok := o.(types.IndirectRef)
		if !ok {
			return o, nil
		}
		if _, cycle := seen[ref]; cycle {
			return nil, ErrPDFManualFragment
		}
		seen[ref] = struct{}{}
		var err error
		o, err = ctx.Dereference(ref)
		if err != nil {
			return nil, ErrPDFManualFragment
		}
	}
	return nil, ErrPDFManualFragment
}

func manualDrawingResolvedNameV1(ctx *model.Context, o types.Object) (string, error) {
	o, err := manualDrawingResolvedObjectV1(ctx, o)
	if err != nil {
		return "", err
	}
	if n, ok := o.(types.Name); ok {
		return string(n), nil
	}
	return "", nil
}

func manualDrawingWhitespaceV1(c byte) bool {
	return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32
}
func manualDrawingDelimiterV1(c byte) bool {
	return manualDrawingWhitespaceV1(c) || c == '(' || c == ')' || c == '<' || c == '>' || c == '[' || c == ']' || c == '{' || c == '}' || c == '/' || c == '%'
}
func manualDrawingHexV1(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// This bounded name scan is deliberately not a PDF interpreter. It skips
// strings/comments/hex literals and inline-image bytes so printable text or
// image data resembling /OC cannot be mistaken for a visibility instruction.
// Names decode PDF #xx escaping. Only optional-content policy names are refused.
func manualFragmentDrawingVisibilityV1(content []byte) error {
	inlineHeader := false
	for i := 0; i < len(content); {
		c := content[i]
		switch {
		case manualDrawingWhitespaceV1(c):
			i++
		case c == '%':
			for i < len(content) && content[i] != 10 && content[i] != 13 {
				i++
			}
		case c == '(':
			depth := 1
			i++
			for i < len(content) && depth > 0 {
				switch content[i] {
				case '\\':
					i += 2
					continue
				case '(':
					depth++
					if depth > 64 {
						return ErrPDFManualFragment
					}
				case ')':
					depth--
				}
				i++
			}
			if depth != 0 || i > len(content) {
				return ErrPDFManualFragment
			}
		case c == '<' && i+1 < len(content) && content[i+1] == '<':
			i += 2
		case c == '<':
			i++
			for i < len(content) && content[i] != '>' {
				i++
			}
			if i == len(content) {
				return ErrPDFManualFragment
			}
			i++
		case c == '/':
			i++
			name := make([]byte, 0, 16)
			for i < len(content) && !manualDrawingDelimiterV1(content[i]) {
				if len(name) > 1024 {
					return ErrPDFManualFragment
				}
				if content[i] == '#' {
					if i+2 >= len(content) {
						return ErrPDFManualFragment
					}
					a, ok := manualDrawingHexV1(content[i+1])
					b, ok2 := manualDrawingHexV1(content[i+2])
					if !ok || !ok2 {
						return ErrPDFManualFragment
					}
					name = append(name, a<<4|b)
					i += 3
				} else {
					name = append(name, content[i])
					i++
				}
			}
			switch string(name) {
			case "OC", "OCProperties", "OCG", "OCMD":
				return ErrPDFManualFragment
			}
		case manualDrawingDelimiterV1(c):
			i++
		default:
			start := i
			for i < len(content) && !manualDrawingDelimiterV1(content[i]) {
				i++
			}
			token := string(content[start:i])
			if token == "BI" {
				inlineHeader = true
			}
			if token == "ID" && inlineHeader {
				if i >= len(content) || !manualDrawingWhitespaceV1(content[i]) {
					return ErrPDFManualFragment
				}
				if content[i] == 13 && i+1 < len(content) && content[i+1] == 10 {
					i += 2
				} else {
					i++
				}
				found := false
				for j := i; j+1 < len(content); j++ {
					if content[j] == 'E' && content[j+1] == 'I' && j > 0 && manualDrawingWhitespaceV1(content[j-1]) && (j+2 == len(content) || manualDrawingDelimiterV1(content[j+2])) {
						i = j + 2
						found = true
						break
					}
				}
				if !found {
					return ErrPDFManualFragment
				}
				inlineHeader = false
			}
		}
	}
	if inlineHeader {
		return ErrPDFManualFragment
	}
	return nil
}
