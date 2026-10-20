// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"

	"github.com/bright-interaction/hash/internal/malwarescan"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const pdfManualInspectOperation = "manual-inspect-v1"
const pdfManualOverlayOperation = "manual-overlay-v1"
const PDFManualOverlayPolicy = "hash-pdf-manual-visible-viewport-v1"
const manualMetadataLimit = 1 << 20
const maxManualViewportPoints = 14400 // Chromium's 200-inch paper limit.

var ErrPDFManualOverlay = errors.New("sanitize: invalid manual PDF placement")

// PDFManualPage retains exact effective boxes, not rounded presentation units.
// Box order is Media, Crop, Trim, Bleed, Art. Rotation is retained verbatim.
type PDFManualPage struct {
	Boxes    [5][4]float64 `json:"boxes"`
	Rotation int           `json:"rotation"`
	UserUnit float64       `json:"user_unit"`
}

type PDFManualGeometry struct {
	SchemaVersion  int             `json:"schema_version"`
	SourceSHA256   string          `json:"source_sha256"`
	SourceBytes    int64           `json:"source_bytes"`
	GeometrySHA256 string          `json:"geometry_sha256"`
	Pages          []PDFManualPage `json:"pages"`
}

// ViewportPoints follows PDF.js's visible CropBox intersection and rotation.
func (p PDFManualPage) ViewportPoints() (float64, float64, error) {
	r, err := manualVisibleBox(p)
	if err != nil {
		return 0, 0, err
	}
	w, h := (r[2]-r[0])*p.UserUnit, (r[3]-r[1])*p.UserUnit
	if manualRotation(p.Rotation)%180 != 0 {
		w, h = h, w
	}
	if !manualFinite(w) || !manualFinite(h) || w <= 0 || h <= 0 || w > maxManualViewportPoints || h > maxManualViewportPoints {
		return 0, 0, ErrPDFManualOverlay
	}
	return w, h, nil
}

func manualFinite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }
func manualRotation(r int) int    { return (r%360 + 360) % 360 }

func manualVisibleBox(p PDFManualPage) ([4]float64, error) {
	if p.Rotation%90 != 0 || !manualFinite(p.UserUnit) || p.UserUnit <= 0 || p.UserUnit > 75000 {
		return [4]float64{}, ErrPDFManualOverlay
	}
	for _, box := range p.Boxes {
		for _, v := range box {
			if !manualFinite(v) || math.Abs(v) > 1e9 {
				return [4]float64{}, ErrPDFManualOverlay
			}
		}
		if box[2] <= box[0] || box[3] <= box[1] {
			return [4]float64{}, ErrPDFManualOverlay
		}
	}
	m, c := p.Boxes[0], p.Boxes[1]
	r := [4]float64{math.Max(m[0], c[0]), math.Max(m[1], c[1]), math.Min(m[2], c[2]), math.Min(m[3], c[3])}
	// PDF.js falls back to MediaBox for a disjoint CropBox.
	if r[2] <= r[0] || r[3] <= r[1] {
		r = m
	}
	return r, nil
}

func manualGeometryInProcess(raw []byte) (PDFManualGeometry, error) {
	ctx, hash, err := observePDFCompositionInput(raw)
	if err != nil {
		return PDFManualGeometry{}, err
	}
	props, err := observedPDFProperties(ctx)
	// Annotation appearances and interactive form widgets require an explicit
	// flattening policy. Never silently strip potentially visible source ink.
	if err != nil || props.Annotations || props.AcroForm || props.EmbeddedFiles {
		return PDFManualGeometry{}, ErrPDFManualOverlay
	}
	pages, err := pdfCompositionGeometry(ctx)
	if err != nil {
		return PDFManualGeometry{}, err
	}
	g := PDFManualGeometry{1, pdfSHA(raw), int64(len(raw)), hash, make([]PDFManualPage, len(pages))}
	for i, p := range pages {
		g.Pages[i] = PDFManualPage(p)
	}
	if validateManualGeometry(g, raw) != nil {
		return PDFManualGeometry{}, ErrPDFManualOverlay
	}
	return g, nil
}

func validateManualGeometry(g PDFManualGeometry, source []byte) error {
	if g.SchemaVersion != 1 || g.SourceBytes < 1 || g.SourceBytes > MaxPDFBytes || !validPDFSHA(g.SourceSHA256) || !validPDFSHA(g.GeometrySHA256) || len(g.Pages) < 1 || len(g.Pages) > MaxPDFPages {
		return ErrPDFManualOverlay
	}
	if source != nil && (g.SourceSHA256 != pdfSHA(source) || g.SourceBytes != int64(len(source))) {
		return ErrPDFManualOverlay
	}
	pages := make([]pdfCompositionRawPage, len(g.Pages))
	for i, p := range g.Pages {
		if _, _, err := p.ViewportPoints(); err != nil {
			return err
		}
		pages[i] = pdfCompositionRawPage(p)
	}
	if pdfCompositionGeometrySHA(pages) != g.GeometrySHA256 {
		return ErrPDFManualOverlay
	}
	return nil
}

// InspectManualPDFWithContext never parses customer bytes in the caller,
// including development. A stale worker cannot satisfy the new protocol.
func InspectManualPDFWithContext(ctx context.Context, source []byte) (PDFManualGeometry, error) {
	if len(source) < 1 {
		return PDFManualGeometry{}, ErrPDFManualOverlay
	}
	if len(source) > MaxPDFBytes {
		return PDFManualGeometry{}, ErrPDFTooLarge
	}
	if err := malwarescan.ScanActive(ctx, source); err != nil {
		return PDFManualGeometry{}, err
	}
	w := activePDFWorker.Load()
	if w == nil {
		return PDFManualGeometry{}, ErrPDFWorkerUnavailable
	}
	_, raw, err := w.run(ctx, pdfWorkerRequest{Operation: pdfManualInspectOperation, Length: len(source)}, source)
	if err != nil {
		return PDFManualGeometry{}, err
	}
	var g PDFManualGeometry
	if decodeManualJSON(raw, &g) != nil || validateManualGeometry(g, source) != nil {
		return PDFManualGeometry{}, ErrPDFWorkerUnavailable
	}
	return g, nil
}

type manualOverlayDescriptor struct {
	Page   int    `json:"page"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type manualOverlayBatch struct {
	SchemaVersion  int                       `json:"schema_version"`
	SourceSHA256   string                    `json:"source_sha256"`
	SourceBytes    int64                     `json:"source_bytes"`
	GeometrySHA256 string                    `json:"geometry_sha256"`
	Pages          int                       `json:"pages"`
	Overlays       []manualOverlayDescriptor `json:"overlays"`
}

type PDFManualOverlayManifest struct {
	SchemaVersion         int    `json:"schema_version"`
	Policy                string `json:"policy"`
	SourceSHA256          string `json:"source_sha256"`
	SourceBytes           int64  `json:"source_bytes"`
	DescriptorSHA256      string `json:"descriptor_sha256"`
	GeometrySHA256        string `json:"geometry_sha256"`
	Pages                 int    `json:"pages"`
	Overlays              int    `json:"overlays"`
	OriginalContentSHA256 string `json:"original_content_sha256"`
	ProcessingSHA256      string `json:"processing_sha256"`
	ProcessingBytes       int64  `json:"processing_bytes"`
	OutputSHA256          string `json:"output_sha256"`
	OutputBytes           int64  `json:"output_bytes"`
}

type PDFManualOverlayResult struct {
	Result
	Overlay PDFManualOverlayManifest
}

func validateManualManifest(m PDFManualOverlayManifest) error {
	if m.SchemaVersion != 1 || m.Policy != PDFManualOverlayPolicy || m.Pages < 1 || m.Pages > MaxPDFPages || m.Overlays < 1 || m.Overlays > m.Pages {
		return ErrPDFManualOverlay
	}
	for _, s := range []string{m.SourceSHA256, m.DescriptorSHA256, m.GeometrySHA256, m.OriginalContentSHA256, m.ProcessingSHA256, m.OutputSHA256} {
		if !validPDFSHA(s) {
			return ErrPDFManualOverlay
		}
	}
	for _, n := range []int64{m.SourceBytes, m.ProcessingBytes, m.OutputBytes} {
		if n < 1 || n > MaxPDFBytes {
			return ErrPDFManualOverlay
		}
	}
	if m.SourceSHA256 == m.OutputSHA256 {
		return ErrPDFManualOverlay
	}
	return nil
}

func validateManualResult(r PDFManualOverlayResult) error {
	m := r.Overlay
	if validateManualManifest(m) != nil || m.OutputSHA256 != pdfSHA(r.Bytes) || m.OutputBytes != int64(len(r.Bytes)) || ValidatePDFResult(r.Report, m.ProcessingSHA256, m.OutputSHA256, m.ProcessingBytes, m.OutputBytes) != nil || r.Report.PDF.PagesAfter != m.Pages || r.Report.PDF.GeometrySHA256After != m.GeometrySHA256 {
		return ErrPDFManualOverlay
	}
	return nil
}

// ApplyManualPDFOverlaysWithContext binds the inspected source and each
// single-page renderer response before admitting composition in the child.
func ApplyManualPDFOverlaysWithContext(ctx context.Context, source []byte, g PDFManualGeometry, overlays map[int][]byte) (PDFManualOverlayResult, error) {
	if validateManualGeometry(g, source) != nil || len(overlays) < 1 || len(overlays) > len(g.Pages) {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	pages := make([]int, 0, len(overlays))
	total := len(source)
	for p, b := range overlays {
		if p < 1 || p > len(g.Pages) || len(b) < 1 || len(b) > MaxPDFBytes-total {
			return PDFManualOverlayResult{}, ErrPDFManualOverlay
		}
		total += len(b)
		pages = append(pages, p)
	}
	sort.Ints(pages)
	batch := manualOverlayBatch{1, g.SourceSHA256, g.SourceBytes, g.GeometrySHA256, len(g.Pages), make([]manualOverlayDescriptor, len(pages))}
	for i, p := range pages {
		batch.Overlays[i] = manualOverlayDescriptor{p, len(overlays[p]), pdfSHA(overlays[p])}
	}
	metadata, err := json.Marshal(batch)
	if err != nil || len(metadata) > manualMetadataLimit || total > MaxPDFBytes-len(metadata) {
		return PDFManualOverlayResult{}, ErrPDFTooLarge
	}
	for _, b := range append([][]byte{source}, manualOverlayBytes(pages, overlays)...) {
		if err := malwarescan.ScanActive(ctx, b); err != nil {
			return PDFManualOverlayResult{}, err
		}
	}
	w := activePDFWorker.Load()
	if w == nil {
		return PDFManualOverlayResult{}, ErrPDFWorkerUnavailable
	}
	raw := make([]byte, 0, total+len(metadata))
	raw = append(raw, metadata...)
	raw = append(raw, source...)
	for _, p := range pages {
		raw = append(raw, overlays[p]...)
	}
	response, out, err := w.run(ctx, pdfWorkerRequest{Operation: pdfManualOverlayOperation, Length: len(raw), ManualMetadataLength: len(metadata)}, raw)
	if err != nil {
		return PDFManualOverlayResult{}, err
	}
	if response.ManualOverlay == nil || response.Report == nil {
		return PDFManualOverlayResult{}, ErrPDFWorkerUnavailable
	}
	r := PDFManualOverlayResult{Result{out, *response.Report}, *response.ManualOverlay}
	if validateManualResult(r) != nil || r.Overlay.SourceSHA256 != g.SourceSHA256 || r.Overlay.SourceBytes != g.SourceBytes || r.Overlay.GeometrySHA256 != g.GeometrySHA256 || r.Overlay.Pages != len(g.Pages) || r.Overlay.DescriptorSHA256 != pdfSHA(metadata) || r.Overlay.Overlays != len(pages) {
		return PDFManualOverlayResult{}, ErrPDFWorkerUnavailable
	}
	return r, nil
}

func manualOverlayBytes(pages []int, m map[int][]byte) [][]byte {
	out := make([][]byte, len(pages))
	for i, p := range pages {
		out[i] = m[p]
	}
	return out
}

func decodeManualJSON(raw []byte, out any) error {
	if len(raw) < 1 || len(raw) > manualMetadataLimit || strictPDFWorkerJSON(raw) != nil {
		return ErrPDFManualOverlay
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF || !manualExactJSON(raw, reflect.TypeOf(out).Elem()) {
		return ErrPDFManualOverlay
	}
	return nil
}

func manualExactJSON(raw []byte, t reflect.Type) bool {
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
			if !ok || !manualExactJSON(v, f.Type) {
				return false
			}
		}
	case reflect.Array, reflect.Slice:
		var a []json.RawMessage
		if json.Unmarshal(raw, &a) != nil || len(a) > MaxPDFPages || (t.Kind() == reflect.Array && len(a) != t.Len()) {
			return false
		}
		for _, v := range a {
			if !manualExactJSON(v, t.Elem()) {
				return false
			}
		}
	}
	return true
}

// manualPlacementMatrix maps the upright observed overlay into the source
// viewport without changing a source box, rotation or UserUnit.
func manualPlacementMatrix(p PDFManualPage, ow, oh float64) ([6]float64, error) {
	w, h, err := p.ViewportPoints()
	if err != nil || !manualFinite(ow) || !manualFinite(oh) || ow <= 0 || oh <= 0 {
		return [6]float64{}, ErrPDFManualOverlay
	}
	// Chromium quantizes paper sizes. Only bounded sub-point rounding is
	// corrected; a wrong renderer page size is not silently stretched to fit.
	if math.Abs(w-ow) > 0.75 || math.Abs(h-oh) > 0.75 {
		return [6]float64{}, ErrPDFManualOverlay
	}
	r, _ := manualVisibleBox(p)
	sx, sy := w/ow/p.UserUnit, h/oh/p.UserUnit
	switch manualRotation(p.Rotation) {
	case 0:
		return [6]float64{sx, 0, 0, sy, r[0], r[1]}, nil
	case 90:
		return [6]float64{0, sx, -sy, 0, r[2], r[1]}, nil
	case 180:
		return [6]float64{-sx, 0, 0, -sy, r[2], r[3]}, nil
	default:
		return [6]float64{0, -sx, sy, 0, r[0], r[3]}, nil
	}
}

type manualFormWitness struct {
	page                                                 int
	baseName, overlayName                                string
	content, resources, overlayContent, overlayResources string
	baseBox, overlayBox                                  [4]float64
	pageGroup, overlayGroup                              string
	calls                                                []byte
}

// Manual content admission supports unfiltered or one no-predictor Flate
// stream, including arrays. DecodeLength in pdfcpu cannot provide a reliable
// pre-allocation limit for arbitrary filter pipelines. Other content encodings
// refuse explicitly; resource images/fonts retain their original encodings.
func manualContentStream(ctx *model.Context, sd *types.StreamDict, remaining int) ([]byte, error) {
	if sd == nil || remaining < 0 {
		return nil, ErrPDFManualOverlay
	}
	for _, k := range []string{"F", "FFilter", "FDecodeParms"} {
		if _, ok := sd.Dict[k]; ok {
			return nil, ErrPDFManualOverlay
		}
	}
	if len(sd.Raw) > MaxPDFBytes {
		return nil, ErrPDFManualOverlay
	}
	if len(sd.FilterPipeline) == 0 {
		if _, ok := sd.Dict["Filter"]; ok || len(sd.Raw) > remaining {
			return nil, ErrPDFManualOverlay
		}
		return bytes.Clone(sd.Raw), nil
	}
	if len(sd.FilterPipeline) != 1 || sd.FilterPipeline[0].Name != "FlateDecode" || sd.FilterPipeline[0].DecodeParms != nil {
		return nil, ErrPDFManualOverlay
	}
	encoded := bytes.NewReader(sd.Raw)
	reader, err := zlib.NewReader(encoded)
	if err != nil {
		return nil, ErrPDFManualOverlay
	}
	content, err := io.ReadAll(io.LimitReader(reader, int64(remaining)+1))
	closeErr := reader.Close()
	if err != nil || closeErr != nil || len(content) > remaining || encoded.Len() != 0 {
		return nil, ErrPDFManualOverlay
	}
	return content, nil
}

func manualPageContent(ctx *model.Context, page types.Dict, usage *manualResourceUsage) ([]byte, error) {
	o, err := ctx.Dereference(page["Contents"])
	if err != nil {
		return nil, ErrPDFManualOverlay
	}
	if o == nil {
		return nil, nil
	}
	streams := types.Array{o}
	if a, ok := o.(types.Array); ok {
		streams = a
	}
	if len(streams) > 65536-usage.nodes {
		return nil, ErrPDFManualOverlay
	}
	var content []byte
	for _, o := range streams {
		usage.nodes++
		if o == nil {
			continue
		}
		sd, _, err := ctx.DereferenceStreamDict(o)
		if err != nil || sd == nil {
			return nil, ErrPDFManualOverlay
		}
		remaining := min((16<<20)-len(content), (32<<20)-usage.content)
		b, err := manualContentStream(ctx, sd, remaining)
		if err != nil {
			return nil, err
		}
		usage.content += len(b)
		content = append(content, b...)
	}
	return content, nil
}

func manualPageContents(ctx *model.Context, usage *manualResourceUsage) ([][]byte, error) {
	out := make([][]byte, ctx.PageCount)
	for i := range out {
		page, _, _, err := ctx.PageDict(i+1, false)
		if err != nil {
			return nil, ErrPDFManualOverlay
		}
		out[i], err = manualPageContent(ctx, page, usage)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func manualOverlayGroup(ctx *model.Context, o types.Object) (types.Object, error) {
	if o == nil {
		return nil, nil
	}
	d, err := ctx.DereferenceDict(o)
	if err != nil || d == nil {
		return nil, ErrPDFManualOverlay
	}
	for k := range d {
		switch k {
		case "Type", "S", "CS", "I", "K":
		default:
			return nil, ErrPDFManualOverlay
		}
	}
	if s := d.NameEntry("S"); s == nil || *s != "Transparency" {
		return nil, ErrPDFManualOverlay
	}
	if v, ok := d["Type"]; ok {
		n, ok := v.(types.Name)
		if !ok || n != "Group" {
			return nil, ErrPDFManualOverlay
		}
	}
	if v, ok := d["CS"]; ok {
		n, ok := v.(types.Name)
		if !ok || (n != "DeviceRGB" && n != "DeviceGray") {
			return nil, ErrPDFManualOverlay
		}
	} else {
		return nil, ErrPDFManualOverlay
	}
	if v, ok := d["K"]; ok {
		n, ok := v.(types.Boolean)
		if !ok || bool(n) {
			return nil, ErrPDFManualOverlay
		}
	}
	if v, ok := d["I"]; ok {
		if _, ok := v.(types.Boolean); !ok {
			return nil, ErrPDFManualOverlay
		}
	}
	// A page transparency group is implicitly isolated. A Form group defaults
	// to non-isolated, so this conversion must make the page semantics explicit.
	out := types.NewDict()
	for k, v := range d {
		out[k] = v
	}
	out["I"] = types.Boolean(true)
	return out, nil
}

func manualOverlayInProcess(raw []byte, n int) (PDFManualOverlayResult, error) {
	if n < 1 || n > manualMetadataLimit || n >= len(raw) {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	metadata := raw[:n]
	var batch manualOverlayBatch
	if decodeManualJSON(metadata, &batch) != nil || batch.SchemaVersion != 1 || batch.SourceBytes < 1 || batch.SourceBytes > int64(len(raw)-n) || batch.Pages < 1 || batch.Pages > MaxPDFPages || len(batch.Overlays) < 1 || len(batch.Overlays) > batch.Pages || !validPDFSHA(batch.SourceSHA256) || !validPDFSHA(batch.GeometrySHA256) {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	base := raw[n : n+int(batch.SourceBytes)]
	rest := raw[n+int(batch.SourceBytes):]
	if pdfSHA(base) != batch.SourceSHA256 {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	g, err := manualGeometryInProcess(base)
	if err != nil || g.GeometrySHA256 != batch.GeometrySHA256 || len(g.Pages) != batch.Pages {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	// Validate all descriptors and inputs before changing the processing copy.
	fragments := make([][]byte, len(batch.Overlays))
	previous := 0
	for i, d := range batch.Overlays {
		if d.Page <= previous || d.Page > batch.Pages || d.Bytes < 1 || d.Bytes > len(rest) || !validPDFSHA(d.SHA256) {
			return PDFManualOverlayResult{}, ErrPDFManualOverlay
		}
		fragments[i], rest = rest[:d.Bytes], rest[d.Bytes:]
		previous = d.Page
		if pdfSHA(fragments[i]) != d.SHA256 {
			return PDFManualOverlayResult{}, ErrPDFManualOverlay
		}
	}
	if len(rest) != 0 {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	ctx, _, err := observePDFCompositionInput(base)
	if err != nil {
		return PDFManualOverlayResult{}, err
	}
	usage := &manualResourceUsage{}
	originals, err := manualPageContents(ctx, usage)
	if err != nil {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	baseBudget := newManualCopyBudget(usage)
	originalResources, originalGroups := make([]string, batch.Pages), make([]string, batch.Pages)
	for i := 0; i < batch.Pages; i++ {
		page, _, attrs, err := ctx.PageDict(i+1, false)
		if err != nil {
			return PDFManualOverlayResult{}, ErrPDFManualOverlay
		}
		originalResources[i], err = manualResourceHashWithBudget(ctx, attrs.Resources, baseBudget)
		if err != nil {
			return PDFManualOverlayResult{}, err
		}
		originalGroups[i], err = manualResourceHashWithBudget(ctx, page["Group"], baseBudget)
		if err != nil {
			return PDFManualOverlayResult{}, err
		}
	}
	witnesses := make([]manualFormWitness, len(fragments))
	for i, fragment := range fragments {
		p := batch.Overlays[i].Page
		witnesses[i], err = composeManualPage(ctx, p, g.Pages[p-1], originals[p-1], fragment, baseBudget, usage)
		if err != nil {
			return PDFManualOverlayResult{}, err
		}
	}
	var processing boundedPDFBuffer
	if pdfapi.WriteContext(ctx, &processing) != nil {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	cleaned, err := cleanPDF("manual-stamped-pdf", "application/pdf", processing.Bytes())
	if err != nil {
		return PDFManualOverlayResult{}, err
	}
	final, _, geometry, err := observePDF(cleaned.Bytes)
	if err != nil || geometry != g.GeometrySHA256 || final.PageCount != batch.Pages {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	verificationUsage := &manualResourceUsage{}
	contents, err := manualPageContents(final, verificationUsage)
	if err != nil {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	byPage := map[int]manualFormWitness{}
	for _, w := range witnesses {
		byPage[w.page] = w
	}
	verificationBudget := newManualCopyBudget(verificationUsage)
	for i, b := range originals {
		if w, ok := byPage[i+1]; ok {
			if !bytes.Equal(contents[i], w.calls) || verifyManualPage(final, w, verificationBudget) != nil {
				return PDFManualOverlayResult{}, ErrPDFManualOverlay
			}
		} else {
			if !bytes.Equal(contents[i], b) {
				return PDFManualOverlayResult{}, ErrPDFManualOverlay
			}
			page, _, attrs, err := final.PageDict(i+1, false)
			if err != nil {
				return PDFManualOverlayResult{}, ErrPDFManualOverlay
			}
			rh, err := manualResourceHashWithBudget(final, attrs.Resources, verificationBudget)
			if err != nil || rh != originalResources[i] {
				return PDFManualOverlayResult{}, ErrPDFManualOverlay
			}
			gh, err := manualResourceHashWithBudget(final, page["Group"], verificationBudget)
			if err != nil || gh != originalGroups[i] {
				return PDFManualOverlayResult{}, ErrPDFManualOverlay
			}
		}
	}
	m := PDFManualOverlayManifest{1, PDFManualOverlayPolicy, g.SourceSHA256, g.SourceBytes, pdfSHA(metadata), g.GeometrySHA256, batch.Pages, len(fragments), providerContentSHA(originals), pdfSHA(processing.Bytes()), int64(processing.Len()), pdfSHA(cleaned.Bytes), int64(len(cleaned.Bytes))}
	r := PDFManualOverlayResult{cleaned, m}
	if validateManualResult(r) != nil {
		return PDFManualOverlayResult{}, ErrPDFManualOverlay
	}
	return r, nil
}

func composeManualPage(dest *model.Context, pageNr int, target PDFManualPage, original, fragment []byte, baseBudget *manualCopyBudget, usage *manualResourceUsage) (manualFormWitness, error) {
	var witness manualFormWitness
	ctx, _, err := observePDFCompositionInput(fragment)
	if err != nil || ctx.PageCount != 1 {
		return witness, ErrPDFManualOverlay
	}
	props, err := observedPDFProperties(ctx)
	if err != nil || props.Annotations || props.AcroForm || props.EmbeddedFiles {
		return witness, ErrPDFManualOverlay
	}
	pages, err := pdfCompositionGeometry(ctx)
	if err != nil {
		return witness, ErrPDFManualOverlay
	}
	f := pages[0]
	ow, oh := f.Boxes[0][2], f.Boxes[0][3]
	if f.Rotation != 0 || f.UserUnit != 1 {
		return witness, ErrPDFManualOverlay
	}
	for _, b := range f.Boxes {
		if b != [4]float64{0, 0, ow, oh} {
			return witness, ErrPDFManualOverlay
		}
	}
	matrix, err := manualPlacementMatrix(target, ow, oh)
	if err != nil {
		return witness, err
	}
	page, _, attrs, err := dest.PageDict(pageNr, false)
	if err != nil {
		return witness, ErrPDFManualOverlay
	}
	fpage, _, fattrs, err := ctx.PageDict(1, false)
	if err != nil || fattrs.Resources == nil {
		return witness, ErrPDFManualOverlay
	}
	content, err := manualPageContent(ctx, fpage, usage)
	if err != nil {
		return witness, ErrPDFManualOverlay
	}
	// The imported Form does not carry the fragment catalog. Refuse visibility
	// policy whose meaning could change when that catalog is discarded.
	if err := manualFragmentVisibilityV1(ctx, content, usage); err != nil {
		return witness, ErrPDFManualOverlay
	}
	resources := types.NewDict()
	for k, v := range attrs.Resources {
		resources[k] = v
	}
	xobjects := types.NewDict()
	if o, ok := resources["XObject"]; ok {
		d, err := dest.DereferenceDict(o)
		if err != nil {
			return witness, ErrPDFManualOverlay
		}
		for k, v := range d {
			xobjects[k] = v
		}
	}
	name := func(prefix string) string {
		for i := 0; i <= 4096; i++ {
			n := fmt.Sprintf("%s%d", prefix, i)
			if _, ok := xobjects[n]; !ok {
				return n
			}
		}
		return ""
	}
	baseName, overlayName := name("HashManualBaseV1_"), name("HashManualOverlayV1_")
	if baseName == "" || overlayName == "" {
		return witness, ErrPDFManualOverlay
	}
	baseHash, err := manualResourceHashWithBudget(dest, attrs.Resources, baseBudget)
	if err != nil {
		return witness, err
	}
	pageGroup, err := manualResourceHashWithBudget(dest, page["Group"], baseBudget)
	if err != nil {
		return witness, err
	}
	// The source page retains its Group. A second Group on the original Form
	// would introduce another transparency compositing boundary.
	base, err := manualForm(dest, original, attrs.Resources, target.Boxes[0], nil)
	if err != nil {
		return witness, err
	}
	copyBudget := newManualCopyBudget(usage)
	copied, semantic, err := manualResourceObject(ctx, dest, fattrs.Resources, 0, copyBudget)
	if err != nil {
		return witness, err
	}
	overlayHash, err := manualSemanticHash(semantic)
	if err != nil {
		return witness, err
	}
	pageGroupObject, err := manualOverlayGroup(ctx, fpage["Group"])
	if err != nil {
		return witness, err
	}
	group, groupSemantic, err := manualResourceObject(ctx, dest, pageGroupObject, 0, copyBudget)
	if err != nil {
		return witness, err
	}
	overlayGroup, err := manualSemanticHash(groupSemantic)
	if err != nil {
		return witness, err
	}
	overlayBox := [4]float64{0, 0, ow, oh}
	overlay, err := manualForm(dest, content, copied, overlayBox, group)
	if err != nil {
		return witness, err
	}
	xobjects[baseName], xobjects[overlayName] = *base, *overlay
	resources["XObject"] = xobjects
	page["Resources"] = resources
	calls := []byte(fmt.Sprintf("q /%s Do Q\nq %.12f %.12f %.12f %.12f %.12f %.12f cm /%s Do Q\n", baseName, matrix[0], matrix[1], matrix[2], matrix[3], matrix[4], matrix[5], overlayName))
	stream, err := dest.NewStreamDictForBuf(calls)
	if err != nil || stream.Encode() != nil {
		return witness, ErrPDFManualOverlay
	}
	ir, err := dest.IndRefForNewObject(*stream)
	if err != nil {
		return witness, ErrPDFManualOverlay
	}
	page["Contents"] = *ir
	return manualFormWitness{page: pageNr, baseName: baseName, overlayName: overlayName, content: pdfSHA(original), resources: baseHash, overlayContent: pdfSHA(content), overlayResources: overlayHash, baseBox: target.Boxes[0], overlayBox: overlayBox, pageGroup: pageGroup, overlayGroup: overlayGroup, calls: calls}, nil
}

func manualForm(ctx *model.Context, content []byte, resources types.Object, box [4]float64, group types.Object) (*types.IndirectRef, error) {
	if len(content) > 16<<20 {
		return nil, ErrPDFManualOverlay
	}
	sd, err := ctx.NewStreamDictForBuf(bytes.Clone(content))
	if err != nil {
		return nil, ErrPDFManualOverlay
	}
	sd.Dict["Type"], sd.Dict["Subtype"] = types.Name("XObject"), types.Name("Form")
	sd.Dict["BBox"] = types.NewNumberArray(box[0], box[1], box[2], box[3])
	sd.Dict["Matrix"] = types.NewNumberArray(1, 0, 0, 1, 0, 0)
	sd.Dict["Resources"] = resources
	if group != nil {
		sd.Dict["Group"] = group
	}
	if sd.Encode() != nil {
		return nil, ErrPDFManualOverlay
	}
	ir, err := ctx.IndRefForNewObject(*sd)
	if err != nil {
		return nil, ErrPDFManualOverlay
	}
	return ir, nil
}

func manualNumberArray(ctx *model.Context, o types.Object, expected []float64) bool {
	a, err := ctx.DereferenceArray(o)
	if err != nil || len(a) != len(expected) {
		return false
	}
	for i, o := range a {
		v, err := ctx.Dereference(o)
		if err != nil {
			return false
		}
		var n float64
		switch v := v.(type) {
		case types.Integer:
			n = float64(v)
		case types.Float:
			n = float64(v)
		default:
			return false
		}
		if !manualFinite(n) || n != expected[i] {
			return false
		}
	}
	return true
}

func verifyManualPage(ctx *model.Context, w manualFormWitness, budget *manualCopyBudget) error {
	page, _, attrs, err := ctx.PageDict(w.page, false)
	if err != nil || attrs.Resources == nil {
		return ErrPDFManualOverlay
	}
	group, err := manualResourceHashWithBudget(ctx, page["Group"], budget)
	if err != nil || group != w.pageGroup {
		return ErrPDFManualOverlay
	}
	x, err := ctx.DereferenceDict(attrs.Resources["XObject"])
	if err != nil {
		return ErrPDFManualOverlay
	}
	for i, n := range []string{w.baseName, w.overlayName} {
		sd, _, err := ctx.DereferenceStreamDict(x[n])
		if err != nil || sd == nil || sd.Dict.NameEntry("Type") == nil || *sd.Dict.NameEntry("Type") != "XObject" || sd.Dict.NameEntry("Subtype") == nil || *sd.Dict.NameEntry("Subtype") != "Form" {
			return ErrPDFManualOverlay
		}
		// Generated Forms have no optional clipping, visibility or external-reference
		// attributes. Reject post-clean surprises instead of ignoring them.
		for k := range sd.Dict {
			switch k {
			case "Type", "Subtype", "BBox", "Matrix", "Resources", "Group", "Length", "Filter", "DecodeParms":
			default:
				return ErrPDFManualOverlay
			}
		}
		hash, rh, box, gh := w.content, w.resources, w.baseBox, ""
		if i == 1 {
			hash, rh, box, gh = w.overlayContent, w.overlayResources, w.overlayBox, w.overlayGroup
		}
		content, err := manualContentStream(ctx, sd, min(16<<20, (32<<20)-budget.usage.content))
		if err != nil {
			return err
		}
		budget.usage.content += len(content)
		if !manualNumberArray(ctx, sd.Dict["BBox"], box[:]) || !manualNumberArray(ctx, sd.Dict["Matrix"], []float64{1, 0, 0, 1, 0, 0}) || pdfSHA(content) != hash {
			return ErrPDFManualOverlay
		}
		actual, err := manualResourceHashWithBudget(ctx, sd.Dict["Resources"], budget)
		if err != nil || actual != rh {
			return ErrPDFManualOverlay
		}
		if i == 0 {
			if _, ok := sd.Dict["Group"]; ok {
				return ErrPDFManualOverlay
			}
		} else {
			actual, err = manualResourceHashWithBudget(ctx, sd.Dict["Group"], budget)
			if err != nil || actual != gh {
				return ErrPDFManualOverlay
			}
		}
	}
	return nil
}

type manualCopiedResource struct {
	object   types.Object
	semantic any
	active   bool
}
type manualResourceUsage struct{ nodes, raw, content, scalar int }

type manualCopyBudget struct {
	usage *manualResourceUsage
	refs  map[types.IndirectRef]*manualCopiedResource
}

func newManualCopyBudget(usage *manualResourceUsage) *manualCopyBudget {
	return &manualCopyBudget{usage: usage, refs: map[types.IndirectRef]*manualCopiedResource{}}
}

// Copy only page resources, never catalogs/page trees. Streams retain exact
// encoded bytes AND their filter dictionaries: pdfcpu Decode deliberately
// leaves some JPEG/JPX data encoded, so decoding and re-Flating corrupts ink.
// No resource stream is expanded by this importer. All overlays share bounded
// aggregate work/raw/content budgets; ref namespaces remain per input context.
func manualResourceObject(src, dst *model.Context, o types.Object, depth int, b *manualCopyBudget) (types.Object, any, error) {
	b.usage.nodes++
	if depth > 64 || b.usage.nodes > 65536 {
		return nil, nil, ErrPDFManualOverlay
	}
	if ref, ok := o.(types.IndirectRef); ok {
		if entry, ok := b.refs[ref]; ok {
			if entry.active {
				return nil, nil, ErrPDFManualOverlay
			}
			return entry.object, entry.semantic, nil
		}
		entry := &manualCopiedResource{active: true}
		b.refs[ref] = entry
		v, err := src.Dereference(ref)
		if err != nil || v == nil {
			return nil, nil, ErrPDFManualOverlay
		}
		copied, semantic, err := manualResourceObject(src, dst, v, depth+1, b)
		if err != nil {
			return nil, nil, err
		}
		if dst != nil {
			if _, ok := copied.(types.IndirectRef); !ok {
				ir, err := dst.IndRefForNewObject(copied)
				if err != nil {
					return nil, nil, ErrPDFManualOverlay
				}
				copied = *ir
			}
		}
		entry.object, entry.semantic, entry.active = copied, semantic, false
		return copied, semantic, nil
	}
	switch v := o.(type) {
	case nil:
		return nil, manualResourceCommit{pdfSHA([]byte("null"))}, nil
	case types.Dict:
		if len(v) > 65536-b.usage.nodes {
			return nil, nil, ErrPDFManualOverlay
		}
		out := types.NewDict()
		semantic := map[string]any{}
		keys := make([]string, 0, len(v))
		for k := range v {
			if len(k) > 1024 || b.usage.scalar > (16<<20)-len(k) {
				return nil, nil, ErrPDFManualOverlay
			}
			b.usage.scalar += len(k)
			if k == "Ref" || k == "OPI" {
				return nil, nil, ErrPDFManualOverlay
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			c, s, err := manualResourceObject(src, dst, v[k], depth+1, b)
			if err != nil {
				return nil, nil, err
			}
			out[k], semantic[hex.EncodeToString([]byte(k))] = c, s
		}
		commit, err := manualCommit(semantic)
		return out, commit, err
	case types.Array:
		if len(v) > 65536-b.usage.nodes {
			return nil, nil, ErrPDFManualOverlay
		}
		out := make(types.Array, len(v))
		semantic := make([]any, len(v))
		for i, e := range v {
			c, s, err := manualResourceObject(src, dst, e, depth+1, b)
			if err != nil {
				return nil, nil, err
			}
			out[i], semantic[i] = c, s
		}
		commit, err := manualCommit(semantic)
		return out, commit, err
	case types.StreamDict:
		for _, k := range []string{"F", "FFilter", "FDecodeParms", "Ref", "OPI"} {
			if _, ok := v.Dict[k]; ok {
				return nil, nil, ErrPDFManualOverlay
			}
		}
		if len(v.Raw) > 16<<20 || b.usage.raw > (64<<20)-len(v.Raw) {
			return nil, nil, ErrPDFManualOverlay
		}
		b.usage.raw += len(v.Raw)
		d := types.NewDict()
		for k, e := range v.Dict {
			if k != "Length" {
				d[k] = e
			}
		}
		c, s, err := manualResourceObject(src, dst, d, depth+1, b)
		if err != nil {
			return nil, nil, err
		}
		semantic, err := manualCommit(map[string]any{"dict": s, "encoded_sha256": pdfSHA(v.Raw), "bytes": len(v.Raw)})
		if err != nil {
			return nil, nil, err
		}
		if dst == nil {
			return nil, semantic, nil
		}
		// Build from the parsed stream while replacing all dictionary references
		// with imports. Writer emits Raw unchanged; Content is deliberately unset.
		sd := v
		sd.Dict = c.(types.Dict)
		sd.Raw = bytes.Clone(v.Raw)
		sd.Content = nil
		sd.StreamOffset = 0
		sd.FilterPipeline = make([]types.PDFFilter, len(v.FilterPipeline))
		for i, f := range v.FilterPipeline {
			sd.FilterPipeline[i].Name = f.Name
			if f.DecodeParms != nil {
				copied, _, err := manualResourceObject(src, dst, f.DecodeParms, depth+1, b)
				if err != nil {
					return nil, nil, err
				}
				sd.FilterPipeline[i].DecodeParms = copied.(types.Dict)
			}
		}
		length := int64(len(sd.Raw))
		sd.StreamLength = &length
		sd.StreamLengthObjNr = nil
		sd.Dict["Length"] = types.Integer(len(sd.Raw))
		ir, err := dst.IndRefForNewObject(sd)
		if err != nil {
			return nil, nil, ErrPDFManualOverlay
		}
		return *ir, semantic, nil
	case types.Integer, types.Float, types.Name, types.StringLiteral, types.HexLiteral, types.Boolean:
		value := v.PDFString()
		if f, ok := v.(types.Float); ok {
			if !manualFinite(float64(f)) {
				return nil, nil, ErrPDFManualOverlay
			}
			value = strconv.FormatFloat(float64(f), 'g', -1, 64)
		}
		size := 0
		switch n := v.(type) {
		case types.Name:
			size = len(n)
		case types.StringLiteral:
			size = len(n)
		case types.HexLiteral:
			size = len(n)
		}
		if size > 1<<20 || b.usage.scalar > (16<<20)-size {
			return nil, nil, ErrPDFManualOverlay
		}
		b.usage.scalar += size
		semantic, err := manualCommit(struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}{fmt.Sprintf("%T", v), hex.EncodeToString([]byte(value))})
		return v, semantic, err
	default:
		return nil, nil, ErrPDFManualOverlay
	}
}

// Compact child commitments keep acyclic alias DAGs from expanding into an
// exponential JSON tree. They are independent of object numbers and namespacing.
type manualResourceCommit struct {
	SHA256 string `json:"sha256"`
}

func manualCommit(semantic any) (manualResourceCommit, error) {
	raw, err := json.Marshal(semantic)
	if err != nil {
		return manualResourceCommit{}, ErrPDFManualOverlay
	}
	return manualResourceCommit{pdfSHA(raw)}, nil
}
func manualSemanticHash(semantic any) (string, error) {
	c, ok := semantic.(manualResourceCommit)
	if !ok || !validPDFSHA(c.SHA256) {
		return "", ErrPDFManualOverlay
	}
	return c.SHA256, nil
}
func manualResourceHashWithBudget(ctx *model.Context, o types.Object, b *manualCopyBudget) (string, error) {
	_, semantic, err := manualResourceObject(ctx, nil, o, 0, b)
	if err != nil {
		return "", err
	}
	return manualSemanticHash(semantic)
}
func manualResourceHash(ctx *model.Context, o types.Object) (string, error) {
	return manualResourceHashWithBudget(ctx, o, newManualCopyBudget(&manualResourceUsage{}))
}
