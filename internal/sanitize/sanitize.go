// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package sanitize implements the bounded upload cleaning pipeline.
//
// Every blob users upload (PDF templates, branding logos, embedded images)
// gets routed through Clean(raw, contentType) BEFORE it reaches MinIO.
// The cleaner removes or rejects these PDF facilities and verifies its output:
//
//	PDFs:   source /Info fields, XMP metadata, /AcroForm forms,
//	        /EmbeddedFiles attachments, annotations/comments and active content.
//	        The PDF writer may generate its own Producer and processing dates;
//	        these are verified and reported separately from removed source data.
//	Images: EXIF, GPS, ICC profiles, thumbnails, edit history. Achieved
//	        by decoding with the stdlib image package and re-encoding
//	        through image/jpeg or image/png, both of which produce metadata-
//	        free output by default.
//	SVG:    <metadata>, <script>, <foreignObject>, comments. Parsed with
//	        the html/golang.org/x/net stack and re-serialised.
//
// Original bytes are never persisted; only the cleaned output goes to
// storage. The Report returned lists every field stripped so the audit
// cert can attest to the cleaning.
package sanitize

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/jpeg"
	"image/png"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/bright-interaction/hash/internal/imageguard"
	"github.com/bright-interaction/hash/internal/malwarescan"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	pdftypes "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// Report captures what was stripped from a single cleaning pass. The
// sanitizer surfaces it to callers so the audit cert can serialize it +
// the log can spot anomalies (e.g. an unexpectedly metadata-rich PDF).
type Report struct {
	Asset        string    `json:"asset"`        // human-friendly source label, e.g. "template-pdf", "logo"
	ContentType  string    `json:"content_type"` // canonical mime
	Method       string    `json:"method"`       // 'pdfcpu' | 'image-reencode' | 'svg-strip' | 'passthrough'
	Stripped     []string  `json:"stripped"`     // field labels: 'author', 'exif', 'gps', 'javascript', etc
	BytesBefore  int64     `json:"bytes_before"`
	BytesAfter   int64     `json:"bytes_after"`
	UnsupportedT bool      `json:"unsupported_type,omitempty"` // true if the type was passed through unchanged
	Provenance   string    `json:"provenance,omitempty"`
	PDF          *PDFProof `json:"pdf,omitempty"`
}

// Result wraps the cleaned bytes + report so callers can write to storage
// AND log the report.
type Result struct {
	Bytes  []byte
	Report Report
}

// ErrActivePDFContent marks a PDF containing an action or active-content
// facility. Hash deliberately rejects these uploads instead of trying to
// preserve a partially functional document: actions can be reachable through
// the catalog, name trees, page/field additional-actions dictionaries, or an
// otherwise innocuous-looking indirect object. A single missed reference is
// enough to re-enable JavaScript, launch, network, or rich-media behaviour in a
// viewer.
var ErrActivePDFContent = errors.New("sanitize: PDF contains active content")

// MaxPDFPages applies to document and template uploads before optimization.
const MaxPDFPages = 500

// MaxPDFBytes bounds all PDF entry points, including renderer/MCP output.
const MaxPDFBytes = 50 << 20

var ErrPDFTooLarge = errors.New("sanitize: PDF exceeds byte limit")

var ErrTooManyPages = errors.New("sanitize: PDF exceeds the page limit")

// Clean dispatches by content type. Unknown content types pass through
// unchanged with Method="passthrough" + UnsupportedT=true so callers can
// log + decide whether to reject.
//
// asset is a human-friendly label for the Report ("template-pdf", "logo"...).
func Clean(asset string, contentType string, raw []byte) (Result, error) {
	return CleanWithContext(context.Background(), asset, contentType, raw)
}

// CleanWithContext requires the configured scanner verdict before parsing.
func CleanWithContext(ctx context.Context, asset string, contentType string, raw []byte) (Result, error) {
	if err := malwarescan.ScanActive(ctx, raw); err != nil {
		return Result{}, err
	}
	if raw == nil {
		return Result{}, errors.New("sanitize: nil input")
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case ct == "application/pdf":
		if worker := activePDFWorker.Load(); worker != nil {
			return worker.clean(ctx, asset, ct, raw)
		}
		return cleanPDF(asset, ct, raw)
	case ct == "image/png":
		return cleanImage(asset, ct, raw, "png")
	case ct == "image/jpeg", ct == "image/jpg":
		return cleanImage(asset, ct, raw, "jpeg")
	case ct == "image/svg+xml":
		return cleanSVG(asset, ct, raw)
	default:
		return Result{
			Bytes: raw,
			Report: Report{
				Asset:        asset,
				ContentType:  ct,
				Method:       "passthrough",
				BytesBefore:  int64(len(raw)),
				BytesAfter:   int64(len(raw)),
				UnsupportedT: true,
			},
		}, nil
	}
}

// boundedPDFBuffer prevents optimizer output from growing without limit.
// This bounds the output buffer, not pdfcpu's internal parsed object graph.
type boundedPDFBuffer struct {
	buffer        bytes.Buffer
	limitExceeded bool
}

func (b *boundedPDFBuffer) Write(p []byte) (int, error) {
	if len(p) > MaxPDFBytes-b.buffer.Len() {
		b.limitExceeded = true
		return 0, ErrPDFTooLarge
	}
	return b.buffer.Write(p)
}
func (b *boundedPDFBuffer) Bytes() []byte { return b.buffer.Bytes() }
func (b *boundedPDFBuffer) Len() int      { return b.buffer.Len() }
func (b *boundedPDFBuffer) Reset()        { b.buffer.Reset() }

// cleanPDF observes the source before validation can repair it, explicitly
// removes metadata, then verifies the rewritten bytes. Optimize alone does
// not remove source Info fields or XMP in the pinned pdfcpu version.
func cleanPDF(asset, ct string, raw []byte) (Result, error) {
	return cleanPDFWithResourcePreservation(asset, ct, raw, false)
}

// The ordered layer importer wraps original painting in a Form while the
// original page Group can still name a page-level ColorSpace. Resource
// consolidation uses only content tokens and can prune that required binding.
// Preserve resources only for that operation; all other cleaner callers retain
// their existing default configuration and stripping/verification policy.
func cleanPDFWithResourcePreservation(asset, ct string, raw []byte, preserveResources bool) (Result, error) {
	if len(raw) > MaxPDFBytes {
		return Result{}, ErrPDFTooLarge
	}
	ctx, before, geometryBefore, err := observePDF(raw)
	if err != nil {
		return Result{}, err
	}
	pages := ctx.PageCount
	if err := removePDFMetadata(ctx); err != nil {
		return Result{}, err
	}
	if preserveResources {
		ctx.Conf.OptimizeResourceDicts = false
	}
	if err := pdfapi.OptimizeContext(ctx); err != nil {
		return Result{}, errors.New("sanitize: PDF optimization failed")
	}
	var out boundedPDFBuffer
	if err := pdfapi.WriteContext(ctx, &out); err != nil {
		if out.limitExceeded {
			return Result{}, ErrPDFTooLarge
		}
		return Result{}, errors.New("sanitize: PDF rewrite failed")
	}
	_, err = secondPassStripWithResourcePreservation(out.Bytes(), &out, preserveResources)
	if err != nil {
		return Result{}, err
	}
	// Removal commands can regenerate object streams and Info. A final controlled
	// rewrite enforces the same policy regardless of which command succeeded.
	ctx, _, _, err = observePDF(out.Bytes())
	if err != nil {
		return Result{}, err
	}
	if err := removePDFMetadata(ctx); err != nil {
		return Result{}, err
	}
	out.Reset()
	if err := pdfapi.WriteContext(ctx, &out); err != nil {
		if out.limitExceeded {
			return Result{}, ErrPDFTooLarge
		}
		return Result{}, errors.New("sanitize: final PDF rewrite failed")
	}
	verified, after, geometryAfter, err := observePDF(out.Bytes())
	if err != nil {
		return Result{}, err
	}
	if verified.PageCount != pages || geometryBefore != geometryAfter {
		return Result{}, errors.New("sanitize: PDF page geometry changed")
	}
	if err := verifyGeneratedInfo(verified); err != nil {
		return Result{}, err
	}

	// Defence in depth: assert that no active construct survived or was
	// introduced by a rewrite pass. Never return bytes we have not checked.
	active, err := activePDFFeatures(out.Bytes())
	if err != nil {
		return Result{}, errors.New("sanitize: sanitized PDF verification failed")
	}
	if len(active) > 0 {
		return Result{}, fmt.Errorf("%w after rewrite: %s", ErrActivePDFContent, strings.Join(active, ", "))
	}

	proof := newPDFProof(raw, out.Bytes(), pages, before, after, geometryBefore, geometryAfter)
	report := Report{Asset: asset, ContentType: ct, Method: "pdfcpu", Stripped: append([]string{}, proof.Removed...), BytesBefore: int64(len(raw)), BytesAfter: int64(out.Len()), Provenance: "observed", PDF: proof}
	if err := ValidatePDFReport(report); err != nil {
		return Result{}, err
	}
	return Result{
		Bytes:  out.Bytes(),
		Report: report,
	}, nil
}

// activePDFFeatures returns a stable list of active constructs found anywhere
// in the parsed PDF object graph. ReadContext materializes every xref entry,
// including objects stored in object streams, so scanning the table also finds
// action dictionaries that are reached indirectly or deliberately left
// outside the normal page tree.
func activePDFFeatures(raw []byte) ([]string, error) {
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	ctx, err := pdfapi.ReadContext(bytes.NewReader(raw), conf)
	if err != nil {
		return nil, err
	}

	found := map[string]struct{}{}
	for _, entry := range ctx.XRefTable.Table {
		if entry == nil || entry.Free || entry.Object == nil {
			continue
		}
		collectActivePDFFeatures(entry.Object, found)
	}

	out := make([]string, 0, len(found))
	for feature := range found {
		out = append(out, feature)
	}
	sort.Strings(out)
	return out, nil
}

// PDF action subtype names from ISO 32000. Hash does not need interactive PDF
// actions in uploaded agreements; rejecting all of them also avoids treating a
// nominally benign GoTo action as safe when it is chained via /Next to a launch
// or JavaScript action.
var pdfActionSubtypes = map[string]struct{}{
	"GoTo": {}, "GoToR": {}, "GoToE": {}, "Launch": {}, "Thread": {},
	"URI": {}, "Sound": {}, "Movie": {}, "Hide": {}, "Named": {},
	"SubmitForm": {}, "ResetForm": {}, "ImportData": {}, "JavaScript": {},
	"SetOCGState": {}, "Rendition": {}, "Trans": {}, "GoTo3DView": {},
}

func collectActivePDFFeatures(obj pdftypes.Object, found map[string]struct{}) {
	switch v := obj.(type) {
	case pdftypes.Dict:
		collectActivePDFDict(v, found)
	case pdftypes.Array:
		for _, item := range v {
			if item != nil {
				collectActivePDFFeatures(item, found)
			}
		}
	case pdftypes.StreamDict:
		collectActivePDFDict(v.Dict, found)
	case *pdftypes.StreamDict:
		if v != nil {
			collectActivePDFDict(v.Dict, found)
		}
	case pdftypes.ObjectStreamDict:
		collectActivePDFDict(v.Dict, found)
	case *pdftypes.ObjectStreamDict:
		if v != nil {
			collectActivePDFDict(v.Dict, found)
		}
	case pdftypes.XRefStreamDict:
		collectActivePDFDict(v.Dict, found)
	case *pdftypes.XRefStreamDict:
		if v != nil {
			collectActivePDFDict(v.Dict, found)
		}
	}
}

func collectActivePDFDict(d pdftypes.Dict, found map[string]struct{}) {
	// These keys are triggers or active-content roots regardless of where the
	// value lives (inline dictionary, stream, array, or indirect reference).
	for _, key := range []string{
		"OpenAction", "AA", "JavaScript", "JS", "XFA", "RichMedia",
		"RichMediaContent", "RichMediaSettings", "3D", "3DD",
	} {
		if _, ok := d[key]; ok {
			found["/"+key] = struct{}{}
		}
	}

	if subtype := d.NameEntry("S"); subtype != nil {
		if _, ok := pdfActionSubtypes[*subtype]; ok {
			found["action:/"+*subtype] = struct{}{}
		}
	}
	if typ := d.NameEntry("Type"); typ != nil && (*typ == "Action" || *typ == "A") {
		found["/Type /"+*typ] = struct{}{}
	}

	for _, value := range d {
		if value != nil {
			collectActivePDFFeatures(value, found)
		}
	}
}

// secondPassStrip runs pdfcpu commands that target specific subtrees and
// returns the labels for whatever was actually removed. We always attempt
// each operation; pdfcpu returns nil errors when a subtree doesn't exist.
//
// Note: pdfcpu's APIs in v0.12 require io.ReadSeeker for input. We feed
// it the already-optimized output from the first pass and overwrite.
func secondPassStrip(in []byte, out *boundedPDFBuffer) ([]string, error) {
	return secondPassStripWithResourcePreservation(in, out, false)
}

func secondPassStripWithResourcePreservation(in []byte, out *boundedPDFBuffer, preserveResources bool) ([]string, error) {
	stripped := []string{}
	current := in

	// Try: remove embedded attachments.
	{
		var buf boundedPDFBuffer
		conf := model.NewDefaultConfiguration()
		conf.ValidationMode = model.ValidationRelaxed
		if preserveResources {
			conf.OptimizeResourceDicts = false
		}
		if err := pdfapi.RemoveAttachments(bytes.NewReader(current), &buf, nil, conf); err == nil && buf.Len() > 0 {
			current = buf.Bytes()
			stripped = append(stripped, "embedded_files")
		}
		if buf.limitExceeded {
			return nil, ErrPDFTooLarge
		}
	}

	// Try: remove form (AcroForm) data.
	{
		var buf boundedPDFBuffer
		conf := model.NewDefaultConfiguration()
		conf.ValidationMode = model.ValidationRelaxed
		if preserveResources {
			conf.OptimizeResourceDicts = false
		}
		if err := pdfapi.RemoveFormFields(bytes.NewReader(current), &buf, nil, conf); err == nil && buf.Len() > 0 {
			current = buf.Bytes()
			stripped = append(stripped, "acroform")
		}
		if buf.limitExceeded {
			return nil, ErrPDFTooLarge
		}
	}

	// Try: remove all annotations (sticky notes, comments, links). Stamps
	// like signature visuals are typically images embedded as XObject
	// streams, not annotations, so this is safe for our signed PDFs.
	{
		var buf boundedPDFBuffer
		conf := model.NewDefaultConfiguration()
		conf.ValidationMode = model.ValidationRelaxed
		if preserveResources {
			conf.OptimizeResourceDicts = false
		}
		if err := pdfapi.RemoveAnnotations(bytes.NewReader(current), &buf, nil, nil, nil, conf); err == nil && buf.Len() > 0 {
			current = buf.Bytes()
			stripped = append(stripped, "annotations")
		}
		if buf.limitExceeded {
			return nil, ErrPDFTooLarge
		}
	}

	// Overwrite the caller's buffer with the final pass.
	out.Reset()
	if _, err := out.Write(current); err != nil {
		return nil, err
	}
	return stripped, nil
}

// cleanImage decodes + re-encodes the image. The stdlib's image package
// does NOT preserve EXIF, GPS, or ICC profile data on encode, so the
// round-trip naturally strips them.
func cleanImage(asset, ct string, raw []byte, format string) (Result, error) {
	img, err := imageguard.Decode(bytes.NewReader(raw), format)
	if err != nil {
		return Result{}, fmt.Errorf("decode %s: %w", format, err)
	}
	var out bytes.Buffer
	switch format {
	case "jpeg":
		if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 92}); err != nil {
			return Result{}, fmt.Errorf("encode jpeg: %w", err)
		}
	case "png":
		if err := png.Encode(&out, img); err != nil {
			return Result{}, fmt.Errorf("encode png: %w", err)
		}
	default:
		return Result{}, fmt.Errorf("unsupported image format %q", format)
	}
	return Result{
		Bytes: out.Bytes(),
		Report: Report{
			Asset:       asset,
			ContentType: ct,
			Method:      "image-reencode",
			Stripped:    []string{"exif", "gps", "icc_profile", "xmp", "thumbnail", "edit_history"},
			BytesBefore: int64(len(raw)),
			BytesAfter:  int64(out.Len()),
		},
	}, nil
}

// cleanSVG strips <metadata>, <script>, <foreignObject>, and XML comments
// from an SVG, then re-serialises through the html/golang.org/x/net stack.
//
// SVG is XML, but golang.org/x/net/html is permissive enough to round-trip
// most SVGs without choking on the XML preamble. We extract everything
// inside the top-level <svg> element and rebuild it.
func cleanSVG(asset, ct string, raw []byte) (Result, error) {
	src := string(raw)
	// Strip XML comments. Conservative regex-free pass to avoid pulling
	// in regexp engines just for this.
	src = stripBetween(src, "<!--", "-->")
	// Strip <script>...</script>.
	src = stripBetween(src, "<script", "</script>")
	// Strip <metadata>...</metadata>.
	src = stripBetween(src, "<metadata", "</metadata>")
	// Strip <foreignObject>...</foreignObject>.
	src = stripBetween(src, "<foreignObject", "</foreignObject>")
	// Strip every on* event-handler attribute (onload, onclick, ...). A full
	// XML parse would be ideal, but x/net/html lowercases attribute names and
	// would corrupt SVG camelCase (viewBox, gradientUnits), breaking the logo
	// render. A targeted regex strip removes the dangerous bits while leaving
	// the SVG structure intact.
	src = svgOnHandlerRE.ReplaceAllString(src, "$1")
	// Strip active-scheme URIs from href / xlink:href so an <a>/<use> can't
	// navigate to script. data:image and #fragment refs are left untouched.
	src = svgActiveHrefRE.ReplaceAllString(src, "$1")

	cleaned := []byte(src)
	return Result{
		Bytes: cleaned,
		Report: Report{
			Asset:       asset,
			ContentType: ct,
			Method:      "svg-strip",
			Stripped:    []string{"xml_comments", "scripts", "metadata", "foreign_objects", "event_handlers", "active_uris"},
			BytesBefore: int64(len(raw)),
			BytesAfter:  int64(len(cleaned)),
		},
	}, nil
}

// svgOnHandlerRE matches an on<word>=<value> attribute (quoted or bare). Group
// 1 is the attribute BOUNDARY: start-of-string, whitespace, the closing quote of
// the previous attribute value, or a slash. Anchoring on the boundary (not a
// leading \s) catches glued attributes like `fill="red"onload=...`, which a
// whitespace-only prefix let through; the boundary char is preserved on strip.
var svgOnHandlerRE = regexp.MustCompile(`(?i)(^|[\s"'/])on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)

// svgActiveHrefRE matches href / xlink:href attributes whose value uses an
// active scheme (javascript:, vbscript:, data:text/html). Same boundary anchor
// as svgOnHandlerRE so a glued `"x"xlink:href="javascript:..."` is caught.
var svgActiveHrefRE = regexp.MustCompile(`(?i)(^|[\s"'/])(?:xlink:)?href\s*=\s*("(?:javascript|vbscript|data:text/html)[^"]*"|'(?:javascript|vbscript|data:text/html)[^']*'|(?:javascript|vbscript):[^\s>]+)`)

// stripBetween removes every span starting with open and ending with
// close (inclusive). Case-insensitive on the open tag for robustness.
func stripBetween(s, open, close string) string {
	var out strings.Builder
	lower := strings.ToLower(s)
	openLower := strings.ToLower(open)
	closeLower := strings.ToLower(close)
	i := 0
	for i < len(s) {
		j := indexFrom(lower, openLower, i)
		if j < 0 {
			out.WriteString(s[i:])
			break
		}
		out.WriteString(s[i:j])
		// Find the matching close from j.
		k := indexFrom(lower, closeLower, j)
		if k < 0 {
			// Unterminated; drop rest of the input to be safe.
			break
		}
		i = k + len(close)
	}
	return out.String()
}

func indexFrom(haystack, needle string, from int) int {
	if from < 0 {
		from = 0
	}
	if from >= len(haystack) {
		return -1
	}
	if at := strings.Index(haystack[from:], needle); at >= 0 {
		return from + at
	}
	return -1
}

// Helper for callers: appends a Report to a JSONB-shaped document
// metadata_redaction_report. Callers that want to accumulate multiple
// reports (e.g. a template PDF + a logo on the same doc) can call
// MergeReports.
func MergeReports(existing []byte, add Report) ([]byte, error) {
	type wire struct {
		SchemaVersion int      `json:"schema_version"`
		Items         []Report `json:"items"`
	}
	var w wire
	if len(existing) > 0 && string(existing) != "{}" {
		if err := jsonUnmarshalLite(existing, &w); err != nil {
			// fall through and start fresh; we never want a malformed
			// existing payload to block a write
			w = wire{}
		}
	}
	if w.SchemaVersion == 0 {
		w.SchemaVersion = 1
	}
	if add.PDF != nil || add.Provenance != "" {
		w.SchemaVersion = 2
	}
	w.Items = append(w.Items, add)
	return jsonMarshalLite(w)
}

// Tiny stdlib JSON wrappers kept in a helper file so the test code can
// shadow them with deterministic ones if needed. Routed through the
// stdlib encoding/json under the hood.

// jsonMarshalLite + jsonUnmarshalLite are declared in helpers.go.

// guard against unused imports while reshuffling.
var _ = io.Discard
