// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"

	"github.com/bright-interaction/hash/internal/malwarescan"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const PDFSigningPagePolicy = "hash-pdf-signing-page-a4-v1"

const pdfComposeSigningPageOperation = "compose-signing-page-v1"

var ErrPDFSigningPageInvalid = errors.New("sanitize: invalid signing page geometry")
var errPDFComposition = errors.New("sanitize: invalid PDF composition proof")

// PDFPageGeometry uses milli-points and a milli-scale for UserUnit. The exact
// parsed geometry is additionally bound by the manifest's GeometrySHA256.
// Boxes are effective Media, Crop, Trim, Bleed and Art boxes, in that order.
type PDFPageGeometry struct {
	BoxesMilliPoints [5][4]int64 `json:"boxes_milli_points"`
	Rotation         int         `json:"rotation"`
	UserUnitMilli    int64       `json:"user_unit_milli"`
}

// PDFCompositionManifest binds both raw renderer inputs and the exact final
// bytes. MergedSHA256 identifies the in-memory processing copy which is the
// source of the accompanying intake proof, not either component or their byte
// concatenation. No recipient IDs, storage references or metadata values cross
// the worker boundary.
type PDFCompositionManifest struct {
	SchemaVersion      int             `json:"schema_version"`
	Policy             string          `json:"policy"`
	BodySHA256         string          `json:"body_sha256"`
	SigningPageSHA256  string          `json:"signing_page_sha256"`
	MergedSHA256       string          `json:"merged_sha256"`
	MergedBytes        int64           `json:"merged_bytes"`
	OutputSHA256       string          `json:"output_sha256"`
	BodyPages          int             `json:"body_pages"`
	FinalPages         int             `json:"final_pages"`
	BodyGeometrySHA256 string          `json:"body_geometry_sha256"`
	GeometrySHA256     string          `json:"geometry_sha256"`
	SigningPage        PDFPageGeometry `json:"signing_page"`
}

// PDFCompositionResult contains the sole publishable output of composition.
// Store Result directly: a second rewrite would invalidate its commitments.
type PDFCompositionResult struct {
	Result
	Composition PDFCompositionManifest
}

// ComposeSigningPageWithContext requires the isolated worker even in explicit
// development. Both components are scanned before any parser is admitted; all
// PDF parsing, merging, cleanup and geometry inspection happens in the child.
func ComposeSigningPageWithContext(ctx context.Context, asset string, bodyPDF, signingPagePDF []byte) (PDFCompositionResult, error) {
	if len(bodyPDF) == 0 || len(signingPagePDF) == 0 {
		return PDFCompositionResult{}, errors.New("sanitize: missing PDF composition input")
	}
	if len(bodyPDF) > MaxPDFBytes || len(signingPagePDF) > MaxPDFBytes-len(bodyPDF) {
		return PDFCompositionResult{}, ErrPDFTooLarge
	}
	if len(asset) > 128 {
		return PDFCompositionResult{}, errPDFComposition
	}
	if err := malwarescan.ScanActive(ctx, bodyPDF); err != nil {
		return PDFCompositionResult{}, err
	}
	if err := malwarescan.ScanActive(ctx, signingPagePDF); err != nil {
		return PDFCompositionResult{}, err
	}
	worker := activePDFWorker.Load()
	if worker == nil {
		return PDFCompositionResult{}, ErrPDFWorkerUnavailable
	}
	return worker.composeSigningPage(ctx, asset, bodyPDF, signingPagePDF)
}

// ValidatePDFCompositionManifest validates stored commitments without PDF
// parsing. Its geometry policy is tied to the pinned Chromium renderer rather
// than pdfcpu's approximate A4 paper-size constant.
func ValidatePDFCompositionManifest(manifest PDFCompositionManifest, outputSHA string, pages int) error {
	if manifest.SchemaVersion != 1 || manifest.Policy != PDFSigningPagePolicy || !validPDFSHA(outputSHA) || manifest.OutputSHA256 != outputSHA || manifest.FinalPages != pages || manifest.BodyPages < 1 || manifest.BodyPages >= MaxPDFPages || manifest.FinalPages != manifest.BodyPages+1 || manifest.MergedBytes < 1 || manifest.MergedBytes > MaxPDFBytes {
		return errPDFComposition
	}
	for _, value := range []string{manifest.BodySHA256, manifest.SigningPageSHA256, manifest.MergedSHA256, manifest.BodyGeometrySHA256, manifest.GeometrySHA256} {
		if !validPDFSHA(value) {
			return errPDFComposition
		}
	}
	if manifest.SigningPage != canonicalSigningPageGeometry() {
		return errPDFComposition
	}
	return nil
}

// ValidatePDFCompositionResult binds the report and manifest to the bytes to
// be stored. The parent does not parse PDFs or independently rebuild the merge.
func ValidatePDFCompositionResult(result PDFCompositionResult) error {
	manifest := result.Composition
	if len(result.Bytes) < 1 || len(result.Bytes) > MaxPDFBytes || ValidatePDFCompositionManifest(manifest, pdfSHA(result.Bytes), manifest.FinalPages) != nil {
		return errPDFComposition
	}
	if ValidatePDFResult(result.Report, manifest.MergedSHA256, manifest.OutputSHA256, manifest.MergedBytes, int64(len(result.Bytes))) != nil || result.Report.PDF.PagesAfter != manifest.FinalPages || result.Report.PDF.GeometrySHA256After != manifest.GeometrySHA256 {
		return errPDFComposition
	}
	return nil
}

// DecodePDFCompositionManifest rejects missing, duplicate, case-variant,
// unknown and null JSON properties. Fixed arrays must have their exact shape:
// encoding/json alone would otherwise accept short arrays or discard extras.
func DecodePDFCompositionManifest(raw []byte) (PDFCompositionManifest, error) {
	var manifest PDFCompositionManifest
	if len(raw) == 0 || len(raw) > pdfWorkerHeaderLimit || strictPDFWorkerJSON(raw) != nil {
		return manifest, errPDFComposition
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF {
		return PDFCompositionManifest{}, errPDFComposition
	}
	var fields, geometry map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || !exactCompositionJSONKeys(fields, []string{"schema_version", "policy", "body_sha256", "signing_page_sha256", "merged_sha256", "merged_bytes", "output_sha256", "body_pages", "final_pages", "body_geometry_sha256", "geometry_sha256", "signing_page"}) || json.Unmarshal(fields["signing_page"], &geometry) != nil || !exactCompositionJSONKeys(geometry, []string{"boxes_milli_points", "rotation", "user_unit_milli"}) {
		return PDFCompositionManifest{}, errPDFComposition
	}
	var boxes [][]int64
	if json.Unmarshal(geometry["boxes_milli_points"], &boxes) != nil || len(boxes) != 5 {
		return PDFCompositionManifest{}, errPDFComposition
	}
	for _, box := range boxes {
		if len(box) != 4 {
			return PDFCompositionManifest{}, errPDFComposition
		}
	}
	if ValidatePDFCompositionManifest(manifest, manifest.OutputSHA256, manifest.FinalPages) != nil {
		return PDFCompositionManifest{}, errPDFComposition
	}
	return manifest, nil
}

func exactCompositionJSONKeys(fields map[string]json.RawMessage, keys []string) bool {
	if len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func canonicalSigningPageGeometry() PDFPageGeometry {
	g := PDFPageGeometry{UserUnitMilli: 1000}
	for i := range g.BoxesMilliPoints {
		g.BoxesMilliPoints[i] = [4]int64{0, 0, 594960, 841920}
	}
	return g
}

// These exact coordinates come from the retained Chromium renderer PDF, whose
// pdfinfo display rounds them to 594.96 x 841.92. The integer manifest is a
// milli-point representation; the geometry hash retains the exact coordinates.
func isCanonicalSigningPage(page pdfCompositionRawPage) bool {
	if page.Rotation != 0 || page.UserUnit != 1 {
		return false
	}
	for _, box := range page.Boxes {
		if box != [4]float64{0, 0, 594.95996, 841.91998} {
			return false
		}
	}
	return true
}

// This mirrors the existing intake geometry representation exactly, so an
// unchanged body prefix has its existing geometry commitment. It deliberately
// leaves the legacy proof's implementation and canonical bytes unchanged.
type pdfCompositionRawPage struct {
	Boxes    [5][4]float64 `json:"boxes"`
	Rotation int           `json:"rotation"`
	UserUnit float64       `json:"user_unit"`
}

func pdfCompositionGeometry(ctx *model.Context) ([]pdfCompositionRawPage, error) {
	boundaries, err := ctx.PageBoundaries(nil)
	if err != nil || len(boundaries) != ctx.PageCount {
		return nil, errPDFComposition
	}
	pages := make([]pdfCompositionRawPage, len(boundaries))
	for i, boundary := range boundaries {
		for j, rect := range []*types.Rectangle{boundary.MediaBox(), boundary.CropBox(), boundary.TrimBox(), boundary.BleedBox(), boundary.ArtBox()} {
			if rect == nil {
				return nil, errPDFComposition
			}
			box := [4]float64{rect.LL.X, rect.LL.Y, rect.UR.X, rect.UR.Y}
			for _, value := range box {
				if math.IsNaN(value) || math.IsInf(value, 0) {
					return nil, errPDFComposition
				}
			}
			pages[i].Boxes[j] = box
		}
		pages[i].Rotation, pages[i].UserUnit = boundary.Rot, 1
		dict, _, _, err := ctx.PageDict(i+1, false)
		if err != nil {
			return nil, errPDFComposition
		}
		if value, ok := dict["UserUnit"]; ok {
			value, err = ctx.Dereference(value)
			if err != nil {
				return nil, errPDFComposition
			}
			switch number := value.(type) {
			case types.Integer:
				pages[i].UserUnit = float64(number)
			case types.Float:
				pages[i].UserUnit = float64(number)
			default:
				return nil, errPDFComposition
			}
			if pages[i].UserUnit <= 0 || math.IsNaN(pages[i].UserUnit) || math.IsInf(pages[i].UserUnit, 0) {
				return nil, errPDFComposition
			}
		}
	}
	return pages, nil
}

func pdfCompositionGeometrySHA(pages []pdfCompositionRawPage) string {
	raw, _ := json.Marshal(pages) // All inspected coordinates are finite.
	return pdfSHA(raw)
}

func observePDFCompositionInput(raw []byte) (*model.Context, string, error) {
	ctx, _, geometry, err := observePDF(raw)
	if err != nil {
		return nil, "", err
	}
	// Inspect the original component before merge can discard its catalog or
	// orphan objects. A suffix action must not disappear into a successful merge.
	features, err := activePDFFeatures(raw)
	if err != nil {
		return nil, "", err
	}
	if len(features) != 0 {
		return nil, "", ErrActivePDFContent
	}
	return ctx, geometry, nil
}

// composeSigningPageInProcess is reachable only in the one-shot worker and
// tests. Production parent code never calls this parser implementation.
func composeSigningPageInProcess(asset string, bodyPDF, signingPagePDF []byte) (PDFCompositionResult, error) {
	if len(bodyPDF) == 0 || len(signingPagePDF) == 0 || len(asset) > 128 {
		return PDFCompositionResult{}, errPDFComposition
	}
	if len(bodyPDF) > MaxPDFBytes || len(signingPagePDF) > MaxPDFBytes-len(bodyPDF) {
		return PDFCompositionResult{}, ErrPDFTooLarge
	}
	body, bodyGeometry, err := observePDFCompositionInput(bodyPDF)
	if err != nil {
		return PDFCompositionResult{}, err
	}
	if body.PageCount >= MaxPDFPages {
		return PDFCompositionResult{}, ErrTooManyPages
	}
	bodyPages := body.PageCount
	body = nil // The merge reparses raw bytes; retain no duplicate parsed graph.
	suffix, _, err := observePDFCompositionInput(signingPagePDF)
	if err != nil {
		return PDFCompositionResult{}, err
	}
	if suffix.PageCount != 1 {
		return PDFCompositionResult{}, ErrPDFSigningPageInvalid
	}
	suffixGeometry, err := pdfCompositionGeometry(suffix)
	if err != nil || !isCanonicalSigningPage(suffixGeometry[0]) {
		return PDFCompositionResult{}, ErrPDFSigningPageInvalid
	}
	suffix = nil
	var merged boundedPDFBuffer
	if err := pdfapi.MergeRaw([]io.ReadSeeker{bytes.NewReader(bodyPDF), bytes.NewReader(signingPagePDF)}, &merged, false, pdfConfiguration()); err != nil {
		if merged.limitExceeded {
			return PDFCompositionResult{}, ErrPDFTooLarge
		}
		return PDFCompositionResult{}, errors.New("sanitize: PDF composition failed")
	}
	// The ordinary intake pipeline runs once on the exact merged processing
	// copy. Its final proof is returned unchanged with the exact inspected bytes.
	cleaned, err := cleanPDF(asset, "application/pdf", merged.Bytes())
	if err != nil {
		return PDFCompositionResult{}, err
	}
	final, _, finalGeometrySHA, err := observePDF(cleaned.Bytes)
	if err != nil || final.PageCount != bodyPages+1 {
		return PDFCompositionResult{}, errPDFComposition
	}
	finalGeometry, err := pdfCompositionGeometry(final)
	if err != nil || pdfCompositionGeometrySHA(finalGeometry[:bodyPages]) != bodyGeometry || !isCanonicalSigningPage(finalGeometry[len(finalGeometry)-1]) || pdfCompositionGeometrySHA(finalGeometry) != finalGeometrySHA {
		return PDFCompositionResult{}, errPDFComposition
	}
	result := PDFCompositionResult{Result: cleaned, Composition: PDFCompositionManifest{SchemaVersion: 1, Policy: PDFSigningPagePolicy, BodySHA256: pdfSHA(bodyPDF), SigningPageSHA256: pdfSHA(signingPagePDF), MergedSHA256: pdfSHA(merged.Bytes()), MergedBytes: int64(merged.Len()), OutputSHA256: pdfSHA(cleaned.Bytes), BodyPages: bodyPages, FinalPages: final.PageCount, BodyGeometrySHA256: bodyGeometry, GeometrySHA256: finalGeometrySHA, SigningPage: canonicalSigningPageGeometry()}}
	if err := ValidatePDFCompositionResult(result); err != nil {
		return PDFCompositionResult{}, err
	}
	return result, nil
}
