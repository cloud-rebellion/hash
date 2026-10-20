// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
)

// PDF-source finalization. A pdf-source document is the uploaded PDF itself;
// there is no block tree to render. We finalize by stamping each filled field
// value + each recipient's signature onto the original PDF at the
// page-percentage coordinates the sender placed in the field designer.
//
// Approach: for every page that carries fields, render a same-size HTML overlay
// (fields absolutely positioned by percentage) to a single-page PDF via the
// existing Gotenberg renderer. The mandatory isolated worker inspects the
// PDF.js-visible viewport and imports each overlay as an independent Form.
// Original boxes, rotation, UserUnit and painting remain unchanged.

// stampItem is one positioned overlay element (a field value or a signature),
// in page-percentage coordinates with pre-rendered inner HTML.
type stampItem = render.PDFStampItemV1

func buildPageOverlayHTML(items []stampItem) string { return render.BuildPageOverlayHTMLV1(items) }
func buildSizedPageOverlayHTML(items []stampItem, width, height float64) string {
	return render.BuildSizedPageOverlayHTMLV1(items, width, height)
}

// loadSourcePDF fetches the uploaded PDF bytes backing a pdf-source document.
func (e *Engine) loadSourcePDF(ctx context.Context, doc *generated.Document) ([]byte, error) {
	if !doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" {
		return nil, errors.New("pdf-source document has no stored pdf")
	}
	if len(doc.PdfSha256) != sha256.Size {
		return nil, errors.New("pdf-source document has no valid SHA-256 commitment")
	}
	var body []byte
	var err error
	if doc.PdfStorageVersionID.Valid && strings.TrimSpace(doc.PdfStorageVersionID.String) != "" {
		body, err = e.Storage.GetVerifiedVersion(ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
	} else if doc.EvidenceVersionPinsRequired {
		return nil, errors.New("pdf-source document is missing its required object VersionId")
	} else {
		body, _, err = e.Storage.ResolveVerifiedLegacy(ctx, doc.PdfStorageKey.String, doc.PdfSha256)
	}
	if err != nil {
		return nil, err
	}
	// Tripwire: the intake recorded pdf_sha256 of these bytes. Refuse to stamp +
	// ed25519-seal content that has drifted from the recorded digest (a
	// storage-layer source swap between intake and finalize). Zero cost, and it
	// also hardens the pre-existing template flow. Legacy/blocks docs with no
	// stored digest (len != 32) are unaffected.
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], doc.PdfSha256) != 1 {
		return nil, errors.New("source pdf digest mismatch: stored bytes differ from the recorded intake hash")
	}
	return body, nil
}

// stampFieldsAndSignatures renders the field/signature overlays for every page
// of a pdf-source document and returns the stamped PDF (without the audit
// cert, which the caller appends). It reads exact archived signature versions
// before rendering any page; no signature is regenerated from row metadata.
func (e *Engine) stampFieldsAndSignatures(ctx context.Context, doc *generated.Document, original []byte) ([]byte, error) {
	geometry, err := sanitize.InspectManualPDFWithContext(ctx, original)
	if err != nil {
		return nil, fmt.Errorf("inspect manual PDF in isolated worker: %w", err)
	}

	fields, err := e.Queries.ListFieldsByDocument(ctx, doc.ID)
	if err != nil {
		return nil, err
	}
	sigs, err := e.Queries.ListSignaturesByDocument(ctx, doc.ID)
	if err != nil {
		return nil, err
	}
	recipients, err := e.Queries.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return nil, err
	}
	// Fitted signatures are complete retained page packages. Sending their span
	// through this legacy HTML renderer would discard the measured frozen output.
	for _, signature := range sigs {
		if signature != nil && signature.SignatureKind == "manual_pdf_fit_v1" {
			return nil, ErrFittedCompositionRequiredV1
		}
	}
	if err := pdflayout.ValidateSignatureRows(doc, recipients, fields, sigs, len(geometry.Pages)); err != nil {
		return nil, fmt.Errorf("stamp PDF parties: %w", err)
	}
	sigByRec := map[string]render.ArchivedSignatureSpan{}
	for _, s := range sigs {
		span, err := e.archivedSignatureSpan(ctx, doc.ID, s)
		if err != nil {
			return nil, fmt.Errorf("stamp stored signature: %w", err)
		}
		sigByRec[s.RecipientID.String()] = span
	}

	// Group overlay items by 1-based page number.
	byPage := map[int][]stampItem{}
	for _, f := range fields {
		inner, err := stampInnerHTML(f, sigByRec)
		if err != nil {
			return nil, err
		}
		if inner == "" {
			continue
		}
		page := int(f.Page)
		if err := validateStampTargetPage(f, len(geometry.Pages)); err != nil {
			return nil, err
		}
		byPage[page] = append(byPage[page], stampItem{
			XPct: numericPct(f.XPct),
			YPct: numericPct(f.YPct),
			WPct: clampWidth(numericPct(f.WPct)),
			HPct: clampWidth(numericPct(f.HPct)),
			HTML: inner,
		})
	}
	if len(byPage) == 0 {
		// Nothing to stamp (a pdf with no placed fields): return as-is so the
		// signed PDF is still the authentic original.
		return original, nil
	}

	overlays, err := e.renderManualPDFOverlays(ctx, geometry, byPage, len(original))
	if err != nil {
		return nil, err
	}
	composed, err := sanitize.ApplyManualPDFOverlaysWithContext(ctx, original, geometry, overlays)
	if err != nil {
		return nil, fmt.Errorf("compose manual PDF in isolated worker: %w", err)
	}
	return composed.Bytes, nil
}

// Each renderer read consumes the remaining framed input budget. This helper
// holds at most the accepted batch plus one bounded response, and stops before
// another page is requested when admission fails.
func (e *Engine) renderManualPDFOverlays(ctx context.Context, geometry sanitize.PDFManualGeometry, byPage map[int][]stampItem, sourceBytes int) (map[int][]byte, error) {
	if sourceBytes < 1 || sourceBytes > sanitize.MaxPDFBytes || geometry.SourceBytes != int64(sourceBytes) {
		return nil, sanitize.ErrPDFTooLarge
	}
	overlays := map[int][]byte{}
	pages := make([]int, 0, len(byPage))
	for page := range byPage {
		pages = append(pages, page)
	}
	sort.Ints(pages)
	total := sourceBytes
	for _, page := range pages {
		items := byPage[page]
		remaining := sanitize.MaxPDFBytes - total
		if remaining < 1 {
			return nil, sanitize.ErrPDFTooLarge
		}
		width, height, err := geometry.Pages[page-1].ViewportPoints()
		if err != nil {
			return nil, err
		}
		html := buildSizedPageOverlayHTML(items, width, height)
		overlayPDF, err := e.PDF.HTMLToPDF(ctx, html, render.PDFOptions{
			MaxResponseBytes: remaining,
			ExactPaperPoints: [2]float64{width, height},
			Margins:          [4]float32{0, 0, 0, 0},
			// Zero margins are intentional here. Suppress the ordinary
			// one-inch document defaults so percentages remain page-relative.
			PreferCSSPageSize: true,
			WaitDelay:         "500ms",
		})
		if err != nil {
			return nil, fmt.Errorf("render overlay page %d: %w", page, err)
		}
		if len(overlayPDF) < 1 || len(overlayPDF) > remaining {
			return nil, sanitize.ErrPDFTooLarge
		}
		total += len(overlayPDF)
		overlays[page] = overlayPDF
	}
	return overlays, nil
}

// validateStampTargetPage is the terminal fail-closed counterpart to Send's
// PDF readiness check. A corrupt/legacy field or a future caller bypassing
// Send must never be silently omitted from the signed artifact.
func validateStampTargetPage(field *generated.DocumentField, pageCount int) error {
	if field == nil {
		return errors.New("stamp pdf: nil field")
	}
	if pageCount < 1 || field.Page < 1 || int(field.Page) > pageCount {
		return fmt.Errorf("stamp pdf: field %s targets page %d outside source page range 1..%d", field.ID, field.Page, pageCount)
	}
	return nil
}

// stampInnerHTML returns the HTML to place for a field: the recipient's
// signature span for signature fields, otherwise the (escaped) filled value.
// Returns "" when there is nothing to stamp (unsigned signature slot, empty
// value) so the page overlay stays minimal.
func stampInnerHTML(f *generated.DocumentField, sigByRec map[string]render.ArchivedSignatureSpan) (string, error) {
	if f.Type == "signature" {
		if !f.RecipientID.Valid {
			return "", nil
		}
		sig, ok := sigByRec[uuid.UUID(f.RecipientID.Bytes).String()]
		if !ok {
			return "", nil
		}
		if sig.HTML() == "" {
			return "", errors.New("stamp stored signature: validated archive is empty")
		}
		return sig.HTML(), nil
	}
	if !f.Value.Valid || strings.TrimSpace(f.Value.String) == "" {
		return "", nil
	}
	val := f.Value.String
	if f.Type == "checkbox" {
		if isTruthy(val) {
			return "&#10003;", nil // check mark
		}
		return "", nil
	}
	return htmlEscape(val), nil
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on", "checked", "x":
		return true
	}
	return false
}

// numericPct converts a pgtype.Numeric percent (stored 0..100 with 4 frac
// digits) to a float64. Mirrors the handler's numericToFloat without crossing
// the package boundary.
func numericPct(n pgtype.Numeric) float64 {
	if !n.Valid || n.Int == nil {
		return 0
	}
	f, _ := new(big.Float).SetInt(n.Int).Float64()
	exp := int(n.Exp)
	for ; exp < 0; exp++ {
		f /= 10
	}
	for ; exp > 0; exp-- {
		f *= 10
	}
	return f
}

// clampWidth keeps a degenerate (zero) width/height field from collapsing to
// an invisible box; a placed field always gets at least a small footprint.
func clampWidth(v float64) float64 {
	if v <= 0 {
		return 12
	}
	return v
}
