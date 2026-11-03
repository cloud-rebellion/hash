// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
)

var errSavedPDFChanged = errors.New("document changed; reload before downloading")

// Download observes saved content, never mutates the document or starts a
// signing ceremony. Completed documents use the immutable final-pdf route.
func checkSavedPDFDownload(r *http.Request, doc *generated.Document) error {
	if r == nil || doc == nil || !doc.UpdatedAt.Valid || doc.Status == "completed" {
		return errSavedPDFChanged
	}
	query := r.URL.Query()
	if len(query["download"]) != 1 || query.Get("download") != "1" || len(query["expected_updated_at"]) != 1 {
		return errSavedPDFChanged
	}
	observed, err := time.Parse(time.RFC3339Nano, query.Get("expected_updated_at"))
	if err != nil || !observed.Equal(doc.UpdatedAt.Time) {
		return errSavedPDFChanged
	}
	if doc.SourceKind == "pdf" {
		if len(query["expected_pdf_sha256"]) != 1 {
			return errSavedPDFChanged
		}
		pin := query.Get("expected_pdf_sha256")
		if len(pin) != 64 || pin != hex.EncodeToString(doc.PdfSha256) {
			return errSavedPDFChanged
		}
	} else if doc.SourceKind != "blocks" {
		return errSavedPDFChanged
	}
	return nil
}

func savedBlocksDownloadHTML(doc *generated.Document, variables map[string]string, brandingCSS string) (string, error) {
	tree, err := blocks.ParseTree(doc.BlocksJson)
	if err != nil {
		return "", err
	}
	html := render.BuildHTMLDocumentV1(brandingCSS, blocks.RenderHTML(tree, variables), "")
	return render.SanitizeForRenderBoundedV1(html)
}

func (s *Server) downloadSavedBlocksPDF(w http.ResponseWriter, r *http.Request, doc *generated.Document, user uuid.UUID, authorize auth.TransactionAuthorization) {
	if s.Sign == nil || s.Sign.PDF == nil {
		writeError(w, http.StatusServiceUnavailable, "pdf renderer unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), resolver.PreviewTimeout)
	defer cancel()
	variables, report, err := s.resolveVariables(ctx, doc)
	if err != nil {
		writeInternalErrorMsg(w, "resolve download variables", err)
		return
	}
	if doc.Status == "draft" {
		if err := resolver.CheckReviewedCRMValues(doc, report); err != nil {
			s.writePreviewError(w, err)
			return
		}
	}
	brand, err := s.resolveBrandingForDoc(ctx, doc)
	if err != nil {
		writeInternalErrorMsg(w, "resolve download branding", err)
		return
	}
	html, err := savedBlocksDownloadHTML(doc, variables, brand.CSSVariables())
	if err != nil {
		writeInternalErrorMsg(w, "prepare saved document PDF", err)
		return
	}
	if err := resolver.CheckPreview(ctx, s.Pool, doc, report, user, authorize); err != nil {
		s.writePreviewError(w, err)
		return
	}
	body, err := s.Sign.PDF.HTMLToPDF(ctx, html, render.PDFOptions{WaitDelay: "1000ms"})
	if err != nil {
		writeInternalErrorMsg(w, "render saved document PDF", err)
		return
	}
	if !bytes.HasPrefix(body, []byte("%PDF-")) {
		writeError(w, http.StatusServiceUnavailable, "pdf renderer returned invalid output")
		return
	}
	// Rendering may take seconds. Recheck current content and the original live
	// credential before exposing any bytes; never return a newer/stale render.
	if err := resolver.CheckPreview(ctx, s.Pool, doc, report, user, authorize); err != nil {
		s.writePreviewError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFileName(doc.Name)+`.pdf"`)
	_, _ = w.Write(body)
}
