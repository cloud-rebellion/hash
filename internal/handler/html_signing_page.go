// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
)

// This helper is shared by approval preview, first creation and revision. The
// application's page is rendered independently; master CSS cannot alter its
// party labels or rectangles. The worker remains the sole PDF composition path.
func (s *Server) composeHTMLSigningPage(ctx context.Context, compiled *htmlmaster.Compiled, input htmlmaster.Input, bodyPDF []byte) (sanitize.PDFCompositionResult, error) {
	pageHTML, err := compiled.SigningPageHTML(input)
	if err != nil {
		return sanitize.PDFCompositionResult{}, err
	}
	var fonts []render.FontAsset
	for _, font := range render.FontAssets() {
		if font.Filename == "Inter.woff2" {
			digest := sha256.Sum256(font.Bytes)
			if hex.EncodeToString(digest[:]) != compiled.SigningPagePolicy().FontSHA256 {
				return sanitize.PDFCompositionResult{}, htmlmaster.ErrInvalid
			}
			fonts = append(fonts, font)
		}
	}
	if len(fonts) != 1 {
		return sanitize.PDFCompositionResult{}, htmlmaster.ErrInvalid
	}
	pagePDF, err := s.Sign.PDF.HTMLToPDF(ctx, pageHTML, render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms", Assets: fonts})
	if err != nil {
		return sanitize.PDFCompositionResult{}, errHTMLDocumentRevisionRenderUnavailable
	}
	return sanitize.ComposeSigningPageWithContext(ctx, "html-branded-signing-page", bodyPDF, pagePDF)
}

// The caller holds the original parent authorization transaction. Every fresh
// materialization gets fresh field UUIDs; the retained old ceremony already
// contains its former IDs, source binding and recipient assertions.
func createHTMLSigningFields(ctx context.Context, q *generated.Queries, doc *generated.Document) error {
	_, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || artifact == nil {
		return err
	}
	parties, err := htmlsource.ContractParties(doc)
	if err != nil {
		return err
	}
	bySlot := map[string]htmlsource.ContractParty{}
	for _, party := range parties {
		bySlot[party.Slot] = party
	}
	for _, rectangle := range artifact.Fields {
		party, ok := bySlot[rectangle.Slot]
		if !ok {
			return htmlsource.ErrInvalid
		}
		options, err := htmlsource.SigningFieldOptions(doc, rectangle.Slot)
		if err != nil {
			return err
		}
		_, err = q.CreateDraftField(ctx, generated.CreateDraftFieldParams{DocumentID: doc.ID, OrgID: doc.OrgID,
			RecipientID: pgtype.UUID{Bytes: party.RecipientID, Valid: true}, Type: "signature", Page: rectangle.Page,
			XPct: signingPercent(rectangle.X), YPct: signingPercent(rectangle.Y), WPct: signingPercent(rectangle.W), HPct: signingPercent(rectangle.H), Required: true,
			Label: pgtype.Text{String: strings.ToUpper(rectangle.Slot[:1]) + rectangle.Slot[1:] + " signature", Valid: true}, OptionsJson: options})
		if err != nil {
			return err
		}
	}
	fields, err := q.ListFieldsByDocument(ctx, doc.ID)
	if err != nil {
		return err
	}
	if err := htmlsource.ValidateSigningFields(doc, fields, artifact.Composition.FinalPages); err != nil {
		return err
	}
	policy, _, err := htmlsource.SigningPage(doc)
	if err != nil {
		return err
	}
	b := policy.Branding
	_, err = q.UpsertDocumentBrandingOverride(ctx, generated.UpsertDocumentBrandingOverrideParams{DocumentID: doc.ID,
		PrimaryHex: signingText(b.PrimaryHex), AccentHex: signingText(b.AccentHex), SurfaceHex: signingText(b.SurfaceHex), TextHex: signingText(b.TextHex), MutedHex: signingText(b.MutedHex),
		LogoUrl: signingText(b.LogoURL), LogoAlt: signingText(b.LogoAlt), FontHeading: signingText(b.FontHeading), FontBody: signingText(b.FontBody), SignatureColor: signingText(b.SignatureColor)})
	if err != nil {
		return errors.Join(errors.New("persist reviewed signing-page branding"), err)
	}
	return nil
}

func signingPercent(n int64) pgtype.Numeric {
	return pgtype.Numeric{Int: big.NewInt(n), Exp: -4, Valid: true}
}
func signingText(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }
