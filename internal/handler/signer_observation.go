// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This public witness identifies the exact PDF shown to one authenticated
// recipient. It contains no storage locator, version capability or raw source.
// Older generic PDFs do not have a persisted page count; their browser must
// still inspect all pages of these exact committed bytes within its bounds.
type signerPDFObservation struct {
	DocumentID              uuid.UUID `json:"document_id"`
	RecipientID             uuid.UUID `json:"recipient_id"`
	PDFSHA256               string    `json:"pdf_sha256"`
	PageCount               int32     `json:"page_count,omitempty"`
	HTMLSourceCommitment    string    `json:"html_source_commitment,omitempty"`
	MaterializationRevision int32     `json:"materialization_revision,omitempty"`
}

var errSignerReadChanged = errors.New("signer document observation changed")

type signerReadObservation struct {
	pdf          *signerPDFObservation
	notice       signerPrivacyNotice
	noticeDigest string
}

// Capture the notice before database or external waits. Recomputing both
// notices at the end could adopt changed instance disclosure settings.
func (s *Server) captureSignerReadObservation(r *http.Request, rc *sign.RecipientContext) (signerReadObservation, error) {
	pdf, err := signerPDFObservationFor(rc)
	if err != nil {
		return signerReadObservation{}, err
	}
	notice, err := s.signerPrivacyNotice(r, rc)
	if err != nil || notice.NoticeDigest == "" {
		return signerReadObservation{}, errSignerReadChanged
	}
	if err := validateSignerMaterialization(r.Context(), s.Queries, rc.Document); err != nil {
		return signerReadObservation{}, errSignerReadChanged
	}
	return signerReadObservation{pdf: pdf, notice: notice, noticeDigest: notice.NoticeDigest}, nil
}

func signerPDFObservationFor(rc *sign.RecipientContext) (*signerPDFObservation, error) {
	if rc == nil || rc.Document == nil || rc.Recipient == nil || rc.Document.ID == uuid.Nil ||
		rc.Recipient.ID == uuid.Nil || rc.Recipient.DocumentID != rc.Document.ID || rc.Recipient.DocOrgID != rc.Document.OrgID {
		return nil, errSignerReadChanged
	}
	doc := rc.Document
	if doc.SourceKind != "pdf" {
		return nil, nil
	}
	if doc.IsEnvelope || !doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" || len(doc.PdfSha256) != sha256.Size ||
		(doc.EvidenceVersionPinsRequired && (!doc.PdfStorageVersionID.Valid || doc.PdfStorageVersionID.String == "")) {
		return nil, errSignerReadChanged
	}
	if err := htmlsource.Validate(doc, false); err != nil {
		return nil, errSignerReadChanged
	}
	commitment := ""
	if len(doc.HtmlSourceJson) > 0 {
		var err error
		commitment, err = htmlsource.Commitment(doc)
		if err != nil {
			return nil, errSignerReadChanged
		}
	}
	out := &signerPDFObservation{DocumentID: doc.ID, RecipientID: rc.Recipient.ID,
		PDFSHA256: hex.EncodeToString(doc.PdfSha256), HTMLSourceCommitment: commitment}
	if doc.HtmlCurrentMaterializationID.Valid {
		if commitment == "" || !doc.HtmlCurrentPageCount.Valid || doc.HtmlCurrentPageCount.Int32 < 1 ||
			doc.HtmlCurrentPageCount.Int32 > 500 || !doc.HtmlCurrentMaterializationSequence.Valid || doc.HtmlCurrentMaterializationSequence.Int32 < 1 {
			return nil, errSignerReadChanged
		}
		out.PageCount = doc.HtmlCurrentPageCount.Int32
		out.MaterializationRevision = doc.HtmlCurrentMaterializationSequence.Int32
	}
	return out, nil
}

func setSignerPDFObservationHeaders(w http.ResponseWriter, observation *signerPDFObservation) {
	if observation == nil {
		return
	}
	w.Header().Set("X-Hash-Document-Id", observation.DocumentID.String())
	w.Header().Set("X-Hash-Recipient-Id", observation.RecipientID.String())
	w.Header().Set("X-Hash-PDF-SHA256", observation.PDFSHA256)
	if observation.PageCount != 0 {
		w.Header().Set("X-Hash-PDF-Pages", strconv.Itoa(int(observation.PageCount)))
	}
	if observation.HTMLSourceCommitment != "" {
		w.Header().Set("X-Hash-HTML-Source-Commitment", observation.HTMLSourceCommitment)
	}
	if observation.MaterializationRevision != 0 {
		w.Header().Set("X-Hash-Materialization-Revision", strconv.Itoa(int(observation.MaterializationRevision)))
	}
}

// Recheck the original admission after queries or external work. A fresh
// token lookup is never allowed to adopt an extended original deadline or a
// different ceremony/source/notice. This authorizes only a read response.
func (s *Server) recheckSignerRead(r *http.Request, original *sign.RecipientContext, observed signerReadObservation) error {
	if original == nil || original.Recipient == nil || original.Document == nil || s.Sign == nil || s.Pool == nil {
		return errSignerReadChanged
	}
	// Storage, compilation and PDF processing have finished. These short
	// read locks retain the exact live parent/recipient while normalized
	// history and disclosure reads wait; they do not authorize any mutation.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	q := generated.New(tx)
	if _, err := q.GetDocumentForShare(ctx, generated.GetDocumentForShareParams{ID: original.Document.ID, OrgID: original.Document.OrgID}); err != nil {
		return errSignerReadChanged
	}
	if _, err := q.GetRecipientForShare(ctx, generated.GetRecipientForShareParams{ID: original.Recipient.ID, DocumentID: original.Document.ID, OrgID: original.Document.OrgID}); err != nil {
		return errSignerReadChanged
	}
	lookup := *s.Sign
	lookup.Queries = q
	fresh, err := lookup.LookupByToken(ctx, original.Recipient.MagicTokenHash)
	if err != nil {
		return err
	}
	if err := sign.ValidateRecipientReadCredential(original, fresh, time.Now()); err != nil {
		return err
	}
	if !sameSignerDocumentSource(original.Document, fresh.Document) {
		return errSignerReadChanged
	}
	newPDF, err := signerPDFObservationFor(fresh)
	if err != nil || !sameSignerPDFObservation(observed.pdf, newPDF) {
		return errSignerReadChanged
	}
	if err := validateSignerMaterialization(ctx, q, fresh.Document); err != nil {
		return errSignerReadChanged
	}
	newNotice, err := s.signerPrivacyNotice(r, fresh)
	if err != nil || observed.noticeDigest == "" || observed.noticeDigest != newNotice.NoticeDigest {
		return errSignerReadChanged
	}
	// The final normalized-history/notice reads may also have waited. Retain
	// both admission deadlines through those reads before releasing the body.
	if err := sign.ValidateRecipientReadCredential(original, fresh, time.Now()); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if err := sign.ValidateRecipientReadCredential(original, fresh, time.Now()); err != nil {
		return err
	}
	return r.Context().Err()
}

func validateSignerMaterialization(ctx context.Context, q htmlmaterialization.Queries, doc *generated.Document) error {
	// Absent HTML source is a supported legacy/static PDF or block document,
	// but orphaned HTML projections are still rejected by Validate.
	if doc == nil || len(doc.HtmlSourceJson) == 0 {
		return htmlsource.Validate(doc, false)
	}
	_, err := htmlmaterialization.Current(ctx, q, doc)
	return err
}

func sameSignerPDFObservation(a, b *signerPDFObservation) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// Active status progression is harmless for a read. The actual document,
// routing policy and source identity must stay exact; read access is not a
// frozen mutation permission or a new signing admission.
func sameSignerDocumentSource(a, b *generated.Document) bool {
	return a != nil && b != nil && a.ID == b.ID && a.OrgID == b.OrgID && a.Name == b.Name &&
		a.SourceKind == b.SourceKind && a.RequiresSignature == b.RequiresSignature &&
		a.IsEnvelope == b.IsEnvelope && a.RoutingTier == b.RoutingTier &&
		a.EvidenceVersionPinsRequired == b.EvidenceVersionPinsRequired &&
		a.PdfStorageKey == b.PdfStorageKey && a.PdfStorageVersionID == b.PdfStorageVersionID && bytes.Equal(a.PdfSha256, b.PdfSha256) &&
		a.HtmlCurrentMaterializationID == b.HtmlCurrentMaterializationID && a.HtmlCurrentMaterializationSequence == b.HtmlCurrentMaterializationSequence &&
		a.HtmlCurrentPageCount == b.HtmlCurrentPageCount && a.HtmlEffectiveSourceCommitment == b.HtmlEffectiveSourceCommitment &&
		bytes.Equal(a.HtmlSourceJson, b.HtmlSourceJson) && bytes.Equal(a.HtmlCurrentSourceJson, b.HtmlCurrentSourceJson) &&
		bytes.Equal(a.BlocksJson, b.BlocksJson) && bytes.Equal(a.VariablesJson, b.VariablesJson)
}

func writeSignerReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, sign.ErrMagicLinkExpired) {
		writeError(w, http.StatusGone, "signing link is no longer valid")
		return
	}
	writeError(w, http.StatusConflict, "the document or signing link changed; reload before continuing")
}
