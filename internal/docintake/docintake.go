// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package docintake holds the one-step "designed proposal -> signable
// pdf-source document" intake shared by the REST import handler and the MCP
// ingest tool, so both take exactly the same verified clean + store + record
// path before the (unchanged) field-designer + sign/stamp/seal flow runs.
package docintake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
)

// ErrSanitizePDF marks a failure to sanitize the input bytes as a PDF, so
// callers can map it to a 400 (bad upload) rather than a 500.
var ErrSanitizePDF = errors.New("docintake: pdf sanitize failed")

// ErrTooManyPages marks an intake whose page count exceeds maxIntakePages, so
// callers map it to a 400. Guards the HTML->PDF amplification vector (a tiny
// input can render into thousands of pages) whose direct-upload 50 MB cap the
// render path bypasses.
var ErrTooManyPages = sanitize.ErrTooManyPages

// maxIntakePages bounds a one-step intake document. Legitimate proposals and
// contracts are far under this; the cap exists to reject amplification bombs
// before downstream processing. Production clean/count operations run in the
// bounded isolated PDF worker; explicit-development/library behavior is separate.
const maxIntakePages = sanitize.MaxPDFPages

const orphanCleanupTimeout = 15 * time.Second

// documentQueries and objectStore keep the intake transaction boundary
// testable. The production *generated.Queries and *storage.Client implement
// these interfaces directly.
type documentQueries interface {
	CreatePDFDocument(context.Context, generated.CreatePDFDocumentParams) (*generated.Document, error)
	UpdateMetadataRedactionReport(context.Context, generated.UpdateMetadataRedactionReportParams) error
}

type objectStore interface {
	PutVersioned(context.Context, string, string, []byte) (storage.StoredObject, error)
	DeleteVersion(context.Context, string, string, []byte) error
}

// OwnedPDFSource identifies the object written by this intake operation. It
// comes directly from PutVersioned, never from a returned database row. A
// successful template intake transfers this exact cleanup identity to its
// caller until the surrounding document transaction has durably committed.
type OwnedPDFSource struct {
	Key       string
	VersionID string
	SHA256    [sha256.Size]byte
}

// PreparedPDFSource is an org-bound, already inspected and stored PDF. Its
// private fields prevent callers from replacing the artifact identity, pages or
// report between preparation and attachment. It retains no caller-owned bytes.
//
// Preparation performs no SQL. Attach performs no storage or PDF processing.
// The caller must compensate OwnedSource on any precommit failure, using a
// detached bounded context, but retain it after any attempted COMMIT until the
// transaction outcome is reconciled. Attach does not commit or compensate.
type PreparedPDFSource struct {
	orgID  uuid.UUID
	owned  OwnedPDFSource
	pages  int
	report json.RawMessage
}

// OwnedSource returns a value copy of the exact PutVersioned cleanup identity,
// independent of any later database query result.
func (p *PreparedPDFSource) OwnedSource() OwnedPDFSource {
	if p == nil {
		return OwnedPDFSource{}
	}
	return p.owned
}

func (p *PreparedPDFSource) PageCount() int {
	if p == nil {
		return 0
	}
	return p.pages
}

// PreparePDFTemplateSource completes bounded cleanup, page inspection, report
// encoding and PutVersioned before the caller acquires its database locks.
func PreparePDFTemplateSource(ctx context.Context, st objectStore, orgID uuid.UUID, data []byte) (*PreparedPDFSource, error) {
	if orgID == uuid.Nil || st == nil {
		return nil, errors.New("organization and PDF object store required")
	}
	cleaned, err := sanitize.CleanWithContext(ctx, "proposal-pdf", "application/pdf", data)
	if err != nil {
		if errors.Is(err, ErrTooManyPages) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrSanitizePDF, err)
	}
	pageCount, err := sanitize.PageCountWithContext(ctx, cleaned.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: count sanitized PDF pages: %w", ErrSanitizePDF, err)
	}
	if pageCount > maxIntakePages {
		return nil, fmt.Errorf("%w: %d pages exceeds the %d-page limit", ErrTooManyPages, pageCount, maxIntakePages)
	}
	return preparePDFSource(ctx, st, orgID, cleaned, pageCount)
}

// PrepareComposedPDFTemplateSource stores the exact once-cleaned output from
// the isolated composition worker. It rechecks the byte/report/manifest proof
// without a second scrub, parser or page-count operation.
func PrepareComposedPDFTemplateSource(ctx context.Context, st objectStore, orgID uuid.UUID, composed sanitize.PDFCompositionResult) (*PreparedPDFSource, error) {
	if orgID == uuid.Nil || st == nil {
		return nil, errors.New("organization and PDF object store required")
	}
	if len(composed.Bytes) == 0 || len(composed.Bytes) > sanitize.MaxPDFBytes {
		return nil, fmt.Errorf("%w: composed PDF output size", ErrSanitizePDF)
	}
	composed.Bytes = bytes.Clone(composed.Bytes)
	if err := sanitize.ValidatePDFCompositionResult(composed); err != nil {
		return nil, fmt.Errorf("%w: composed PDF proof: %w", ErrSanitizePDF, err)
	}
	return preparePDFSource(ctx, st, orgID, composed.Result, composed.Composition.FinalPages)
}

func preparePDFSource(ctx context.Context, st objectStore, orgID uuid.UUID, cleaned sanitize.Result, pageCount int) (*PreparedPDFSource, error) {
	output := sha256.Sum256(cleaned.Bytes)
	if sanitize.ValidatePDFReport(cleaned.Report) != nil || cleaned.Report.PDF.OutputSHA256 != hex.EncodeToString(output[:]) ||
		cleaned.Report.BytesAfter != int64(len(cleaned.Bytes)) || cleaned.Report.PDF.PagesAfter != pageCount {
		return nil, fmt.Errorf("%w: cleaned PDF report differs from exact output or pages", ErrSanitizePDF)
	}
	// Report construction must not discover an error after either storage or
	// SQL has already acquired an externally visible artifact identity.
	report, err := sanitize.MergeReports(nil, cleaned.Report)
	if err != nil {
		return nil, fmt.Errorf("build metadata redaction report: %w", err)
	}
	key := path.Join("org", orgID.String(), "documents", uuid.NewString()+".pdf")
	stored, err := st.PutVersioned(ctx, key, "application/pdf", cleaned.Bytes)
	if err != nil {
		return nil, err
	}
	return &PreparedPDFSource{orgID: orgID, owned: OwnedPDFSource{Key: key, VersionID: stored.VersionID, SHA256: stored.SHA256}, pages: pageCount, report: bytes.Clone(report)}, nil
}

// Attach creates the template-backed document and its measured report using
// only SQL. The caller owns the surrounding transaction, authorization, quota
// and fresh template/CRM admission. Wrong-org or zero preparations fail before
// SQL. On every error the owned artifact remains available for caller cleanup.
func (p *PreparedPDFSource) Attach(ctx context.Context, q documentQueries, orgID, userID uuid.UUID, name string, templateID uuid.UUID, expiresAt pgtype.Timestamptz) (*generated.Document, error) {
	if templateID == uuid.Nil {
		return nil, errors.New("template ID required")
	}
	return p.attach(ctx, q, orgID, userID, name, pgtype.UUID{Bytes: templateID, Valid: true}, expiresAt)
}

func (p *PreparedPDFSource) attach(ctx context.Context, q documentQueries, orgID, userID uuid.UUID, name string, templateID pgtype.UUID, expiresAt pgtype.Timestamptz) (*generated.Document, error) {
	if p == nil || q == nil || orgID == uuid.Nil || userID == uuid.Nil || p.orgID != orgID ||
		p.owned.Key == "" || p.owned.VersionID == "" || p.pages < 1 || p.pages > maxIntakePages || len(p.report) == 0 {
		return nil, errors.New("valid prepared PDF source, same organization and user required")
	}
	owned := p.owned
	doc, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{
		OrgID: orgID, TemplateID: templateID, Name: name,
		PdfStorageKey: pgtype.Text{String: owned.Key, Valid: true}, PdfSha256: owned.SHA256[:],
		PdfStorageVersionID: pgtype.Text{String: owned.VersionID, Valid: true}, EvidenceVersionPinsRequired: true,
		SenderID: userID, ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("create PDF document: %w", err)
	}
	if doc == nil || doc.ID == uuid.Nil {
		return nil, errors.New("create PDF document: missing document identity")
	}
	if err := q.UpdateMetadataRedactionReport(ctx, generated.UpdateMetadataRedactionReportParams{ID: doc.ID, MetadataRedactionReport: bytes.Clone(p.report)}); err != nil {
		return nil, fmt.Errorf("persist metadata redaction report: %w", err)
	}
	return doc, nil
}

// CreatePDFSourceDocument sanitizes the PDF bytes (strips /Info, XMP, JS,
// AcroForm, attachments, annotations), stores the cleaned copy, and creates a
// template-less pdf-source document ready for the field designer. Returns the
// document and its page count. The sign/stamp/seal path downstream is
// untouched, so the frozen audit-cert + hash-chain wire format is never
// affected by this intake.
func CreatePDFSourceDocument(ctx context.Context, q documentQueries, st objectStore, orgID, userID uuid.UUID, name string, data []byte) (*generated.Document, int, error) {
	doc, pages, _, err := createPDFSourceDocument(ctx, q, st, orgID, userID, name, pgtype.UUID{}, pgtype.Timestamptz{}, data)
	return doc, pages, err
}

// CreatePDFTemplateDocument takes the same bounded scan/clean/count/store path
// for a freshly rendered approved master. The caller must retain template and
// actor authorization and attach the immutable materialization in the same tx.
// On success it also returns the owned source for exact compensation of later
// failures. On failure intake performs its own detached, bounded compensation;
// the returned ownership is zero and cleanup failures remain joined errors.
func CreatePDFTemplateDocument(ctx context.Context, q documentQueries, st objectStore, orgID, userID uuid.UUID, name string, templateID uuid.UUID, expiresAt pgtype.Timestamptz, data []byte) (*generated.Document, int, OwnedPDFSource, error) {
	if orgID == uuid.Nil || userID == uuid.Nil || templateID == uuid.Nil {
		return nil, 0, OwnedPDFSource{}, errors.New("organization, user and template IDs required")
	}
	return createPDFSourceDocument(ctx, q, st, orgID, userID, name, pgtype.UUID{Bytes: templateID, Valid: true}, expiresAt, data)
}

// CreateComposedPDFTemplateDocument stores the exact once-cleaned output from
// the isolated composition worker. Re-cleaning would invalidate its component
// and geometry manifest. The pure validator rechecks bytes and measured proof
// before the first object or database write.
func CreateComposedPDFTemplateDocument(ctx context.Context, q documentQueries, st objectStore, orgID, userID uuid.UUID, name string, templateID uuid.UUID, expiresAt pgtype.Timestamptz, composed sanitize.PDFCompositionResult) (*generated.Document, int, OwnedPDFSource, error) {
	if orgID == uuid.Nil || userID == uuid.Nil || templateID == uuid.Nil {
		return nil, 0, OwnedPDFSource{}, errors.New("organization, user and template IDs required")
	}
	prepared, err := PrepareComposedPDFTemplateSource(ctx, st, orgID, composed)
	if err != nil {
		return nil, 0, OwnedPDFSource{}, err
	}
	return attachPreparedPDFSource(ctx, q, st, prepared, orgID, userID, name, pgtype.UUID{Bytes: templateID, Valid: true}, expiresAt)
}

func createPDFSourceDocument(ctx context.Context, q documentQueries, st objectStore, orgID, userID uuid.UUID, name string, templateID pgtype.UUID, expiresAt pgtype.Timestamptz, data []byte) (*generated.Document, int, OwnedPDFSource, error) {
	prepared, err := PreparePDFTemplateSource(ctx, st, orgID, data)
	if err != nil {
		return nil, 0, OwnedPDFSource{}, err
	}
	return attachPreparedPDFSource(ctx, q, st, prepared, orgID, userID, name, templateID, expiresAt)
}

func attachPreparedPDFSource(ctx context.Context, q documentQueries, st objectStore, prepared *PreparedPDFSource, orgID, userID uuid.UUID, name string, templateID pgtype.UUID, expiresAt pgtype.Timestamptz) (*generated.Document, int, OwnedPDFSource, error) {
	doc, err := prepared.attach(ctx, q, orgID, userID, name, templateID, expiresAt)
	if err != nil {
		owned := prepared.OwnedSource()
		cleanupErr := deleteAfterFailedWrite(ctx, st, owned.Key, storage.StoredObject{VersionID: owned.VersionID, SHA256: owned.SHA256})
		if cleanupErr != nil {
			return nil, 0, OwnedPDFSource{}, errors.Join(
				err,
				fmt.Errorf("delete orphaned PDF %q: %w", owned.Key, cleanupErr),
			)
		}
		return nil, 0, OwnedPDFSource{}, err
	}
	return doc, prepared.PageCount(), prepared.OwnedSource(), nil
}

func deleteAfterFailedWrite(parent context.Context, st objectStore, key string, stored storage.StoredObject) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), orphanCleanupTimeout)
	defer cancel()
	return st.DeleteVersion(cleanupCtx, key, stored.VersionID, stored.SHA256[:])
}

// Compile-time assertions keep interface drift visible at the storage/query
// boundary rather than surfacing only in a handler build.
var _ objectStore = (*storage.Client)(nil)
var _ documentQueries = (*generated.Queries)(nil)
