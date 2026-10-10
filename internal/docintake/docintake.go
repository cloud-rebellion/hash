// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package docintake holds the one-step "designed proposal -> signable
// pdf-source document" intake shared by the REST import handler and the MCP
// ingest tool, so both take exactly the same verified clean + store + record
// path before the (unchanged) field-designer + sign/stamp/seal flow runs.
package docintake

import (
	"context"
	"crypto/sha256"
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

func createPDFSourceDocument(ctx context.Context, q documentQueries, st objectStore, orgID, userID uuid.UUID, name string, templateID pgtype.UUID, expiresAt pgtype.Timestamptz, data []byte) (*generated.Document, int, OwnedPDFSource, error) {
	cleaned, err := sanitize.CleanWithContext(ctx, "proposal-pdf", "application/pdf", data)
	if err != nil {
		if errors.Is(err, ErrTooManyPages) {
			return nil, 0, OwnedPDFSource{}, err
		}
		return nil, 0, OwnedPDFSource{}, fmt.Errorf("%w: %w", ErrSanitizePDF, err)
	}
	// Reject an amplification bomb BEFORE storing it or handing it to the
	// downstream pdfcpu passes.
	pageCount, err := sanitize.PageCountWithContext(ctx, cleaned.Bytes)
	if err != nil {
		return nil, 0, OwnedPDFSource{}, fmt.Errorf("%w: count sanitized PDF pages: %w", ErrSanitizePDF, err)
	}
	if pageCount > maxIntakePages {
		return nil, 0, OwnedPDFSource{}, fmt.Errorf("%w: %d pages exceeds the %d-page limit", ErrTooManyPages, pageCount, maxIntakePages)
	}
	key := path.Join("org", orgID.String(), "documents", uuid.NewString()+".pdf")
	stored, err := st.PutVersioned(ctx, key, "application/pdf", cleaned.Bytes)
	if err != nil {
		return nil, 0, OwnedPDFSource{}, err
	}
	d, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{
		OrgID:                       orgID,
		TemplateID:                  templateID,
		Name:                        name,
		PdfStorageKey:               pgtype.Text{String: key, Valid: true},
		PdfSha256:                   stored.SHA256[:],
		PdfStorageVersionID:         pgtype.Text{String: stored.VersionID, Valid: true},
		EvidenceVersionPinsRequired: true,
		SenderID:                    userID,
		ExpiresAt:                   expiresAt,
	})
	if err != nil {
		// Object storage and PostgreSQL cannot share a transaction. If the DB
		// insert fails after Put succeeded, compensate immediately using a
		// context detached from the request cancellation that commonly caused
		// the DB error. Otherwise every failed upload leaves an unreferenced PDF
		// in the bucket forever.
		cleanupErr := deleteAfterFailedWrite(ctx, st, key, stored)
		if cleanupErr != nil {
			return nil, 0, OwnedPDFSource{}, errors.Join(
				fmt.Errorf("create PDF document: %w", err),
				fmt.Errorf("delete orphaned PDF %q: %w", key, cleanupErr),
			)
		}
		return nil, 0, OwnedPDFSource{}, fmt.Errorf("create PDF document: %w", err)
	}
	// Record the measured source cleaning on the document so the audit cert can
	// reference it without a template lookup.
	rep, rerr := sanitize.MergeReports(nil, cleaned.Report)
	if rerr != nil {
		cleanupErr := deleteAfterFailedWrite(ctx, st, key, stored)
		return nil, 0, OwnedPDFSource{}, errors.Join(fmt.Errorf("build metadata redaction report: %w", rerr), cleanupErr)
	}
	if err := q.UpdateMetadataRedactionReport(ctx, generated.UpdateMetadataRedactionReportParams{
		ID: d.ID, MetadataRedactionReport: rep,
	}); err != nil {
		cleanupErr := deleteAfterFailedWrite(ctx, st, key, stored)
		return nil, 0, OwnedPDFSource{}, errors.Join(fmt.Errorf("persist metadata redaction report: %w", err), cleanupErr)
	}
	return d, pageCount, OwnedPDFSource{Key: key, VersionID: stored.VersionID, SHA256: stored.SHA256}, nil
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
