// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type purgeObjectDeleter interface {
	DeleteVersion(context.Context, string, string, []byte) error
}

type purgeObjectVersion struct {
	key, versionID string
	digest         []byte
}

type purgeRowDelete func(context.Context, *generated.Document) (int64, error)

type softDeletePurgeQueries interface {
	LockClaimedSoftDeletedDocumentForPurge(context.Context, generated.LockClaimedSoftDeletedDocumentForPurgeParams) (*generated.Document, error)
	TryCollabArchivePrivacyFence(context.Context, uuid.UUID) (bool, error)
	HasPendingDocumentPrivacyRequests(context.Context, generated.HasPendingDocumentPrivacyRequestsParams) (bool, error)
	HasOtherDocumentSourceReferences(context.Context, generated.HasOtherDocumentSourceReferencesParams) (bool, error)
	HasRetainedDraftEvidenceForPurge(context.Context, generated.HasRetainedDraftEvidenceForPurgeParams) (bool, error)
	DeleteClaimedSoftDeletedDocument(context.Context, generated.DeleteClaimedSoftDeletedDocumentParams) (int64, error)
}

type softDeletePurgeTransaction struct {
	queries  softDeletePurgeQueries
	commit   func(context.Context) error
	rollback func(context.Context) error
}

type softDeletePurgeBegin func(context.Context) (softDeletePurgeTransaction, error)

// Soft-delete purge loop (carryover from audit fix #10).
//
// fix #10 changed DeleteDraftDocument from a hard DROP to flipping
// documents.deleted_at, plus added a PurgeSoftDeletedDocuments query
// that takes a cutoff timestamp. This loop is the cron that actually
// runs the purge so the grace window doesn't grow without bound.
//
// Cadence: every 6 hours. Cutoff: 90 days after deleted_at, matching
// the privacy-policy retention statement for in-flight DSR requests.
//
// Per-tick work is bounded and leased. A row is not hard-deleted until its
// document-owned source object is removed; storage failures leave the row (and
// therefore its cleanup key) available for a later retry.

const (
	softDeletePurgeInterval   = 6 * time.Hour
	softDeleteGraceWindow     = 90 * 24 * time.Hour
	softDeletePurgeBatch      = 100
	softDeleteClaimTimeout    = 5 * time.Second
	softDeleteTotalTimeout    = 20 * time.Second
	softDeleteObjectTimeout   = 15 * time.Second
	softDeleteRollbackTimeout = 2 * time.Second
)

func (w *worker) loopSoftDeletePurge(ctx context.Context) {
	tick := time.NewTicker(softDeletePurgeInterval)
	defer tick.Stop()
	w.runSoftDeletePurgeOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runSoftDeletePurgeOnce(ctx)
		}
	}
}

func (w *worker) runSoftDeletePurgeOnce(ctx context.Context) {
	started := time.Now()
	state := w.runSoftDeletePurgeOnceObserved(ctx)
	w.reportInvocation385(ctx, flarereport.JobSoftDeletePurge, started, state)
}
func (w *worker) runSoftDeletePurgeOnceObserved(ctx context.Context) flarereport.JobInvocationState {
	cutoff := pgtype.Timestamptz{Time: time.Now().Add(-softDeleteGraceWindow), Valid: true}
	claimCtx, cancelClaim := context.WithTimeout(ctx, softDeleteClaimTimeout)
	claimed, err := w.queries.ClaimSoftDeletedDocumentsForPurge(claimCtx, generated.ClaimSoftDeletedDocumentsForPurgeParams{
		Cutoff: cutoff, BatchLimit: softDeletePurgeBatch,
	})
	cancelClaim()
	if err != nil {
		slog.Warn("soft_delete_purge: claim failed", "err", err, "cutoff", cutoff.Time)
		return flarereport.InvocationUnavailable
	}
	state := flarereport.InvocationReturned
	deleted := 0
	for _, doc := range claimed {
		if doc == nil {
			state = flarereport.InvocationUnobservable
			continue
		}
		rows, err := purgeClaimedSoftDeletedDocument(ctx, doc, cutoff, w.storage, w.beginSoftDeletePurge)
		if err != nil {
			state = mergeWorkerInvocation385(state, flarereport.InvocationPartial)
			slog.Warn("soft_delete_purge: protected cleanup failed", "document_id", doc.ID, "err", err)
			continue
		}
		if rows > 0 {
			deleted++
		}
	}
	slog.Debug("soft_delete_purge: tick complete", "cutoff", cutoff.Time, "claimed", len(claimed), "deleted", deleted)
	return state
}
func (w *worker) beginSoftDeletePurge(ctx context.Context) (softDeletePurgeTransaction, error) {
	if w.pool == nil || w.queries == nil {
		return softDeletePurgeTransaction{}, errors.New("soft delete purge: database unavailable")
	}
	// Fresh privacy checks must see commits made before the parent/organization
	// fences. A fixed snapshot would keep stale global request eligibility.
	tx, err := w.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return softDeletePurgeTransaction{}, err
	}
	return softDeletePurgeTransaction{
		queries: w.queries.WithTx(tx), commit: tx.Commit, rollback: tx.Rollback,
	}, nil
}

func purgeClaimedSoftDeletedDocument(ctx context.Context, claim *generated.Document, cutoff pgtype.Timestamptz, objects purgeObjectDeleter, begin softDeletePurgeBegin) (int64, error) {
	if claim == nil || begin == nil || !cutoff.Valid || !claim.UpdatedAt.Valid {
		return 0, errors.New("soft delete purge: exact document lease and transaction are required")
	}
	totalCtx, cancel := context.WithTimeout(ctx, softDeleteTotalTimeout)
	defer cancel()
	tx, err := begin(totalCtx)
	if err != nil {
		return 0, fmt.Errorf("begin protected purge: %w", err)
	}
	if tx.rollback == nil {
		return 0, errors.New("soft delete purge: rollback is required")
	}
	defer func() {
		rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(totalCtx), softDeleteRollbackTimeout)
		defer cancelRollback()
		_ = tx.rollback(rollbackCtx)
	}()
	if tx.queries == nil || tx.commit == nil {
		return 0, errors.New("soft delete purge: transaction queries and commit are required")
	}
	lockedDoc, err := tx.queries.LockClaimedSoftDeletedDocumentForPurge(totalCtx, generated.LockClaimedSoftDeletedDocumentForPurgeParams{
		ID: claim.ID, OrgID: claim.OrgID, Cutoff: cutoff, UpdatedAt: claim.UpdatedAt,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// A stale lease or an already-locked parent must not cause object I/O.
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("lock exact purge lease: %w", err)
	}
	if lockedDoc == nil || lockedDoc.ID != claim.ID || lockedDoc.OrgID != claim.OrgID {
		return 0, errors.New("soft delete purge: locked document does not match the claim")
	}
	acquired, err := tx.queries.TryCollabArchivePrivacyFence(totalCtx, lockedDoc.OrgID)
	if err != nil {
		return 0, fmt.Errorf("lock privacy fence: %w", err)
	}
	if !acquired {
		return 0, nil
	}
	pending, err := tx.queries.HasPendingDocumentPrivacyRequests(totalCtx, generated.HasPendingDocumentPrivacyRequestsParams{
		DocumentID: lockedDoc.ID, OrgID: lockedDoc.OrgID,
	})
	if err != nil {
		return 0, fmt.Errorf("check pending privacy requests: %w", err)
	}
	if pending {
		return 0, nil
	}
	retained, err := tx.queries.HasRetainedDraftEvidenceForPurge(totalCtx, generated.HasRetainedDraftEvidenceForPurgeParams{DocumentID: lockedDoc.ID, OrgID: lockedDoc.OrgID})
	if err != nil {
		return 0, fmt.Errorf("check retained draft evidence: %w", err)
	}
	if retained {
		return 0, errors.New("soft delete purge: retained evidence or sealing state requires review")
	}
	sourceKey, err := ownedPurgeSourceKey(lockedDoc)
	if err != nil {
		return 0, err
	}
	if sourceKey != "" {
		shared, err := tx.queries.HasOtherDocumentSourceReferences(totalCtx, generated.HasOtherDocumentSourceReferencesParams{
			DocumentID: lockedDoc.ID, ObjectKey: sourceKey,
		})
		if err != nil {
			return 0, fmt.Errorf("check shared source references: %w", err)
		}
		if shared {
			// Another durable row owns the cleanup reference; retain the object
			// and allow only this expired draft's parent row to be removed.
			sourceKey = ""
		}
	}
	rows, err := deleteClaimedSoftDeletedSourceAndRow(totalCtx, lockedDoc, sourceKey, objects, func(ctx context.Context, doc *generated.Document) (int64, error) {
		return tx.queries.DeleteClaimedSoftDeletedDocument(ctx, generated.DeleteClaimedSoftDeletedDocumentParams{
			ID: doc.ID, OrgID: doc.OrgID, DeletedAt: cutoff, UpdatedAt: doc.UpdatedAt,
		})
	})
	if err != nil {
		return 0, err
	}
	if rows != 1 {
		return 0, errors.New("soft delete purge: protected document lease was not deleted")
	}
	if err := tx.commit(totalCtx); err != nil {
		return 0, fmt.Errorf("commit protected purge: %w", err)
	}
	return rows, nil
}

func cleanupClaimedSoftDeletedDocument(ctx context.Context, doc *generated.Document, objects purgeObjectDeleter, deleteRow purgeRowDelete) (int64, error) {
	if doc == nil || deleteRow == nil {
		return 0, errors.New("soft delete purge: document and row delete are required")
	}
	key, err := ownedPurgeSourceKey(doc)
	if err != nil {
		return 0, err
	}
	return deleteClaimedSoftDeletedSourceAndRow(ctx, doc, key, objects, deleteRow)
}

func deleteClaimedSoftDeletedSourceAndRow(ctx context.Context, doc *generated.Document, key string, objects purgeObjectDeleter, deleteRow purgeRowDelete) (int64, error) {
	if key != "" {
		version := doc.PdfStorageVersionID
		if !version.Valid || version.String == "" || strings.TrimSpace(version.String) != version.String || len(version.String) > 1024 {
			return 0, errors.New("soft delete purge: source version requires review")
		}
		object, err := purgeOwnedSourceVersion(doc)
		if err != nil {
			return 0, err
		}
		if object == nil || object.key != key {
			return 0, errors.New("soft delete purge: source cleanup commitment requires review")
		}
		if objects == nil {
			return 0, errors.New("soft delete purge: storage unavailable")
		}
		deleteCtx, cancel := context.WithTimeout(ctx, softDeleteObjectTimeout)
		err = objects.DeleteVersion(deleteCtx, key, version.String, object.digest)
		cancel()
		if err != nil {
			return 0, fmt.Errorf("delete source object: %w", err)
		}
	}
	return deleteRow(ctx, doc)
}

func ownedPurgeSourceKey(doc *generated.Document) (string, error) {
	if err := validateHTMLPurgeSource(doc); err != nil {
		return "", err
	}
	if doc != nil && doc.Status == "draft" && doc.SourceKind != "pdf" &&
		doc.PdfStorageKey.Valid && doc.PdfStorageKey.String != "" {
		return "", errors.New("soft delete purge: source kind and cleanup reference require review")
	}
	key := purgeOwnedSourceKey(doc)
	if key == "" {
		if doc != nil && doc.Status == "draft" && !doc.TemplateID.Valid && doc.SourceKind == "pdf" &&
			(!doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "") {
			return "", errors.New("soft delete purge: source cleanup key requires review")
		}
		return "", nil
	}
	// Intake uses a separate object UUID, not the document ID, in this exact
	// four-part namespace. Reject unrelated or malformed keys rather than
	// losing the only durable cleanup reference by deleting their parent row.
	parts := strings.Split(key, "/")
	if len(parts) != 4 || parts[0] != "org" || parts[1] != doc.OrgID.String() || parts[2] != "documents" || !strings.HasSuffix(parts[3], ".pdf") {
		return "", errors.New("soft delete purge: source namespace requires review")
	}
	objectName := strings.TrimSuffix(parts[3], ".pdf")
	objectID, err := uuid.Parse(objectName)
	if err != nil || objectID == uuid.Nil || objectID.String() != objectName {
		return "", errors.New("soft delete purge: source namespace requires review")
	}
	return key, nil
}

// purgeOwnedSourceKey identifies independently owned PDF draft sources.
// Static PDF template clones share their source object and must retain it.
// HTML materializations instead own a fresh object; callers validate their
// source provenance before admitting cleanup. Final/audit aliases are legal
// evidence and must never be removed by draft cleanup.
func purgeOwnedSourceKey(doc *generated.Document) string {
	if doc == nil || doc.Status != "draft" || doc.SourceKind != "pdf" || (doc.TemplateID.Valid && len(doc.HtmlSourceJson) == 0) ||
		!doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" {
		return ""
	}
	key := doc.PdfStorageKey.String
	if (doc.FinalPdfKey.Valid && doc.FinalPdfKey.String == key) ||
		(doc.AuditCertKey.Valid && doc.AuditCertKey.String == key) ||
		(doc.AuditPayloadKey.Valid && doc.AuditPayloadKey.String == key) ||
		(doc.AuditSignatureKey.Valid && doc.AuditSignatureKey.String == key) {
		return ""
	}
	return key
}

func purgeOwnedSourceVersion(doc *generated.Document) (*purgeObjectVersion, error) {
	if err := validateHTMLPurgeSource(doc); err != nil {
		return nil, err
	}
	if doc == nil || doc.Status != "draft" || (doc.TemplateID.Valid && len(doc.HtmlSourceJson) == 0) ||
		!doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" {
		return nil, nil
	}
	key := doc.PdfStorageKey.String
	if (doc.FinalPdfKey.Valid && doc.FinalPdfKey.String == key) ||
		(doc.AuditCertKey.Valid && doc.AuditCertKey.String == key) {
		return nil, nil
	}
	if !doc.EvidenceVersionPinsRequired || !doc.PdfStorageVersionID.Valid ||
		strings.TrimSpace(doc.PdfStorageVersionID.String) == "" || len(doc.PdfSha256) != sha256.Size {
		return nil, errors.New("soft delete purge: draft source lacks its exact-version cleanup commitment")
	}
	return &purgeObjectVersion{
		key: key, versionID: doc.PdfStorageVersionID.String, digest: append([]byte(nil), doc.PdfSha256...),
	}, nil
}

func validateHTMLPurgeSource(doc *generated.Document) error {
	if doc == nil || len(doc.HtmlSourceJson) == 0 {
		return nil
	}
	if err := htmlsource.Validate(doc, false); err != nil {
		return fmt.Errorf("soft delete purge: HTML source provenance requires review: %w", err)
	}
	return nil
}
