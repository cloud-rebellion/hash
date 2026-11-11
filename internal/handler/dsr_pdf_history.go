// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/objectretire"
)

// dsrHistoryGateV1 is the outcome of the per-document checks that every document
// whose PDF revision history a DSR erasure would remove must pass, the linked
// document included.
type dsrHistoryGateV1 struct {
	// Authorized is false when the actor neither owns nor sent the document and
	// is not an org owner. Revision read and replace are owner-or-sender too.
	Authorized bool
	// Eligible is false while the document is in an active or unsealed evidence
	// ceremony, or holds collaboration recovery archives (see
	// documentAllowsDestructiveErasure).
	Eligible bool
}

// dsrHistoryGateDocumentV1 locks one in-scope document and applies the checks.
// Documents are gated in the order the selection query returns them (by id), but
// that order is NOT globally consistent: the request has already locked its
// linked document, which can have a higher id than other in-scope documents. Two
// erasures with different linked documents would therefore deadlock, so
// handleTransitionDSR serializes erasure fulfilment per organization first
// (LockDSRErasureFulfilmentV1) and maps a deadlock that still happens against a
// writer outside this path to a retryable 503 (writeDSRRetryableV1).
func dsrHistoryGateDocumentV1(ctx context.Context, q *generated.Queries, orgID, actorID uuid.UUID, actorIsOwner bool, documentID uuid.UUID) (dsrHistoryGateV1, error) {
	doc, err := q.GetDocumentForPrivacyUpdate(ctx, generated.GetDocumentForPrivacyUpdateParams{DocumentID: documentID, OrgID: orgID})
	if err != nil {
		return dsrHistoryGateV1{}, fmt.Errorf("lock document: %w", err)
	}
	gate := dsrHistoryGateV1{Authorized: actorIsOwner || doc.SenderID == actorID}
	hasRecoveryArchives, err := q.HasCollabRecoveryArchivesForDSR(ctx, generated.HasCollabRecoveryArchivesForDSRParams{DocumentID: doc.ID, OrgID: orgID})
	if err != nil {
		return dsrHistoryGateV1{}, fmt.Errorf("check collaboration recovery archives: %w", err)
	}
	signatures, err := q.ListSignaturesByDocument(ctx, doc.ID)
	if err != nil {
		return dsrHistoryGateV1{}, fmt.Errorf("load signatures: %w", err)
	}
	gate.Eligible = !hasRecoveryArchives && documentAllowsDestructiveErasure(doc, len(signatures) > 0)
	return gate, nil
}

// dsrHistoryActorIsOwnerV1 reads the actor's live role under the share lock the
// transaction already holds.
func dsrHistoryActorIsOwnerV1(ctx context.Context, q *generated.Queries, orgID, actorID uuid.UUID) (bool, error) {
	user, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: actorID, OrgID: orgID})
	if err != nil {
		return false, fmt.Errorf("load actor role: %w", err)
	}
	return user.Role == string(auth.RoleOwner), nil
}

// erasePDFRevisionHistoryTx erases one document's PDF revision and review rows
// inside the caller's DSR transaction and appends one audit event for it (the
// document id, revision, review and object counts, and the DSR id, no subject
// data). It deletes no stored object: the exact object versions that nothing
// else names are recorded as pending object deletions in this same transaction
// (M127) and returned for the caller to attempt AFTER the transaction commits.
// A request that rolls back records nothing and deletes nothing; a request that
// commits owes the object store those deletions durably, so a storage fault, a
// crash or an ambiguous commit cannot strand the subject's PDF with no record.
// The document stays: its current PDF and every key another row names are kept.
func (s *Server) erasePDFRevisionHistoryTx(ctx context.Context, tx pgx.Tx, q *generated.Queries, orgID, actorID, requestID, documentID uuid.UUID) ([]*generated.PendingObjectDeletionsV1, audit.PendingEvent, error) {
	doc, err := q.GetDocumentForPrivacyUpdate(ctx, generated.GetDocumentForPrivacyUpdateParams{DocumentID: documentID, OrgID: orgID})
	if err != nil {
		return nil, audit.PendingEvent{}, fmt.Errorf("lock document: %w", err)
	}
	objects, err := q.ListDocumentPDFRevisionObjects(ctx, generated.ListDocumentPDFRevisionObjectsParams{DocumentID: documentID, OrgID: orgID})
	if err != nil {
		return nil, audit.PendingEvent{}, fmt.Errorf("list revision objects: %w", err)
	}
	reviews, err := q.CountDocumentPDFReviewsForDSR(ctx, generated.CountDocumentPDFReviewsForDSRParams{DocumentID: documentID, OrgID: orgID})
	if err != nil {
		return nil, audit.PendingEvent{}, fmt.Errorf("count reviews: %w", err)
	}
	revisions, err := q.EraseDocumentPDFHistory(ctx, generated.EraseDocumentPDFHistoryParams{DocumentID: documentID, Purge: false})
	if err != nil {
		return nil, audit.PendingEvent{}, fmt.Errorf("erase rows: %w", err)
	}
	own := map[string]bool{}
	for _, key := range []string{doc.PdfStorageKey.String, doc.RenderedPdfKey.String, doc.FinalPdfKey.String, doc.AuditCertKey.String, doc.AuditPayloadKey.String, doc.AuditSignatureKey.String} {
		own[key] = true
	}
	seen := map[string]bool{}
	var retire []objectretire.Object
	for _, object := range objects {
		if own[object.ObjectKey] || seen[object.ObjectKey] || object.ObjectKey == "" {
			continue
		}
		seen[object.ObjectKey] = true
		shared, err := q.HasOtherDocumentSourceReferences(ctx, generated.HasOtherDocumentSourceReferencesParams{DocumentID: documentID, ObjectKey: object.ObjectKey})
		if err != nil {
			return nil, audit.PendingEvent{}, fmt.Errorf("check shared references: %w", err)
		}
		if shared {
			continue
		}
		retire = append(retire, objectretire.Object{Key: object.ObjectKey, VersionID: object.VersionID, SHA256: object.Sha256})
	}
	if len(retire) > 0 && s.Storage == nil {
		return nil, audit.PendingEvent{}, errors.New("storage unavailable")
	}
	pendingDeletions, err := objectretire.Record(ctx, q, orgID, documentID, &requestID, retire)
	if err != nil {
		return nil, audit.PendingEvent{}, err
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID:       orgID,
		ActorUserID: &actorID,
		DocumentID:  &documentID,
		Kind:        audit.KindDataSubjectPDFHistoryErased,
		Payload: map[string]any{
			"request_id":     requestID,
			"document_id":    documentID,
			"revision_count": revisions,
			"review_count":   reviews,
			"object_count":   len(retire),
		},
	})
	if err != nil {
		return nil, audit.PendingEvent{}, fmt.Errorf("audit history erasure: %w", err)
	}
	if err = measureBorrowedAuditEventV1(ctx, q, orgID, documentID, pending.ID); err != nil {
		return nil, audit.PendingEvent{}, fmt.Errorf("measure history erasure audit: %w", err)
	}
	return pendingDeletions, pending, nil
}

// dsrRetireBudget bounds the time the post-commit attempts hold the response.
// The erasure has already committed and every object has a pending row, so a
// slow or hung object store must not keep the caller waiting toward the 60 s
// request timeout, where a client that gives up would see an error for an erasure
// that succeeded. The budget caps each delete call as well as the start of the
// next one (objectretire.AttemptAll); with one bookkeeping write of up to 5 s the
// response waits at most about 10 s. Whatever is not confirmed gone in time stays
// pending and the worker sweep drains it.
const dsrRetireBudget = 5 * time.Second

// retireDSRHistoryObjectsV1 makes the first attempt at deleting the stored
// revision objects of a committed erasure. The rows that named them are gone, but
// each object has a pending row written in the erasure's transaction, so a
// failure here cannot lose the obligation. A failure the store reports is counted
// against the row. A delete cut short by dsrRetireBudget is not counted: the row
// keeps its grace period and the worker sweep, which counts every failure, retries
// until the exact version is gone.
func (s *Server) retireDSRHistoryObjectsV1(ctx context.Context, pending []*generated.PendingObjectDeletionsV1) {
	if len(pending) == 0 {
		return
	}
	done := objectretire.AttemptAll(ctx, s.Queries, s.Storage, pending, dsrRetireBudget)
	if done < len(pending) {
		slog.Warn("DSR revision object retirement incomplete after commit; the worker sweep retries from the pending rows", "pending", len(pending)-done)
	}
}
