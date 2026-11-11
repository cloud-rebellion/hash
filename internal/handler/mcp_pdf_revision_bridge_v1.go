// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/docintake"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type mcpPDFRevisionBridgeV1 struct{ server *Server }

func (s *Server) MCPPDFRevisionBridgeV1() mcp.PDFRevisionBridgeV1 {
	return &mcpPDFRevisionBridgeV1{server: s}
}

// safeMCPPDFRevisionFailureV1 keeps the actionable refusals (stale pins, state,
// human review required) and collapses everything else.
func safeMCPPDFRevisionFailureV1(err error) error {
	if err == nil {
		return nil
	}
	var business *pdfRevisionBusinessV1
	if errors.As(err, &business) {
		return errors.New(business.message)
	}
	for _, known := range []error{auth.ErrMutationPermissionRevoked, auth.ErrMutationCredentialExpired, context.Canceled, context.DeadlineExceeded, errHumanReviewRequiredV1,
		authoring.ErrDocumentNotFound, authoring.ErrDocumentNotDraft, authoring.ErrDocumentHasEvidence} {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, malwarescan.ErrDetected) {
		return errors.New("upload rejected by malware scanner")
	}
	if errors.Is(err, docintake.ErrSanitizePDF) || errors.Is(err, docintake.ErrTooManyPages) {
		return errors.New("the PDF could not be sanitized or exceeds the page limit")
	}
	if message, ok := sendReviewGateMessageV1(err); ok {
		return errors.New(message)
	}
	return errors.New("PDF revision unavailable or refused")
}

func (b *mcpPDFRevisionBridgeV1) ReplacePDFV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.PDFReplaceInputV1) (out any, failure error) {
	defer func() { failure = safeMCPPDFRevisionFailureV1(failure) }()
	if err := validMCPDesignActorV1(ctx, a); err != nil {
		return nil, err
	}
	pins, err := parsePDFRevisionPinsV1(in.ExpectedUpdatedAt, in.ExpectedPDFSHA256)
	if err != nil {
		return nil, err
	}
	ctx = withPDFRevisionToolV1(ctx, "replace_document_pdf")
	result, err := b.server.replaceDraftPDFOwnedV1(ctx, a.Actor, id, pins, in.PDF, in.Summary)
	if err != nil {
		return nil, err
	}
	defer result.Release()
	return map[string]any{
		"document_id": result.Document.ID, "revision": result.Revision.Sequence, "page_count": result.PageCount,
		"updated_at": result.Document.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "pdf_sha256": hex.EncodeToString(result.Document.PdfSha256),
		"review_required": true, "placement_reset": true,
	}, nil
}

func (b *mcpPDFRevisionBridgeV1) documentV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID) (*generated.Document, error) {
	d, err := b.server.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: id, OrgID: a.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, authoring.ErrDocumentNotFound
	}
	return d, err
}

func (b *mcpPDFRevisionBridgeV1) PDFHistoryV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID) (out any, failure error) {
	defer func() { failure = safeMCPPDFRevisionFailureV1(failure) }()
	if err := validMCPDesignActorV1(ctx, a); err != nil {
		return nil, err
	}
	d, err := b.documentV1(ctx, a, id)
	if err != nil {
		return nil, err
	}
	// Same rule as the REST reads: the key's user is an owner or the sender.
	user, err := b.server.Queries.GetUser(ctx, a.UserID)
	// A key credential has no session generation; the key itself was checked by
	// validMCPDesignActorV1. A lookup failure is not a revocation: it surfaces
	// as the generic unavailable failure so a client can retry.
	switch pdfRevisionReadAccessV1(user, err, a.OrgID, a.UserID, d.SenderID, 0, false) {
	case pdfRevisionAccessUnavailableV1:
		return nil, err
	case pdfRevisionAccessDeniedV1:
		return nil, auth.ErrMutationPermissionRevoked
	}
	return b.server.pdfHistoryV1(ctx, d)
}

func (b *mcpPDFRevisionBridgeV1) ReviewPDFV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.PDFReviewInputV1) (out any, failure error) {
	defer func() { failure = safeMCPPDFRevisionFailureV1(failure) }()
	if err := validMCPDesignActorV1(ctx, a); err != nil {
		return nil, err
	}
	pins, err := parsePDFRevisionPinsV1(in.ExpectedUpdatedAt, in.ExpectedPDFSHA256)
	if err != nil {
		return nil, err
	}
	d, err := b.documentV1(ctx, a, id)
	if err != nil {
		return nil, err
	}
	// A signing document is reviewed by a human in a staff session; the same
	// rule is enforced again under the lock and by the M124 trigger.
	if err = requireNonSigningForAgentReviewV1(d.Metadata); err != nil {
		return nil, err
	}
	state, err := b.server.Queries.GetPDFReviewStateV1(ctx, generated.GetPDFReviewStateV1Params{DocumentID: id, OrgID: a.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, pdfRevisionConflictV1("this document has no replaced PDF to review")
	}
	if err != nil {
		return nil, err
	}
	if err = mcp.DesignPageCoverageV1(in.ReviewedPages, int(state.PageCount)); err != nil {
		return nil, &pdfRevisionBusinessV1{400, err.Error(), "pdf_review_pages_invalid"}
	}
	ctx = withPDFRevisionToolV1(ctx, "review_document_pdf")
	result, err := b.server.reviewDraftPDFOwnedV1(ctx, a.Actor, id, pins, reviewerKindAgentV1, state.PageCount)
	if err != nil {
		return nil, err
	}
	defer result.Release()
	return map[string]any{
		"document_id": result.Document.ID, "reviewer_kind": result.Review.ReviewerKind, "reviewed_pages": result.Review.ReviewedPages,
		"updated_at": result.Document.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "pdf_review_required": false,
	}, nil
}

var _ mcp.PDFRevisionBridgeV1 = (*mcpPDFRevisionBridgeV1)(nil)
