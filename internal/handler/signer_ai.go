// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/aiauthoring"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type signerClarifierInput struct {
	BlockID       string `json:"block_id"`
	SelectionText string `json:"selection_text"`
	Question      string `json:"question"`
	Locale        string `json:"locale"`
}

type signerClarifierGuard struct {
	admitted  *sign.RecipientContext
	document  *generated.Document
	recipient *generated.Recipient
	notice    sign.Article13NoticeEvidence
}

func (g *signerClarifierGuard) recheck(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	// A mutable server-side extension cannot extend this already-admitted
	// request's original deadline. A shorter live deadline also takes effect.
	for _, deadline := range []time.Time{g.admitted.Recipient.MagicTokenExpiresAt.Time, g.admitted.Document.ExpiresAt.Time} {
		if !deadline.IsZero() && !now.Before(deadline) {
			return sign.ErrMagicLinkExpired
		}
	}
	if err := sign.ValidateLockedRecipientCredential(g.admitted, g.recipient, g.document, now); err != nil {
		return err
	}
	return sign.ValidateLockedNoticeEvidence(g.admitted, g.document, g.notice)
}

func lockSignerClarifier(ctx context.Context, tx pgx.Tx, rc *sign.RecipientContext, notice sign.Article13NoticeEvidence) (*signerClarifierGuard, error) {
	if rc == nil || rc.Document == nil || rc.Recipient == nil {
		return nil, sign.ErrMagicLinkExpired
	}
	q := generated.New(tx)
	var family []*generated.Document
	if rc.Document.ParentEnvelopeID.Valid {
		root, err := q.GetDocumentForShare(ctx, generated.GetDocumentForShareParams{ID: uuid.UUID(rc.Document.ParentEnvelopeID.Bytes), OrgID: rc.Document.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, authoring.ErrAIAppDocumentClosed
		}
		if err != nil {
			return nil, err
		}
		if !root.IsEnvelope || root.ParentEnvelopeID.Valid {
			return nil, authoring.ErrAIAppDocumentClosed
		}
		family = append(family, root)
	}
	doc, err := q.GetDocumentForShare(ctx, generated.GetDocumentForShareParams{ID: rc.Document.ID, OrgID: rc.Document.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, authoring.ErrAIAppDocumentClosed
	}
	if err != nil {
		return nil, err
	}
	if doc.ParentEnvelopeID != rc.Document.ParentEnvelopeID {
		return nil, authoring.ErrAIAppDocumentClosed
	}
	family = append(family, doc)
	recipient, err := q.GetRecipientForShare(ctx, generated.GetRecipientForShareParams{ID: rc.Recipient.ID, DocumentID: doc.ID, OrgID: doc.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sign.ErrMagicLinkExpired
	}
	if err != nil {
		return nil, err
	}
	guard := &signerClarifierGuard{admitted: rc, document: doc, recipient: recipient, notice: notice}
	if err = guard.recheck(ctx); err != nil {
		return nil, err
	}
	fence, err := q.TryCollabArchivePrivacyFence(ctx, doc.OrgID)
	if err != nil {
		return nil, err
	}
	if !fence {
		return nil, authoring.ErrPrivacyReviewChanging
	}
	for _, member := range family {
		switch member.Status {
		case "sent", "in_progress", "changes_requested":
		default:
			return nil, authoring.ErrAIAppDocumentClosed
		}
		pending, err := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: member.ID, OrgID: member.OrgID})
		if err != nil {
			return nil, err
		}
		if pending {
			return nil, authoring.ErrPendingPrivacyReview
		}
	}
	return guard, nil
}

// completeSignerClarifier keeps recipient authentication separate from staff
// authorization. Request/notice evidence commits before dispatch; the same
// original magic token and notice are reacquired and rechecked for delivery.
// Accounting survives cancellation and refused results, with no staff actor.
func (s *Server) completeSignerClarifier(r *http.Request, ctx context.Context, request *sign.SignerAIRequestV1, in signerClarifierInput) (*aiauthoring.ResultV1[aiapps.ClarifyResult], error) {
	if s.Clarifier == nil || s.Clarifier.Runtime == nil {
		return nil, errors.New("AI completion dependencies unavailable")
	}
	result, err := aiauthoring.CompleteSignerClarifierV1(r.Context(), ctx, aiauthoring.DependenciesV1{Pool: s.Pool, Sessions: s.HTMLCreationSessions, Audit: s.Audit}, request, s.Clarifier.Runtime, aiauthoring.SignerClarifyInputV1{BlockID: in.BlockID, SelectionText: in.SelectionText, Question: in.Question, Locale: in.Locale})
	return result, signerClarifierFailureV1(err)
}
func signerClarifierFailureV1(err error) error {
	if errors.Is(err, pdfadmission.ErrSignerAIExpiredV1) {
		return errors.Join(sign.ErrMagicLinkExpired, err)
	}
	if errors.Is(err, pdfadmission.ErrSignerAINoticeV1) {
		return errors.Join(sign.ErrInvalidNoticeEvidence, err)
	}
	if errors.Is(err, authoring.ErrAIAppDocumentClosed) {
		return errors.Join(sign.ErrDocumentNotSignable, err)
	}
	return err
}

func (s *Server) writeSignerClarifierError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sign.ErrMagicLinkExpired):
		writeError(w, http.StatusGone, "magic link expired")
	case errors.Is(err, sign.ErrInvalidNoticeEvidence):
		writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
	case errors.Is(err, authoring.ErrAIAppDocumentClosed):
		writeError(w, http.StatusConflict, "this document is no longer active")
	case errors.Is(err, authoring.ErrAIBlockNotFound):
		writeError(w, http.StatusNotFound, authoring.ErrAIBlockNotFound.Error())
	default:
		s.writeDraftAuthoringError(w, "signer clarification failed", err)
	}
}
