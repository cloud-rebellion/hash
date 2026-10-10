// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
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
func (s *Server) completeSignerClarifier(r *http.Request, rc *sign.RecipientContext, notice sign.Article13NoticeEvidence, in signerClarifierInput) (aiapps.ClarifyResult, error) {
	zero := aiapps.ClarifyResult{}
	if s.Pool == nil || s.Audit == nil || s.Clarifier == nil || s.Clarifier.Runtime == nil {
		return zero, errors.New("signer AI dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(r.Context(), signerClarifierTimeout)
	defer cancel()
	accounting, releaseAccounting, err := authoring.ReserveAIAccounting(ctx, s.Pool)
	if err != nil {
		return zero, err
	}
	defer releaseAccounting()
	requestTx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return zero, err
	}
	defer func() { _ = authoring.Rollback(ctx, requestTx) }()
	requested, err := lockSignerClarifier(ctx, requestTx, rc, notice)
	if err != nil {
		return zero, err
	}
	requestPayload, err := bindSignerNoticeAuditPayload(notice, map[string]any{"via": "signer", "tool": "clarify_clause", "block_id": in.BlockID, "locale": in.Locale})
	if err != nil {
		return zero, err
	}
	// Keep the established Article13 event alongside the unique accounting
	// receipt. Neither record is a fabricated acknowledgement by the sender.
	requestEvent, err := s.Audit.LogTx(ctx, requestTx, audit.Entry{OrgID: requested.document.OrgID, DocumentID: &requested.document.ID, RecipientID: &requested.recipient.ID, Kind: "clarifier.requested", IP: clientIP(r), UserAgent: r.UserAgent(), Payload: requestPayload})
	if err != nil {
		return zero, err
	}
	receipt, err := s.Audit.LogTx(ctx, requestTx, audit.Entry{OrgID: requested.document.OrgID, DocumentID: &requested.document.ID, RecipientID: &requested.recipient.ID, Kind: "ai.requested", IP: clientIP(r), UserAgent: r.UserAgent(), Payload: requestPayload})
	if err != nil {
		return zero, err
	}
	if err = requested.recheck(ctx); err != nil {
		return zero, err
	}
	if err = requestTx.Commit(ctx); err != nil {
		return zero, err
	}
	s.Audit.Publish(requestEvent)
	s.Audit.Publish(receipt)
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return zero, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := lockSignerClarifier(ctx, tx, rc, notice)
	if err != nil {
		return zero, err
	}
	clauseText, surrounding := in.SelectionText, ""
	if in.BlockID != "" {
		block, err := authoring.AIAppBlock(guard.document, in.BlockID)
		if err != nil {
			return zero, err
		}
		if clauseText == "" {
			clauseText = block.Text
		}
		// This helper parses the same locked block tree and supplies neighbours.
		tree, err := blocks.ParseTree(guard.document.BlocksJson)
		if err != nil {
			return zero, err
		}
		_, before, after := lookupBlockWithNeighbours(tree, in.BlockID)
		surrounding = before + "\n\n" + after
	}
	observed := false
	runtime := s.Clarifier.Runtime.ForAuditedRequest(generated.New(tx), func(_ context.Context, p generated.InsertAICompletionAuditParams) error {
		if observed || p.OrgID != guard.document.OrgID || !p.DocumentID.Valid || uuid.UUID(p.DocumentID.Bytes) != guard.document.ID || p.ActorUserID.Valid {
			return errors.New("signer AI usage receipt mismatch")
		}
		observed = true
		costCtx, costCancel := context.WithTimeout(context.WithoutCancel(r.Context()), authoring.MutationTimeout)
		defer costCancel()
		usage, err := generated.New(accounting).InsertRequestedSignerAICompletionAudit(costCtx, generated.InsertRequestedSignerAICompletionAuditParams{
			RequestEventID: receipt.ID, OrgID: guard.document.OrgID, DocumentID: guard.document.ID, RecipientID: guard.recipient.ID,
			Provider: p.Provider, Model: p.Model, PromptName: p.PromptName, PromptVersion: p.PromptVersion, ShieldActive: p.ShieldActive,
			InputTokens: p.InputTokens, OutputTokens: p.OutputTokens, LatencyMs: p.LatencyMs, Success: p.Success, Error: p.Error, TransferJurisdiction: p.TransferJurisdiction,
		})
		if err != nil {
			slog.Error("signer AI usage persistence failed", "request_event_id", receipt.ID, "org_id", guard.document.OrgID)
			return errors.New("signer AI usage persistence failed")
		}
		costTx, err := accounting.BeginTx(costCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return errors.New("signer AI completion event persistence failed")
		}
		defer func() { _ = authoring.Rollback(costCtx, costTx) }()
		payload, err := bindSignerNoticeAuditPayload(notice, map[string]any{"via": "signer", "tool": "clarify_clause", "request_event_id": receipt.ID.String(), "usage_id": usage.ID.String(), "provider": p.Provider, "model": p.Model, "shield_active": p.ShieldActive, "input_tokens": p.InputTokens, "output_tokens": p.OutputTokens, "success": p.Success, "transfer_jurisdiction": p.TransferJurisdiction})
		if err != nil {
			return err
		}
		costEvent, err := s.Audit.LogTx(costCtx, costTx, audit.Entry{OrgID: guard.document.OrgID, DocumentID: &guard.document.ID, RecipientID: &guard.recipient.ID, Kind: "ai.completed", Payload: payload})
		if err != nil {
			slog.Error("signer AI completion event persistence failed", "request_event_id", receipt.ID, "org_id", guard.document.OrgID)
			return errors.New("signer AI completion event persistence failed")
		}
		if err = costTx.Commit(costCtx); err != nil {
			return errors.New("signer AI completion event persistence failed")
		}
		s.Audit.Publish(costEvent)
		return nil
	})
	if err = guard.recheck(ctx); err != nil {
		return zero, err
	}
	result, err := (&aiapps.Clarifier{Runtime: runtime}).Clarify(ctx, aiapps.ClarifyInput{OrgID: guard.document.OrgID, DocumentID: guard.document.ID, Locale: in.Locale, ClauseText: clauseText, SurroundingContext: surrounding, Question: in.Question})
	if err != nil {
		return zero, err
	}
	if err = guard.recheck(ctx); err != nil {
		return zero, err
	}
	answerPayload, err := bindSignerNoticeAuditPayload(notice, map[string]any{"via": "signer", "tool": "clarify_clause", "request_event_id": receipt.ID.String(), "block_id": in.BlockID, "locale": in.Locale, "shield_active": result.ShieldActive, "latency_ms": result.LatencyMs, "input_tokens": result.InputTokens, "output_tokens": result.OutputTokens})
	if err != nil {
		return zero, err
	}
	answered, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: guard.document.OrgID, DocumentID: &guard.document.ID, RecipientID: &guard.recipient.ID, Kind: "clarifier.answered", IP: clientIP(r), UserAgent: r.UserAgent(), Payload: answerPayload})
	if err != nil {
		return zero, err
	}
	if err = guard.recheck(ctx); err != nil {
		return zero, err
	}
	if err = tx.Commit(ctx); err != nil {
		return zero, err
	}
	s.Audit.Publish(answered)
	return result, nil
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
