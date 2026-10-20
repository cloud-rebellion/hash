// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"
	"fmt"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Each fixed scalar/recovery phase keeps the parent-before-intent lock order
// and uses the actual operation's original deadline and genuine native owner.
func (e *Engine) readOwnedSendIntentV1(ctx context.Context, o *ownedSendOperationV1) (intent pdfadmission.HTMLSendRetentionProjectionV1, failure error) {
	if !o.valid(ctx) {
		return intent, pdfadmission.ErrHTMLSendWorkV1
	}
	var source *pdfadmission.ApplicationHTMLSendWorkV1
	var retained *pdfadmission.ApplicationHTMLSendRetentionStateV1
	failure = o.phaseV1(pdfadmission.HTMLSendIntentReadV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		if _, err := p.work.StateV1(call); err != nil {
			return err
		}
		if _, err := p.work.ReadIntentV1(call); err != nil {
			return err
		}
		var err error
		retained, err = p.work.CaptureSendRetentionStateV1(call)
		if err == nil {
			source = p.work
		}
		return err
	})
	if failure != nil {
		return intent, failure
	}
	intent, failure = retained.SnapshotV1()
	if failure != nil {
		return intent, failure
	}
	// Only this actual read's scalar projection escapes; no actor/key/string or
	// original row remains in use. Its synchronous callback, COMMIT and CloseSQL
	// joined before ending the exact private Work consumer and reconciling.
	failure = o.retireIntentReadWorkV1(source)
	return intent, failure
}
func (e *Engine) completedOwnedSendResultV1(ctx context.Context, o *ownedSendOperationV1) (out SendResult, failure error) {
	if !o.valid(ctx) {
		return out, pdfadmission.ErrHTMLSendWorkV1
	}
	failure = o.phaseV1(pdfadmission.HTMLSendCompletedV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		state, err := p.work.StateV1(call)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDocumentNotFound
		}
		if err != nil {
			return fmt.Errorf("resume send sealing: reconcile completed document: %w", err)
		}
		var ok bool
		out, ok = completedOwnedSendStatusV1(state)
		if ok {
			return nil
		}
		return fmt.Errorf("resume send sealing: intent unavailable while document status is %s: %w", state.BoundedStatus, ErrNotDraft)
	})
	return out, failure
}

// This exact scalar projection preserves completedSendSealingStatus without
// manufacturing a partially populated Document or reconstructing token links.
func completedOwnedSendStatusV1(state *generated.GetHTMLSendDocumentStateHeaderV1Row) (SendResult, bool) {
	if state != nil && state.HasPackageSendHistory {
		return SendResult{}, false
	}
	if state == nil || !state.EvidenceVersionPinsRequired || !state.SentAt.Valid || state.SentAt.Time.IsZero() ||
		!state.Article13NoticeEpochAt.Valid || !state.Article13NoticeEpochAt.Time.Equal(state.SentAt.Time) ||
		!state.HasSupportedArticle13NoticeSchema || !state.Article13NoticeEpochV61Committed {
		return SendResult{}, false
	}
	if _, err := article13.CanonicalSentAt(state.SentAt.Time); err != nil {
		return SendResult{}, false
	}
	switch state.BoundedStatus {
	case "sent", "in_progress", "changes_requested", "finalizing", "completed", "declined", "voided", "expired":
		return SendResult{Status: state.BoundedStatus}, true
	default:
		return SendResult{}, false
	}
}
func (e *Engine) ensureOwnedSendRetainUntilV1(ctx context.Context, o *ownedSendOperationV1, intent pdfadmission.HTMLSendRetentionProjectionV1) (pdfadmission.HTMLSendRetentionProjectionV1, error) {
	if !o.valid(ctx) || intent.DocumentID != o.document || intent.OrgID != o.org {
		return pdfadmission.HTMLSendRetentionProjectionV1{}, errors.New("resume send sealing: retention deadline dependencies unavailable")
	}
	if _, err := canonicalOwnedSendSealingRetainUntilV1(intent); err != nil {
		return pdfadmission.HTMLSendRetentionProjectionV1{}, fmt.Errorf("resume send sealing: %w", err)
	}
	reloaded, err := e.readOwnedSendIntentV1(ctx, o)
	if err != nil {
		return pdfadmission.HTMLSendRetentionProjectionV1{}, fmt.Errorf("resume send sealing: reload retention commitment: %w", err)
	}
	if _, err := canonicalOwnedSendSealingRetainUntilV1(reloaded); err != nil {
		return pdfadmission.HTMLSendRetentionProjectionV1{}, fmt.Errorf("resume send sealing: %w", err)
	}
	if reloaded.DocumentID != intent.DocumentID || reloaded.OrgID != intent.OrgID || !reloaded.Article13NoticeEpochAt.Time.Equal(intent.Article13NoticeEpochAt.Time) || !reloaded.RetainUntil.Time.Equal(intent.RetainUntil.Time) {
		return pdfadmission.HTMLSendRetentionProjectionV1{}, errors.New("resume send sealing: immutable retention commitment changed during reload")
	}
	return reloaded, nil
}
func (e *Engine) reloadOwnedCompletedSendIntentV1(ctx context.Context, o *ownedSendOperationV1) (pdfadmission.HTMLSendRetentionProjectionV1, error) {
	intent, err := e.readOwnedSendIntentV1(ctx, o)
	if err != nil {
		return pdfadmission.HTMLSendRetentionProjectionV1{}, err
	}
	if _, err = canonicalOwnedSendSealingRetainUntilV1(intent); err != nil {
		return pdfadmission.HTMLSendRetentionProjectionV1{}, err
	}
	if !intent.RetentionCompletedAt.Valid {
		return pdfadmission.HTMLSendRetentionProjectionV1{}, errors.New("retention intent did not complete during concurrent handoff")
	}
	return intent, nil
}
func (e *Engine) abortOwnedUnstartedSendV1(ctx context.Context, o *ownedSendOperationV1) error {
	if !o.valid(ctx) {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	return o.phaseV1(pdfadmission.HTMLSendAbortV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		state, err := p.work.StateV1(call)
		if err != nil {
			return err
		}
		intent, err := p.work.ReadIntentV1(call)
		if err != nil {
			return err
		}
		if !sendSealingReversible(intent) {
			return errors.New("retention already started; sealing state is not reversible")
		}
		if state.BoundedStatus != "sealing" {
			return fmt.Errorf("document status is %s, want sealing", state.BoundedStatus)
		}
		if state.ParentEnvelopeID.Valid {
			return pdfadmission.ErrHTMLSendWorkV1
		}
		// Reversible recovery must not demand the invalid/missing child source which
		// caused refusal. Original root->intent locks already fence topology; this
		// fixed original execrows mutation returns no scalable body or member view.
		if state.IsEnvelope {
			if _, err = q.AbortEnvelopeChildrenSendSealing(call, generated.AbortEnvelopeChildrenSendSealingParams{ParentEnvelopeID: pgtype.UUID{Bytes: o.document, Valid: true}, OrgID: o.org}); err != nil {
				return err
			}
		}
		rows, err := q.AbortDocumentSendSealing(call, generated.AbortDocumentSendSealingParams{ID: o.document, OrgID: o.org})
		if err != nil || rows != 1 {
			return fmt.Errorf("abort document sealing: rows=%d err=%w", rows, err)
		}
		rows, err = q.DeleteSendSealingIntent(call, generated.DeleteSendSealingIntentParams{DocumentID: o.document, OrgID: o.org})
		if err != nil || rows != 1 {
			return fmt.Errorf("delete aborted sealing intent: rows=%d err=%w", rows, err)
		}
		return nil
	})
}
func (e *Engine) markOwnedSendRetentionV1(ctx context.Context, o *ownedSendOperationV1, complete bool) (rows int64, failure error) {
	if !o.valid(ctx) {
		return 0, pdfadmission.ErrHTMLSendWorkV1
	}
	failure = o.phaseV1(pdfadmission.HTMLSendIntentMarkV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		if _, err := p.work.StateV1(call); err != nil {
			return err
		}
		var err error
		if complete {
			rows, err = q.MarkSendSealingRetentionComplete(call, generated.MarkSendSealingRetentionCompleteParams{DocumentID: o.document, OrgID: o.org})
		} else {
			rows, err = q.MarkSendSealingRetentionStarted(call, generated.MarkSendSealingRetentionStartedParams{DocumentID: o.document, OrgID: o.org})
		}
		return err
	})
	return rows, failure
}
func (e *Engine) recordOwnedSendFailureV1(ctx context.Context, o *ownedSendOperationV1, cause error) {
	if cause == nil || !o.valid(ctx) {
		return
	}
	_ = o.phaseV1(pdfadmission.HTMLSendIntentMarkV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		if _, err := p.work.StateV1(call); err != nil {
			return err
		}
		_, err := q.MarkSendSealingAttemptFailed(call, generated.MarkSendSealingAttemptFailedParams{DocumentID: o.document, OrgID: o.org, LastError: pgtype.Text{String: truncateString(cause.Error(), 1000), Valid: true}})
		return err
	})
}
