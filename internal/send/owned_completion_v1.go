// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This is the original standalone final transaction, on one genuine native
// completion Work. No caller transaction/result length grants output or SQL.
// Family membership is held outside this finite native scope, never omitted.
func (e *Engine) completeOwnedSealedSendV1(ctx context.Context, o *ownedSendOperationV1, prepared *ownedSendCompletionSnapshotV1) (out SendResult, failure error) {
	if prepared == nil || prepared.reference == nil || !prepared.reference.MatchesOperationV1(o.native) || prepared.operation != o || !o.valid(ctx) {
		return out, errors.New("complete send sealing: prepared snapshot unavailable")
	}
	var invites []pendingInvite
	var sent *generated.Document
	var intentActor Actor
	var queueBacked, expiredBeforeInvite bool
	failure = o.phaseV1(pdfadmission.HTMLSendCompletionV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		state, err := p.work.StateV1(call)
		if err != nil {
			return fmt.Errorf("complete send sealing: lock document: %w", err)
		}
		if state.BoundedStatus != "sealing" {
			if completed, ok := completedOwnedSendStatusV1(state); ok {
				out = completed
				return nil
			}
			return fmt.Errorf("complete send sealing: document status is %s, want sealing", state.BoundedStatus)
		}
		if state.ParentEnvelopeID.Valid {
			return pdfadmission.ErrHTMLSendWorkV1
		}
		// Original lock direction is document->intent. Original durable intent
		// decisions precede any recipient/token/mutation work or full source parse.
		intent, err := p.work.ReadIntentV1(call)
		if err != nil {
			return fmt.Errorf("complete send sealing: lock intent: %w", err)
		}
		if intent.PresignExecutionID.Valid {
			return ErrDelegatedRecoveryUnavailable
		}
		if !intent.RetentionCompletedAt.Valid {
			return errors.New("complete send sealing: evidence retention is not durable")
		}
		deadline, err := canonicalSendSealingRetainUntil(intent)
		if err != nil {
			return fmt.Errorf("complete send sealing: %w", err)
		}
		retainUntil := deadline.Format(time.RFC3339)
		models, err := p.work.ReadModelsV1(call)
		if err != nil {
			return err
		}
		doc := models.Document
		confirmation, err := p.work.ReadConfirmationV1(call)
		if err != nil {
			return fmt.Errorf("complete send sealing: load lawful-basis confirmation: %w", err)
		}
		if err = requireConfirmedLawfulBasis(doc, confirmation); err != nil {
			return fmt.Errorf("complete send sealing: %w", err)
		}
		matches, err := p.work.CompareCompletionRootV1(call, prepared.reference)
		if err != nil {
			return err
		}
		if !matches {
			return fmt.Errorf("%w: %s", ErrDraftChangedDuringSend, doc.ID)
		}
		source, err := p.work.NewSourceV1(call)
		if err != nil {
			return err
		}
		var members []*ownedSendFamilyMemberV1
		var envelopeRoles []string
		if doc.IsEnvelope {
			members, err = readOwnedEnvelopeMembersV1(call, p.work)
			if err != nil {
				return fmt.Errorf("complete send envelope: re-list children: %w", err)
			}
			envelopeRoles, err = validateOwnedEnvelopeMembersV1(call, doc.ID, members, "sealing", true)
			if err != nil {
				return err
			}
			membershipChanged, changedChild, err := p.work.CompareCompletionChildrenV1(call, prepared.reference)
			if err != nil {
				return err
			}
			if membershipChanged {
				return errors.New("send envelope: child membership changed while preparing send")
			}
			if changedChild != uuid.Nil {
				return fmt.Errorf("send envelope: child %s changed while preparing send", changedChild)
			}
		}
		if err = validateOwnedResolvedSealedSnapshotV1(source, doc); err != nil {
			return err
		}
		if err = validateOwnedResolvedFamilySnapshotV1(members); err != nil {
			return err
		}
		if err = source.ValidateCurrentV1(); err != nil {
			return fmt.Errorf("complete send sealing: HTML source: %w", err)
		}
		recipients, err := p.work.ReadRecipientsV1(call)
		if err != nil {
			return fmt.Errorf("complete send sealing: list recipients: %w", err)
		}
		if err = validateOwnedSendRecipientsV1(source, doc, envelopeRoles, recipients); err != nil {
			return err
		}
		if doc.SourceKind == "pdf" {
			fields, err := p.work.ReadFieldsV1(call)
			if err != nil {
				return fmt.Errorf("complete send PDF: list fields: %w", err)
			}
			if doc.RequiresSignature {
				if err = validateOwnedPDFSignatureFieldsV1(source, doc, recipients, fields, prepared.pageCount); err != nil {
					return err
				}
			} else if err = validateAcknowledgementFields(fields); err != nil {
				return err
			}
		}
		expired, err := q.IsSendSealingExpired(call, generated.IsSendSealingExpiredParams{ID: doc.ID, OrgID: doc.OrgID})
		if err != nil {
			return fmt.Errorf("complete send sealing: inspect expiry: %w", err)
		}
		expiredBeforeInvite = expired.Valid && expired.Bool
		a := actorFromSendSealingIntent(intent)
		intentActor = a
		exp := magictoken.Expiry(doc.ExpiresAt, e.now())
		out = SendResult{Status: "sent"}
		if !expiredBeforeInvite {
			// Real native input/output credit precedes token/hash, URL, link, invite,
			// locale rendering and private queue-message construction.
			if err = p.work.PrepareCompletionOutputsV1(call, e.PublicURL, e.OrgName); err != nil {
				return err
			}
			out.Links = make([]SignLink, 0, len(recipients))
			invites = make([]pendingInvite, 0, len(recipients))
			for _, rec := range recipients {
				token, err := p.work.RotateAndMarkRecipientV1(call, rec.ID, exp)
				if err != nil {
					return err
				}
				signURL := e.PublicURL + "/sign/" + token
				beaconURL := e.PublicURL + "/e/o/" + token
				out.Links = append(out.Links, SignLink{RecipientID: rec.ID, Email: rec.Email, Name: rec.Name, Role: rec.Role, URL: signURL})
				invites = append(invites, pendingInvite{rec.ID, rec.Email, rec.Name, rec.Role, rec.Locale, signURL, beaconURL})
			}
		}
		sent, err = p.work.CompleteDocumentSendV1(call)
		if err != nil {
			return fmt.Errorf("complete document send sealing: %w", err)
		}
		if sent == nil || sent.ID != doc.ID || sent.OrgID != doc.OrgID || sent.Status != "sent" {
			return errors.New("complete document send sealing returned invalid state")
		}
		doc = sent
		var sentChildren []*generated.Document
		if doc.IsEnvelope {
			sentChildren, err = p.work.CompleteEnvelopeMembersSealingV1(call, sent)
			if err != nil {
				return fmt.Errorf("complete envelope child send sealing: %w", err)
			}
		}
		if !expiredBeforeInvite {
			if err = q.UpsertReminderSchedule(call, generated.UpsertReminderScheduleParams{DocumentID: doc.ID, Column2: []byte("[{\"days_after_send\":3},{\"days_after_send\":7}]"), FiresRemaining: 2}); err != nil {
				return fmt.Errorf("complete send sealing: reminder schedule: %w", err)
			}
		}
		queueBacked = usesDurableEmailQueue(e.Mailer)
		if queueBacked {
			// Render ALL original messages before the first enqueue, preserving the
			// original failure/queue order. Each is a real pre-funded Work output.
			messages := make([]dispatch.Message, 0, len(invites))
			for _, invite := range invites {
				message, err := p.work.RenderInviteV1(call, invite.recID)
				if err != nil {
					return fmt.Errorf("complete send sealing: render invite: %w", err)
				}
				messages = append(messages, message)
			}
			for _, message := range messages {
				if err = p.work.EnqueueEmailDeliveryV1(call, message); err != nil {
					return fmt.Errorf("complete send sealing: persist invite outbox: %w", err)
				}
			}
		}
		entries := make([]audit.Entry, 0, len(invites)+(2*len(sentChildren))+2)
		for i := range invites {
			invite := &invites[i]
			entries = append(entries, e.auditEntry(a, &doc.ID, &invite.recID, audit.KindRecipientInvited, map[string]any{"email": invite.email, "role": invite.role}))
		}
		payload := map[string]any{"recipient_count": len(out.Links), "evidence_retained": true, "lawful_basis": doc.LawfulBasis, "lawful_basis_confirmed": true, "retain_until": retainUntil}
		if expiredBeforeInvite {
			payload["expired_before_invite"] = true
		}
		for _, child := range sentChildren {
			childPayload := map[string]any{"envelope_id": doc.ID.String(), "propagated": true, "retain_until": retainUntil}
			if expiredBeforeInvite {
				childPayload["expired_before_invite"] = true
			}
			childEntry, err := e.documentSentAuditEntry(a, child, childPayload)
			if err != nil {
				return fmt.Errorf("complete envelope child send sealing: audit epoch: %w", err)
			}
			entries = append(entries, childEntry)
		}
		entry, err := e.documentSentAuditEntry(a, doc, payload)
		if err != nil {
			return fmt.Errorf("complete document send sealing: audit epoch: %w", err)
		}
		entries = append(entries, entry)
		if expiredBeforeInvite {
			expiredDoc, err := p.work.ExpireCompletedSendV1(call)
			if err != nil {
				return fmt.Errorf("complete expired send sealing: expire document: %w", err)
			}
			if expiredDoc == nil || expiredDoc.Status != "expired" {
				return errors.New("complete expired send sealing returned invalid document state")
			}
			if err = q.InvalidateRecipientTokens(call, doc.ID); err != nil {
				return fmt.Errorf("complete expired send sealing: invalidate recipient tokens: %w", err)
			}
			if err = q.CancelReminder(call, doc.ID); err != nil {
				return fmt.Errorf("complete expired send sealing: cancel reminder: %w", err)
			}
			var expiredChildIDs []uuid.UUID
			if doc.IsEnvelope {
				expiredChildIDs, err = p.work.ExpireEnvelopeMembersV1(call)
				if err != nil {
					return err
				}
			}
			if len(expiredChildIDs) != len(sentChildren) {
				return fmt.Errorf("complete expired send sealing: expired %d of %d envelope children", len(expiredChildIDs), len(sentChildren))
			}
			entries = append(entries, audit.Entry{OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindDocumentExpired, Payload: map[string]any{"before_invite": true, "irreversible_sealing_recovery": true}})
			for _, childID := range expiredChildIDs {
				childID := childID
				entries = append(entries, audit.Entry{OrgID: doc.OrgID, DocumentID: &childID, Kind: audit.KindDocumentExpired, Payload: map[string]any{"envelope_id": doc.ID.String(), "propagated": true, "before_invite": true, "irreversible_sealing_recovery": true}})
			}
			out.Status = "expired"
			out.Links = nil
		}
		if err = p.appendAuditEntriesV1(call, entries); err != nil {
			return fmt.Errorf("complete send sealing: audit send: %w", err)
		}
		rows, err := q.DeleteSendSealingIntent(call, generated.DeleteSendSealingIntentParams{DocumentID: doc.ID, OrgID: doc.OrgID})
		if err != nil || rows != 1 {
			return fmt.Errorf("complete send sealing: delete intent: rows=%d err=%w", rows, err)
		}
		return nil
	})
	if failure != nil {
		return SendResult{}, failure
	}
	// phaseV1 has committed, published, joined original SQL and retained all
	// model/output consumers. Direct mailers keep the operation until true join.
	if sent != nil && !queueBacked && !expiredBeforeInvite {
		for _, invite := range invites {
			o.sendEmailV1(dispatch.KindInvite, invite.email, invite.name, sent.Name, intentActor.Email, invite.signURL, invite.beaconURL, invite.locale, sent.RequiresSignature)
		}
	}
	return out, nil
}
