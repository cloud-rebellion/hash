// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
)

func htmlCeremonyAdmissionErrorV1(err error) error {
	// Original semantic source/refusal sentinels remain business failures even
	// when a native source stage joins its availability sentinel for context.
	if errors.Is(err, htmlsource.ErrInvalid) || errors.Is(err, htmlsource.ErrReviewRequired) || errors.Is(err, htmlmaterialization.ErrInvalid) || errors.Is(err, htmlmaster.ErrInvalid) || errors.Is(err, htmlmaster.ErrLimit) || errors.Is(err, htmlmaster.ErrContractIncomplete) {
		return err
	}
	// Completed faults from privately tagged fixed mutation statements remain internal
	// failures. Context/unknown outcomes take precedence; generic session, cache,
	// measurement and source refusals keep their original availability mapping.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || errors.Is(err, pdfadmission.ErrApplicationSessionCommitUnknownV1) {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	if pdfadmission.IsInternalApplicationWriteFailureV1(err) {
		return err
	}
	if errors.Is(err, pdfadmission.ErrHTMLCeremonyWorkflowV1) || errors.Is(err, pdfadmission.ErrHTMLRevisionReadV1) || errors.Is(err, pdfadmission.ErrHTMLRevisionSourceV1) ||
		errors.Is(err, pdfadmission.ErrHTMLRevisionCollectionsV1) || errors.Is(err, pdfadmission.ErrBlocksWriterV1) || errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) || errors.Is(err, pdfadmission.ErrHTMLAuditEventV1) ||
		errors.Is(err, pdfadmission.ErrApplicationSessionV1) || errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	return err
}
func closeHTMLCeremonyWorkflowV1(original context.Context, work *pdfadmission.ApplicationHTMLCeremonyWorkflowV1) {
	if work == nil {
		return
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(original), 5*time.Second)
	defer cancel()
	_ = work.CloseV1(cleanup)
}
func htmlCeremonyPolicyPinsV1(actual *pdfadmission.HTMLCeremonyParticipantPolicyV1) htmlCeremonyDocumentPinsV1 {
	if actual == nil {
		return htmlCeremonyDocumentPinsV1{}
	}
	return htmlCeremonyDocumentPinsV1{present: true, document: actual.DocumentID, org: actual.OrgID, name: actual.Name, lawfulBasis: actual.LawfulBasis, noticeSchema: actual.NoticeSchema,
		sentAt: actual.SentAt, noticeEpoch: actual.NoticeEpochAt, expiresAt: actual.ExpiresAt, noticeCommitted: actual.NoticeCommitted}
}

// The existing public method now retains its immutable native read throughout
// the mutation and notification, instead of relying on a mutable returned model.
func (e *Engine) RequestChanges(ctx context.Context, rc *RecipientContext, in ChangeRequestInput) error {
	if rc == nil || rc.readLease == nil {
		if rc != nil && rc.Document != nil && len(rc.Document.HtmlSourceJson) != 0 {
			return ErrSigningAdmissionUnavailableV1
		}
		// Preserve the original pure non-HTML input refusal order, but no
		// unowned model may select a pooled/unmeasured mutation.
		if err := validateNoticeEvidence(rc, in.Notice); err != nil {
			return err
		}
		if strings.TrimSpace(in.Message) == "" && strings.TrimSpace(in.Proposed) == "" {
			return errors.New("describe the change you need")
		}
		return ErrSigningAdmissionUnavailableV1
	}
	original, scope, release, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return err
	}
	defer release()
	if err = validateNoticeEvidence(original, in.Notice); err != nil {
		return err
	}
	if strings.TrimSpace(in.Message) == "" && strings.TrimSpace(in.Proposed) == "" {
		return errors.New("describe the change you need")
	}
	if e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return ErrSigningAdmissionUnavailableV1
	}
	work, err := e.WorkRuntime.SessionsV1().NewHTMLParticipantChangesV1(ctx, scope)
	if err != nil {
		return htmlCeremonyAdmissionErrorV1(err)
	}
	defer closeHTMLCeremonyWorkflowV1(ctx, work)
	if err = work.OpenV1(); err != nil {
		return htmlCeremonyAdmissionErrorV1(err)
	}
	var pending audit.PendingEvent
	var event *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	var messages []dispatch.Message
	var finishNotification func()
	err = work.WithTxV1(func(call context.Context, db generated.DBTX, _ *pdfadmission.ApplicationHTMLRevisionReaderV1) error {
		access, err := work.ReadAccessV1(call, in.Notice.Snapshot.Schema)
		if err != nil {
			return fmt.Errorf("lock document: %w", err)
		}
		// Exact original locked notice before state/envelope/credential. These real
		// fixed pins are sufficient here; Name/basis/committed are read below under
		// a separate raw loan at their original private-credential decision point.
		noticePins := htmlCeremonyDocumentPinsV1{present: true, document: access.DocumentID, org: access.OrgID,
			noticeSchema: in.Notice.Snapshot.Schema, sentAt: access.SentAt, noticeEpoch: access.NoticeEpochAt}
		if !access.NoticeSchemaMatchesInput {
			return ErrInvalidNoticeEvidence
		}
		if err = validateHTMLCeremonyNoticePinsV1(noticePins, original.Recipient.ID, in.Notice); err != nil {
			return err
		}
		if !access.ActiveCeremony {
			return ErrDocumentNotSignable
		}
		if access.IsEnvelope {
			return fmt.Errorf("%w: request changes", ErrEnvelopeTransitionUnsupported)
		}
		recipient, err := work.ReadParticipantV1(call)
		if err != nil {
			return err
		}
		credentialAt := e.now()
		if err = validateLockedRecipientPrefixV1(original, recipient, htmlCeremonyDocumentPinsV1{present: true, document: access.DocumentID, org: access.OrgID}, credentialAt); err != nil {
			return err
		}
		policy, err := work.ReadParticipantPolicyV1(call)
		if err != nil {
			return err
		}
		pins := htmlCeremonyPolicyPinsV1(policy)
		if err = validateLockedRecipientPinsV1(original, recipient, pins, credentialAt); err != nil {
			return err
		}
		if recipient.DocumentID != original.Document.ID || !recipientCanRequestChanges(recipient.Role, recipient.Status) {
			return ErrRecipientNotEligibleForChanges
		}
		captured, err := work.HasCapturedEvidenceV1(call)
		if err != nil {
			return fmt.Errorf("inspect change-request evidence: %w", err)
		}
		if captured {
			return ErrRevisionWouldDestroyEvidence
		}
		models, err := work.ReadParticipantDocumentV1(call, func(a pdfadmission.HTMLRevisionReadAccessV1) error { return nil })
		if err != nil {
			return err
		}
		locked := models.Document
		// Retain all full-model original checks as well as their early bounded forms.
		if err = ValidateLockedNoticeEvidence(original, locked, in.Notice); err != nil {
			return err
		}
		if err = ValidateLockedRecipientCredential(original, recipient, locked, credentialAt); err != nil {
			return err
		}
		change, err := work.CreateParticipantChangeV1(call, pdfadmission.HTMLParticipantChangeInputV1{Message: in.Message, BlockID: in.BlockID, Quote: in.Quote, Context: in.Context, Proposed: in.Proposed})
		if err != nil {
			return fmt.Errorf("record change request: %w", err)
		}
		if err = work.PauseForChangesV1(call); errors.Is(err, pgx.ErrNoRows) {
			return ErrDocumentNotSignable
		} else if err != nil {
			return err
		}
		if e.Mailer != nil {
			if _, err = work.ReadNotificationSenderV1(call); err != nil {
				return fmt.Errorf("load change-request notification sender: %w", err)
			}
			approveAt, denyAt := e.changeNotificationTimesV1()
			notification, err := work.NewChangeNotificationV1(call, e.OrgName, e.BaseURL, e.ActionSecret, approveAt, denyAt)
			if err != nil {
				return err
			}
			context, to, releaseNotification, err := notification.BorrowContextV1(call)
			if err != nil {
				return err
			}
			finishNotification = releaseNotification
			messages, err = e.prepareNotificationTx(call, notification, dispatch.KindChangesRequested, to, context)
			if err != nil {
				return fmt.Errorf("prepare change-request notification: %w", err)
			}
		}
		ownedInput, err := work.ParticipantChangeInputV1(call)
		if err != nil {
			return err
		}
		// The SAME immutable Evidence passed validateNoticeEvidence and the locked
		// notice predicate above. Binding these fixed new map keys reuses that exact
		// successful pure validation; it changes neither values nor notice decision.
		// Ownedaudit prices/copies/encodes the entire typed Snapshot before SQL.
		// The actual native INSERT supplied this validated ID. Context/proposed
		// come from the same immutable private input as message/block/quote.
		// New fields bind fresh preimages only; historical events stay unchanged.
		payload := map[string]any{"message": ownedInput.Message, "block_id": ownedInput.BlockID, "quote": ownedInput.Quote,
			article13.AuditNoticeSchemaKey: in.Notice.Schema, article13.AuditNoticeDigestKey: in.Notice.Digest, article13.AuditNoticeSnapshotKey: in.Notice.Snapshot,
			"change_request": change.ID.String(), "context": ownedInput.Context, "proposed": ownedInput.Proposed}
		session, err := work.AuditSessionV1(call)
		if err != nil {
			return err
		}
		documentID, recipientID := locked.ID, recipient.ID
		pending, event, err = ownedaudit.LogV1(e.Audit, call, session, pdfadmission.HTMLAuditChangesRequestedV1, audit.Entry{OrgID: locked.OrgID, DocumentID: &documentID, RecipientID: &recipientID,
			Kind: audit.KindChangesRequested, IP: in.IP, UserAgent: in.UserAgent, Payload: payload})
		if err != nil {
			return fmt.Errorf("audit change request: %w", err)
		}
		if err = ValidateLockedRecipientCredential(original, recipient, locked, e.now()); err != nil {
			return err
		}
		return ValidateLockedNoticeEvidence(original, locked, in.Notice)
	})
	if finishNotification != nil {
		defer finishNotification()
	}
	if err != nil {
		if event != nil {
			event.CloseConsumerV1()
		}
		return htmlCeremonyAdmissionErrorV1(err)
	}
	if err = work.CommitV1(); err != nil {
		event.CloseConsumerV1()
		return fmt.Errorf("commit change request: %w", htmlCeremonyAdmissionErrorV1(err))
	}
	if err = ownedaudit.PublishV1(e.Audit, pending, event); err != nil {
		event.CloseConsumerV1()
		return htmlCeremonyAdmissionErrorV1(err)
	}
	e.deliverPostCommitEmails(messages)
	return nil
}

// Original token minting consumes two distinct engine clock observations ONLY
// when email action links are enabled. No captured clock is substituted for
// the later post-audit credential deadline check.
func (e *Engine) changeNotificationTimesV1() (approveAt, denyAt time.Time) {
	if e.ActionSecret != "" {
		approveAt = e.now()
		denyAt = e.now()
	}
	return
}
