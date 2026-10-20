// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"sync"
)

type ownedHistoricalFinalizationPublicationV1 struct {
	once          sync.Once
	operation     *ownedBlocksSignatureOperationV1
	org, document uuid.UUID
	events        []*pdfadmission.ApplicationHTMLAuditEventConsumerV1
	err           error
}

func (o *ownedHistoricalFinalizationPublicationV1) closeV1() error {
	if o == nil {
		return nil
	}
	o.once.Do(func() {
		for _, event := range o.events {
			if event != nil {
				event.CloseConsumerV1()
			}
		}
		o.events = nil
		if o.operation != nil {
			o.err = o.operation.closeV1()
		}
	})
	return o.err
}
func (c *completionCredentialCapture) closeHistoricalPublicationV1() error {
	if c == nil {
		return nil
	}
	var inputErr error
	if c.finalizationInput != nil {
		inputErr = c.finalizationInput.closeV1()
		c.finalizationInput = nil
	}
	if c.publication == nil {
		return inputErr
	}
	owner := c.publication
	c.publication = nil
	return errors.Join(inputErr, owner.closeV1())
}
func (l *signerReadLeaseV1) registerHistoricalPublicationV1(e *Engine, owner *ownedHistoricalFinalizationPublicationV1) error {
	if l == nil || e == nil || owner == nil || owner.operation == nil || e.WorkRuntime == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.issuer != e || l.reader == nil || l.original == nil || l.original.Document == nil || l.historicalPublication != nil || owner.operation.factory != e.WorkRuntime.SessionsV1() || owner.org != l.original.Document.OrgID || owner.document != l.original.Document.ID {
		return ErrSigningAdmissionUnavailableV1
	}
	l.historicalPublication = owner
	return nil
}
func (e *Engine) retainHistoricalPublicationForRecipientV1(rc *RecipientContext, capture *completionCredentialCapture) error {
	if err := e.retainHistoricalFinalizationInputForRecipientV1(rc, capture); err != nil {
		return err
	}
	if capture == nil || capture.publication == nil {
		return nil
	}
	owner := capture.publication
	if rc == nil || rc.readLease == nil {
		return errors.Join(ErrSigningAdmissionUnavailableV1, owner.closeV1())
	}
	if err := rc.readLease.registerHistoricalPublicationV1(e, owner); err != nil {
		return errors.Join(err, owner.closeV1())
	}
	capture.publication = nil
	return nil
}
func (e *Engine) prepareHistoricalCompletionNotificationsOwnedV1(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1, capture *completionCredentialCapture) ([]dispatch.Message, error) {
	if err := w.ReadHistoricalCompletionRecipientsV1(call); err != nil {
		return nil, fmt.Errorf("list completion recipients: %w", err)
	}
	id := uuid.Nil
	if capture != nil {
		id = capture.recipientID
	}
	token, err := w.RotateHistoricalCompletionCredentialsV1(call, e.now(), id)
	if err != nil {
		return nil, err
	}
	if capture != nil && !capture.ownerOnly {
		capture.rawToken = token
		if strings.TrimSpace(token) == "" {
			return nil, fmt.Errorf("completed recipient %s did not receive an artifact credential", capture.recipientID)
		}
	}
	if err = w.ReadHistoricalCompletionSenderV1(call); err != nil {
		return nil, fmt.Errorf("load completion sender: %w", err)
	}
	messages, err := w.RenderHistoricalCompletionMessagesV1(call, e.BaseURL, e.OrgName)
	if err != nil {
		return nil, err
	}
	if err = w.EnqueueHistoricalCompletionMessagesV1(call); err != nil {
		return nil, fmt.Errorf("persist completion outbox: %w", err)
	}
	// The durable outbox is the sole delivery owner, including test mailers and
	// temporarily absent SMTP configuration. Direct post-commit delivery would
	// duplicate that queued effect.
	_ = messages
	return nil, nil
}

// This separate actual native operation performs the original terminal SQL,
// token/outbox and completion audit unit. It returns its typed real consumer on
// success AND error; the caller must transfer it into the real response lease
// or close it only after its actual nonescaping local result/error last use.
func (e *Engine) publishHistoricalFinalizationOwnedV1(ctx context.Context, prepared *generated.Document, stagedIntent *generated.DocumentFinalizationIntent, capture *completionCredentialCapture) (*generated.Document, bool, *ownedHistoricalFinalizationPublicationV1, error) {
	if e == nil || ctx == nil || prepared == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || e.Audit == nil {
		return nil, false, nil, ErrSigningAdmissionUnavailableV1
	}
	return e.publishHistoricalFinalizationScopeOwnedV1(ctx, prepared.OrgID, prepared.ID, stagedIntent, nil, capture)
}
func (e *Engine) publishHistoricalFinalizationFromReferenceOwnedV1(ctx context.Context, reference *pdfadmission.ApplicationHistoricalFinalizationPublicationReferenceV1, capture *completionCredentialCapture) (*generated.Document, bool, *ownedHistoricalFinalizationPublicationV1, error) {
	if e == nil || ctx == nil || reference == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || e.Audit == nil {
		return nil, false, nil, ErrSigningAdmissionUnavailableV1
	}
	org, document, err := reference.ScopeV1(ctx, e.WorkRuntime.SessionsV1())
	if err != nil {
		return nil, false, nil, errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	return e.publishHistoricalFinalizationScopeOwnedV1(ctx, org, document, nil, reference, capture)
}
func (e *Engine) publishHistoricalFinalizationScopeOwnedV1(ctx context.Context, org, document uuid.UUID, stagedIntent *generated.DocumentFinalizationIntent, reference *pdfadmission.ApplicationHistoricalFinalizationPublicationReferenceV1, capture *completionCredentialCapture) (completed *generated.Document, did bool, owner *ownedHistoricalFinalizationPublicationV1, failure error) {
	client, ok := e.Storage.(*storage.Client)
	if !ok || client == nil {
		return nil, false, nil, ErrSigningAdmissionUnavailableV1
	}
	factory := e.WorkRuntime.SessionsV1()
	native, err := factory.NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return nil, false, nil, blockSignatureFailureV1(err)
	}
	operation := &ownedBlocksSignatureOperationV1{native: native, factory: factory, original: ctx}
	owner = &ownedHistoricalFinalizationPublicationV1{operation: operation, org: org, document: document}
	defer func() { failure = blockSignatureFailureV1(failure) }()
	var pending []audit.PendingEvent
	var notifications []dispatch.Message
	err = operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationPublicationV1, func(call context.Context, session *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return fmt.Errorf("publish finalization: lock document: %w", err)
		}
		models, err := w.ReadModelsV1(call)
		if err != nil {
			return fmt.Errorf("publish finalization: lock document: %w", err)
		}
		locked := models.Document
		if locked.Status == "completed" && locked.FinalPdfKey.Valid && locked.AuditCertKey.Valid {
			completed = locked
			return nil
		}
		if locked.Status != "finalizing" {
			return ErrDocumentRevisedDuringFinalize
		}
		intent, err := w.ReadHistoricalFinalizationIntentV1(call)
		if err != nil {
			return fmt.Errorf("publish finalization: lock intent: %w", err)
		}
		if _, err = validateHistoricalFinalizationModeOwnedV1(call, w, locked, intent.Mode); err != nil {
			return err
		}
		if err = validateFinalizationIntentAfterModeV1(locked, intent); err != nil {
			return err
		}
		if !intent.RetentionStartedAt.Valid || !intent.RetentionCompletedAt.Valid {
			return errors.New("publish finalization: immutable retention is incomplete")
		}
		if reference != nil && !reference.MatchesIntentV1(intent) {
			return errors.New("publish finalization: intent changed during resume")
		}
		if stagedIntent != nil && !finalizationIntentsEqual(stagedIntent, intent) {
			return errors.New("publish finalization: intent changed during resume")
		}
		evidence, err := w.NewHistoricalFinalizationEvidenceV1(call, client)
		if err != nil {
			return err
		}
		if err = evidence.VerifyIntentArtifactsV1(); err != nil {
			return err
		}
		if err = e.historicalFinalizationReadinessOwnedV1(call, w, intent.Mode); err != nil {
			return err
		}
		children, err := w.HistoricalFinalizationMembersV1(call)
		if err != nil {
			return err
		}
		for _, child := range children {
			if child == nil || !envelopeChildStatusMatchesParent(locked.Status, child.Status) || !child.CompletionEffectiveAtBound || !completionEffectiveTimesEqual(child.CompletionEffectiveAt, locked.CompletionEffectiveAt) || !retentionTimesEqual(child.FinalizationRetainUntil, locked.FinalizationRetainUntil) {
				return errors.New("publish finalization: child is not frozen to the envelope commitment")
			}
		}
		checkFit := func(item *pdfadmission.ApplicationHTMLSendWorkV1) error {
			err := item.CheckHistoricalPublicationCompatibilityV1(call)
			if errors.Is(err, pdfadmission.ErrHistoricalFittedPublicationV1) {
				return ErrFittedCompositionRequiredV1
			}
			return err
		}
		if err = checkFit(w); err != nil {
			return err
		}
		for _, child := range children {
			member := w.EnvelopeMemberForAuditV1(call, child.ID)
			if member == nil {
				return ErrSigningAdmissionUnavailableV1
			}
			if err = checkFit(member); err != nil {
				return err
			}
		}
		completed, children, err = w.CompleteHistoricalPublicationV1(call)
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("publish finalization: terminal SQL guard rejected the retained intent")
		}
		if err != nil {
			return fmt.Errorf("publish finalization: complete document: %w", err)
		}
		if err = w.CancelHistoricalCompletionReminderV1(call); err != nil {
			return fmt.Errorf("publish finalization: cancel reminder: %w", err)
		}
		if err = w.InvalidateHistoricalCompletionTokensV1(call); err != nil {
			return fmt.Errorf("publish finalization: invalidate ceremony credentials: %w", err)
		}
		notifications, err = e.prepareHistoricalCompletionNotificationsOwnedV1(call, w, capture)
		if err != nil {
			return err
		}
		pending = make([]audit.PendingEvent, 0, len(children)+1)
		owner.events = make([]*pdfadmission.ApplicationHTMLAuditEventConsumerV1, 0, len(children)+1)
		logOne := func(document uuid.UUID, child bool) error {
			payload, oneErr := w.HistoricalCompletionPayloadV1(call, document)
			if oneErr != nil {
				return fmt.Errorf("publish finalization: completion audit payload: %w", oneErr)
			}
			var event audit.PendingEvent
			var consumer *pdfadmission.ApplicationHTMLAuditEventConsumerV1
			entry := audit.Entry{OrgID: completed.OrgID, DocumentID: &document, Kind: audit.KindDocumentCompleted, Payload: payload}
			if child {
				member := w.EnvelopeMemberForAuditV1(call, document)
				if member == nil {
					return ErrSigningAdmissionUnavailableV1
				}
				event, consumer, oneErr = ownedaudit.LogEnvelopeMemberV1(e.Audit, call, member, pdfadmission.HTMLAuditHistoricalCompletedV1, entry)
			} else {
				event, consumer, oneErr = ownedaudit.LogV1(e.Audit, call, session, pdfadmission.HTMLAuditHistoricalCompletedV1, entry)
			}
			if consumer != nil {
				owner.events = append(owner.events, consumer)
			}
			if oneErr != nil {
				return oneErr
			}
			if oneErr = w.BindHistoricalCompletionAuditV1(call, document, consumer); oneErr != nil {
				return oneErr
			}
			pending = append(pending, event)
			return nil
		}
		for _, child := range children {
			if err = logOne(child.ID, true); err != nil {
				return fmt.Errorf("publish finalization: audit envelope child completion: %w", err)
			}
		}
		if err = logOne(completed.ID, false); err != nil {
			return fmt.Errorf("publish finalization: audit completion: %w", err)
		}
		count, err := w.DeletePublishedHistoricalIntentV1(call)
		if err != nil || count != 1 {
			return fmt.Errorf("publish finalization: delete intent: rows=%d err=%w", count, err)
		}
		did = true
		return nil
	})
	if err != nil {
		return nil, false, owner, err
	}
	for index, event := range pending {
		if err = ownedaudit.PublishV1(e.Audit, event, owner.events[index]); err != nil {
			return nil, false, owner, err
		}
	}
	e.deliverPostCommitEmails(notifications)
	return completed, did, owner, nil
}
