// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// One fixed scalar identity phase followed by one real root-first mutation.
// REST/MCP actor policy and the worker's actual due schedule retain their own
// authority; the native identity result is only a rechecked membership hint.
func (e *Engine) remindOwnedV1(ctx context.Context, a Actor, document uuid.UUID, automatic bool) (count int, failure error) {
	if !automatic {
		if err := requireActorAuthorization(a); err != nil {
			return 0, err
		}
	}
	if e == nil || ctx == nil || document == uuid.Nil || a.OrgID == uuid.Nil {
		return 0, pdfadmission.ErrReminderV1
	}
	// Preserve the original manual transaction budget. Scheduled work gets one
	// genuine finite entry lifetime too, before any SQL child is constructed.
	duration := 10 * time.Second
	if automatic {
		duration = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	identity, err := e.newOwnedSendOperationV1(callCtx, a.OrgID, document)
	if err != nil {
		return 0, err
	}
	var native *pdfadmission.ApplicationHTMLSendOperationV1
	var root uuid.UUID
	err = identity.phaseV1(pdfadmission.HTMLReminderIdentityV1, func(call context.Context, p *ownedSendPhaseV1, _ *generated.Queries, _ pgx.Tx) error {
		var err error
		native, root, err = p.work.NewReminderRootOperationV1(call)
		return err
	})
	identity.closeConsumerV1()
	if err != nil {
		if native != nil {
			native.CloseConsumerV1()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrDocumentNotFound
		}
		return 0, err
	}
	deadline, _ := callCtx.Deadline()
	o := &ownedSendOperationV1{engine: e, runtime: e.WorkRuntime, factory: e.WorkRuntime.SessionsV1(), native: native, original: callCtx, deadline: deadline, org: a.OrgID, document: root}
	o.self = o
	defer o.closeConsumerV1()
	purpose := pdfadmission.HTMLReminderManualV1
	if automatic {
		purpose = pdfadmission.HTMLReminderScheduledV1
	}
	queue := usesDurableEmailQueue(e.Mailer)
	delivery := e.Mailer != nil
	var messages []dispatch.Message
	err = o.phaseV1(purpose, func(call context.Context, p *ownedSendPhaseV1, _ *generated.Queries, tx pgx.Tx) error {
		state, err := p.work.StateV1(call)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDocumentNotFound
		}
		if err != nil {
			return err
		}
		if state.BoundedStatus != "sent" && state.BoundedStatus != "in_progress" {
			return ErrNotRemindable
		}
		if state.ExpiresAt.Valid && !state.ExpiresAt.Time.After(e.now()) {
			return ErrNotRemindable
		}
		if _, err = p.work.ReadModelsV1(call); err != nil {
			return err
		}
		subject, err := p.work.ReminderSubjectV1(call)
		if err != nil {
			return err
		}
		// This is an actual privately selected root/member from the same native
		// operation. A mutable preflight document cannot select the subject.
		models, err := subject.ReminderModelsV1(call)
		if err != nil {
			return err
		}
		doc := models.Document
		if doc.ID != document || doc.OrgID != a.OrgID {
			return pdfadmission.ErrReminderV1
		}
		if doc.Status != "sent" && doc.Status != "in_progress" {
			return ErrNotRemindable
		}
		if doc.ExpiresAt.Valid && !doc.ExpiresAt.Time.After(e.now()) {
			return ErrNotRemindable
		}
		var actorUser *generated.User
		if !automatic {
			actorUser, err = subject.ReadActorV1(call, *a.UserID)
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrMutationPermissionRevoked
			}
			if err != nil {
				return err
			}
			if actorUser.Role != string(auth.RoleOwner) && actorUser.Role != string(auth.RoleSender) {
				return auth.ErrMutationPermissionRevoked
			}
			a.Email = actorUser.Email
			if err = reauthorizeLifecycleActor(call, tx, a, actorUser); err != nil {
				return err
			}
		}
		producer, due, err := subject.StartReminderV1(call, e.now())
		if err != nil {
			return fmt.Errorf("start native reminder: %w", err)
		}
		if !due {
			return nil
		}
		if automatic {
			// A scheduler has no human actor. Resolve only the actual subject's
			// sender presentation; no fabricated user or authorization callback.
			actorUser, err = subject.ReadActorV1(call, doc.SenderID)
			if err != nil {
				return err
			}
			if actorUser.ID != doc.SenderID || actorUser.OrgID != doc.OrgID || actorUser.Email == "" {
				return pdfadmission.ErrReminderV1
			}
		}
		if _, err = subject.ReadRecipientsV1(call); err != nil {
			return fmt.Errorf("read native reminder recipients: %w", err)
		}
		if err = producer.PrepareV1(call, e.PublicURL, e.OrgName, a.IP, a.Via, a.Tool, queue, delivery, e.now()); err != nil {
			return fmt.Errorf("prepare native reminder: %w", err)
		}
		count, err = producer.CountV1(call)
		if err != nil {
			return fmt.Errorf("count native reminders: %w", err)
		}
		for i := 0; i < count; i++ {
			if err = producer.RotateV1(call, i); err != nil {
				return fmt.Errorf("rotate native reminder capability: %w", err)
			}
		}
		if !automatic {
			if err = producer.ResetManualScheduleV1(call); err != nil {
				return fmt.Errorf("reset native reminder schedule: %w", err)
			}
		}
		if delivery {
			messages = make([]dispatch.Message, count)
			for i := range messages {
				messages[i], err = producer.RenderV1(call, i)
				if err != nil {
					return fmt.Errorf("render reminder email: %w", err)
				}
			}
		}
		if queue {
			for i := 0; i < count; i++ {
				if err = producer.EnqueueV1(call, i); err != nil {
					return fmt.Errorf("persist reminder outbox: %w", err)
				}
			}
		}
		for i := 0; i < count; i++ {
			event, owner, err := ownedaudit.LogReminderV1(e.Audit, call, producer, audit.Entry{OrgID: doc.OrgID, DocumentID: &doc.ID})
			if err != nil {
				return fmt.Errorf("audit reminder: %w", err)
			}
			p.pending = append(p.pending, ownedSendPendingAuditV1{event: event, owner: owner})
		}
		if !automatic {
			if err = reauthorizeLifecycleActor(call, tx, a, actorUser); err != nil {
				return err
			}
		}
		// Keep the final real Engine policy-clock check after all org audit and
		// credential waits. The same native tx will own COMMIT or rollback.
		if err = producer.FinishV1(call, e.now()); err != nil {
			return fmt.Errorf("finish native reminder: %w", err)
		}
		return nil
	})
	if errors.Is(err, pdfadmission.ErrReminderDeadlineV1) {
		return 0, fmt.Errorf("%w: document deadline has passed", ErrNotRemindable)
	}
	if err != nil {
		return 0, err
	}
	if delivery && !queue {
		for _, message := range messages {
			o.sendPreparedReminderV1(message)
		}
	}
	return count, nil
}

// The already-rendered bounded message is consumed without another unfunded
// render. Original native Work/body grants remain until all actual mail calls
// join, even after request cancellation, SQL retirement or Remind's return.
func (o *ownedSendOperationV1) sendPreparedReminderV1(msg dispatch.Message) {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	o.mailers++
	o.mu.Unlock()
	go func() {
		defer func() {
			msg = dispatch.Message{}
			o.mu.Lock()
			o.mailers--
			works := o.retireConsumersLockedV1()
			o.mu.Unlock()
			o.releaseWorksV1(works)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := o.engine.Mailer.Send(ctx, msg); err != nil {
			slog.Warn("reminder: email send failed", "to", dispatch.MaskEmail(msg.To), "err", dispatch.ScrubEmails(err.Error()))
		}
	}()
}
