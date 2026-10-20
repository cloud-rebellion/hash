// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
)

func (l *signerReadLeaseV1) registerSignerViewRequestV1(e *Engine, h *pdfadmission.ApplicationSignerViewRequestV1) error {
	if l == nil || h == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.issuer != e || l.reader == nil || l.original == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	l.signerViewRequests = append(l.signerViewRequests, h)
	return nil
}

func (e *Engine) markViewedOwnedV1(ctx context.Context, rc *RecipientContext, evidence ParticipantResponseEvidence) (failure error) {
	defer func() {
		if errors.Is(failure, pdfadmission.ErrSignerViewRequestV1) {
			failure = errors.Join(ErrSigningAdmissionUnavailableV1, failure)
		}
		failure = blockSignatureFailureV1(failure)
	}()
	if e == nil || ctx == nil || rc == nil || rc.readLease == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return ErrSigningAdmissionUnavailableV1
	}
	// Keep the ordinary public-read deadline. A shorter caller deadline wins.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	original, _, finishOriginal, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return err
	}
	defer finishOriginal()
	doc, rec := original.Document, original.Recipient
	if doc == nil || rec == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	factory := e.WorkRuntime.SessionsV1()
	request, err := factory.NewSignerViewRequestV1(ctx, rc.readLease.reader, evidence.IP, evidence.UserAgent, evidence.Notice)
	if err != nil {
		return err
	}
	if err = rc.readLease.registerSignerViewRequestV1(e, request); err != nil {
		request.CloseConsumerV1()
		return err
	}
	if err = validateNoticeEvidence(original, evidence.Notice); err != nil {
		return err
	}
	native, err := factory.NewHTMLSendOperationV1(ctx, doc.OrgID, doc.ID)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		failure = errors.Join(failure, native.CloseV1(cleanup))
	}()
	stage, err := native.OpenSQLV1(pdfadmission.HTMLSignerViewMutationV1)
	if err != nil {
		return err
	}
	stageClosed := false
	defer func() {
		if !stageClosed {
			failure = errors.Join(failure, stage.CloseSQLV1())
		}
	}()
	call, session := stage.ContextV1(), stage.SessionV1()
	if call == nil || session == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	if _, err = session.NewAdmissionV1(call); err != nil {
		return err
	}
	var pending audit.PendingEvent
	var auditOwner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	defer func() {
		if auditOwner != nil {
			auditOwner.CloseConsumerV1()
		}
	}()
	err = stage.WithTxV1(func(actual context.Context, _ generated.DBTX) error {
		w, err := session.NewHTMLSendWorkV1(actual, stage)
		if err != nil {
			return err
		}
		if _, err = w.StateV1(actual); err != nil {
			return fmt.Errorf("lock document for viewed event: %w", err)
		}
		models, err := w.ReadModelsV1(actual)
		if err != nil {
			return err
		}
		locked := models.Document
		if err = ValidateLockedNoticeEvidence(original, locked, evidence.Notice); err != nil {
			return err
		}
		if err = checkActiveCeremonyAccess(locked); err != nil {
			return err
		}
		finishMutation, err := w.BeginSignerViewMutationV1(actual, request)
		if err != nil {
			return err
		}
		defer finishMutation()
		fresh, err := w.ReadSignerViewRecipientV1(actual)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMagicLinkExpired
		}
		if err != nil {
			return err
		}
		if err = ValidateLockedRecipientCredential(original, fresh, locked, e.now()); err != nil {
			return err
		}
		if fresh.Status != "pending" && fresh.Status != "sent" {
			return nil
		}
		if err = w.MarkSignerViewedV1(actual); err != nil {
			return err
		}
		payload, err := responseAuditPayload(nil, evidence.Notice)
		if err != nil {
			return fmt.Errorf("bind view notice evidence: %w", err)
		}
		ip, ua, err := request.MetadataV1()
		if err != nil {
			return err
		}
		pending, auditOwner, err = ownedaudit.LogV1(e.Audit, actual, session, pdfadmission.HTMLAuditSignerViewedV1, audit.Entry{OrgID: doc.OrgID, DocumentID: &doc.ID, RecipientID: &rec.ID, Kind: audit.KindDocumentViewed, IP: ip, UserAgent: ua, Payload: payload})
		if err != nil {
			return fmt.Errorf("audit document view: %w", err)
		}
		// The token may expire naturally during an audit-head wait. The native
		// recipient SHARE lock retains rotation while this final check runs.
		fresh, err = w.ReadSignerViewRecipientV1(actual)
		if err != nil {
			return err
		}
		return ValidateLockedRecipientCredential(original, fresh, locked, e.now())
	})
	if err != nil {
		return err
	}
	if err = session.CommitV1(call); err != nil {
		_ = session.CommitDispatchObservationV1()
		return fmt.Errorf("commit document view: %w", err)
	}
	if err = stage.CloseSQLV1(); err != nil {
		return err
	}
	stageClosed = true
	if auditOwner != nil {
		if err = ownedaudit.PublishV1(e.Audit, pending, auditOwner); err != nil {
			return err
		}
		auditOwner = nil
	}
	return nil
}
