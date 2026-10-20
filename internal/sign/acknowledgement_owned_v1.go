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
	"github.com/bright-interaction/hash/internal/recipients"
)

func (l *signerReadLeaseV1) registerAcknowledgementRequestV1(e *Engine, request *pdfadmission.ApplicationAcknowledgementRequestV1) error {
	if l == nil || request == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.issuer != e || l.reader == nil || l.original == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	l.acknowledgementRequests = append(l.acknowledgementRequests, request)
	return nil
}

func acknowledgementFailureV1(err error) error {
	if errors.Is(err, pdfadmission.ErrAcknowledgementRequestV1) {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	return blockSignatureFailureV1(err)
}

// One native transaction replaces the original pooled Accept transaction.
// Original notice/mode/tier/status/expiry/role/already-accepted/declined checks
// retain their order. No missing runtime or original read may use a pool path.
func (e *Engine) acceptAcknowledgementOwnedV1(ctx context.Context, rc *RecipientContext, evidence ParticipantResponseEvidence) (result *Result, failure error) {
	defer func() { failure = acknowledgementFailureV1(failure) }()
	if e == nil || ctx == nil || rc == nil || rc.readLease == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	original, _, finishOriginal, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return nil, err
	}
	defer finishOriginal()
	doc, rec := original.Document, original.Recipient
	if doc == nil || rec == nil {
		return nil, ErrInvalidNoticeEvidence
	}
	factory := e.WorkRuntime.SessionsV1()
	packageRequest, err := factory.NewPackageResponseRequestV1(ctx, rc.readLease.reader, evidence.PackageResponse, "accepted")
	if err != nil {
		return nil, err
	}
	if err = rc.readLease.registerPackageResponseRequestV1(e, packageRequest); err != nil {
		packageRequest.CloseConsumerV1()
		return nil, err
	}
	request, err := factory.NewAcknowledgementRequestV1(ctx, rc.readLease.reader, evidence.IP, evidence.UserAgent, evidence.Notice)
	if err != nil {
		return nil, err
	}
	if err = rc.readLease.registerAcknowledgementRequestV1(e, request); err != nil {
		request.CloseConsumerV1()
		return nil, err
	}
	native, err := factory.NewHTMLSendOperationV1(ctx, doc.OrgID, doc.ID)
	if err != nil {
		return nil, err
	}
	operationClosed := false
	closeOperation := func() error {
		if operationClosed {
			return nil
		}
		operationClosed = true
		native.EndConsumerV1()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		// Only this operation's actual stages, physical fences and admissions
		// determine its outcome. A concurrent comment's pending cleanup keeps
		// its own debt; it cannot strand an acknowledged response after COMMIT.
		// Unknown retirement of our own session still denies further dispatch.
		if err := native.CloseV1(cleanup); err != nil {
			return fmt.Errorf("retire acknowledgement operation: %w", err)
		}
		return nil
	}
	defer func() { failure = errors.Join(failure, closeOperation()) }()
	stage, err := native.OpenSQLV1(pdfadmission.HTMLAcknowledgementMutationV1)
	if err != nil {
		return nil, err
	}
	stageClosed := false
	defer func() {
		if !stageClosed {
			failure = errors.Join(failure, stage.CloseSQLV1())
		}
	}()
	call, session := stage.ContextV1(), stage.SessionV1()
	if call == nil || session == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if _, err = session.NewAdmissionV1(call); err != nil {
		return nil, err
	}
	var remaining int64
	var retried bool
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
			return fmt.Errorf("lock document: %w", err)
		}
		models, err := w.ReadModelsV1(actual)
		if err != nil {
			return fmt.Errorf("lock document: %w", err)
		}
		locked := models.Document
		if err = ValidateLockedNoticeEvidence(original, locked, evidence.Notice); err != nil {
			return err
		}
		if locked.RequiresSignature {
			return ErrNotAcknowledgement
		}
		if err = requireSESTypedSignature(locked); err != nil {
			return err
		}
		if locked.Status != "sent" && locked.Status != "in_progress" {
			return ErrDocumentNotSignable
		}
		finishMutation, err := w.BeginAcknowledgementMutationV1(actual, request)
		if err != nil {
			return err
		}
		defer finishMutation()
		finishPackage, err := w.BeginPackageResponseV1(actual, packageRequest)
		if err != nil {
			return err
		}
		defer finishPackage()
		if err = w.ValidatePackageResponseV1(actual); err != nil {
			return err
		}
		fresh, err := w.ReadAcknowledgementRecipientV1(actual)
		if err != nil {
			return err
		}
		if err = checkLockedMagicLinkExpiry(fresh, locked, e.now()); err != nil {
			return err
		}
		if fresh.DocumentID != doc.ID || !recipients.CanRespond(fresh.Role) {
			return ErrRecipientNotEligibleForResponse
		}
		if fresh.Status == "accepted" {
			matched, retryErr := w.MatchPriorPackageResponseV1(actual)
			if retryErr != nil {
				return retryErr
			}
			if !matched {
				return ErrAlreadyAccepted
			}
			remaining, retryErr = w.CountPackageResponseRetryRemainingV1(actual)
			if retryErr != nil {
				return retryErr
			}
			retried = true
			return ValidateLockedRecipientCredential(original, fresh, locked, e.now())
		}
		if fresh.Status == "declined" {
			return errors.New("recipient already declined")
		}
		if err = w.PrepareResponseReportFamilyV1(actual); err != nil {
			return responseReportAdmissionErrorV1(err)
		}
		if err = w.MarkAcknowledgementAcceptedV1(actual); err != nil {
			return err
		}
		remaining, err = w.CountAcknowledgementPendingV1(actual)
		if err != nil {
			return err
		}
		acceptedPayload, err := responseAuditPayload(map[string]any{"recipient_email": rec.Email}, evidence.Notice)
		if err != nil {
			return fmt.Errorf("bind acceptance notice evidence: %w", err)
		}
		ip, userAgent, err := request.MetadataV1()
		if err != nil {
			return err
		}
		packageEvent, err := w.PackageResponseAuditV1(actual, acceptedPayload)
		if err != nil {
			return err
		}
		entry := audit.Entry{OrgID: doc.OrgID, DocumentID: &doc.ID, RecipientID: &rec.ID, Kind: audit.KindDocumentAccepted, IP: ip, UserAgent: userAgent, Payload: acceptedPayload}
		if packageEvent {
			pending, auditOwner, err = ownedaudit.LogPackageResponseV1(e.Audit, actual, w, entry)
		} else {
			pending, auditOwner, err = ownedaudit.LogV1(e.Audit, actual, session, pdfadmission.HTMLAuditAcknowledgedV1, entry)
		}
		if err != nil {
			return fmt.Errorf("audit acceptance: %w", err)
		}
		if err = w.RecordPackageResponseV1(actual, auditOwner); err != nil {
			return err
		}
		if err = w.AdmitResponseReportV1(actual, auditOwner); err != nil {
			return responseReportAdmissionErrorV1(err)
		}
		// The original recipient lock spans capacity/freeze work too. Preserve
		// the final real Engine clock/credential check after that work, with the
		// existing maximum of two genuine recipient reads.
		fresh, err = w.ReadAcknowledgementRecipientV1(actual)
		if err != nil {
			return err
		}
		return ValidateLockedRecipientCredential(original, fresh, locked, e.now())
	})
	if err != nil {
		return nil, err
	}
	if err = session.CommitV1(call); err != nil {
		_ = session.CommitDispatchObservationV1()
		return nil, fmt.Errorf("commit accept: %w", err)
	}
	if err = stage.CloseSQLV1(); err != nil {
		return nil, err
	}
	stageClosed = true
	if !retried {
		if err = ownedaudit.PublishV1(e.Audit, pending, auditOwner); err != nil {
			return nil, err
		}
	}
	pending = audit.PendingEvent{}
	auditOwner = nil
	// Every locked source/mutation view ends before the separate historical
	// completion operation. The request/result loan remains with rc until its
	// actual response last use; hook publication has its own joined consumer.
	if err = closeOperation(); err != nil {
		return nil, err
	}
	if remaining > 0 {
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}
	completionCredential := &completionCredentialCapture{recipientID: rec.ID}
	completedDoc, did, completionErr := e.completeAcknowledgedDocument(ctx, doc.OrgID, doc.ID, completionCredential)
	if err = e.retainHistoricalPublicationForRecipientV1(rc, completionCredential); err != nil {
		return nil, err
	}
	if completionErr != nil || !did {
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}
	return &Result{DocumentID: doc.ID, Status: "completed", Completed: true, FinalPDFKey: acknowledgedFinalKey(completedDoc), FinalPDFURL: completedArtifactPath(completionCredential.rawToken), AuditCertURL: completedAuditCertificatePath(completionCredential.rawToken), PackagePortalURL: completedPackagePortalPathV1(completionCredential.rawToken)}, nil
}
