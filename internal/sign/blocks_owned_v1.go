// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"time"
)

func blockSignatureFailureV1(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pdfadmission.ErrSignerReadCredentialV1) {
		return errors.Join(ErrMagicLinkExpired, err)
	}
	for _, known := range []error{pdfadmission.ErrSignerPackageReadV1, pdfadmission.ErrPackageResponseRequestV1, pdfadmission.ErrBlockSignatureRequestV1, pdfadmission.ErrHTMLSendWorkV1, pdfadmission.ErrApplicationSessionV1, pdfadmission.ErrApplicationSessionUnknownV1, pdfadmission.ErrHTMLAuthoringReadV1, pdfadmission.ErrHTMLRevisionSourceV1, pdfadmission.ErrHTMLAuditEventV1, pdfadmission.ErrHistoricalFinalizationEvidenceV1} {
		if errors.Is(err, known) {
			return errors.Join(ErrSigningAdmissionUnavailableV1, err)
		}
	}
	return err
}
func ownedBlocksSignatureEntryV1(rc *RecipientContext) bool {
	if rc == nil || rc.Document == nil {
		return false
	}
	if rc.readLease != nil {
		l := rc.readLease
		l.mu.Lock()
		isBlocks := l.original != nil && l.original.Document != nil && (l.original.Document.SourceKind == "blocks" || l.original.Document.SourceKind == "pdf")
		l.mu.Unlock()
		if isBlocks {
			return true
		}
	}
	return rc.Document.SourceKind == "blocks" || rc.Document.SourceKind == "pdf"
}
func (l *signerReadLeaseV1) registerBlockSignatureRequestV1(e *Engine, h *pdfadmission.ApplicationBlockSignatureRequestV1) error {
	if l == nil || h == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.issuer != e || l.reader == nil || l.original == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	l.blockSignatureRequests = append(l.blockSignatureRequests, h)
	return nil
}

type ownedBlocksSignatureOperationV1 struct {
	native   *pdfadmission.ApplicationHTMLSendOperationV1
	factory  *pdfadmission.ApplicationSessionFactoryV1
	original context.Context
}

func (o *ownedBlocksSignatureOperationV1) phaseV1(purpose pdfadmission.HTMLSendSQLPurposeV1, fn func(context.Context, *pdfadmission.ApplicationSessionV1, *pdfadmission.ApplicationHTMLSendWorkV1) error) error {
	stage, err := o.native.OpenSQLV1(purpose)
	if err != nil {
		return err
	}
	ctx := stage.ContextV1()
	session := stage.SessionV1()
	if ctx == nil || session == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	defer func() { _ = stage.CloseSQLV1() }()
	if _, err = session.NewAdmissionV1(ctx); err != nil {
		return err
	}
	var preparedWork *pdfadmission.ApplicationHTMLSendWorkV1
	err = stage.WithTxV1(func(call context.Context, _ generated.DBTX) error {
		work, err := session.NewHTMLSendWorkV1(call, stage)
		if err != nil {
			return err
		}
		if purpose == pdfadmission.HTMLBlockSignPreparationV1 {
			preparedWork = work
		}
		return fn(call, session, work)
	})
	if err != nil {
		return err
	}
	err = session.CommitV1(ctx)
	if err != nil {
		_ = session.CommitDispatchObservationV1()
		return err
	}
	if preparedWork != nil {
		if err = stage.CloseSQLV1(); err != nil {
			return err
		}
		preparedWork.CloseConsumerV1()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(o.original), 5*time.Second)
		defer stop()
		err = o.factory.ReconcileCleanupV1(cleanup)
		if err != nil && (!errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return err
		}
	}
	return nil
}
func (o *ownedBlocksSignatureOperationV1) closeV1() error {
	if o == nil || o.native == nil || o.factory == nil || o.original == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	o.native.CloseConsumerV1()
	cleanup, stop := context.WithTimeout(context.WithoutCancel(o.original), 5*time.Second)
	defer stop()
	err := o.factory.ReconcileCleanupV1(cleanup)
	if err != nil && (!errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return err
	}
	return nil
}

// The reachable historical blocks/PDF route uses actual native source, SQL, provider and audit
// owners. No unavailable runtime/request can fall back to Pool.Begin or a
// configured child full-row callback. Finalization is a distinct boundary.
func (e *Engine) signBlocksOwnedV1(ctx context.Context, rc *RecipientContext, in SignInput) (result *Result, failure error) {
	defer func() { failure = blockSignatureFailureV1(failure) }()
	if e == nil || rc == nil || rc.readLease == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	original, _, finishOriginal, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return nil, err
	}
	defer finishOriginal()
	doc, rec := original.Document, original.Recipient
	if doc == nil || rec == nil || (doc.SourceKind != "blocks" && doc.SourceKind != "pdf") {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if err = requireSESTypedSignature(doc); err != nil {
		return nil, err
	}
	if err = validateNoticeEvidence(original, in.Notice); err != nil {
		return nil, err
	}
	if doc.SigningAdmissionPolicy == "pdf-static-v1" {
		if _, err = e.validateFittedRequestV1(ctx, original, in); err != nil {
			return nil, err
		}
	}
	if err = requireHistoricalSigningAdmissionV1(doc); err != nil {
		return nil, err
	}
	factory := e.WorkRuntime.SessionsV1()
	packageRequest, err := factory.NewPackageResponseRequestV1(ctx, rc.readLease.reader, in.PackageResponse, "signed")
	if err != nil {
		return nil, err
	}
	if err = rc.readLease.registerPackageResponseRequestV1(e, packageRequest); err != nil {
		packageRequest.CloseConsumerV1()
		return nil, err
	}
	request, err := factory.NewBlockSignatureRequestV1(ctx, rc.readLease.reader, in.TypedName, in.Font, in.IP, in.UserAgent)
	if err != nil {
		return nil, err
	}
	if err = rc.readLease.registerBlockSignatureRequestV1(e, request); err != nil {
		request.CloseConsumerV1()
		return nil, err
	}
	native, err := factory.NewHTMLSendOperationV1(ctx, doc.OrgID, doc.ID)
	if err != nil {
		return nil, err
	}
	operation := &ownedBlocksSignatureOperationV1{native: native, factory: factory, original: ctx}
	defer func() {
		if err := operation.closeV1(); err != nil {
			failure = errors.Join(failure, err)
		}
	}()
	if doc.SourceKind == "pdf" {
		err = operation.phaseV1(pdfadmission.HTMLBlockSignPreparationV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
			if _, err := w.StateV1(call); err != nil {
				return err
			}
			if _, err := w.ReadModelsV1(call); err != nil {
				return err
			}
			if _, err := w.ReadFieldsV1(call); err != nil {
				return fmt.Errorf("prepare PDF signature targets: %w", err)
			}
			return request.PrepareHistoricalPDFV1(call, w)
		})
	} else if doc.IsEnvelope {
		if e.EnvelopeChildren == nil {
			return nil, errors.New("find signature field: envelope children unavailable")
		}
		err = operation.phaseV1(pdfadmission.HTMLBlockSignPreparationV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
			if _, err := w.StateV1(call); err != nil {
				return err
			}
			if _, err := w.ReadModelsV1(call); err != nil {
				return err
			}
			if _, err := w.ReadEnvelopeMembersV1(call); err != nil {
				return err
			}
			return request.PrepareEnvelopeV1(call, w)
		})
	} else {
		err = request.PrepareStandaloneV1()
	}
	if err != nil {
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
	err = operation.phaseV1(pdfadmission.HTMLBlockSignMutationV1, func(call context.Context, session *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return fmt.Errorf("lock document: %w", err)
		}
		models, err := w.ReadModelsV1(call)
		if err != nil {
			return fmt.Errorf("lock document: %w", err)
		}
		locked := models.Document
		if err = requireHistoricalSigningAdmissionV1(locked); err != nil {
			return err
		}
		if err = ValidateLockedNoticeEvidence(original, locked, in.Notice); err != nil {
			return err
		}
		if locked.Status != "sent" && locked.Status != "in_progress" {
			return ErrDocumentNotSignable
		}
		if err = requireSESTypedSignature(locked); err != nil {
			return err
		}
		if err = w.BeginBlockSignatureMutationV1(call, request); err != nil {
			return err
		}
		finishPackage, err := w.BeginPackageResponseV1(call, packageRequest)
		if err != nil {
			return err
		}
		defer finishPackage()
		if err = w.ValidatePackageResponseV1(call); err != nil {
			return err
		}
		fresh, err := w.ReadBlockSignatureRecipientV1(call)
		if err != nil {
			return err
		}
		if err = ValidateLockedRecipientCredential(original, fresh, locked, e.now()); err != nil {
			return err
		}
		if fresh.DocumentID != doc.ID || !recipients.CanRespond(fresh.Role) {
			return ErrRecipientNotEligibleForResponse
		}
		if fresh.Status == "signed" {
			matched, retryErr := w.MatchPriorSignedPackageResponseV1(call, request)
			if retryErr != nil {
				return retryErr
			}
			if !matched {
				return ErrAlreadySigned
			}
			if _, retryErr = w.RequiredBlockSignatureRolesV1(call); retryErr != nil {
				return retryErr
			}
			remaining, retryErr = w.CountPackageResponseRetryRemainingV1(call)
			if retryErr != nil {
				return retryErr
			}
			retried = true
			return ValidateLockedRecipientCredential(original, fresh, locked, e.now())
		}
		if fresh.Status == "declined" {
			return errors.New("recipient already declined")
		}
		if locked.IsEnvelope && e.EnvelopeChildren == nil {
			return errors.New("resolve signer roles: envelope children unavailable")
		}
		roles, err := w.RequiredBlockSignatureRolesV1(call)
		if err != nil {
			return err
		}
		if _, required := signerRoleSet(roles)[fresh.Role]; !required {
			return ErrRecipientNotEligibleForResponse
		}
		if err = w.PrepareResponseReportFamilyV1(call); err != nil {
			return responseReportAdmissionErrorV1(err)
		}
		unfilled, err := w.CountBlockSignatureUnfilledV1(call)
		if err != nil {
			return fmt.Errorf("check required signer fields: %w", err)
		}
		if unfilled > 0 {
			return fmt.Errorf("%d required field(s) unfilled", unfilled)
		}
		if _, err = w.ReadFieldsV1(call); err != nil {
			return err
		}
		if doc.SourceKind == "pdf" || locked.SourceKind == "pdf" {
			err = w.ValidateHistoricalPDFSignatureTargetsV1(call)
			if errors.Is(err, pdfadmission.ErrHistoricalPDFSignaturePreparationChangedV1) {
				return ErrSignaturePreparationChanged
			}
			if err != nil {
				return err
			}
		} else if _, err = w.FindOrCreateBlockSignatureFieldV1(call); err != nil {
			return err
		}
		client, ok := e.Storage.(*storage.Client)
		if !ok || client == nil {
			return errors.New("store signature span: concrete evidence storage unavailable")
		}
		if err = request.StoreEvidenceV1(call, w, client); err != nil {
			return err
		}
		sig, err := w.InsertBlockSignatureV1(call)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAlreadySigned
		}
		if err != nil {
			return fmt.Errorf("insert signature row: %w", err)
		}
		if err = w.MarkBlockSignatureSignedV1(call); err != nil {
			return err
		}
		remaining, err = w.CountBlockSignatureRemainingV1(call)
		if err != nil {
			return err
		}
		view, err := request.PreparedViewV1()
		if err != nil {
			return err
		}
		payload, err := responseAuditPayload(map[string]any{"font": view.Font, "typed_name": view.TypedName, "image_sha256": fmt.Sprintf("%x", sig.ImageSha256), "signature_id": sig.ID}, in.Notice)
		if err != nil {
			return fmt.Errorf("bind signature notice evidence: %w", err)
		}
		packageEvent, err := w.PackageResponseAuditV1(call, payload)
		if err != nil {
			return err
		}
		entry := audit.Entry{OrgID: doc.OrgID, DocumentID: &doc.ID, RecipientID: &rec.ID, Kind: audit.KindDocumentSigned, IP: view.IP, UserAgent: view.UserAgent, Payload: payload}
		if packageEvent {
			pending, auditOwner, err = ownedaudit.LogPackageResponseV1(e.Audit, call, w, entry)
		} else {
			pending, auditOwner, err = ownedaudit.LogV1(e.Audit, call, session, pdfadmission.HTMLAuditBlockSignedV1, entry)
		}
		if err != nil {
			return fmt.Errorf("audit signature: %w", err)
		}
		if err = w.RecordPackageResponseV1(call, auditOwner); err != nil {
			return err
		}
		if err = w.AdmitResponseReportV1(call, auditOwner); err != nil {
			return responseReportAdmissionErrorV1(err)
		}
		fresh, err = w.ReadBlockSignatureRecipientV1(call)
		if err != nil {
			return err
		}
		return ValidateLockedRecipientCredential(original, fresh, locked, e.now())
	})
	if err != nil {
		return nil, err
	}
	if !retried {
		if err = ownedaudit.PublishV1(e.Audit, pending, auditOwner); err != nil {
			return nil, err
		}
	}
	auditOwner = nil
	// The signature transaction and every source/member view have completed their
	// final use before the separate finalization call graph begins. The request's
	// original/result CPU loan remains with rc through actual response last use.
	if err = operation.closeV1(); err != nil {
		return nil, err
	}
	if remaining > 0 {
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}
	completionCredential := &completionCredentialCapture{recipientID: rec.ID}
	finalKey, _, _, ferr := e.finalize(ctx, doc.OrgID, doc.ID, completionCredential)
	if err := e.retainHistoricalPublicationForRecipientV1(rc, completionCredential); err != nil {
		return nil, err
	}
	if ferr != nil {
		if !errors.Is(ferr, ErrFinalizeInProgress) && !errors.Is(ferr, ErrDocumentRevisedDuringFinalize) {
			slog.Error("document finalization failed after signature commit", "document_id", doc.ID, "org_id", doc.OrgID, "err", ferr)
		}
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}
	return &Result{DocumentID: doc.ID, Status: "completed", Completed: true, FinalPDFKey: finalKey, FinalPDFURL: completedArtifactPath(completionCredential.rawToken), AuditCertURL: completedAuditCertificatePath(completionCredential.rawToken), PackagePortalURL: completedPackagePortalPathV1(completionCredential.rawToken)}, nil
}
