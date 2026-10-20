// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5/pgconn"
)

func signerFieldsFailureV1(failure error) error {
	if errors.Is(failure, pdfadmission.ErrSignerFieldsRequestV1) {
		return errors.Join(ErrSigningAdmissionUnavailableV1, failure)
	}
	// The native DBTX tags every failed statement with ErrApplicationSessionV1.
	// A concrete server execution error retains the field route's generic500;
	// it is not evidence that resource admission failed. Unresolved retirement,
	// commit or cancellation still takes the unavailable path.
	var databaseError *pgconn.PgError
	if errors.As(failure, &databaseError) &&
		!errors.Is(failure, pdfadmission.ErrApplicationSessionUnknownV1) &&
		!errors.Is(failure, pdfadmission.ErrApplicationSessionCommitUnknownV1) &&
		!errors.Is(failure, context.Canceled) && !errors.Is(failure, context.DeadlineExceeded) {
		return failure
	}
	return blockSignatureFailureV1(failure)
}

type ownedSignerFieldsOperationV1 struct {
	native   *pdfadmission.ApplicationHTMLSendOperationV1
	factory  *pdfadmission.ApplicationSessionFactoryV1
	original context.Context
}

func (o *ownedSignerFieldsOperationV1) closeV1() error {
	if o == nil || o.native == nil || o.factory == nil || o.original == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	o.native.CloseConsumerV1()
	cleanup, stop := context.WithTimeout(context.WithoutCancel(o.original), 5*time.Second)
	defer stop()
	return o.factory.ReconcileCleanupV1(cleanup)
}

// NewSignerFieldsRequestV1 reserves the existing bounded JSON capture before
// decoding. Only the real original reader supplies recipient/document scope.
func (e *Engine) NewSignerFieldsRequestV1(ctx context.Context, rc *RecipientContext, evidence ParticipantResponseEvidence) (*pdfadmission.ApplicationSignerFieldsRequestV1, error) {
	if e == nil || ctx == nil || rc == nil || rc.readLease == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	original, _, finish, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return nil, err
	}
	defer finish()
	request, err := e.WorkRuntime.SessionsV1().NewSignerFieldsRequestV1(ctx, rc.readLease.reader, evidence.IP, evidence.UserAgent, evidence.Notice)
	if err != nil {
		return nil, errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	l := rc.readLease
	l.mu.Lock()
	if l.closed || l.issuer != e || l.reader == nil || l.original == nil {
		l.mu.Unlock()
		request.CloseConsumerV1()
		return nil, ErrSigningAdmissionUnavailableV1
	}
	l.signerFieldsRequests = append(l.signerFieldsRequests, request)
	l.mu.Unlock()
	if err = validateNoticeEvidence(original, evidence.Notice); err != nil {
		return nil, err
	}
	return request, nil
}

// This callback is the fixed application field policy, not a configurable SQL
// adapter. It receives no transaction or DBTX. The actual native operation
// commits update+audit+measurement together and retains result bodies on the
// original recipient lease until the handler has serialized its response.
func (e *Engine) WithSignerFieldsMutationV1(ctx context.Context, rc *RecipientContext, request *pdfadmission.ApplicationSignerFieldsRequestV1, mutate func(context.Context, *RecipientContext, *generated.Document, *pdfadmission.ApplicationHTMLSendWorkV1, func(audit.Entry) error) error) (failure error) {
	defer func() {
		failure = signerFieldsFailureV1(failure)
	}()
	if e == nil || ctx == nil || rc == nil || rc.readLease == nil || request == nil || mutate == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return ErrSigningAdmissionUnavailableV1
	}
	original, _, finish, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return err
	}
	defer finish()
	l := rc.readLease
	l.mu.Lock()
	registered := false
	for _, h := range l.signerFieldsRequests {
		if h == request {
			registered = true
			break
		}
	}
	l.mu.Unlock()
	if !registered {
		return ErrSigningAdmissionUnavailableV1
	}
	count, err := request.ValueCountV1()
	if err != nil {
		return err
	}
	doc, rec := original.Document, original.Recipient
	if doc == nil || rec == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	factory := e.WorkRuntime.SessionsV1()
	native, err := factory.NewHTMLSendOperationV1(ctx, doc.OrgID, doc.ID)
	if err != nil {
		return err
	}
	operation := &ownedSignerFieldsOperationV1{native: native, factory: factory, original: ctx}
	l.mu.Lock()
	if l.closed || l.issuer != e {
		l.mu.Unlock()
		return errors.Join(ErrSigningAdmissionUnavailableV1, operation.closeV1())
	}
	l.signerFieldsOperations = append(l.signerFieldsOperations, operation)
	l.mu.Unlock()
	stage, err := native.OpenSQLV1(pdfadmission.HTMLSignerFieldsMutationV1)
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
	var pending []audit.PendingEvent
	var owners []*pdfadmission.ApplicationHTMLAuditEventConsumerV1
	defer func() {
		for _, owner := range owners {
			if owner != nil {
				owner.CloseConsumerV1()
			}
		}
	}()
	err = stage.WithTxV1(func(actual context.Context, _ generated.DBTX) error {
		w, err := session.NewHTMLSendWorkV1(actual, stage)
		if err != nil {
			return err
		}
		if _, err = w.StateV1(actual); err != nil {
			return err
		}
		models, err := w.ReadModelsV1(actual)
		if err != nil {
			return err
		}
		finishMutation, err := w.BeginSignerFieldsMutationV1(actual, request)
		if err != nil {
			return err
		}
		defer finishMutation()
		appendAudit := func(entry audit.Entry) error {
			if len(pending) >= count || entry.DocumentID == nil || *entry.DocumentID != doc.ID || entry.OrgID != doc.OrgID || entry.RecipientID == nil || *entry.RecipientID != rec.ID || entry.ActorUserID != nil || entry.Kind != audit.KindDocumentFieldFill {
				return pdfadmission.ErrSignerFieldsRequestV1
			}
			p, owner, err := ownedaudit.LogV1(e.Audit, actual, session, pdfadmission.HTMLAuditSignerFieldFilledV1, entry)
			if err != nil {
				return err
			}
			pending = append(pending, p)
			owners = append(owners, owner)
			return nil
		}
		if err = mutate(actual, original, models.Document, w, appendAudit); err != nil {
			return err
		}
		if len(pending) != count {
			return pdfadmission.ErrSignerFieldsRequestV1
		}
		return w.SignerFieldsWritesCompleteV1(actual)
	})
	if err != nil {
		return err
	}
	if err = session.CommitV1(call); err != nil {
		_ = session.CommitDispatchObservationV1()
		return err
	}
	if err = stage.CloseSQLV1(); err != nil {
		return err
	}
	stageClosed = true
	for i, p := range pending {
		if err = ownedaudit.PublishV1(e.Audit, p, owners[i]); err != nil {
			return err
		}
		owners[i] = nil
	}
	return nil
}
