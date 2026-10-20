// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package packageauthoring

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"time"
)

func SaveLayoutV1(ctx context.Context, d DependenciesV1, actor authoring.Actor, input *pdfadmission.ApplicationDocumentPackageInputV1, ip, ua string) (out OutcomeV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || input == nil {
		return out, pdfadmission.ErrDocumentPackageInputV1
	}
	failure = input.WithLayoutV1(ctx, actor.OrgID, func(in pdfadmission.DocumentPackageLayoutInputV1) (operationErr error) {
		session, e := d.Sessions.OpenV1(ctx, actor.OrgID, in.Root)
		var admission *pdfadmission.ApplicationAdmissionV1
		var reader *pdfadmission.ApplicationHTMLRevisionReaderV1
		var event *pdfadmission.ApplicationHTMLAuditEventConsumerV1
		var pending audit.PendingEvent
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			if event != nil {
				event.CloseConsumerV1()
			}
			if reader != nil {
				reader.CloseConsumerV1()
			}
			var retirement error
			if session != nil {
				retirement = session.CloseV1(cleanup)
			}
			if admission != nil {
				_, e := admission.ReconcileCleanupV1(cleanup)
				retirement = errors.Join(retirement, e)
			}
			if retirement != nil {
				if out.State == "committed" || out.State == "unknown" {
					out.ReconciliationRequired = true
					out.Cause = errors.Join(out.Cause, retirement)
				} else {
					operationErr = errors.Join(operationErr, retirement)
				}
			}
		}()
		if e != nil {
			return e
		}
		admission, e = session.NewAdmissionV1(ctx)
		if e != nil {
			return e
		}
		var result pdfadmission.DocumentPackageLayoutResultV1
		e = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
			var e error
			reader, e = session.NewHTMLRevisionReaderV1(call)
			if e != nil {
				return e
			}
			guard, e := readStaffDraftRootV1(call, db, reader, actor, in.Root)
			if e != nil {
				return e
			}
			result, e = reader.ApplyDocumentPackageLayoutV1(call, in, actor.UserID, ip, ua, func(appendCtx context.Context, actual *pdfadmission.ApplicationHTMLAuditEventConsumerV1) error {
				var appendErr error
				pending, event, appendErr = ownedaudit.AppendDocumentPackageLayoutV1(d.Audit, appendCtx, actual, audit.Entry{OrgID: actor.OrgID, DocumentID: &in.Root})
				return appendErr
			})
			if errors.Is(e, pdfadmission.ErrDocumentPackagePendingPrivacyV1) {
				return authoring.ErrPendingPrivacyReview
			}
			if errors.Is(e, pdfadmission.ErrDocumentPackagePrivacyChangingV1) {
				return authoring.ErrPrivacyReviewChanging
			}
			if e != nil {
				return e
			}
			return guard.Recheck(call)
		})
		if e != nil {
			return e
		}
		if result.ChangedRows == 0 {
			out.State = "unchanged"
			out.Layout = &result
			return nil
		}
		if result.EventID == uuid.Nil || event == nil {
			return pdfadmission.ErrDocumentPackageWriteV1
		}
		if e = session.CommitV1(ctx); e != nil {
			if !session.CommitDispatchObservationV1().NeverDispatchedV1() {
				out.State = "unknown"
				out.ReconciliationRequired = true
				out.Message = "reload attachments and reconcile this operation before retrying"
				out.Cause = e
				return nil
			}
			return e
		}
		out.State = "committed"
		out.Layout = &result
		if e = ownedaudit.PublishV1(d.Audit, pending, event); e != nil {
			out.ReconciliationRequired = true
			out.Cause = e
			out.Message = "attachment layout saved; publication reconciliation is required"
		}
		return nil
	})
	return out, failure
}
