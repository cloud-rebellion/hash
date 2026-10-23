// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package amendmentauthoring

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/noticeaccess"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"time"
)

func closeNoticeStageV1(ctx context.Context, session *pdfadmission.ApplicationSessionV1, admission *pdfadmission.ApplicationAdmissionV1) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var e error
	if session != nil {
		e = session.CloseV1(cleanup)
	}
	if admission != nil {
		_, err := admission.ReconcileCleanupV1(cleanup)
		e = errors.Join(e, err)
	}
	return e
}

// Closing a native consumer is a signal, not coordinator credit. The old
// physical session is already closed, but its original admission must reconcile
// again AFTER the broad pair's actual last use before a fresh pair is opened.
func retireNoticeInitialAdmissionV1(ctx context.Context, admission *pdfadmission.ApplicationAdmissionV1) error {
	if admission == nil {
		return amendments.ErrUnavailableV1
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	pending, err := admission.ReconcileCleanupV1(cleanup)
	if err != nil {
		return err
	}
	observed := admission.PendingV1()
	if pending != 0 || observed.Loans != 0 || observed.RetainedPages != 0 || !observed.ClientCleaned || !observed.ServerRetired {
		return pdfadmission.ErrApplicationSessionUnknownV1
	}
	return nil
}

func IssueNoticeV1(ctx context.Context, d DependenciesV1, engine *noticeaccess.EngineV1, actor authoring.Actor, original, amendmentID uuid.UUID, in amendments.IssueNoticeV1, ip, ua string) (result *ResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || engine == nil || actor.Authorize == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || original == uuid.Nil || amendmentID == uuid.Nil {
		return nil, amendments.ErrUnavailableV1
	}
	if e := in.ValidateV1(); e != nil {
		return nil, e
	}
	result = newResultV1()
	var session *pdfadmission.ApplicationSessionV1
	var admission *pdfadmission.ApplicationAdmissionV1
	var initialAdmission *pdfadmission.ApplicationAdmissionV1
	var noticeOwner *pdfadmission.ApplicationLaterAmendmentNoticeV1
	var event *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	var pending audit.PendingEvent
	defer func() {
		if event != nil {
			event.CloseConsumerV1()
		}
		if noticeOwner != nil {
			noticeOwner.CloseConsumerV1()
		}
		e := closeNoticeStageV1(ctx, session, admission)
		if e != nil {
			if out, ok := result.state.value.(amendments.OutcomeV1); ok && (out.State == "committed" || out.State == "unknown") {
				out.ReconciliationRequired = true
				result.state.value = out
			} else {
				failure = errors.Join(failure, e)
			}
		}
		if failure != nil {
			result.CloseConsumerV1()
		}
		// Provider/preparation refusal may still own the initial pair. The
		// genuine notice borrower and result consumer have now closed above;
		// re-observe THAT original admission, never merely a later SQL session.
		if initialAdmission != nil {
			failure = errors.Join(failure, retireNoticeInitialAdmissionV1(ctx, initialAdmission))
		}
	}()
	var e error
	session, e = d.Sessions.OpenV1(ctx, actor.OrgID, original)
	if e != nil {
		return result, e
	}
	admission, e = session.NewAdmissionV1(ctx)
	if e != nil {
		return result, e
	}
	if e = result.bindAdmissionV1(ctx, admission); e != nil {
		return result, e
	}
	var candidate uuid.UUID
	var replay *amendments.NoticeV1
	e = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var e error
		candidate, e = session.ResolveLaterAmendmentCandidateV1(call, amendmentID)
		if e != nil {
			return e
		}
		pair, e := session.NewDocumentPackageSelectionV1(call, candidate)
		result.state.pair = pair
		if e != nil {
			return e
		}
		gate, guard := readGateV1(call, db, actor, true)
		_, e = pair.ReadDocumentsV1(call, actor.UserID, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
			if a.OrgID != actor.OrgID || (a.DocumentID != original && a.DocumentID != candidate) {
				return authoring.ErrDocumentNotFound
			}
			return nil
		}, gate)
		if e != nil {
			return e
		}
		noticeOwner, replay, e = pair.NewLaterAmendmentNoticeV1(call, ctx, amendmentID, in, actor.UserID)
		if e != nil {
			return e
		}
		if *guard == nil {
			return auth.ErrMutationPermissionRevoked
		}
		return (*guard).recheck(call)
	})
	if e != nil {
		return result, fmt.Errorf("notice initial selection: %w", e)
	}
	if replay != nil {
		result.state.value = amendments.OutcomeV1{State: "unchanged", RequestID: in.RequestID, Notice: replay}
		return result, nil
	}
	if noticeOwner == nil {
		return result, amendments.ErrUnavailableV1
	}
	// Provider I/O is outside physical SQL. Unknown retirement never acquires a
	// second session or releases any still-live debt for this initial operation.
	if e = closeNoticeStageV1(ctx, session, admission); e != nil {
		return result, fmt.Errorf("notice initial session retirement: %w", e)
	}
	session = nil
	initialAdmission = admission
	admission = nil
	if e = noticeOwner.PrepareV1(engine); e != nil {
		return result, fmt.Errorf("notice exact-file preparation: %w", e)
	}
	firstPair := result.state.pair
	result.state.pair = nil
	firstPair.CloseConsumerV1()
	if e = retireNoticeInitialAdmissionV1(ctx, initialAdmission); e != nil {
		return result, fmt.Errorf("notice initial consumer retirement: %w", e)
	}
	initialAdmission = nil
	session, e = d.Sessions.OpenV1(ctx, actor.OrgID, original)
	if e != nil {
		return result, e
	}
	admission, e = session.NewAdmissionV1(ctx)
	if e != nil {
		return result, e
	}
	if e = result.bindAdmissionV1(ctx, admission); e != nil {
		return result, e
	}
	var out amendments.OutcomeV1
	e = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		pair, e := session.NewDocumentPackageSelectionV1(call, candidate)
		result.state.pair = pair
		if e != nil {
			return e
		}
		gate, guard := readGateV1(call, db, actor, true)
		_, e = pair.ReadDocumentsV1(call, actor.UserID, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
			if a.OrgID != actor.OrgID || (a.DocumentID != original && a.DocumentID != candidate) {
				return authoring.ErrDocumentNotFound
			}
			return nil
		}, gate)
		if e != nil {
			return e
		}
		out, e = pair.CommitLaterAmendmentNoticeV1(call, noticeOwner, actor.UserID, ip, ua, d.PublicURL, func(c context.Context, actual *pdfadmission.ApplicationHTMLAuditEventConsumerV1) error {
			var e error
			pending, event, e = ownedaudit.AppendLaterAmendmentV1(d.Audit, c, actual, audit.Entry{OrgID: actor.OrgID, DocumentID: &original})
			return e
		})
		if e != nil {
			return e
		}
		if *guard == nil {
			return auth.ErrMutationPermissionRevoked
		}
		return (*guard).recheck(call)
	})
	if e != nil {
		return result, fmt.Errorf("notice fresh commit selection: %w", e)
	}
	if out.State == "unchanged" {
		result.state.value = out
		return result, nil
	}
	if e = session.CommitV1(ctx); e != nil {
		if !session.CommitDispatchObservationV1().NeverDispatchedV1() {
			result.state.value = amendments.OutcomeV1{State: "unknown", RequestID: in.RequestID, ReconciliationRequired: true}
			return result, nil
		}
		return result, e
	}
	if event == nil {
		return result, amendments.ErrUnavailableV1
	}
	if e = ownedaudit.PublishV1(d.Audit, pending, event); e != nil {
		out.ReconciliationRequired = true
	}
	result.state.value = out
	return result, nil
}

func RevokeV1(ctx context.Context, d DependenciesV1, actor authoring.Actor, original, amendmentID, accessID uuid.UUID, ip, ua string) (result *ResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || actor.Authorize == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || original == uuid.Nil || amendmentID == uuid.Nil || accessID == uuid.Nil {
		return nil, amendments.ErrUnavailableV1
	}
	result = newResultV1()
	session, e := d.Sessions.OpenV1(ctx, actor.OrgID, original)
	var admission *pdfadmission.ApplicationAdmissionV1
	var event *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	var pending audit.PendingEvent
	defer func() {
		if event != nil {
			event.CloseConsumerV1()
		}
		closeErr := closeNoticeStageV1(ctx, session, admission)
		if closeErr != nil {
			if out, ok := result.state.value.(amendments.RevokeOutcomeV1); ok && (out.State == "committed" || out.State == "unknown") {
				out.ReconciliationRequired = true
				result.state.value = out
			} else {
				failure = errors.Join(failure, closeErr)
			}
		}
		if failure != nil {
			result.CloseConsumerV1()
		}
	}()
	if e != nil {
		return result, e
	}
	admission, e = session.NewAdmissionV1(ctx)
	if e != nil {
		return result, e
	}
	if e = result.bindAdmissionV1(ctx, admission); e != nil {
		return result, e
	}
	var out amendments.RevokeOutcomeV1
	e = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		candidate, e := session.ResolveLaterAmendmentCandidateV1(call, amendmentID)
		if e != nil {
			return e
		}
		pair, e := session.NewDocumentPackageSelectionV1(call, candidate)
		result.state.pair = pair
		if e != nil {
			return e
		}
		gate, guard := readGateV1(call, db, actor, true)
		_, e = pair.ReadDocumentsV1(call, actor.UserID, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
			if a.OrgID != actor.OrgID || (a.DocumentID != original && a.DocumentID != candidate) {
				return authoring.ErrDocumentNotFound
			}
			return nil
		}, gate)
		if e != nil {
			return e
		}
		out, e = pair.RevokeLaterAmendmentAccessV1(call, amendmentID, accessID, actor.UserID, ip, ua, func(c context.Context, actual *pdfadmission.ApplicationHTMLAuditEventConsumerV1) error {
			var e error
			pending, event, e = ownedaudit.AppendLaterAmendmentV1(d.Audit, c, actual, audit.Entry{OrgID: actor.OrgID, DocumentID: &original})
			return e
		})
		if e != nil {
			return e
		}
		if *guard == nil {
			return auth.ErrMutationPermissionRevoked
		}
		return (*guard).recheck(call)
	})
	if e != nil {
		return result, e
	}
	if out.State == "unchanged" {
		result.state.value = out
		return result, nil
	}
	if e = session.CommitV1(ctx); e != nil {
		if !session.CommitDispatchObservationV1().NeverDispatchedV1() {
			result.state.value = amendments.RevokeOutcomeV1{Schema: amendments.SchemaV1, State: "unknown", AccessID: accessID, ReconciliationRequired: true}
			return result, nil
		}
		return result, e
	}
	if event == nil {
		return result, amendments.ErrUnavailableV1
	}
	if e = ownedaudit.PublishV1(d.Audit, pending, event); e != nil {
		out.ReconciliationRequired = true
	}
	result.state.value = out
	return result, nil
}
