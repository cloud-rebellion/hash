// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// These internal result owners preserve the original transport response. A
// native model remains retained through the caller's actual last use. Close is
// a consumer signal; the native factory independently owns physical cleanup.
type ChangeResolutionResultV1 struct {
	*generated.ChangeRequest
	self    *ChangeResolutionResultV1
	once    *sync.Once
	release func()
}

func (r *ChangeResolutionResultV1) CloseConsumerV1() {
	if r != nil && r.self == r && r.once != nil {
		r.once.Do(func() {
			r.ChangeRequest = nil
			if r.release != nil {
				r.release()
				r.release = nil
			}
		})
	}
}

type CeremonyRevisionResultV1 struct {
	*generated.Document
	self    *CeremonyRevisionResultV1
	once    *sync.Once
	release func()
}

func (r *CeremonyRevisionResultV1) CloseConsumerV1() {
	if r != nil && r.self == r && r.once != nil {
		r.once.Do(func() {
			r.Document = nil
			if r.release != nil {
				r.release()
				r.release = nil
			}
		})
	}
}
func newChangeResolutionResultV1(row *generated.ChangeRequest, release func()) *ChangeResolutionResultV1 {
	r := &ChangeResolutionResultV1{ChangeRequest: row, release: release, once: &sync.Once{}}
	r.self = r
	return r
}
func newCeremonyRevisionResultV1(row *generated.Document, release func()) *CeremonyRevisionResultV1 {
	r := &CeremonyRevisionResultV1{Document: row, release: release, once: &sync.Once{}}
	r.self = r
	return r
}

func (e *Engine) ResolveChange(ctx context.Context, org, doc, change uuid.UUID, approve bool) (*ChangeResolutionResultV1, error) {
	return e.resolveChangeOwnedV1(ctx, org, doc, change, uuid.Nil, approve, nil)
}
func (e *Engine) ResolveChangeWithAuthorization(ctx context.Context, org, doc, change, user uuid.UUID, approve bool, authorize auth.TransactionAuthorization) (*ChangeResolutionResultV1, error) {
	if user == uuid.Nil || authorize == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	return e.resolveChangeOwnedV1(ctx, org, doc, change, user, approve, authorize)
}
func (e *Engine) resolveChangeOwnedV1(original context.Context, org, doc, change, user uuid.UUID, approve bool, authorize auth.TransactionAuthorization) (*ChangeResolutionResultV1, error) {
	ctx, cancel := context.WithTimeout(original, 10*time.Second)
	defer cancel()
	if e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	work, err := e.WorkRuntime.SessionsV1().NewHTMLCeremonyWorkflowV1(ctx, org, doc, user, pdfadmission.HTMLCeremonyChangeDecisionV1)
	if err != nil {
		return nil, htmlCeremonyAdmissionErrorV1(err)
	}
	transfer := false
	defer func() {
		if !transfer {
			closeHTMLCeremonyWorkflowV1(ctx, work)
		}
	}()
	if err = work.OpenV1(); err != nil {
		return nil, htmlCeremonyAdmissionErrorV1(err)
	}
	var result *generated.ChangeRequest
	var releaseResult func()
	var pending audit.PendingEvent
	var event *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	err = work.WithTxV1(func(call context.Context, db generated.DBTX, _ *pdfadmission.ApplicationHTMLRevisionReaderV1) error {
		if _, err := work.ReadAccessV1(call, ""); errors.Is(err, pgx.ErrNoRows) {
			return ErrChangeRequestNotFound
		} else if err != nil {
			return err
		}
		var actor *generated.User
		tx := &htmlCeremonyPolicyTxV1{DBTX: db}
		afterActor := func(a pdfadmission.HTMLRevisionReadAccessV1) error {
			if err := call.Err(); err != nil {
				return err
			}
			if !a.ChangesRequested {
				return ErrNotRevisable
			}
			err := work.PreflightChangeV1(call, change, func(open bool) error {
				if !open {
					return ErrChangeAlreadyResolved
				}
				return nil
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrChangeRequestNotFound
			}
			return err
		}
		_, err := work.ReadActorDocumentV1(call, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
			if authorize == nil {
				return afterActor(a)
			}
			return nil
		}, func(a pdfadmission.HTMLRevisionReadAccessV1, u *generated.User) error {
			if u == nil || (u.Role != string(auth.RoleSender) && u.Role != string(auth.RoleOwner)) {
				return auth.ErrMutationPermissionRevoked
			}
			actor = u
			fresh := *u
			if err := authorize(call, tx, &fresh); err != nil {
				return err
			}
			return afterActor(a)
		})
		if err != nil {
			return err
		}
		cr, err := work.ReadChangeV1(call, change)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrChangeRequestNotFound
		}
		if err != nil {
			return err
		}
		if cr.DocumentID != doc {
			return ErrChangeRequestNotFound
		}
		if !changeRequestCanResolve(cr.Status) {
			return ErrChangeAlreadyResolved
		}
		resolution := "denied"
		if approve {
			resolution = "approved"
			orgRow, err := work.ReadApprovalOrgV1(call)
			if err != nil {
				return fmt.Errorf("load change approval mode: %w", err)
			}
			if orgRow.ChangeApprovalMode == "auto_apply" {
				captured, err := work.HasCapturedEvidenceV1(call)
				if err != nil {
					return fmt.Errorf("inspect auto-apply evidence: %w", err)
				}
				if captured {
					return ErrRevisionWouldDestroyEvidence
				}
				// The fixed native writer derives the actual blocks/change from
				// its private retained source. PDF/HTML retain the original no-op.
				if err = work.ApplyApprovedBlockChangeV1(call); err != nil {
					return err
				}
			}
		}
		if _, err = work.ResolveChangeV1(call, approve); err != nil {
			return fmt.Errorf("update change resolution: %w", err)
		}
		entry := audit.Entry{OrgID: org, DocumentID: &doc, Kind: audit.KindChangesRequested, Payload: map[string]any{"change_request": change.String(), "resolution": resolution}}
		if actor != nil {
			id := actor.ID
			entry.ActorUserID = &id
		}
		session, err := work.AuditSessionV1(call)
		if err != nil {
			return err
		}
		pending, event, err = ownedaudit.LogV1(e.Audit, call, session, pdfadmission.HTMLAuditChangeDecisionV1, entry)
		if err != nil {
			return fmt.Errorf("audit change resolution: %w", err)
		}
		if authorize != nil {
			fresh := *actor
			if err = authorize(call, tx, &fresh); err != nil {
				return err
			}
		}
		if err = call.Err(); err != nil {
			return err
		}
		result, releaseResult, err = work.BorrowChangeV1(call)
		return err
	})

	if err != nil {
		if releaseResult != nil {
			releaseResult()
		}
		if event != nil {
			event.CloseConsumerV1()
		}
		return nil, htmlCeremonyAdmissionErrorV1(err)
	}
	if err = work.CommitV1(); err != nil {
		releaseResult()
		event.CloseConsumerV1()
		return nil, fmt.Errorf("commit change resolution: %w", htmlCeremonyAdmissionErrorV1(err))
	}
	if err = ownedaudit.PublishV1(e.Audit, pending, event); err != nil {
		releaseResult()
		event.CloseConsumerV1()
		return nil, htmlCeremonyAdmissionErrorV1(err)
	}
	transfer = true
	return newChangeResolutionResultV1(result, func() { releaseResult(); closeHTMLCeremonyWorkflowV1(ctx, work) }), nil
}

func (e *Engine) Revise(ctx context.Context, org, doc uuid.UUID) (*CeremonyRevisionResultV1, error) {
	return e.reviseOwnedV1(ctx, org, doc, uuid.Nil, nil)
}
func (e *Engine) ReviseWithAuthorization(ctx context.Context, org, doc, user uuid.UUID, authorize auth.TransactionAuthorization) (*CeremonyRevisionResultV1, error) {
	if user == uuid.Nil || authorize == nil {
		return nil, ErrRevisionNotAuthorized
	}
	return e.reviseOwnedV1(ctx, org, doc, user, authorize)
}
func (e *Engine) reviseOwnedV1(original context.Context, org, doc, user uuid.UUID, authorize auth.TransactionAuthorization) (*CeremonyRevisionResultV1, error) {
	ctx, cancel := context.WithTimeout(original, 10*time.Second)
	defer cancel()
	if e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	work, err := e.WorkRuntime.SessionsV1().NewHTMLCeremonyWorkflowV1(ctx, org, doc, user, pdfadmission.HTMLCeremonyRetireV1)
	if err != nil {
		return nil, htmlCeremonyAdmissionErrorV1(err)
	}
	transfer := false
	defer func() {
		if !transfer {
			closeHTMLCeremonyWorkflowV1(ctx, work)
		}
	}()
	if err = work.OpenV1(); err != nil {
		return nil, htmlCeremonyAdmissionErrorV1(err)
	}
	var result *generated.Document
	var releaseResult func()
	var pending audit.PendingEvent
	var event *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	err = work.WithTxV1(func(call context.Context, db generated.DBTX, reader *pdfadmission.ApplicationHTMLRevisionReaderV1) error {
		access, err := work.ReadAccessV1(call, "")
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionDocumentNotFound
		}
		if err != nil {
			return fmt.Errorf("lock document for revision: %w", err)
		}
		var actor *generated.User
		tx := &htmlCeremonyPolicyTxV1{DBTX: db}
		afterActor := func(a pdfadmission.HTMLRevisionReadAccessV1) error {
			if !a.ChangesRequested {
				return ErrNotRevisable
			}
			if access.IsEnvelope {
				return fmt.Errorf("%w: revise", ErrEnvelopeTransitionUnsupported)
			}
			captured, err := work.HasCapturedEvidenceV1(call)
			if err != nil {
				return fmt.Errorf("inspect revision evidence: %w", err)
			}
			if captured {
				return ErrRevisionWouldDestroyEvidence
			}
			return nil
		}
		models, err := work.ReadActorDocumentV1(call, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
			if authorize == nil {
				return afterActor(a)
			}
			return nil
		}, func(a pdfadmission.HTMLRevisionReadAccessV1, u *generated.User) error {
			if u == nil || (u.Role != string(auth.RoleSender) && u.Role != string(auth.RoleOwner)) {
				return ErrRevisionNotAuthorized
			}
			actor = u
			if err := authorize(call, tx, u); err != nil {
				return err
			}
			return afterActor(a)
		})
		if err != nil {
			return err
		}
		if err = rejectUnsupportedEnvelopeTransition(models.Document, "revise"); err != nil {
			return err
		}
		// The original CaptureRetiredCeremony is a no-op for ordinary
		// non-HTML sources. Preserve every reviewed HTML source/snapshot check.
		if len(models.Document.HtmlSourceJson) != 0 {
			source, err := work.NewSourceV1(call)
			if err != nil {
				return err
			}
			defer source.CloseConsumerV1()
			// Retired ceremony requires the original reviewed-source decision BEFORE
			// Current and complete history capture. No claimed SHA substitutes this.
			if err = source.ValidateV1(); err != nil {
				return fmt.Errorf("archive retired HTML ceremony: %w", err)
			}
			if err = source.ValidateRetirementReviewV1(); err != nil {
				return fmt.Errorf("archive retired HTML ceremony: %w", err)
			}
			if err = source.ValidateCurrentV1(); err != nil {
				return fmt.Errorf("archive retired HTML ceremony: %w", err)
			}
			if _, err = source.CommitmentV1(); err != nil {
				return fmt.Errorf("archive retired HTML ceremony: %w", err)
			}
			collections, err := reader.NewCollectionsV1(call)
			if err != nil {
				return err
			}
			defer collections.CloseConsumerV1()
			if err = work.CaptureRetiredV1(call, source, collections); err != nil {
				return fmt.Errorf("archive retired HTML ceremony: %w", err)
			}
		}
		if _, err = work.ReopenDraftV1(call); err != nil {
			return fmt.Errorf("reopen document for revision: %w", err)
		}
		q := generated.New(db)
		if err = q.ResolveChangeRequests(call, doc); err != nil {
			return err
		}
		if err = q.ResetRecipientsForRevision(call, doc); err != nil {
			return err
		}
		if err = q.InvalidateRecipientTokens(call, doc); err != nil {
			return fmt.Errorf("invalidate revised ceremony tokens: %w", err)
		}
		entry := audit.Entry{OrgID: org, DocumentID: &doc, Kind: audit.KindDocumentRevised}
		if actor != nil {
			id := actor.ID
			entry.ActorUserID = &id
		}
		session, err := work.AuditSessionV1(call)
		if err != nil {
			return err
		}
		pending, event, err = ownedaudit.LogV1(e.Audit, call, session, pdfadmission.HTMLAuditCeremonyRetiredV1, entry)
		if err != nil {
			return fmt.Errorf("audit revision: %w", err)
		}
		if authorize != nil {
			if err = authorize(call, tx, actor); err != nil {
				return err
			}
		}
		if err = call.Err(); err != nil {
			return err
		}
		result, releaseResult, err = work.BorrowDocumentV1(call)
		return err
	})

	if err != nil {
		if releaseResult != nil {
			releaseResult()
		}
		if event != nil {
			event.CloseConsumerV1()
		}
		return nil, htmlCeremonyAdmissionErrorV1(err)
	}
	if err = work.CommitV1(); err != nil {
		releaseResult()
		event.CloseConsumerV1()
		return nil, fmt.Errorf("commit revise: %w", htmlCeremonyAdmissionErrorV1(err))
	}
	if err = ownedaudit.PublishV1(e.Audit, pending, event); err != nil {
		releaseResult()
		event.CloseConsumerV1()
		return nil, htmlCeremonyAdmissionErrorV1(err)
	}
	transfer = true
	return newCeremonyRevisionResultV1(result, func() { releaseResult(); closeHTMLCeremonyWorkflowV1(ctx, work) }), nil
}
