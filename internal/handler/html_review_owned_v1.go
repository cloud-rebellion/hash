// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type htmlReviewBusinessV1 struct {
	status  int
	message string
}

func (e *htmlReviewBusinessV1) Error() string { return e.message }
func htmlReviewConflictV1(message string) error {
	return &htmlReviewBusinessV1{http.StatusConflict, message}
}

// Review has LockDraft's own policy/order, not the stricter ordinary revision
// sender check. MarkReviewed keeps its original later SQL authorization gate.
func readHTMLReviewOwnedV1(call context.Context, db generated.DBTX, work *pdfadmission.ApplicationHTMLCeremonyWorkflowV1, actor authoring.Actor, id uuid.UUID, expected time.Time, pdf []byte) (*generated.Document, *htmlRevisionPolicyGuardV1, error) {
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, nil, auth.ErrMutationPermissionRevoked
	}
	tx := &htmlCreationPolicyTxV1{DBTX: db}
	q := generated.New(db)
	access, err := work.ReadAccessV1(call, "")
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, authoring.ErrDocumentNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	var guard *htmlRevisionPolicyGuardV1
	models, err := work.ReadActorDocumentV1(call, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
		if a.DocumentID != id || a.OrgID != actor.OrgID {
			return authoring.ErrDocumentNotFound
		}
		if !a.Draft {
			return authoring.ErrDocumentNotDraft
		}
		return nil
	}, func(a pdfadmission.HTMLRevisionReadAccessV1, user *generated.User) error {
		if user == nil || (user.Role != string(auth.RoleSender) && user.Role != string(auth.RoleOwner)) {
			return auth.ErrMutationPermissionRevoked
		}
		guard = &htmlRevisionPolicyGuardV1{user: *user, tx: tx, authorize: actor.Authorize}
		if err := guard.Recheck(call); err != nil {
			return err
		}
		retained, err := q.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: id, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect draft evidence: %w", err)
		}
		if retained {
			return authoring.ErrDocumentHasEvidence
		}
		fence, err := q.TryCollabArchivePrivacyFence(call, actor.OrgID)
		if err != nil {
			return fmt.Errorf("fence draft privacy review: %w", err)
		}
		if !fence {
			return authoring.ErrPrivacyReviewChanging
		}
		pending, err := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: id, OrgID: actor.OrgID})
		if err != nil {
			return fmt.Errorf("inspect draft privacy review: %w", err)
		}
		if pending {
			return authoring.ErrPendingPrivacyReview
		}
		if err := call.Err(); err != nil {
			return err
		}
		if !a.HasHTMLSource || !a.UpdatedAt.Time.Equal(expected) || !bytes.Equal(access.PDFSHA256, pdf) {
			return htmlReviewConflictV1("document changed; preview and review its current PDF again")
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if guard == nil {
		return nil, nil, auth.ErrMutationPermissionRevoked
	}
	return models.Document, guard, nil
}
func (s *Server) reviewHTMLDocumentOwnedV1(parent context.Context, actor authoring.Actor, id uuid.UUID, in htmlDocumentReviewInput, expected time.Time, pdf []byte) (document *generated.Document, release func(), failure error) {
	if s.HTMLCreationSessions == nil {
		return nil, nil, pdfadmission.ErrHTMLCeremonyWorkflowV1
	}
	original, cancel := context.WithTimeout(parent, authoring.MutationTimeout)
	work, err := s.HTMLCreationSessions.NewHTMLCeremonyWorkflowV1(original, actor.OrgID, id, actor.UserID, pdfadmission.HTMLCeremonyReviewV1)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			cancel()
			cleanup, stop := revisionCleanupContextV1(parent)
			defer stop()
			failure = errors.Join(failure, work.CloseV1(cleanup))
		}
	}()
	if err = work.OpenV1(); err != nil {
		return nil, nil, err
	}
	var pending audit.PendingEvent
	var consumer *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	var finishResult func()
	err = work.WithTxV1(func(call context.Context, db generated.DBTX, _ *pdfadmission.ApplicationHTMLRevisionReaderV1) error {
		current, guard, e := readHTMLReviewOwnedV1(call, db, work, actor, id, expected, pdf)
		if e != nil {
			return e
		}
		if len(current.HtmlSourceJson) == 0 || !current.UpdatedAt.Time.Equal(expected) || !bytes.Equal(current.PdfSha256, pdf) {
			return htmlReviewConflictV1("document changed; preview and review its current PDF again")
		}
		source, e := work.NewSourceV1(call)
		if e != nil {
			return e
		}
		defer source.CloseConsumerV1()
		if e = source.ValidateV1(); e != nil {
			return htmlReviewSourceErrorV1(e, false)
		}
		commitment, e := source.CommitmentV1()
		if e != nil {
			return htmlReviewSourceErrorV1(e, false)
		}
		if e = source.ValidateCurrentV1(); e != nil {
			return htmlReviewSourceErrorV1(e, true)
		}
		if (current.HtmlCurrentMaterializationID.Valid && in.ExpectedHTMLSourceCommitment == "") || (in.ExpectedHTMLSourceCommitment != "" && in.ExpectedHTMLSourceCommitment != commitment) {
			return htmlReviewConflictV1("document source changed; preview and review its current PDF again")
		}
		_, e = work.MarkReviewedV1(call, expected, pdf)
		if errors.Is(e, pgx.ErrNoRows) {
			return &htmlReviewBusinessV1{http.StatusForbidden, "only the document sender or an owner can review this PDF"}
		}
		if e != nil {
			return e
		}
		session, e := work.AuditSessionV1(call)
		if e != nil {
			return e
		}
		pending, consumer, e = ownedaudit.LogV1(s.Audit, call, session, pdfadmission.HTMLAuditHTMLReviewV1, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &id, Kind: audit.KindDocumentUpdated,
			Payload: map[string]any{"html_pdf_reviewed": true, "pdf_sha256": in.ExpectedPDFSHA256, "html_source_commitment": commitment}})
		if e != nil {
			return e
		}
		if e = guard.Recheck(call); e != nil {
			return e
		}
		document, finishResult, e = work.BorrowDocumentV1(call)
		return e
	})
	if err != nil {
		if consumer != nil {
			consumer.CloseConsumerV1()
		}
		if finishResult != nil {
			finishResult()
		}
		return nil, nil, err
	}
	if err = work.CommitV1(); err != nil {
		consumer.CloseConsumerV1()
		finishResult()
		return nil, nil, err
	}
	if err = ownedaudit.PublishV1(s.Audit, pending, consumer); err != nil {
		consumer.CloseConsumerV1()
		finishResult()
		return nil, nil, err
	}
	transferred = true
	var once sync.Once
	return document, func() {
		once.Do(func() {
			finishResult()
			cancel()
			cleanup, stop := revisionCleanupContextV1(parent)
			defer stop()
			_ = work.CloseV1(cleanup)
		})
	}, nil
}
func (s *Server) writeOwnedHTMLReviewErrorV1(w http.ResponseWriter, err error) {
	var business *htmlReviewBusinessV1
	if errors.As(err, &business) {
		writeError(w, business.status, business.message)
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, pdfadmission.ErrHTMLCeremonyWorkflowV1) || errors.Is(err, pdfadmission.ErrHTMLRevisionReadV1) || errors.Is(err, pdfadmission.ErrHTMLRevisionSourceV1) || errors.Is(err, pdfadmission.ErrHTMLAuditEventV1) || errors.Is(err, pdfadmission.ErrApplicationSessionV1) || errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "document review unavailable")
		return
	}
	s.writeDraftAuthoringError(w, "authorize HTML document review", err)
}

func htmlReviewSourceErrorV1(err error, current bool) error {
	if errors.Is(err, htmlsource.ErrInvalid) || errors.Is(err, htmlsource.ErrReviewRequired) || errors.Is(err, htmlmaster.ErrInvalid) || errors.Is(err, htmlmaster.ErrLimit) || errors.Is(err, htmlmaster.ErrContractIncomplete) || errors.Is(err, htmlmaterialization.ErrInvalid) {
		if current {
			return htmlReviewConflictV1("document source or history is inconsistent; review unavailable")
		}
		return htmlReviewConflictV1(err.Error())
	}
	return err
}
