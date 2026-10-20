// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package negotiationauthoring

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DependenciesV1 struct {
	Sessions *pdfadmission.ApplicationSessionFactoryV1
	Audit    *audit.Logger
}
type ActorV1 struct {
	OrgID, UserID      uuid.UUID
	Authorize          auth.TransactionAuthorization
	Via, IP, UserAgent string
}
type InputV1 = pdfadmission.ManualNegotiationInputV1
type ResultV1 struct {
	Proposal *generated.DocumentProposal
	state    *resultStateV1
}
type resultStateV1 struct {
	once    sync.Once
	factory *pdfadmission.ApplicationSessionFactoryV1
	reader  *pdfadmission.ApplicationHTMLRevisionReaderV1
	writer  *pdfadmission.ApplicationManualNegotiationMutationV1
	event   *pdfadmission.ApplicationHTMLAuditEventConsumerV1
}

func (r *ResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		if s.event != nil {
			s.event.CloseConsumerV1()
		}
		if s.writer != nil {
			s.writer.CloseConsumerV1()
		}
		if s.reader != nil {
			s.reader.CloseConsumerV1()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if s.factory != nil {
			_ = s.factory.ReconcileCleanupV1(cleanup)
		}
	})
}

// Only the four fixed manual actions can enter this shared REST/MCP producer.
// It does not accept a SQL callback, audit payload, caller document or grant.
// Provider dispatch/accounting remains the original separate workflow.
func MutateV1(ctx context.Context, d DependenciesV1, actor ActorV1, document uuid.UUID, in InputV1) (result *ResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || document == uuid.Nil || (actor.Via != "rest" && actor.Via != "mcp") {
		return nil, errors.New("native manual negotiation dependencies unavailable")
	}
	switch in.Operation {
	case pdfadmission.ManualProposalCreateV1, pdfadmission.ManualProposalStatusV1:
	case pdfadmission.ManualNegotiationSettingV1, pdfadmission.ManualBilingualTargetV1:
		if actor.Via != "rest" {
			return nil, errors.New("manual setting transport unavailable")
		}
	default:
		return nil, pdfadmission.ErrManualNegotiationMutationV1
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	session, err := d.Sessions.OpenV1(ctx, actor.OrgID, document)
	if err != nil {
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			err = errors.Join(err, session.CloseV1(cleanup))
		}
		return nil, err
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		return nil, errors.Join(err, session.CloseV1(cleanup))
	}
	state := &resultStateV1{factory: d.Sessions}
	result = &ResultV1{state: state}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		closeErr := session.CloseV1(cleanup)
		_, reconcileErr := admission.ReconcileCleanupV1(cleanup)
		failure = errors.Join(failure, closeErr, reconcileErr)
	}()
	var pending audit.PendingEvent
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLRevisionReaderV1(call)
		if err != nil {
			return err
		}
		state.writer, err = session.NewManualNegotiationMutationV1(call, state.reader)
		if err != nil {
			return err
		}
		if err = state.writer.LockRootV1(call); errors.Is(err, pgx.ErrNoRows) {
			return authoring.ErrDocumentNotFound
		} else if err != nil {
			return err
		}
		tx := &nativeNegotiationPolicyTxV1{DBTX: db}
		q := generated.New(tx)
		var original generated.User
		_, err = state.reader.ReadDocumentWithActorV1(call, actor.UserID, func(access pdfadmission.HTMLRevisionReadAccessV1) error {
			if access.DocumentID != document || access.OrgID != actor.OrgID {
				return authoring.ErrDocumentNotFound
			}
			return nil
		}, func(_ pdfadmission.HTMLRevisionReadAccessV1, user *generated.User) error {
			if user == nil || user.ID != actor.UserID || user.OrgID != actor.OrgID || (user.Role != string(auth.RoleSender) && user.Role != string(auth.RoleOwner)) {
				return auth.ErrMutationPermissionRevoked
			}
			original = *user
			checked := original
			if err := actor.Authorize(call, tx, &checked); err != nil {
				return err
			}
			fence, err := q.TryCollabArchivePrivacyFence(call, actor.OrgID)
			if err != nil {
				return err
			}
			if !fence {
				return authoring.ErrPrivacyReviewChanging
			}
			policy, err := state.writer.PolicyV1(call)
			if err != nil {
				return err
			}
			check := func(id uuid.UUID, allowed, draft bool) error {
				if !allowed {
					return authoring.ErrAIAppDocumentClosed
				}
				if draft {
					retained, err := q.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: id, OrgID: actor.OrgID})
					if err != nil {
						return err
					}
					if retained {
						return authoring.ErrDocumentHasEvidence
					}
				}
				privacy, err := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: id, OrgID: actor.OrgID})
				if err != nil {
					return err
				}
				if privacy {
					return authoring.ErrPendingPrivacyReview
				}
				return call.Err()
			}
			if policy.RootDocumentID != document {
				if err := check(policy.RootDocumentID, policy.RootAllowed, policy.RootDraft); err != nil {
					return err
				}
			}
			return check(policy.DocumentID, policy.DocumentAllowed, policy.DocumentDraft)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return authoring.ErrDocumentNotFound
		}
		if err != nil {
			return err
		}
		if err = state.writer.AcceptActualDocumentV1(call); err != nil {
			return err
		}
		result.Proposal, err = state.writer.MutateV1(call, actor.UserID, in)
		if err != nil {
			return err
		}
		var purpose pdfadmission.HTMLAuditPurposeV1
		payload := map[string]any{"via": actor.Via}
		switch in.Operation {
		case pdfadmission.ManualProposalCreateV1:
			purpose = pdfadmission.HTMLAuditManualProposalCreatedV1
			payload["proposal_id"] = result.Proposal.ID.String()
			payload["block_id"] = in.BlockID
			payload["kind"] = in.ProposalKind
			payload["ai_assisted"] = in.AIAssisted
			if actor.Via == "mcp" {
				payload["tool"] = "propose_counter_clause"
			}
		case pdfadmission.ManualProposalStatusV1:
			purpose = pdfadmission.HTMLAuditManualProposalStatusV1
			payload["proposal_id"] = in.ProposalID.String()
			payload["status"] = in.Status
		case pdfadmission.ManualNegotiationSettingV1:
			purpose = pdfadmission.HTMLAuditManualNegotiationSettingV1
			payload["enabled"] = in.Enabled
		case pdfadmission.ManualBilingualTargetV1:
			purpose = pdfadmission.HTMLAuditManualBilingualTargetV1
			payload["lang"] = in.Lang
		}
		id, user := document, actor.UserID
		pending, state.event, err = ownedaudit.LogV1(d.Audit, call, session, purpose, audit.Entry{OrgID: actor.OrgID, ActorUserID: &user, DocumentID: &id, Kind: purpose.KindV1(), IP: actor.IP, UserAgent: actor.UserAgent, Payload: payload})
		if err != nil {
			return fmt.Errorf("audit manual negotiation mutation: %w", err)
		}
		checked := original
		if err = actor.Authorize(call, tx, &checked); err != nil {
			return err
		}
		return call.Err()
	})
	if err != nil {
		return result, err
	}
	if err = session.CommitV1(ctx); err != nil {
		return result, fmt.Errorf("commit manual negotiation mutation: %w", err)
	}
	if err = ownedaudit.PublishV1(d.Audit, pending, state.event); err != nil {
		return result, err
	}
	return result, nil
}
