// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package bindingauthoring

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"sync"
	"time"
)

type DependenciesV1 struct {
	Sessions *pdfadmission.ApplicationSessionFactoryV1
	Audit    *audit.Logger
}
type ActorV1 struct {
	OrgID, UserID            uuid.UUID
	Authorize                auth.TransactionAuthorization
	Via, Tool, IP, UserAgent string
}
type InputV1 struct {
	Variable, SourceKind, SourceRef, SourcePath, Fallback string
	Delete                                                bool
}
type ResultV1 struct {
	Binding *generated.DocumentVariableBinding
	state   *resultStateV1
}
type resultStateV1 struct {
	once    sync.Once
	factory *pdfadmission.ApplicationSessionFactoryV1
	reader  *pdfadmission.ApplicationHTMLRevisionReaderV1
	writer  *pdfadmission.ApplicationVariableBindingMutationV1
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

// One shared producer for existing REST/MCP bind/unbind. It preserves original
// all-organization sender/owner policy, original admitted credential and fixed
// payload semantics. It cannot adopt caller SQL or repair historical events.
func MutateV1(ctx context.Context, d DependenciesV1, actor ActorV1, document uuid.UUID, in InputV1) (result *ResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || document == uuid.Nil {
		return nil, errors.New("native variable binding dependencies unavailable")
	}
	if in.Delete {
		if err := resolver.ValidateBindingName(in.Variable); err != nil {
			return nil, err
		}
	} else if err := resolver.ValidateBinding(in.Variable, resolver.SourceKind(in.SourceKind), in.SourceRef, in.SourcePath, in.Fallback); err != nil {
		return nil, err
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
		state.writer, err = session.NewVariableBindingMutationV1(call, state.reader)
		if err != nil {
			return err
		}
		draft, err := state.writer.LockRootV1(call)
		if errors.Is(err, pgx.ErrNoRows) {
			return authoring.ErrDocumentNotFound
		}
		if err != nil {
			return err
		}
		if !draft {
			return authoring.ErrDocumentNotDraft
		}
		tx := &nativeBindingPolicyTxV1{DBTX: db}
		q := generated.New(tx)
		var original generated.User
		_, err = state.reader.ReadDocumentWithActorV1(call, actor.UserID, func(access pdfadmission.HTMLRevisionReadAccessV1) error {
			if access.DocumentID != document || access.OrgID != actor.OrgID {
				return authoring.ErrDocumentNotFound
			}
			if !access.Draft {
				return authoring.ErrDocumentNotDraft
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
			retained, err := q.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: document, OrgID: actor.OrgID})
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
			privacy, err := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: document, OrgID: actor.OrgID})
			if err != nil {
				return fmt.Errorf("inspect draft privacy review: %w", err)
			}
			if privacy {
				return authoring.ErrPendingPrivacyReview
			}
			return call.Err()
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
		if in.Delete {
			err = state.writer.DeleteV1(call, in.Variable)
		} else {
			result.Binding, err = state.writer.UpsertV1(call, in.Variable, in.SourceKind, in.SourceRef, in.SourcePath, in.Fallback)
		}
		if err != nil {
			return fmt.Errorf("mutate variable binding: %w", err)
		}
		payload := map[string]any{"via": actor.Via, "tool": actor.Tool, "variable": in.Variable}
		if !in.Delete && in.SourceKind != "" {
			payload["source_kind"] = in.SourceKind
		}
		id, user := document, actor.UserID
		pending, state.event, err = ownedaudit.LogV1(d.Audit, call, session, pdfadmission.HTMLAuditVariableBindingV1, audit.Entry{OrgID: actor.OrgID, ActorUserID: &user, DocumentID: &id, Kind: audit.KindDocumentUpdated, IP: actor.IP, UserAgent: actor.UserAgent, Payload: payload})
		if err != nil {
			return fmt.Errorf("audit variable binding mutation: %w", err)
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
		return result, fmt.Errorf("commit variable binding mutation: %w", err)
	}
	if err = ownedaudit.PublishV1(d.Audit, pending, state.event); err != nil {
		return result, err
	}
	return result, nil
}
