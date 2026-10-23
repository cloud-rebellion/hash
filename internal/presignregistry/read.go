// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
)

func workflowView(s *transactionState, id uuid.UUID, revision int64) (WorkflowView, error) {
	var out WorkflowView
	h, err := s.q.GetPresignWorkflowHeadForShare(s.ctx, generated.GetPresignWorkflowHeadForShareParams{OrgID: s.actor.orgID, ID: id})
	if err != nil {
		return out, lookupError(err)
	}
	if revision == 0 {
		revision = h.CurrentRevision
	}
	r, err := s.q.GetPresignWorkflowRevisionForShare(s.ctx, generated.GetPresignWorkflowRevisionForShareParams{OrgID: s.actor.orgID, WorkflowID: id, Revision: revision})
	if err != nil {
		return out, lookupError(err)
	}
	d, p, err := decodeWorkflow(r)
	if err != nil {
		return out, err
	}
	retired, err := s.q.IsPresignWorkflowRetired(s.ctx, generated.IsPresignWorkflowRetiredParams{OrgID: s.actor.orgID, WorkflowID: id, Revision: revision})
	if err != nil {
		return out, err
	}
	return WorkflowView{OrgID: s.actor.orgID, UserID: s.actor.userID, Definition: d, DefinitionSHA256: p.Snapshot().Workflow.ContentSHA256, Policy: p.Snapshot(), PolicyReference: p.Reference(), CurrentRevision: h.CurrentRevision, Archived: h.ArchivedAt.Valid, Retired: retired}, nil
}

func (e *Engine) GetWorkflow(ctx context.Context, a SessionActor, id uuid.UUID, revision int64) (WorkflowView, error) {
	var out WorkflowView
	if id == uuid.Nil || revision < 0 {
		return out, ErrInvalid
	}
	err := e.transaction(ctx, a, func(s *transactionState) error { var err error; out, err = workflowView(s, id, revision); return err })
	return out, err
}

func (e *Engine) ListWorkflows(ctx context.Context, a SessionActor) ([]WorkflowView, error) {
	out := []WorkflowView{}
	err := e.transaction(ctx, a, func(s *transactionState) error {
		rows, err := s.q.ListPresignWorkflowHeads(s.ctx, a.orgID)
		if err != nil {
			return err
		}
		for _, h := range rows {
			v, err := workflowView(s, h.ID, 0)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return nil
	})
	return out, err
}

func grantView(s *transactionState, id uuid.UUID, revision int64, owner bool) (GrantView, error) {
	var out GrantView
	if owner && s.user.Role != "owner" {
		return out, auth.ErrMutationPermissionRevoked
	}
	h, err := s.q.GetPresignGrantHeadForShare(s.ctx, generated.GetPresignGrantHeadForShareParams{OrgID: s.actor.orgID, ID: id})
	if err != nil {
		return out, lookupError(err)
	}
	if !owner && h.GrantorUserID != s.actor.userID {
		return out, ErrNotFound
	}
	if revision == 0 {
		revision = h.CurrentRevision
	}
	r, err := s.q.GetPresignGrantRevisionForShare(s.ctx, generated.GetPresignGrantRevisionForShareParams{OrgID: s.actor.orgID, GrantID: id, Revision: revision})
	if err != nil {
		return out, lookupError(err)
	}
	g, err := decodeGrant(r, h)
	if err != nil {
		return out, err
	}
	now, err := clock(s)
	if err != nil {
		return out, err
	}
	next, err := s.q.NextPresignExecutionUse(s.ctx, generated.NextPresignExecutionUseParams{OrgID: s.actor.orgID, GrantID: id, GrantRevision: revision})
	if err != nil || next < 1 {
		return out, errors.Join(ErrUnavailable, err)
	}
	consumed := int64(next) - 1
	available := false
	if s.executionViews && eligible(s.user) && h.GrantorUserID == s.actor.userID && h.CurrentRevision == revision && !h.RevokedAt.Valid &&
		!now.Before(g.Snapshot().NotBefore) && now.Before(g.Snapshot().ExpiresAt) && consumed < g.Snapshot().MaxUses {
		_, policy, activeErr := activePolicy(s, g.Snapshot().Policy)
		if activeErr == nil {
			executor := policy.Snapshot().Executor
			available = executor.Kind == presign.ExecutorMember && executor.UserID == s.actor.userID
		} else if !errors.Is(activeErr, ErrConflict) && !errors.Is(activeErr, ErrNotFound) && !errors.Is(activeErr, auth.ErrMutationPermissionRevoked) {
			return out, activeErr
		}
	}
	return GrantView{OrgID: s.actor.orgID, UserID: s.actor.userID, Grant: g.Snapshot(), Reference: g.Reference(), CurrentRevision: h.CurrentRevision, Revoked: h.RevokedAt.Valid, RevocationReason: h.RevokedReason.String, Expired: !now.Before(g.Snapshot().ExpiresAt), ConsumedUses: consumed, ExecutionAvailable: available}, nil
}

func (e *Engine) getGrant(ctx context.Context, a SessionActor, id uuid.UUID, revision int64, owner bool) (GrantView, error) {
	var out GrantView
	if id == uuid.Nil || revision < 0 {
		return out, ErrInvalid
	}
	err := e.transaction(ctx, a, func(s *transactionState) error {
		var err error
		out, err = grantView(s, id, revision, owner)
		return err
	})
	return out, err
}
func (e *Engine) GetOwnGrant(ctx context.Context, a SessionActor, id uuid.UUID, revision int64) (GrantView, error) {
	return e.getGrant(ctx, a, id, revision, false)
}
func (e *Engine) GetGrantAsOwner(ctx context.Context, a SessionActor, id uuid.UUID, revision int64) (GrantView, error) {
	return e.getGrant(ctx, a, id, revision, true)
}

func (e *Engine) listGrants(ctx context.Context, a SessionActor, owner bool) ([]GrantView, error) {
	out := []GrantView{}
	err := e.transaction(ctx, a, func(s *transactionState) error {
		var rows []*generated.PresignGrant
		var err error
		if owner {
			if s.user.Role != "owner" {
				return auth.ErrMutationPermissionRevoked
			}
			rows, err = s.q.ListPresignGrantHeads(s.ctx, a.orgID)
		} else {
			rows, err = s.q.ListOwnPresignGrantHeads(s.ctx, generated.ListOwnPresignGrantHeadsParams{OrgID: a.orgID, GrantorUserID: a.userID})
		}
		if err != nil {
			return err
		}
		for _, h := range rows {
			v, err := grantView(s, h.ID, 0, owner)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return nil
	})
	return out, err
}
func (e *Engine) ListOwnGrants(ctx context.Context, a SessionActor) ([]GrantView, error) {
	return e.listGrants(ctx, a, false)
}
func (e *Engine) ListGrantsAsOwner(ctx context.Context, a SessionActor) ([]GrantView, error) {
	return e.listGrants(ctx, a, true)
}

// ErrorCode is a stable redacted route classification. Conditional stale
// writes use ErrConflict at their own boundary; an audit-wrapped no-row never
// becomes a conflict. Raw backend diagnostics must not enter a response.
func ErrorCode(err error) int {
	switch {
	case err == nil:
		return 200
	case errors.Is(err, ErrAudit):
		return 500
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		return 401
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		return 403
	case errors.Is(err, ErrNotFound):
		return 404
	case errors.Is(err, ErrConflict):
		return 409
	case errors.Is(err, ErrInvalid):
		return 400
	case errors.Is(err, ErrUnavailable):
		return 503
	default:
		return 500
	}
}
