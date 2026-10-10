// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const workflowPurpose = "presign.workflow.confirm.v1"

func normalizedWorkflow(in WorkflowIntent) (WorkflowIntent, error) {
	if in.ExpectedRevision < 0 || in.ExpectedRevision >= presign.MaxRevision || in.Definition.Revision != in.ExpectedRevision+1 || in.ExpectedOrgID != in.Definition.OrgID {
		return in, invalid("next workflow revision")
	}
	in.Definition.Template.ApprovedAt = in.Definition.Template.ApprovedAt.UTC().Truncate(time.Microsecond)
	raw, _, _, err := CanonicalDefinition(in.Definition)
	if err != nil {
		return in, err
	}
	d, err := DecodeDefinition(raw)
	in.Definition = d
	return in, err
}

func buildPolicy(d WorkflowDefinition, approvedBy uuid.UUID, at time.Time) (presign.Policy, error) {
	_, hash, rules, err := CanonicalDefinition(d)
	if err != nil {
		return presign.Policy{}, err
	}
	return presign.NewPolicy(presign.PolicySnapshot{SchemaVersion: 1, ID: d.PolicyID, OrgID: d.OrgID, Revision: d.Revision, Template: d.Template, Workflow: presign.WorkflowPin{ID: d.ID, Revision: d.Revision, ContentSHA256: hash, ApprovedBy: approvedBy, ApprovedAt: at}, Executor: d.Executor, Operation: d.Operation, Rules: rules, MaxGrantDurationSeconds: d.MaxGrantDurationSeconds, MaxUses: d.MaxUses, ApprovedBy: approvedBy, ApprovedAt: at})
}

func decodeWorkflow(r *generated.PresignWorkflowRevision) (WorkflowDefinition, presign.Policy, error) {
	var d WorkflowDefinition
	var p presign.Policy
	if r == nil {
		return d, p, ErrUnavailable
	}
	d, err := DecodeDefinition(r.CanonicalDefinition)
	if err != nil {
		return d, p, ErrUnavailable
	}
	raw, h, _, err := CanonicalDefinition(d)
	if err != nil || !bytes.Equal(raw, r.CanonicalDefinition) || h != hex.EncodeToString(r.DefinitionSha256) || d.OrgID != r.OrgID || d.ID != r.WorkflowID || d.PolicyID != r.PolicyID || d.Revision != r.Revision || d.Template.ID != r.TemplateID || d.Template.Version != int64(r.TemplateVersion) || d.Template.ContentSHA256 != hex.EncodeToString(r.TemplateContentSha256) || !r.ApprovedAt.Valid {
		return d, p, ErrUnavailable
	}
	p, err = presign.DecodePolicy(r.CanonicalPolicy)
	if err != nil {
		return d, p, ErrUnavailable
	}
	expected, err := buildPolicy(d, r.ApprovedBy, r.ApprovedAt.Time)
	if err != nil || p.Commitment() != expected.Commitment() || p.Commitment() != hex.EncodeToString(r.PolicySha256) || !bytes.Equal(p.CanonicalJSON(), r.CanonicalPolicy) {
		return d, p, ErrUnavailable
	}
	return d, p, nil
}

func validateLiveDefinition(s *transactionState, d WorkflowDefinition) error {
	u, err := s.q.GetUserForShare(s.ctx, generated.GetUserForShareParams{ID: d.Executor.UserID, OrgID: s.actor.orgID})
	if err != nil {
		return lookupError(err)
	}
	if !eligible(u) {
		return auth.ErrMutationPermissionRevoked
	}
	if d.Executor.Kind == presign.ExecutorAPIKey {
		credential, err := s.q.GetPresignExecutorAPIKeyForShare(s.ctx, generated.GetPresignExecutorAPIKeyForShareParams{OrgID: s.actor.orgID, UserID: d.Executor.UserID, ID: d.Executor.CredentialID})
		if err != nil {
			return lookupError(err)
		}
		now, err := clock(s)
		if err != nil {
			return err
		}
		if !credential.ExpiresAt.Valid || !now.Before(credential.ExpiresAt.Time) {
			return auth.ErrMutationCredentialExpired
		}
		author, workflow := false, false
		for _, v := range credential.Scopes {
			if v == "admin" || v == "write" {
				author = true
				workflow = true
			}
			author = author || v == "write:authoring"
			workflow = workflow || v == "write:workflow"
		}
		if !author || !workflow {
			return auth.ErrMutationPermissionRevoked
		}
	}
	// The selected historical revision lock alone does not freeze archival.
	if _, err := s.q.GetTemplateForShare(s.ctx, generated.GetTemplateForShareParams{ID: d.Template.ID, OrgID: s.actor.orgID}); err != nil {
		return lookupError(err)
	}
	r, err := s.q.GetHTMLTemplateRevisionForShare(s.ctx, generated.GetHTMLTemplateRevisionForShareParams{TemplateID: d.Template.ID, OrgID: s.actor.orgID, Version: int32(d.Template.Version)})
	if err != nil {
		return lookupError(err)
	}
	if !r.ApprovedBy.Valid || !r.ApprovedAt.Valid || uuid.UUID(r.ApprovedBy.Bytes) != d.Template.ApprovedBy || !r.ApprovedAt.Time.Equal(d.Template.ApprovedAt) || hex.EncodeToString(r.ContentSha256) != d.Template.ContentSHA256 {
		return ErrConflict
	}
	if err := ValidateDefinitionAgainstTemplate(d, r.HtmlMasterJson, r.VariablesJson); err != nil {
		return err
	}
	if c := d.DataRules.CRM; c != nil {
		row, err := s.q.GetCRMConnectionByOrgForShare(s.ctx, s.actor.orgID)
		if err != nil {
			return lookupError(err)
		}
		if row.ID != c.ConnectionID || row.Generation != c.Generation || row.Status != "active" || row.Origin != c.Origin || row.CrmTeamID != c.TeamID || row.CrmUserID != c.UserID {
			return ErrConflict
		}
	}
	return nil
}

func validateWorkflowHead(s *transactionState, in WorkflowIntent) error {
	h, err := s.q.GetPresignWorkflowHeadForUpdate(s.ctx, generated.GetPresignWorkflowHeadForUpdateParams{OrgID: s.actor.orgID, ID: in.Definition.ID})
	if in.ExpectedRevision == 0 {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return ErrConflict
	}
	if err != nil {
		return lookupError(err)
	}
	if h.ArchivedAt.Valid || h.CurrentRevision != in.ExpectedRevision {
		return ErrConflict
	}
	r, err := s.q.GetPresignWorkflowRevisionForShare(s.ctx, generated.GetPresignWorkflowRevisionForShareParams{OrgID: s.actor.orgID, WorkflowID: h.ID, Revision: h.CurrentRevision})
	if err != nil {
		return err
	}
	_, _, err = decodeWorkflow(r)
	if err != nil {
		return err
	}
	if r.PolicyID != in.Definition.PolicyID {
		return ErrConflict
	}
	return nil
}

func (e *Engine) PreviewWorkflow(ctx context.Context, a SessionActor, in WorkflowIntent) (WorkflowPreview, error) {
	var out WorkflowPreview
	if err := witness(a, in.ExpectedOrgID, in.ExpectedUserID, in.RequestID); err != nil {
		return out, err
	}
	in, err := normalizedWorkflow(in)
	if err != nil {
		return out, err
	}
	digest, _ := commandDigest(OperationApproveWorkflow, in)
	err = e.transaction(ctx, a, func(s *transactionState) error {
		if s.user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		if err := validateLiveDefinition(s, in.Definition); err != nil {
			return err
		}
		if err := validateWorkflowHead(s, in); err != nil {
			return err
		}
		_, hash, rules, _ := CanonicalDefinition(in.Definition)
		token, expiry, err := e.mint(s, workflowPurpose, in.RequestID, digest, "")
		if err != nil {
			return err
		}
		out = WorkflowPreview{OrgID: a.orgID, UserID: a.userID, Intent: in, DefinitionSHA256: hash, Rules: rules, Receipt: token, ExpiresAt: expiry}
		return nil
	})
	return out, err
}

func (e *Engine) ApproveWorkflow(ctx context.Context, a SessionActor, input ConfirmWorkflowInput) (Outcome, error) {
	var out Outcome
	in := input.Intent
	if err := witness(a, in.ExpectedOrgID, in.ExpectedUserID, in.RequestID); err != nil {
		return out, err
	}
	if !input.Confirmed {
		return out, invalid("explicit workflow approval")
	}
	in, err := normalizedWorkflow(in)
	if err != nil {
		return out, err
	}
	digest, _ := commandDigest(OperationApproveWorkflow, in)
	err = e.transaction(ctx, a, func(s *transactionState) error {
		prior, err := priorRequest(s, in.RequestID, OperationApproveWorkflow, digest)
		if err != nil {
			return err
		}
		if prior != nil {
			out = *prior
			return nil
		}
		if s.user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		if err := e.verify(s, workflowPurpose, input.Receipt, in.RequestID, digest, ""); err != nil {
			return err
		}
		if err := validateLiveDefinition(s, in.Definition); err != nil {
			return err
		}
		if err := validateWorkflowHead(s, in); err != nil {
			return err
		}
		d := in.Definition
		now, err := clock(s)
		if err != nil {
			return err
		}
		policy, err := buildPolicy(d, a.userID, now)
		if err != nil {
			return invalid("confirmed policy snapshot")
		}
		raw, hash, _, _ := CanonicalDefinition(d)
		if in.ExpectedRevision == 0 {
			_, err = s.q.InsertPresignWorkflowHead(s.ctx, generated.InsertPresignWorkflowHeadParams{OrgID: a.orgID, ID: d.ID, Name: d.Name})
		} else {
			_, err = s.q.AdvancePresignWorkflowHead(s.ctx, generated.AdvancePresignWorkflowHeadParams{OrgID: a.orgID, ID: d.ID, Name: d.Name, CurrentRevision: in.ExpectedRevision})
		}
		if err != nil {
			return err
		}
		_, err = s.q.InsertPresignWorkflowRevision(s.ctx, generated.InsertPresignWorkflowRevisionParams{OrgID: a.orgID, WorkflowID: d.ID, Revision: d.Revision, PolicyID: d.PolicyID, CanonicalDefinition: raw, DefinitionSha256: unhex(hash), CanonicalPolicy: policy.CanonicalJSON(), PolicySha256: unhex(policy.Commitment()), TemplateID: d.Template.ID, TemplateVersion: int32(d.Template.Version), TemplateContentSha256: unhex(d.Template.ContentSHA256), ApprovedBy: a.userID, ApprovedAt: timestamp(now)})
		if err != nil {
			return err
		}
		out, err = finishMutation(s, in.RequestID, OperationApproveWorkflow, digest, "workflow", presign.Reference{ID: d.ID, Revision: d.Revision, SHA256: hash})
		s.final = func() error {
			if err := validateLiveDefinition(s, d); err != nil {
				return err
			}
			return e.verify(s, workflowPurpose, input.Receipt, in.RequestID, digest, "")
		}
		return err
	})
	return out, err
}

func (e *Engine) workflowStateMutation(ctx context.Context, a SessionActor, in ResourceMutationInput, archive bool) (Outcome, error) {
	var out Outcome
	if err := witness(a, in.ExpectedOrgID, in.ExpectedUserID, in.RequestID); err != nil {
		return out, err
	}
	if !in.Confirmed || in.Reference.ID == uuid.Nil || in.Reference.Revision < 1 || !validSHA(in.Reference.SHA256) {
		return out, invalid("exact confirmed workflow reference")
	}
	op := OperationRetireWorkflow
	if archive {
		op = OperationArchiveWorkflow
	}
	digest, _ := commandDigest(op, in)
	err := e.transaction(ctx, a, func(s *transactionState) error {
		prior, err := priorRequest(s, in.RequestID, op, digest)
		if err != nil {
			return err
		}
		if prior != nil {
			out = *prior
			return nil
		}
		if s.user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		h, err := s.q.GetPresignWorkflowHeadForUpdate(s.ctx, generated.GetPresignWorkflowHeadForUpdateParams{OrgID: a.orgID, ID: in.Reference.ID})
		if err != nil {
			return lookupError(err)
		}
		r, err := s.q.GetPresignWorkflowRevisionForShare(s.ctx, generated.GetPresignWorkflowRevisionForShareParams{OrgID: a.orgID, WorkflowID: h.ID, Revision: in.Reference.Revision})
		if err != nil {
			return lookupError(err)
		}
		if _, _, err := decodeWorkflow(r); err != nil {
			return err
		}
		if hex.EncodeToString(r.DefinitionSha256) != in.Reference.SHA256 || h.ArchivedAt.Valid {
			return ErrConflict
		}
		var changed int64
		if archive {
			if h.CurrentRevision != in.Reference.Revision {
				return ErrConflict
			}
			changed, err = s.q.ArchivePresignWorkflow(s.ctx, generated.ArchivePresignWorkflowParams{OrgID: a.orgID, ID: h.ID, CurrentRevision: h.CurrentRevision})
		} else {
			changed, err = s.q.RetirePresignWorkflowRevision(s.ctx, generated.RetirePresignWorkflowRevisionParams{OrgID: a.orgID, WorkflowID: h.ID, Revision: in.Reference.Revision, RetiredBy: a.userID})
		}
		if err != nil {
			return err
		}
		if changed != 1 {
			return ErrConflict
		}
		out, err = finishMutation(s, in.RequestID, op, digest, "workflow", in.Reference)
		return err
	})
	return out, err
}

func (e *Engine) RetireWorkflow(ctx context.Context, a SessionActor, in ResourceMutationInput) (Outcome, error) {
	return e.workflowStateMutation(ctx, a, in, false)
}
func (e *Engine) ArchiveWorkflow(ctx context.Context, a SessionActor, in ResourceMutationInput) (Outcome, error) {
	return e.workflowStateMutation(ctx, a, in, true)
}
