// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// This scalar locator is private service coordination, never an execution
// view or fresh authority. Committed readback must use the native document
// owner and full exact retained loader before returning public result fields.
type ExecutionRequestLocatorV1 struct {
	State                   string
	DocumentID, ExecutionID uuid.UUID
}

func executionRequestLocatorV1(s *transactionState, a ExecutionActorV1, request uuid.UUID) (ExecutionRequestLocatorV1, error) {
	var out ExecutionRequestLocatorV1
	row, err := s.q.GetPresignExecutionRequestLocatorV1(s.ctx, generated.GetPresignExecutionRequestLocatorV1Params{OrgID: a.OrgID(), ExecutorKind: a.identity.Kind,
		ExecutorUserID: a.UserID(), ExecutorCredentialID: a.identity.CredentialID, RequestID: request})
	if err != nil {
		return out, lookupError(err)
	}
	out.State = row.State
	document, execution := row.DocumentID, row.ExecutionID
	if out.State == "closed" && !document.Valid && !execution.Valid {
		return out, nil
	}
	if out.State != "committed" || !document.Valid || !execution.Valid {
		return ExecutionRequestLocatorV1{}, ErrUnavailable
	}
	out.DocumentID = uuid.UUID(document.Bytes)
	out.ExecutionID = uuid.UUID(execution.Bytes)
	if out.DocumentID == uuid.Nil || out.ExecutionID == uuid.Nil {
		return ExecutionRequestLocatorV1{}, ErrUnavailable
	}
	return out, nil
}

func (e *Engine) LocateExecutionRequestV1(ctx context.Context, a ExecutionActorV1, request uuid.UUID) (ExecutionRequestLocatorV1, error) {
	var out ExecutionRequestLocatorV1
	if a.session.authorize == nil || request == uuid.Nil {
		return out, auth.ErrMutationPermissionRevoked
	}
	err := e.transaction(ctx, a.session, func(s *transactionState) error {
		var err error
		out, err = executionRequestLocatorV1(s, a, request)
		return err
	})
	return out, err
}

// CloseExecutionRequestV1 reuses the existing authenticated org/member
// transaction and audit path. It locks the ORIGINAL request before checking
// outcomes, so it cannot race a complete execution into a false tombstone.
// No current grant permission is needed to resolve one's retained request.
func (e *Engine) CloseExecutionRequestV1(ctx context.Context, a ExecutionActorV1, request, expectedOrg, expectedUser uuid.UUID, confirmed bool) (ExecutionRequestLocatorV1, error) {
	var out ExecutionRequestLocatorV1
	if a.session.authorize == nil || a.OrgID() != expectedOrg || a.UserID() != expectedUser || request == uuid.Nil || !confirmed {
		return out, ErrInvalid
	}
	err := e.transaction(ctx, a.session, func(s *transactionState) error {
		if err := s.q.LockPresignExecutionRequest(s.ctx, generated.LockPresignExecutionRequestParams{OrgID: a.OrgID(), ExecutorKind: a.identity.Kind,
			ExecutorUserID: a.UserID(), ExecutorCredentialID: a.identity.CredentialID, RequestID: request}); err != nil {
			return err
		}
		prior, err := executionRequestLocatorV1(s, a, request)
		if err == nil {
			out = prior
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		out = ExecutionRequestLocatorV1{State: "closed"}
		actor := a.UserID()
		s.event = &audit.Entry{OrgID: a.OrgID(), ActorUserID: &actor, Kind: "presign.execution.request.closed",
			Payload: map[string]any{"request_id": request, "executor_kind": a.identity.Kind, "executor_user_id": a.UserID(), "executor_credential_id": a.identity.CredentialID}}
		s.final = func() error {
			if s.auditEventID == uuid.Nil {
				return ErrAudit
			}
			if err := s.q.ClosePreparingPresignExecutionRequestV1(s.ctx, generated.ClosePreparingPresignExecutionRequestV1Params{OrgID: a.OrgID(), ExecutorKind: a.identity.Kind,
				ExecutorUserID: a.UserID(), ExecutorCredentialID: a.identity.CredentialID, RequestID: request}); err != nil {
				return err
			}
			_, err := s.q.InsertClosedPresignExecutionRequest(s.ctx, generated.InsertClosedPresignExecutionRequestParams{OrgID: a.OrgID(), ExecutorKind: a.identity.Kind,
				ExecutorUserID: a.UserID(), ExecutorCredentialID: a.identity.CredentialID, RequestID: request, OriginalCredentialSha256: unhex(a.CredentialCommitment()), AuditEventID: s.auditEventID})
			return err
		}
		return nil
	})
	return out, err
}
