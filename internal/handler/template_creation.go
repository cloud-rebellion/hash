// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errTemplateNotFound = errors.New("template not found")

// createTemplateAuthorized binds template creation to the admitted session,
// not just the identity that middleware observed before scanning/storage waits.
func (s *Server) createTemplateAuthorized(r *http.Request, userID, orgID uuid.UUID,
	mutate func(context.Context, *generated.Queries) (*generated.Template, error), event func(*generated.Template) audit.Entry,
) (*generated.Template, error) {
	return s.mutateTemplateAuthorized(r, userID, orgID, uuid.Nil,
		func(ctx context.Context, q *generated.Queries, _ *generated.Template) (*generated.Template, error) {
			return mutate(ctx, q)
		}, event)
}

// mutateTemplateAuthorized locks the current tenant library entry before live
// membership and original-session authorization. This also keeps omitted input
// values tied to the row that is actually updated, not a pre-wait snapshot.
// A nil templateID means creation and therefore needs only the member guard.
func (s *Server) mutateTemplateAuthorized(r *http.Request, userID, orgID, templateID uuid.UUID,
	mutate func(context.Context, *generated.Queries, *generated.Template) (*generated.Template, error), event func(*generated.Template) audit.Entry,
) (*generated.Template, error) {
	authorize, err := s.sessionDraftAuthorization(r, orgID, userID)
	if err != nil {
		return nil, err
	}
	if s.Pool == nil || s.Audit == nil {
		return nil, errors.New("template mutation dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	q := generated.New(tx)
	var current *generated.Template
	if templateID != uuid.Nil {
		current, err = q.GetTemplateForUpdate(ctx, generated.GetTemplateForUpdateParams{ID: templateID, OrgID: orgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errTemplateNotFound
		}
		if err != nil {
			return nil, err
		}
	}
	guard, err := authoring.LockAuthor(ctx, tx, authoring.Actor{OrgID: orgID, UserID: userID, Authorize: authorize})
	if err != nil {
		return nil, err
	}
	template, err := mutate(ctx, q, current)
	if err != nil {
		return nil, err
	}
	if template == nil || template.ID == uuid.Nil || template.OrgID != orgID {
		return nil, errors.New("template mutation returned no tenant-scoped template")
	}
	pending, err := s.Audit.LogTx(ctx, tx, event(template))
	if err != nil {
		return nil, err
	}
	if err := guard.Recheck(ctx); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.Audit.Publish(pending)
	return template, nil
}

func (s *Server) writeTemplateMutationError(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, errTemplateNotFound) {
		writeError(w, http.StatusNotFound, "template not found")
		return
	}
	s.writeDraftAuthoringError(w, operation, err)
}
