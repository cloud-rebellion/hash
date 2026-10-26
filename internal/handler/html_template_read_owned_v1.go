// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The original transport supplies its live authorization, never a cookie
// substitute. Success retains native source/canonical work until the caller
// closes the consumer AFTER response serialization. SQL cleanup is joined
// before return; errors return neither a response nor a usable consumer.
func (s *Server) readHTMLTemplateDetailOwnedV1(parent context.Context, org, user, id uuid.UUID, authorize auth.TransactionAuthorization) (response templateResponse, closeConsumer func(), failure error) {
	if parent == nil || org == uuid.Nil || user == uuid.Nil || id == uuid.Nil || authorize == nil {
		return response, nil, auth.ErrMutationPermissionRevoked
	}
	ctx, cancel := context.WithTimeout(parent, authoring.MutationTimeout)
	defer cancel()
	o, err := s.openHTMLAuthoringV1(ctx, org, id)
	if err != nil {
		return response, nil, htmlTemplateReadFailureV1(err)
	}
	defer func() {
		failure = errors.Join(failure, o.closeSQLV1(ctx))
		if failure != nil {
			response = templateResponse{}
			closeConsumer = nil
			o.closeConsumerV1(ctx)
			failure = htmlTemplateReadFailureV1(failure)
		}
	}()
	failure = o.session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		q := generated.New(db)
		tx := &htmlCreationPolicyTxV1{DBTX: db, reader: o.reader}
		// This locked scalar observation supplies the current version, never a
		// caller-provided size. Native reader admission precedes either body.
		header, err := q.GetHTMLAuthoringTemplateHeaderV1(call, generated.GetHTMLAuthoringTemplateHeaderV1Params{TemplateID: id, OrgID: org})
		if err != nil {
			return err
		}
		if err = o.reader.AcquireActorV1(call, org, user, false); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrMutationPermissionRevoked
			}
			return err
		}
		member, err := q.GetUserForShare(call, generated.GetUserForShareParams{ID: user, OrgID: org})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrMutationPermissionRevoked
			}
			return err
		}
		if member == nil || member.ID != user || member.OrgID != org {
			return auth.ErrMutationPermissionRevoked
		}
		switch auth.Role(member.Role) {
		case auth.RoleViewer, auth.RoleSender, auth.RoleOwner:
		default:
			return auth.ErrMutationPermissionRevoked
		}
		copy := *member
		if err = authorize(call, tx, &copy); err != nil {
			return err
		}
		template, revision, err := o.reader.ReadTemplateRevisionV1(call, id, header.Version)
		if err != nil {
			return err
		}
		response, err = toHTMLTemplateDetailResponseOwnedV1(call, o.reader, template, revision)
		if err != nil {
			return err
		}
		copy = *member
		return authorize(call, tx, &copy)
	})
	if failure != nil {
		return templateResponse{}, nil, failure
	}
	closeConsumer = func() { o.closeConsumerV1(ctx) }
	return response, closeConsumer, nil
}

func htmlTemplateReadFailureV1(err error) error {
	switch {
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		return auth.ErrMutationCredentialExpired
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		return auth.ErrMutationPermissionRevoked
	case errors.Is(err, pgx.ErrNoRows):
		return errTemplateNotFound
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		// SQL, parser and connection details may contain private values. Native
		// factory/registry state still retains any unresolved physical cleanup.
		return pdfadmission.ErrHTMLAuthoringReadV1
	}
}
