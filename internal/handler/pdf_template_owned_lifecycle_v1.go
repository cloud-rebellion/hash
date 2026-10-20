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
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/pdftemplateauthoring"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http"
	"time"
)

func (s *Server) readOwnedPDFTemplateV1(w http.ResponseWriter, r *http.Request, user auth.SessionUser, id uuid.UUID) {
	authorize, ok := s.sessionMutationAuthorization(w, r, user)
	if !ok {
		return
	}
	result, err := pdftemplateauthoring.ReadV1(r.Context(), s.HTMLCreationSessions, pdftemplateauthoring.ReadActorV1{OrgID: user.OrgID, UserID: user.UserID, Authorize: authorize}, id)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		if errors.Is(err, pdftemplateauthoring.ErrTemplateNotFoundV1) {
			writeError(w, http.StatusNotFound, "template not found")
		} else if errors.Is(err, auth.ErrMutationPermissionRevoked) || errors.Is(err, auth.ErrMutationCredentialExpired) {
			s.writeDraftAuthoringError(w, "read template failed", err)
		} else {
			writeError(w, http.StatusServiceUnavailable, "PDF template temporarily unavailable")
		}
		return
	}
	writeTemplateResponse(w, http.StatusOK, result.Template)
}

// Supplied unrelated blocks/variables retain the outer handler's original
// validation. The PDF branch changes only fields, exactly as before: omitted
// fields retain the actual locked row; supplied fields use the original layout
// canonicalizer/current verified page count. Name remains ignored in this path.
func (s *Server) finishOwnedPDFTemplateFieldsV1(w http.ResponseWriter, r *http.Request, user, org, id uuid.UUID, fields []byte) {
	authorize, err := s.sessionDraftAuthorization(r, org, user)
	if err != nil {
		s.writeTemplateMutationError(w, "update template failed", err)
		return
	}
	if s.HTMLCreationSessions == nil || s.Audit == nil {
		s.writeTemplateMutationError(w, "update template failed", errors.New("native PDF template mutation unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	var session *pdfadmission.ApplicationSessionV1
	var admission *pdfadmission.ApplicationAdmissionV1
	var reader *pdfadmission.ApplicationHTMLAuthoringReaderV1
	var source *pdfadmission.ApplicationPDFTemplateSourceV1
	var writer *pdfadmission.ApplicationPDFTemplateFieldsMutationV1
	defer func() {
		if writer != nil {
			writer.CloseConsumerV1()
		} else if source != nil {
			source.CloseConsumerV1()
		}
		if reader != nil {
			reader.CloseConsumerV1()
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer stop()
		if session != nil {
			_ = session.CloseV1(cleanup)
		}
		if admission != nil {
			_, _ = admission.ReconcileCleanupV1(cleanup)
		}
	}()
	session, err = s.HTMLCreationSessions.OpenV1(ctx, org, id)
	if err == nil {
		admission, err = session.NewAdmissionV1(ctx)
	}
	var template *generated.Template
	if err == nil {
		err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
			var err error
			reader, err = session.NewHTMLAuthoringReaderV1(call)
			if err != nil {
				return err
			}
			source, err = session.NewPDFTemplateSourceV1(call, reader)
			if err != nil {
				return err
			}
			if err = source.LockUpdateHeaderV1(call, id); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return errTemplateNotFound
				}
				return err
			}
			if err = reader.AcquireActorV1(call, org, user, false); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return auth.ErrMutationPermissionRevoked
				}
				return err
			}
			tx := &nativePDFTemplatePolicyTxV1{DBTX: db}
			guard, err := authoring.LockAuthor(call, tx, authoring.Actor{OrgID: org, UserID: user, Authorize: authorize})
			if err != nil {
				return err
			}
			if _, err = source.ReadLockedUpdateV1(call); err != nil {
				return err
			}
			writer, err = session.NewPDFTemplateFieldsMutationV1(call, source)
			if err != nil {
				return err
			}
			template, err = writer.UpdateFieldsV1(call, fields)
			if err != nil {
				return err
			}
			if err = writer.LogUpdatedV1(call, s.Audit, user); err != nil {
				return err
			}
			return guard.Recheck(call)
		})
	}
	if err == nil {
		err = session.CommitV1(ctx)
	}
	if err == nil {
		err = writer.PublishV1(s.Audit)
	}
	if err != nil {
		if errors.Is(err, pdflayout.ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, pdfadmission.ErrPDFTemplateSourceV1) || errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) || errors.Is(err, pdfadmission.ErrApplicationAdmissionV1) || errors.Is(err, pdfadmission.ErrApplicationSessionV1) {
			writeError(w, http.StatusServiceUnavailable, "PDF template temporarily unavailable")
			return
		}
		s.writeTemplateMutationError(w, "update template failed", err)
		return
	}
	writeTemplateResponse(w, http.StatusOK, template)
}
