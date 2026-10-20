// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// The real upload handler alone allocated templateID and wrote this exact
// storage version before its original member/credential SQL stage. Fresh row,
// source measurement, org-only audit append and real publication share the
// native physical owner; no caller row or cached size supplies write authority.
func (s *Server) finishOwnedPDFTemplateUploadV1(w http.ResponseWriter, r *http.Request, userID, orgID, templateID uuid.UUID, name, key string, stored storage.StoredObject, report sanitize.Report, pageCount int, size int64) {
	committed, commitAttempted := false, false
	var session *pdfadmission.ApplicationSessionV1
	var admission *pdfadmission.ApplicationAdmissionV1
	var reader *pdfadmission.ApplicationHTMLAuthoringReaderV1
	var writer *pdfadmission.ApplicationPDFTemplateCreationV1
	defer func() {
		if writer != nil {
			writer.CloseConsumerV1()
		}
		if reader != nil {
			reader.CloseConsumerV1()
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		if session != nil {
			_ = session.CloseV1(cleanup)
		}
		if admission != nil {
			_, _ = admission.ReconcileCleanupV1(cleanup)
		}
	}()
	fail := func(operation string, cause error) {
		if !committed && !commitAttempted {
			cleanupErr := errors.New("storage unavailable for orphan cleanup")
			if s.Storage != nil {
				cleanupErr = deleteObjectDetached(r.Context(), s.Storage, cleanupObjectVersion{Key: key, VersionID: stored.VersionID, SHA256: stored.SHA256[:]})
			}
			if cleanupErr != nil {
				writeInternalErrorMsg(w, "create template failed; orphan cleanup failed", errors.Join(cause, cleanupErr))
				return
			}
		}
		s.writeTemplateMutationError(w, operation, cause)
	}
	authorize, err := s.sessionDraftAuthorization(r, orgID, userID)
	if err != nil {
		fail("create template failed", err)
		return
	}
	if s.HTMLCreationSessions == nil || s.Audit == nil {
		fail("create template failed", errors.New("native PDF template creation unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	session, err = s.HTMLCreationSessions.OpenV1(ctx, orgID, templateID)
	if err != nil {
		fail("create template failed", err)
		return
	}
	admission, err = session.NewAdmissionV1(ctx)
	if err != nil {
		fail("create template failed", err)
		return
	}
	var tpl *generated.Template
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		writer, err = session.NewPDFTemplateCreationV1(call, reader)
		if err != nil {
			return err
		}
		if err = reader.AcquireActorV1(call, orgID, userID, false); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrMutationPermissionRevoked
			}
			return err
		}
		tx := &nativePDFTemplatePolicyTxV1{DBTX: db}
		guard, err := authoring.LockAuthor(call, tx, authoring.Actor{OrgID: orgID, UserID: userID, Authorize: authorize})
		if err != nil {
			return err
		}
		proof, err := authoring.BindPDFTemplateSanitization(report, key, stored.SHA256[:], stored.VersionID, int32(pageCount))
		if err != nil {
			return err
		}
		tpl, err = writer.CreatePDFTemplateV1(call, generated.CreatePDFTemplateParams{OrgID: orgID, Name: name, PdfStorageKey: pgtype.Text{String: key, Valid: true}, PdfSha256: stored.SHA256[:], PdfStorageVersionID: pgtype.Text{String: stored.VersionID, Valid: true}, EvidenceVersionPinRequired: true, PageCount: pgtype.Int4{Int32: int32(pageCount), Valid: true}, FieldsJson: json.RawMessage(`[]`), CreatedBy: userID, PdfSanitizationReport: proof})
		if err != nil {
			return err
		}
		if err = writer.MeasureFreshSourceV1(call); err != nil {
			return err
		}
		if err = writer.LogUploadCreatedV1(call, s.Audit, size); err != nil {
			return err
		}
		return guard.Recheck(call)
	})
	if err != nil {
		fail("create template failed", err)
		return
	}
	commitAttempted = true
	if err = session.CommitV1(ctx); err != nil {
		s.writeTemplateMutationError(w, "commit template creation failed", err)
		return
	}
	committed = true
	if err = writer.PublishV1(s.Audit); err != nil {
		s.writeTemplateMutationError(w, "publish template creation failed", err)
		return
	}
	writeTemplateResponse(w, http.StatusCreated, tpl)
}
