// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package packageauthoring

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http"
	"time"
)

type DependenciesV1 struct {
	Sessions *pdfadmission.ApplicationSessionFactoryV1
	Storage  *storage.Client
	Audit    *audit.Logger
}
type OutcomeV1 struct {
	Layout                 *pdfadmission.DocumentPackageLayoutResultV1     `json:"layout,omitempty"`
	State                  string                                          `json:"state"`
	Attachment             *pdfadmission.DocumentPackageAttachmentResultV1 `json:"attachment,omitempty"`
	ReconciliationRequired bool                                            `json:"reconciliation_required"`
	Message                string                                          `json:"message,omitempty"`
	Cause                  error                                           `json:"-"`
}

// The caller retains the same input owner through response serialization.
// Choices are consumed once on their original bounded context; PDF/report pins
// cannot enter through this transport-neutral service.
func SelectV1(ctx context.Context, d DependenciesV1, actor authoring.Actor, input *pdfadmission.ApplicationDocumentPackageInputV1, ip, ua string) (out OutcomeV1, failure error) {
	if d.Sessions == nil || d.Storage == nil || d.Audit == nil || input == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return out, pdfadmission.ErrDocumentPackageOperationV1
	}
	failure = input.WithSelectionV1(ctx, actor.OrgID, func(in pdfadmission.DocumentPackageSelectionInputV1) (err error) {
		op, e := d.Sessions.NewDocumentPackageOperationV1(ctx, actor.OrgID, in.Root, in.Member, actor.UserID, d.Storage)
		defer func() {
			if op == nil {
				return
			}
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			closeErr := op.CloseV1(cleanup)
			if closeErr == nil {
				return
			}
			if op.CommitAcknowledgedV1() || out.State == "unknown" {
				out.ReconciliationRequired = true
				out.Cause = errors.Join(out.Cause, closeErr)
			} else {
				err = errors.Join(err, closeErr)
			}
		}()
		if e != nil {
			return e
		}
		policy := func(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1) (func(context.Context) error, error) {
			_, guards, e := ReadDraftSelectionV1(call, db, owner, actor, [2]uuid.UUID{in.Root, in.Member}, in.Expected, in.Draft)
			if e != nil {
				return nil, e
			}
			return func(c context.Context) error {
				for _, guard := range guards {
					if e := guard.Recheck(c); e != nil {
						return e
					}
				}
				return c.Err()
			}, nil
		}
		if e = op.ReadSourcesV1(policy); e != nil {
			return e
		}
		result, e := ownedaudit.SelectDocumentPackageAttachmentV1(d.Audit, op, policy, in.Intent, audit.Entry{OrgID: actor.OrgID, DocumentID: &in.Root, IP: ip, UserAgent: ua})
		if op.CommitAcknowledgedV1() && result.EventID != uuid.Nil {
			out = OutcomeV1{State: "committed", Attachment: &result, ReconciliationRequired: e != nil, Cause: e}
			if e != nil {
				out.Message = "Attachment saved. Refresh before making another change."
			}
			return nil
		}
		if op.CommitDispatchedV1() {
			out = OutcomeV1{State: "unknown", ReconciliationRequired: true, Message: "The save outcome is unknown. Refresh the agreement attachments before retrying.", Cause: e}
			return nil
		}
		return e
	})
	return out, failure
}
func PublicErrorV1(err error) (int, string) {
	switch {
	case errors.Is(err, pdfadmission.ErrDocumentPackageInputTooLargeV1), errors.Is(err, pdfadmission.ErrDocumentPackageLayoutInputTooLargeV1):
		return http.StatusRequestEntityTooLarge, "attachment selection request is too large"
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		return http.StatusUnauthorized, "the original login has expired"
	case errors.Is(err, workguard.ErrUnavailableV1):
		return http.StatusServiceUnavailable, "attachment processing capacity is unavailable"
	case errors.Is(err, pdfadmission.ErrDocumentPackageInputV1):
		return http.StatusBadRequest, "invalid attachment selection request"
	case errors.Is(err, auth.ErrMutationPermissionRevoked), errors.Is(err, auth.ErrDocScopeMismatch):
		return http.StatusForbidden, "attachment selection is not permitted"
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, authoring.ErrDocumentNotFound):
		return http.StatusNotFound, "document not found"
	case errors.Is(err, ErrChangedV1), errors.Is(err, pdfadmission.ErrDocumentPackageSourceChangedV1):
		return http.StatusConflict, "document or attachments changed; reload and review"
	case errors.Is(err, authoring.ErrDocumentNotDraft), errors.Is(err, authoring.ErrDocumentHasEvidence):
		return http.StatusConflict, "document is not editable"
	case errors.Is(err, authoring.ErrPendingPrivacyReview), errors.Is(err, authoring.ErrPrivacyReviewChanging):
		return http.StatusConflict, "document changes await privacy review"
	case errors.Is(err, htmlsource.ErrReviewRequired), errors.Is(err, htmlsource.ErrInvalid), errors.Is(err, htmlmaterialization.ErrInvalid), errors.Is(err, pdfadmission.ErrDocumentPackageWriteV1), errors.Is(err, pdfadmission.ErrDocumentPackageDraftV1):
		return http.StatusConflict, "attachment is not eligible or its position is occupied; reload and review"
	case errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1):
		return http.StatusUnprocessableEntity, "the exact attachment package could not be verified"
	default:
		return http.StatusServiceUnavailable, "attachment selection could not be completed"
	}
}
