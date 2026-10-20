// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package packageauthoring

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"time"
)

// Caller owns successful result through the synchronous response, then CloseV1.
func PreviewV1(ctx context.Context, d DependenciesV1, actor authoring.Actor, root, member uuid.UUID, expected pdfadmission.DocumentPackagePreviewExpectedV1) (result *pdfadmission.ApplicationDocumentPackagePreviewV1, failure error) {
	if d.Sessions == nil || d.Storage == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, pdfadmission.ErrDocumentPackageInputV1
	}
	result, failure = d.Sessions.NewDocumentPackagePreviewV1(ctx, actor.OrgID, root, member, actor.UserID, d.Storage, expected)
	defer func() {
		if failure != nil && result != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			failure = errors.Join(failure, result.CloseV1(cleanup))
			result = nil
		}
	}()
	if failure != nil {
		return result, failure
	}
	failure = result.LoadV1(func(call context.Context, db generated.DBTX, reader *pdfadmission.ApplicationHTMLRevisionReaderV1) (func(context.Context) error, error) {
		guard, e := readStaffDraftRootV1(call, db, reader, actor, root)
		if e != nil {
			return nil, e
		}
		return guard.Recheck, nil
	})
	if errors.Is(failure, pdfadmission.ErrDocumentPackagePendingPrivacyV1) {
		failure = errors.Join(authoring.ErrPendingPrivacyReview, failure)
	}
	if errors.Is(failure, pdfadmission.ErrDocumentPackagePrivacyChangingV1) {
		failure = errors.Join(authoring.ErrPrivacyReviewChanging, failure)
	}
	return result, failure
}
