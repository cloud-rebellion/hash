// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ownedaudit

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

// Fixed selection producer; scope supplies request IP/UA and expected audit
// org/root only. Native state derives actor, schema, every pin and payload.
// Publication is permitted only by the same session's known successful commit.
func SelectDocumentPackageAttachmentV1(logger *audit.Logger, operation *pdfadmission.ApplicationDocumentPackageOperationV1,
	policy pdfadmission.DocumentPackageSourcePolicyV1, intent pdfadmission.DocumentPackageAttachmentIntentV1,
	scope audit.Entry) (pdfadmission.DocumentPackageAttachmentResultV1, error) {
	if logger == nil || operation == nil || scope.DocumentID == nil {
		return pdfadmission.DocumentPackageAttachmentResultV1{}, pdfadmission.ErrDocumentPackageWriteV1
	}
	var pending audit.PendingEvent
	var owner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	result, err := operation.SelectAttachmentV1(policy, intent, scope.IP, scope.UserAgent,
		func(ctx context.Context, actual *pdfadmission.ApplicationHTMLAuditEventConsumerV1) error {
			var e error
			pending, owner, e = logPreparedOwnerV1(logger, ctx, actual, scope)
			return e
		})
	if owner == nil || result.EventID == uuid.Nil || !operation.CommitAcknowledgedV1() {
		if owner != nil {
			owner.CloseConsumerV1()
		}
		return pdfadmission.DocumentPackageAttachmentResultV1{}, errors.Join(pdfadmission.ErrDocumentPackageWriteV1, err)
	}
	publicationErr := PublishV1(logger, pending, owner)
	if publicationErr != nil && owner != nil {
		owner.CloseConsumerV1()
	}
	return result, errors.Join(err, publicationErr)
}

// AppendDocumentPackageLayoutV1 consumes only the actual fixed native event.
// Publication is deliberately separate and requires its acknowledged COMMIT.
func AppendDocumentPackageLayoutV1(logger *audit.Logger, ctx context.Context, owner *pdfadmission.ApplicationHTMLAuditEventConsumerV1, scope audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if logger == nil || owner == nil || scope.DocumentID == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentPackageWriteV1
	}
	return logPreparedOwnerV1(logger, ctx, owner, scope)
}
