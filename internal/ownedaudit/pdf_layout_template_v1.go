// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ownedaudit

import (
	"context"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

func LogPDFLayoutTemplateCreatedV1(logger *audit.Logger, ctx context.Context, producer *pdfadmission.ApplicationPDFLayoutCaptureV1, scope audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if logger == nil || producer == nil || scope.DocumentID == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrPDFLayoutCaptureV1
	}
	owner, err := producer.NewAuditV1(ctx)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	return logPreparedOwnerV1(logger, ctx, owner, scope)
}
