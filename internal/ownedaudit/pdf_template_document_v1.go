// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ownedaudit

import (
	"context"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// Fixed original template layout event sequence; its private native producer
// constructs every payload from its genuine prepared source and fresh SQL
// recipient/field/document results. The shared hash/append path is unchanged.
func LogPDFTemplateDocumentV1(logger *audit.Logger, ctx context.Context, producer *pdfadmission.ApplicationPDFTemplateDocumentV1, scope audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if logger == nil || producer == nil || scope.DocumentID == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrPDFTemplateDocumentV1
	}
	owner, err := producer.NewNextAuditV1(ctx)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	return logPreparedOwnerV1(logger, ctx, owner, scope)
}
