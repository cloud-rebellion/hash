// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ownedaudit

import (
	"context"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// Fixed original automation event order and payloads come only from the actual
// fresh producer. Hash/append/M94 and joined publication use the existing path.
func LogAutomationMaterializationV1(logger *audit.Logger, ctx context.Context, producer *pdfadmission.ApplicationAutomationAuditsV1, scope audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if logger == nil || producer == nil || scope.DocumentID == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrAutomationMaterializationV1
	}
	owner, err := producer.NewNextAuditV1(ctx)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	return logPreparedOwnerV1(logger, ctx, owner, scope)
}
