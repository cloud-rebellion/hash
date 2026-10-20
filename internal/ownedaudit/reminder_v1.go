// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ownedaudit

import (
	"context"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

func LogReminderV1(l *audit.Logger, ctx context.Context, producer *pdfadmission.ApplicationReminderV1, scope audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || producer == nil || scope.DocumentID == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrReminderV1
	}
	owner, err := producer.NewNextAuditV1(ctx)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	return logPreparedOwnerV1(l, ctx, owner, scope)
}
