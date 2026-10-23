// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ownedaudit

import (
	"context"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// Same native event and acknowledged-COMMIT publication contract. No separate
// audit transaction and no historical participant-report body is expanded.
func AppendLaterAmendmentV1(l *audit.Logger, ctx context.Context, owner *pdfadmission.ApplicationHTMLAuditEventConsumerV1, scope audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || owner == nil || scope.DocumentID == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrHTMLAuditEventV1
	}
	return logPreparedOwnerV1(l, ctx, owner, scope)
}
