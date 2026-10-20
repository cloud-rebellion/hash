// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ownedaudit

import (
	"context"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// A package event can only be produced by the actual native response work.
// Historical generic event constructors cannot append this expanded schema.
func LogPackageResponseV1(l *audit.Logger, ctx context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, e audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || work == nil || e.DocumentID == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrPackageResponseRequestV1
	}
	owner, err := work.NewPackageResponseAuditV1(ctx, e.Kind, e.IP, e.UserAgent, e.Payload)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	return logPreparedOwnerV1(l, ctx, owner, e)
}
