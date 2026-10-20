// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ownedaudit

import (
	"context"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

func LogDocumentAIRequestV1(l *audit.Logger, ctx context.Context, w *pdfadmission.ApplicationDocumentAIWorkV1, ip, ua string) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || w == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	identity, err := w.AuditIdentityV1()
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	if identity.ActorID == uuid.Nil || identity.RecipientID != uuid.Nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	owner, err := w.NewRequestAuditV1(ctx, ip, ua)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	doc, actor := identity.DocumentID, identity.ActorID
	return logPreparedOwnerV1(l, ctx, owner, audit.Entry{OrgID: identity.OrgID, DocumentID: &doc, ActorUserID: &actor, Kind: "ai.requested", IP: ip, UserAgent: ua})
}
func LogDocumentAIResultV1(l *audit.Logger, ctx context.Context, w *pdfadmission.ApplicationDocumentAIWorkV1, r *pdfadmission.ApplicationDocumentAIRequestReceiptV1, e audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || w == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	identity, err := w.AuditIdentityV1()
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	if identity.ActorID == uuid.Nil || identity.RecipientID != uuid.Nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	if e.OrgID != identity.OrgID || e.DocumentID == nil || *e.DocumentID != identity.DocumentID || e.ActorUserID == nil || *e.ActorUserID != identity.ActorID || e.RecipientID != nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	owner, err := w.NewResultAuditV1(ctx, r, e.Kind, e.IP, e.UserAgent, e.Payload)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	return logPreparedOwnerV1(l, ctx, owner, e)
}
func LogDocumentAICostV1(l *audit.Logger, ctx context.Context, c *pdfadmission.ApplicationDocumentAICostV1) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || c == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	identity, err := c.AuditIdentityV1()
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	if identity.ActorID == uuid.Nil || identity.RecipientID != uuid.Nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	owner, err := c.NewAuditV1(ctx)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	doc, actor := identity.DocumentID, identity.ActorID
	return logPreparedOwnerV1(l, ctx, owner, audit.Entry{OrgID: identity.OrgID, DocumentID: &doc, ActorUserID: &actor, Kind: "ai.completed"})
}
