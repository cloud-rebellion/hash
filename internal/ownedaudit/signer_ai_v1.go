// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ownedaudit

import (
	"context"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

func LogSignerAIRequestV1(l *audit.Logger, ctx context.Context, w *pdfadmission.ApplicationDocumentAIWorkV1, clarifier bool) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || w == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	id, err := w.AuditIdentityV1()
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	if id.ActorID != uuid.Nil || id.RecipientID == uuid.Nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	owner, err := w.NewSignerRequestAuditV1(ctx, clarifier)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	doc, rec := id.DocumentID, id.RecipientID
	return logPreparedOwnerV1(l, ctx, owner, audit.Entry{OrgID: id.OrgID, DocumentID: &doc, RecipientID: &rec})
}
func LogSignerAICostV1(l *audit.Logger, ctx context.Context, c *pdfadmission.ApplicationDocumentAICostV1) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || c == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	id, err := c.AuditIdentityV1()
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	if id.ActorID != uuid.Nil || id.RecipientID == uuid.Nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	owner, err := c.NewAuditV1(ctx)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	doc, rec := id.DocumentID, id.RecipientID
	return logPreparedOwnerV1(l, ctx, owner, audit.Entry{OrgID: id.OrgID, DocumentID: &doc, RecipientID: &rec})
}
func LogSignerAIAnswerV1(l *audit.Logger, ctx context.Context, w *pdfadmission.ApplicationDocumentAIWorkV1, r *pdfadmission.ApplicationDocumentAIRequestReceiptV1, shield bool, latency, input, output int) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || w == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	id, err := w.AuditIdentityV1()
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	if id.ActorID != uuid.Nil || id.RecipientID == uuid.Nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrDocumentAIAuditV1
	}
	owner, err := w.NewSignerAnswerAuditV1(ctx, r, shield, latency, input, output)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	doc, rec := id.DocumentID, id.RecipientID
	return logPreparedOwnerV1(l, ctx, owner, audit.Entry{OrgID: id.OrgID, DocumentID: &doc, RecipientID: &rec})
}
